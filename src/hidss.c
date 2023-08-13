// Copyright (c) 2023 James Buren
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <limits.h>
#include <errno.h>
#include <hidapi.h>
#include "hidss.h"

#define output(A,...) printf("%s: "A"\n",global.program,__VA_ARGS__)

#if defined(__linux__)
#define LOCK_BASEDIR "/run/hidss/"
#else
#define LOCK_BASEDIR "/var/run/hidss/"
#endif
#define LOCK_BASEDIR_LEN (sizeof(LOCK_BASEDIR)-1)

enum {
    MODE_UNKNOWN,
    MODE_ENUMERATE,
    MODE_COMMAND,
    MODE_UPLOAD,
    MODE_MODEL,
};

enum {
    DEVICE_VID = 0x0483,
    DEVICE_PID = 0x0065,
    HID_HEADER_SIZE = 1,
    HID_REPORT_SIZE = 64,
    HID_WRITE_PACKET_SIZE = HID_HEADER_SIZE + HID_REPORT_SIZE,
    HID_READ_PACKET_SIZE = HID_REPORT_SIZE,
    YMODEM_128_PACKETS = 3,
    YMODEM_1024_PACKETS = 17,
    COMMAND_ARGS = 64,
    TIMEOUT_DEFAULT = 0,
    BRIGHTNESS_DEFAULT = 100,
};

static struct {
    char program[256];
    uid_t uid;
    uid_t euid;
    char upload_path[PATH_MAX];
    char device_path[PATH_MAX];
    intptr_t lock;
    hid_device *device;
    intptr_t mode;
    long timeout;
    long brightness;
} global;

static inline const wchar_t *wsnull(const wchar_t *ws) {
    return ((ws == NULL) ? L"" : ws);
}

static size_t str_copy(char *dst, size_t n, const char *src) {
    char *end = memccpy(dst, src, '\0', n);
    size_t len;

    if(end == NULL) {
        len = n - 1;
        dst[len] = '\0';
    } else {
        len = end - dst - 1;
    }

    return len;
}

static bool str_to_long(const char *s, long *n) {
    char *e;
    errno = 0;
    *n = strtol(s, &e, 0);
    return (errno == 0 && s != e && *e == '\0');
}

static inline bool in_range(long n, long l, long h) {
    return (n >= l && n <= h);
}

static bool packet_write(hid_device *device, const unsigned char buf[static HID_WRITE_PACKET_SIZE]) {
    int rv = hid_write(device, buf, HID_WRITE_PACKET_SIZE);

    if(rv < 0) {
        output("%s: %ls", "hid_write", hid_error(device));
        return false;
    }

    if(rv != HID_WRITE_PACKET_SIZE) {
        output("%s: %s: %d", __func__, "short packet", rv);
        return false;
    }

    return true;
}

static bool packet_read(hid_device *device, unsigned char buf[static HID_READ_PACKET_SIZE], unsigned char byte) {
    int rv = hid_read(device, buf, HID_READ_PACKET_SIZE);

    if(rv < 0) {
        output("%s: %ls", "hid_read", hid_error(device));
        return false;
    }

    if(rv != HID_READ_PACKET_SIZE) {
        output("%s: %s: %d", __func__, "short packet", rv);
        return false;
    }

    if(buf[0] != 0x06 || buf[1] != byte) {
        output("%s: %s", __func__, "unexpected response");
        return false;
    }

    return true;
}

static bool file_get_contents(const char *path, unsigned char **data, long *data_size, long low, long high) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if(fd == -1) {
        output("%s: %s", "open", strerror(errno));
        goto err_0;
    }

    struct stat st;

    if(fstat(fd, &st) == -1) {
        output("%s: %s", "fstat", strerror(errno));
        goto err_1;
    }

    long size = st.st_size;

    if(!in_range(size, low, high)) {
        output(
            "size of %s not in range of %d to %d",
            path,
            HIDSS_THEME_MIN_SIZE,
            HIDSS_THEME_MAX_SIZE
        );
        goto err_1;
    }

    unsigned char *buf = malloc(size);

    if(buf == NULL) {
        output("%s: %s", "malloc", strerror(errno));
        goto err_1;
    }

    ssize_t n = read(fd, buf, size);

    if(n < 0) {
        output("%s: %s", "read", strerror(errno));
        goto err_2;
    }

    if(n != size) {
        output("failed to read whole file: %s", path);
        goto err_2;
    }

    close(fd);

    *data = buf;
    *data_size = size;

    return true;

err_2:
    free(buf);
err_1:
    close(fd);
err_0:
    return false;
}

static void mode_set(int mode, int *mode_sets) {
    global.mode = mode;
    (*mode_sets)++;
}

static bool privileges_drop(void) {
    if(seteuid(global.uid) == -1) {
        output("%s: %s", "seteuid", strerror(errno));
        return false;
    }
    return true;
}

static bool privileges_restore(void) {
    if(seteuid(global.euid) == -1) {
        output("%s: %s", "seteuid", strerror(errno));
        return false;
    }
    return true;
}

static bool device_lock(void) {
    const char *dp = global.device_path;

    if(strncmp(dp, "/dev/", 5) == 0) {
        dp += 5;
    }

    if(strchr(dp, '/') != NULL) {
        output("%s", "device path cannot contain a /");
        return false;
    }

    if(mkdir(LOCK_BASEDIR, 0750) == -1 && errno != EEXIST) {
        output("%s: %s", "mkdir", strerror(errno));
        return false;
    }

    char path[PATH_MAX];

    str_copy(path, sizeof(path), LOCK_BASEDIR);
    str_copy(path + LOCK_BASEDIR_LEN, sizeof(path) - LOCK_BASEDIR_LEN, dp);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);

    if(fd == -1) {
        output("%s: %s", "open", strerror(errno));
        return false;
    }

    if(flock(fd, LOCK_EX | LOCK_NB) == -1) {
        output("%s: %s", "flock", strerror(errno));
        close(fd);
        return false;
    }

    global.lock = fd;

    return true;
}

static bool device_first_path(char path[static PATH_MAX]) {
    struct hid_device_info *dis = hid_enumerate(DEVICE_VID, DEVICE_PID);

    if(dis == NULL) {
        return false;
    }

    str_copy(path, PATH_MAX, dis->path);

    hid_free_enumeration(dis);

    return true;
}

static bool device_find_path(const char *path) {
    struct hid_device_info *dis = hid_enumerate(DEVICE_VID, DEVICE_PID);
    bool found = false;

    for(struct hid_device_info *di = dis; di != NULL; di = di->next) {
        if(strcmp(di->path, path) == 0) {
            found = true;
            break;
        }
    }

    hid_free_enumeration(dis);

    return found;
}

static bool device_open(hid_device **device) {
    char (*path)[PATH_MAX] = &global.device_path;

    if(**path == '\0') {
        if(!device_first_path(*path)) {
            output("%s", "non-existent device path");
            return false;
        }
    } else {
        if(!device_find_path(*path)) {
            output("%s", "non-existent device path");
            return false;
        }
    }

    if(!device_lock()) {
        return false;
    }

    if((*device = hid_open_path(*path)) == NULL) {
        output("%s: %ls", "hid_open_path", hid_error(NULL));
        return false;
    }

    global.device = *device;

    return true;
}

static bool device_reopen(time_t delay, hid_device **device) {
    hid_close(global.device);

    global.device = NULL;

    struct timespec req = {
        .tv_sec = delay,
        .tv_nsec = 0,
    };
    struct timespec rem;

    while(nanosleep(&req, &rem) == -1) {
        req = rem;
    }

    if((*device = hid_open_path(global.device_path)) == NULL) {
        output("%s: %ls", "hid_open_path", hid_error(NULL));
        return false;
    }

    global.device = *device;

    return true;
}

static bool device_command(bool add_header, const char *command, hid_device *device) {
    // Command Report (max of 64 bytes)
    // u8: 0x01 (report id) (optional in some cases)
    // u8: variable length string (command)
    // rest is null padding
    unsigned char buf[HID_WRITE_PACKET_SIZE];
    unsigned char *pos = buf;
    unsigned char *end = buf + sizeof(buf);

    *pos++ = 0x00;

    if(add_header) {
        *pos++ = 0x01;
    }

    while(*command != '\0') {
        *pos++ = *command++;
    }

    *pos++ = '\0';

    memset(pos, 0x00, end - pos);

    if(!packet_write(device, buf)) {
        return false;
    }

    return true;
}

static bool device_boot_mode(unsigned char buf[static HID_READ_PACKET_SIZE], hid_device **device) {
    if(!device_command(true, "model", *device)) {
        return false;
    }

    int rv = hid_read_timeout(*device, buf, HID_READ_PACKET_SIZE, 100);

    if(rv == HID_READ_PACKET_SIZE) {
        return true;
    }

    if(!privileges_restore()) {
        return false;
    }

    if(!device_reopen(5, device)) {
        return false;
    }

    if(!privileges_drop()) {
        return false;
    }

    if(!device_command(true, "model", *device)) {
        return false;
    }

    rv = hid_read(*device, buf, HID_READ_PACKET_SIZE);

    if(rv < 0) {
        output("%s: %ls", "hid_read", hid_error(*device));
        return false;
    }

    if(rv != HID_READ_PACKET_SIZE) {
        output("%s: %s: %d", "packet_read", "short packet", rv);
        return false;
    }

    return true;
}

static bool device_ymodem_mode(hid_device *device) {
    if(!device_command(true, "reset", device)) {
        return false;
    }

    if(!device_command(false, "ymodem", device)) {
        return false;
    }

    unsigned char buf[HID_READ_PACKET_SIZE];

    if(!packet_read(device, buf, 0x43)) {
        return false;
    }

    return true;
}

static void ymodem_crc(unsigned char *buf, long size) {
    static const unsigned short table[256] = {
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
        0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
        0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
        0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
        0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
        0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
        0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
        0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
        0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
        0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
        0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
        0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
        0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
        0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
        0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
        0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
        0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
        0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
        0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
        0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
        0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
        0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
        0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
        0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
        0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
    };
    unsigned char *pos = buf + 3;
    unsigned short crc = 0x0000;

    for(long i = 0; i < size; i++) {
        crc = (table[(crc >> 8) ^ *pos++] ^ (crc << 8));
    }

    *pos++ = ((crc & 0xff00) >> 8);
    *pos++ = ((crc & 0x00ff) >> 0);
}

static bool ymodem_metadata_block(const char *filename, long size, hid_device *device) {
    // u8: 0x01 (128 byte data block)
    // u8: 0x00 (frame number)
    // u8: 0xff (complement of frame number)
    // u8: filename (variable length string, null terminated)
    // u8: filesize (variable length string, null terminated)
    // null padding for remainder of data block
    // u8: upper byte of CRC16 for data block
    // u8: lower byte of CRC16 for data block
    // null padding for extraneous bytes
    unsigned char block[YMODEM_128_PACKETS * HID_REPORT_SIZE];
    unsigned char *pos = block;
    unsigned char *data_end = block + 3 + 128;
    unsigned char *block_end = block + sizeof(block);

    *pos++ = 0x01;
    *pos++ = 0x00;
    *pos++ = 0xff;

    while(*filename != '\0') {
        *pos++ = *filename++;
    }

    *pos++ = '\0';

    if(size >= 0) {
        pos += 1 + sprintf((char *) pos, "%ld", size);
    }

    memset(pos, 0x00, data_end - pos);

    ymodem_crc(block, 128);

    pos = data_end + 2;

    memset(pos, 0x00, block_end - pos);

    unsigned char buf[HID_WRITE_PACKET_SIZE];

    for(size_t i = 0; i < YMODEM_128_PACKETS; i++) {
        buf[0] = 0x00;
        memcpy(&buf[1], &block[i * HID_REPORT_SIZE], HID_REPORT_SIZE);

        if(!packet_write(device, buf)) {
            return false;
        }
    }

    if(!packet_read(device, buf, (size >= 0) ? 0x43 : 0x00)) {
        return false;
    }

    return true;
}

static bool ymodem_data_block(unsigned char *frame, long *size, unsigned char **data, hid_device *device) {
    // u8: 0x02 (1024 byte data block)
    // u8: 0x01 (frame number)
    // u8: 0xfe (complement of frame number)
    // u8: up to 1024 bytes of user data, padded with 0x1A if needed
    // u8: upper byte of CRC16 for data block
    // u8: lower byte of CRC16 for data block
    // null padding for extraneous bytes
    unsigned char block[YMODEM_1024_PACKETS * HID_REPORT_SIZE];
    unsigned char *pos = block;
    unsigned char *data_end = block + 3 + 1024;
    unsigned char *block_end = block + sizeof(block);

    *pos++ = 0x02;
    *pos++ = *frame;
    *pos++ = ~*frame;
    *frame += 1;

    if(*size >= 1024) {
        memcpy(pos, *data, 1024);
        *size -= 1024;
        pos += 1024;
        *data += 1024;
    } else {
        memcpy(pos, *data, *size);
        pos += *size;
        *data += *size;
        *size = 0;
        memset(pos, 0x1A, data_end - pos);
    }

    ymodem_crc(block, 1024);

    pos = data_end + 2;

    memset(pos, 0x00, block_end - pos);

    unsigned char buf[HID_WRITE_PACKET_SIZE];

    for(size_t i = 0; i < YMODEM_1024_PACKETS; i++) {
        buf[0] = 0x00;
        memcpy(&buf[1], &block[i * HID_REPORT_SIZE], HID_REPORT_SIZE);

        if(!packet_write(device, buf)) {
            return false;
        }
    }

    if(!packet_read(device, buf, (*size > 0) ? 0x43 : 0x00)) {
        return false;
    }

    return true;
}

static bool ymodem_data_blocks(long size, unsigned char *data, hid_device *device) {
    long total = size;
    unsigned char frame = 0x01;

    while(size > 0) {
        if(size == total) {
            printf("%ld\t%ld\t%.1f%%\n", 0L, total, 0.0);
        }

        if(!ymodem_data_block(&frame, &size, &data, device)) {
            return false;
        }

        long count = total - size;
        double progress = 100.0 * count / total;
        printf("%ld\t%ld\t%.1f%%\n", count, total, progress);
    }

    unsigned char buf[HID_WRITE_PACKET_SIZE];
    unsigned char *pos = buf;
    unsigned char *end = buf + sizeof(buf);

    *pos++ = 0x00;
    *pos++ = 0x04;

    memset(pos, 0x00, end - pos);

    if(!packet_write(device, buf)) {
        return false;
    }

    if(!packet_read(device, buf, 0x43)) {
        return false;
    }

    return true;
}

static void cleanup(void) {
    hid_close(global.device);
    if(global.lock >= 0) {
        close(global.lock);
    }
    hid_exit();
}

static bool parse_args(int argc, char **argv) {
    str_copy(global.program, sizeof(global.program), argv[0]);
    global.uid = getuid();
    global.euid = geteuid();
    global.lock = -1;

    tzset();

    if(atexit(cleanup) != 0) {
        output("%s: %s", "atexit", strerror(errno));
        return false;
    }

    if(signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        output("%s: %s", "signal", strerror(errno));
        return false;
    }

    if(hid_init() != 0) {
        output("%s: %ls", "hid_init", hid_error(NULL));
        return false;
    }

    int opt;
    static const char options[] = ":ecu:md:h";
    int mode_sets = 0;
    bool device_path_set = false;

    while((opt = getopt(argc, argv, options)) != -1) {
        switch(opt) {
            case 'e':
                mode_set(MODE_ENUMERATE, &mode_sets);
                break;

            case 'c':
                mode_set(MODE_COMMAND, &mode_sets);
                break;

            case 'u':
                mode_set(MODE_UPLOAD, &mode_sets);
                str_copy(global.upload_path, sizeof(global.upload_path), optarg);
                break;

            case 'm':
                mode_set(MODE_MODEL, &mode_sets);
                break;

            case 'd':
                device_path_set = true;
                str_copy(global.device_path, sizeof(global.device_path), optarg);
                break;

            case 'h':
                printf(
                    "Usage: %s [options]\n"
                    "\n"
                    "Available options:\n"
                    "  -e          enumerate detected devices\n"
                    "  -c          command mode for selected device\n"
                    "  -u <string> upload file to selected device\n"
                    "  -m          print model of selected device\n"
                    "  -d <string> device path of selected device\n"
                    "  -h          this help text\n"
                    "\n"
                    "Available commands (one per line to stdin):\n"
                    "  widget <key> <value> ...\n"
                    "  sensor <key> <value> ...\n"
                    "  datetime [<timeout>] [<brightness>]\n",
                    global.program
                );
                return false;

            case ':':
                output("missing argument for '%c'", optopt);
                return false;

            case '?':
                output("unknown option '%c'", optopt);
                return false;
        }
    }

    if(optind < argc) {
        output("%s", "extraneous arguments found");
        return false;
    }

    if(mode_sets == 0) {
        output("%s", "no mode requested");
        return false;
    }

    if(mode_sets > 1) {
        output("%s", "only one mode may be requested");
        return false;
    }

    if(global.mode == MODE_ENUMERATE && device_path_set) {
        output("%s", "option 'e' cannot be used with option 'd'");
        return false;
    }

    return true;
}

static int enumerate(void) {
    struct hid_device_info *dis = hid_enumerate(DEVICE_VID, DEVICE_PID);

    if(!privileges_drop()) {
        return EXIT_FAILURE;
    }

    for(struct hid_device_info *di = dis; di != NULL; di = di->next) {
        const wchar_t *serial_number = wsnull(di->serial_number);
        const wchar_t *manufacturer = wsnull(di->manufacturer_string);
        const wchar_t *product = wsnull(di->product_string);

        printf(
            "Device Path\t%s\n"
            "Serial Number\t%ls\n"
            "Manufacturer\t%ls\n"
            "Product Name\t%ls\n"
            "\n",
            di->path,
            serial_number,
            manufacturer,
            product
        );
    }

    hid_free_enumeration(dis);

    return EXIT_SUCCESS;
}

static void command_parse_args(char *line, const char *args[static COMMAND_ARGS], size_t *args_len) {
    static const char delim[] = " \t\n";
    char *ctx = NULL;
    size_t i = 0;

    if((args[i] = strtok_r(line, delim, &ctx)) != NULL) {
        for(i++; i < COMMAND_ARGS; i++) {
            if((args[i] = strtok_r(NULL, delim, &ctx)) == NULL) {
                break;
            }
        }
    }

    *args_len = i;
}

static void command_widget(const char *args[static COMMAND_ARGS], size_t args_len, hid_device *device) {
    if(args_len < 1 + 2 * 1) {
        output("%s: %s", args[0], "too few arguments");
        return;
    }

    if(args_len > 1 + 2 * 20) {
        output("%s: %s", args[0], "too many arguments");
        return;
    }

    if((args_len % 2) != 1) {
        output("%s: %s", args[0], "number of arguments must be even");
        return;
    }

    // Widget Report (max of 64 bytes)
    // u8: 0x00 (report id)
    // u8: 0 to 20 (number of fields)
    // u8: key, u16be: value (field layout, may be repeated)
    // key is widget id from current theme
    // rest is null padding
    unsigned char buf[HID_WRITE_PACKET_SIZE];
    unsigned char *pos = buf;
    unsigned char *end = buf + sizeof(buf);
    unsigned char *len = buf + 2;

    *pos++ = 0x00;
    *pos++ = 0x00;
    *pos++ = 0x00;

    for(size_t i = 1; i < args_len; ) {
        const char *key_arg = args[i++];
        long key;

        if(!str_to_long(key_arg, &key)) {
            output(
                "%s: argument %zu is not an integer: %s",
                args[0],
                i - 1,
                key_arg
            );
            return;
        }

        if(!in_range(key, HIDSS_WIDGET_KEY_MIN, HIDSS_WIDGET_KEY_MAX)) {
            output(
                "%s: argument %zu not in range of %d to %d",
                args[0],
                i - 1,
                HIDSS_WIDGET_KEY_MIN,
                HIDSS_WIDGET_KEY_MAX
            );
            return;
        }

        const char *val_arg = args[i++];
        long val;

        if(!str_to_long(val_arg, &val)) {
            output(
                "%s: argument %zu is not an integer: %s",
                args[0],
                i - 1,
                val_arg
            );
            return;
        }

        if(!in_range(val, HIDSS_WIDGET_VALUE_MIN, HIDSS_WIDGET_VALUE_MAX)) {
            output(
                "%s: argument %zu not in range of %d to %d",
                args[0],
                i - 1,
                HIDSS_WIDGET_VALUE_MIN,
                HIDSS_WIDGET_VALUE_MAX
            );
            return;
        }

        (*len)++;
        *pos++ = (key & 0xff);
        *pos++ = ((val & 0xff00) >> 8);
        *pos++ = ((val & 0x00ff) >> 0);
    }

    memset(pos, 0x00, end - pos);

    if(!packet_write(device, buf)) {
        return;
    }

    output("%s", "ok");
}

static void command_sensor(const char *args[static COMMAND_ARGS], size_t args_len, hid_device *device) {
    if(args_len < 1 + 2 * 1) {
        output("%s: %s", args[0], "too few arguments");
        return;
    }

    if(args_len > 1 + 2 * 20) {
        output("%s: %s", args[0], "too many arguments");
        return;
    }

    if((args_len % 2) != 1) {
        output("%s: %s", args[0], "number of arguments must be even");
        return;
    }

    // Sensor Report (max of 64 bytes)
    // u8: 0x02 (report id)
    // u8: 0 to 20 (number of fields)
    // u8: key, s16be: value (field layout, may be repeated)
    // fields:
    // 1: cpu temperature (celsius)
    // 2: cpu clock (megahertz)
    // 3: cpu usage (percentage)
    // 4: cpu fan (rpm)
    // 5: gpu temperature (celsius)
    // 6: gpu clock (megahertz)
    // 7: gpu usage (percentage)
    // 8: gpu memory clock (megahertz)
    // 9: gpu memory usage (percentage)
    // 10: ram used (megabytes)
    // 11: ram available (megabytes)
    // 12: ram usage (percentage)
    // 13: disk temperature (celsius)
    // 14: disk total (gigabytes)
    // 15: disk used (gigabytes)
    // 16: disk available (gigabytes)
    // 17: disk usage (percentage)
    // 18: network upload (kilobytes per second)
    // 19: network download (kilobytes per second)
    // 20: sound volume (percentage)
    // rest is null padding
    unsigned char buf[HID_WRITE_PACKET_SIZE];
    unsigned char *pos = buf;
    unsigned char *end = buf + sizeof(buf);
    unsigned char *len = buf + 2;

    *pos++ = 0x00;
    *pos++ = 0x02;
    *pos++ = 0x00;

    for(size_t i = 1; i < args_len; ) {
        const char *key_arg = args[i++];
        long key;

        if(!str_to_long(key_arg, &key)) {
            output(
                "%s: argument %zu is not an integer: %s",
                args[0],
                i - 1,
                key_arg
            );
            return;
        }

        if(!in_range(key, HIDSS_SENSOR_KEY_MIN, HIDSS_SENSOR_KEY_MAX)) {
            output(
                "%s: argument %zu not in range of %d to %d",
                args[0],
                i - 1,
                HIDSS_SENSOR_KEY_MIN,
                HIDSS_SENSOR_KEY_MAX
            );
            return;
        }

        const char *val_arg = args[i++];
        long val;

        if(!str_to_long(val_arg, &val)) {
            output(
                "%s: argument %zu is not an integer: %s",
                args[0],
                i - 1,
                val_arg
            );
            return;
        }

        if(!in_range(val, HIDSS_SENSOR_VALUE_MIN, HIDSS_SENSOR_VALUE_MAX)) {
            output(
                "%s: argument %zu not in range of %d to %d",
                args[0],
                i - 1,
                HIDSS_SENSOR_VALUE_MIN,
                HIDSS_SENSOR_VALUE_MAX
            );
            return;
        }

        (*len)++;
        *pos++ = (key & 0xff);
        *pos++ = ((val & 0xff00) >> 8);
        *pos++ = ((val & 0x00ff) >> 0);
    }

    memset(pos, 0x00, end - pos);

    if(!packet_write(device, buf)) {
        return;
    }

    output("%s", "ok");
}

static void command_datetime(const char *args[static COMMAND_ARGS], size_t args_len, hid_device *device) {
    if(args_len > 1 + 2) {
        output("%s: %s", args[0], "too many arguments");
        return;
    }

    long timeout;

    if(args_len > 1) {
        const char *timeout_arg = args[1];

        if(!str_to_long(timeout_arg, &timeout)) {
            output(
                "%s: argument %zu is not an integer: %s",
                args[0],
                (size_t) 1,
                timeout_arg
            );
            return;
        }

        if(!in_range(timeout, HIDSS_TIMEOUT_MIN, HIDSS_TIMEOUT_MAX)) {
            output(
                "%s: argument %zu not in range of %d to %d",
                args[0],
                (size_t) 1,
                HIDSS_TIMEOUT_MIN,
                HIDSS_TIMEOUT_MAX
            );
            return;
        }
    } else {
        timeout = global.timeout;
    }

    long brightness;

    if(args_len > 2) {
        const char *brightness_arg = args[2];

        if(!str_to_long(brightness_arg, &brightness)) {
            output(
                "%s: argument %zu is not an integer: %s",
                args[0],
                (size_t) 2,
                brightness_arg
            );
            return;
        }

        if(!in_range(brightness, HIDSS_BRIGHTNESS_MIN, HIDSS_BRIGHTNESS_MAX)) {
            output(
                "%s: argument %zu not in range of %d to %d",
                args[0],
                (size_t) 2,
                HIDSS_BRIGHTNESS_MIN,
                HIDSS_BRIGHTNESS_MAX
            );
            return;
        }
    } else {
        brightness = global.brightness;
    }

    time_t ts;

    if(time(&ts) == (time_t) -1) {
        output("%s: %s: %s", args[0], "time", strerror(errno));
        return;
    }

    struct tm tm;

    if(localtime_r(&ts, &tm) == NULL) {
        output("%s: %s: %s", args[0], "localtime_r", strerror(errno));
        return;
    }

    // DateTime & Backlight Report (max of 64 bytes)
    // u8: 0x03 (report id)
    // u8: 1 (number of fields)
    // u8: 21 (field)
    // u8: year (counts from 2000)
    // u8: month
    // u8: day
    // u8: hour
    // u8: minute
    // u8: second
    // u8: backlight timeout (0 to 255, 1/8th of a second, less than a second disables it)
    // u8: backlight brightness (1 to 100)
    // rest is null padding
    unsigned char buf[HID_WRITE_PACKET_SIZE];
    unsigned char *pos = buf;
    unsigned char *end = buf + sizeof(buf);

    *pos++ = 0x00;
    *pos++ = 0x03;
    *pos++ = 0x01;
    *pos++ = 0x15;
    *pos++ = tm.tm_year - 100;
    *pos++ = tm.tm_mon + 1;
    *pos++ = tm.tm_mday;
    *pos++ = tm.tm_hour;
    *pos++ = tm.tm_min;
    *pos++ = tm.tm_sec;
    *pos++ = timeout & 0xff;
    *pos++ = brightness & 0xff;

    memset(pos, 0x00, end - pos);

    if(!packet_write(device, buf)) {
        return;
    }

    output("%s", "ok");

    global.timeout = timeout;
    global.brightness = brightness;
}

static int command(void) {
    hid_device *device;

    if(!device_open(&device)) {
        return EXIT_FAILURE;
    }

    if(!privileges_drop()) {
        return EXIT_FAILURE;
    }

    char line[LINE_MAX];

    global.timeout = TIMEOUT_DEFAULT;
    global.brightness = BRIGHTNESS_DEFAULT;

    while(fgets(line, LINE_MAX, stdin) != NULL) {
        const char *args[COMMAND_ARGS];
        size_t args_len;

        command_parse_args(line, args, &args_len);

        if(args_len == 0) {
            output("%s", "no command");
            continue;
        }

        const char *cmd = args[0];

        if(strcmp(cmd, "widget") == 0) {
            command_widget(args, args_len, device);
        } else if(strcmp(cmd, "sensor") == 0) {
            command_sensor(args, args_len, device);
        } else if(strcmp(cmd, "datetime") == 0) {
            command_datetime(args, args_len, device);
        } else {
            output("%s: %s", "unknown command", cmd);
        }
    }

    return EXIT_SUCCESS;
}

static bool upload_ymodem(const char *filename, unsigned char *data, long size, hid_device *device) {
    if(!device_ymodem_mode(device)) {
        return false;
    }

    if(!ymodem_metadata_block(filename, size, device)) {
        return false;
    }

    if(!ymodem_data_blocks(size, data, device)) {
        return false;
    }

    if(!ymodem_metadata_block("", -1, device)) {
        return false;
    }

    return true;
}

static int upload_theme(const char *path, hid_device *device) {
    unsigned char *buf;
    long size;

    if(!file_get_contents(path, &buf, &size, HIDSS_THEME_MIN_SIZE, HIDSS_THEME_MAX_SIZE)) {
        goto err_0;
    }

    if(!upload_ymodem(HIDSS_THEME_FILENAME, buf, size, device)) {
        goto err_1;
    }

    free(buf);

    return EXIT_SUCCESS;

err_1:
    free(buf);
err_0:
    return EXIT_FAILURE;
}

static int upload_firmware(const char *path, hid_device *device) {
    unsigned char *data;
    long size;

    if(!file_get_contents(path, &data, &size, HIDSS_FIRWMARE_MIN_SIZE, HIDSS_FIRMWARE_MAX_SIZE)) {
        goto err_0;
    }

    unsigned char buf[HID_READ_PACKET_SIZE];

    if(!device_boot_mode(buf, &device)) {
        goto err_1;
    }

    if(!upload_ymodem(HIDSS_FIRMWARE_FILENAME, data, size, device)) {
        goto err_1;
    }

    free(data);

    return EXIT_SUCCESS;

err_1:
    free(data);
err_0:
    return EXIT_FAILURE;
}

static int upload(void) {
    hid_device *device;

    if(!device_open(&device)) {
        return EXIT_FAILURE;
    }

    if(!privileges_drop()) {
        return EXIT_FAILURE;
    }

    const char *path = global.upload_path;
    const char *base = strrchr(path, '/');

    if(base == NULL) {
        base = path;
    } else {
        base++;
    }

    if(strcmp(base, HIDSS_THEME_FILENAME) == 0) {
        return upload_theme(path, device);
    } if(strcmp(base, HIDSS_FIRMWARE_FILENAME) == 0) {
        return upload_firmware(path, device);
    } else {
        output("unknown file type: %s", path);
        return EXIT_FAILURE;
    }
}

static int model(void) {
    hid_device *device;

    if(!device_open(&device)) {
        return EXIT_FAILURE;
    }

    if(!privileges_drop()) {
        return EXIT_FAILURE;
    }

    unsigned char buf[HID_READ_PACKET_SIZE];

    if(!device_boot_mode(buf, &device)) {
        return EXIT_FAILURE;
    }

    if(!device_ymodem_mode(device)) {
        return false;
    }

    if(!ymodem_metadata_block("", -1, device)) {
        return false;
    }

    printf("%s\n", buf);

    return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
    if(!parse_args(argc, argv)) {
        return EXIT_FAILURE;
    }

    if(global.mode == MODE_ENUMERATE) {
        return enumerate();
    }

    if(global.mode == MODE_COMMAND) {
        return command();
    }

    if(global.mode == MODE_UPLOAD) {
        return upload();
    }

    if(global.mode == MODE_MODEL) {
        return model();
    }

    return EXIT_SUCCESS;
}
