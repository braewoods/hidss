// Copyright (c) 2024 James Buren
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

#include "common.h"

#define COMMAND_DELIMITERS " \t\n"

enum {
    PROGNAME_MAX = 256,
    COMMAND_MAX_ARGS = 64,
};

static char progname[PROGNAME_MAX];

static void command_parse_args(char *line, const char *args[static COMMAND_MAX_ARGS], size_t *len) {
    size_t i = 0;
    char *ctx = NULL;

    args[i] = strtok_r(line, COMMAND_DELIMITERS, &ctx);
    if (args[i] != NULL) {
        for (i++; i < COMMAND_MAX_ARGS; i++) {
            args[i] = strtok_r(NULL, COMMAND_DELIMITERS, &ctx);

            if (args[i] == NULL)
                break;
        }
    }

    *len = i;
}

static bool command_parse_argument(const char *arg, long *num, size_t i, long low, long high) {
    if (!strtolong(arg, num, 0)) {
        output(
            "argument %zu is not an integer: %s",
            i,
            arg
        );
        return false;
    }

    if (!inrange(*num, low, high)) {
        output(
            "argument %zu not in range of %ld to %ld",
            i,
            low,
            high
        );
        return false;
    }

    return true;
}

static bool command_widget(struct device *dev, const char **args, size_t len) {
    uint8_t keys[HIDSS_WIDGET_FIELDS_MAX];
    uint16_t vals[HIDSS_WIDGET_FIELDS_MAX];
    size_t i;
    size_t j;

    if (len < 2 * HIDSS_WIDGET_FIELDS_MIN) {
        output("too few arguments");
        return false;
    }

    if (len > 2 * HIDSS_WIDGET_FIELDS_MAX) {
        output("too many arguments");
        return false;
    }

    if ((len % 2) != 0) {
        output("arguments must appear in pairs");
        return false;
    }

    for (i = j = 0; i < len; j++) {
        const char *key_arg = args[i++];
        long key;
        const char *val_arg = args[i++];
        long val;

        if (!command_parse_argument(key_arg, &key, i, HIDSS_WIDGET_KEY_MIN, HIDSS_WIDGET_KEY_MAX))
            return false;

        if (!command_parse_argument(val_arg, &val, i, HIDSS_WIDGET_VALUE_MIN, HIDSS_WIDGET_VALUE_MAX))
            return false;

        keys[j] = key;
        vals[j] = val;
    }

    if (!device_send_widget(dev, keys, vals, j))
        return false;

    output("ok");
    return true;
}

static bool command_sensor(struct device *dev, const char **args, size_t len) {
    uint8_t keys[HIDSS_SENSOR_FIELDS_MAX];
    uint16_t vals[HIDSS_SENSOR_FIELDS_MAX];
    size_t i;
    size_t j;

    if (len < 2 * HIDSS_SENSOR_FIELDS_MIN) {
        output("too few arguments");
        return false;
    }

    if (len > 2 * HIDSS_SENSOR_FIELDS_MAX) {
        output("too many arguments");
        return false;
    }

    if ((len % 2) != 0) {
        output("arguments must appear in pairs");
        return false;
    }

    for (i = j = 0; i < len; j++) {
        const char *key_arg = args[i++];
        long key;
        const char *val_arg = args[i++];
        long val;

        if (!command_parse_argument(key_arg, &key, i, HIDSS_SENSOR_KEY_MIN, HIDSS_SENSOR_KEY_MAX))
            return false;

        if (!command_parse_argument(val_arg, &val, i, HIDSS_SENSOR_VALUE_MIN, HIDSS_SENSOR_VALUE_MAX))
            return false;

        keys[j] = key;
        vals[j] = val;
    }

    if (!device_send_sensor(dev, keys, vals, j))
        return false;

    output("ok");
    return true;
}

static bool command_datetime(struct device *dev, const char **args, size_t len, uint8_t *timeout, uint8_t *brightness) {
    long n;
    uint8_t new_timeout;
    uint8_t new_brightness;

    if (len > 2) {
        output("too many arguments");
        return false;
    }

    if (len > 0) {
        if (!command_parse_argument(args[0], &n, 1, HIDSS_TIMEOUT_MIN, HIDSS_TIMEOUT_MAX))
            return false;

        new_timeout = n;
    } else {
        new_timeout = *timeout;
    }

    if (len > 1) {
        if (!command_parse_argument(args[1], &n, 2, HIDSS_BRIGHTNESS_MIN, HIDSS_BRIGHTNESS_MAX))
            return false;

        new_brightness = n;
    } else {
        new_brightness = *brightness;
    }

    if (!device_send_datetime(dev, new_timeout, new_brightness))
        return false;

    *timeout = new_timeout;
    *brightness = new_brightness;

    output("ok");
    return true;
}

static uint32_t crc32c(const uint8_t *pos, size_t size) {
    static const uint32_t table[256] = {
        0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4, 0xc79a971f, 0x35f1141c, 0x26a1e7e8, 0xd4ca64eb,
        0x8ad958cf, 0x78b2dbcc, 0x6be22838, 0x9989ab3b, 0x4d43cfd0, 0xbf284cd3, 0xac78bf27, 0x5e133c24,
        0x105ec76f, 0xe235446c, 0xf165b798, 0x030e349b, 0xd7c45070, 0x25afd373, 0x36ff2087, 0xc494a384,
        0x9a879fa0, 0x68ec1ca3, 0x7bbcef57, 0x89d76c54, 0x5d1d08bf, 0xaf768bbc, 0xbc267848, 0x4e4dfb4b,
        0x20bd8ede, 0xd2d60ddd, 0xc186fe29, 0x33ed7d2a, 0xe72719c1, 0x154c9ac2, 0x061c6936, 0xf477ea35,
        0xaa64d611, 0x580f5512, 0x4b5fa6e6, 0xb93425e5, 0x6dfe410e, 0x9f95c20d, 0x8cc531f9, 0x7eaeb2fa,
        0x30e349b1, 0xc288cab2, 0xd1d83946, 0x23b3ba45, 0xf779deae, 0x05125dad, 0x1642ae59, 0xe4292d5a,
        0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a, 0x7da08661, 0x8fcb0562, 0x9c9bf696, 0x6ef07595,
        0x417b1dbc, 0xb3109ebf, 0xa0406d4b, 0x522bee48, 0x86e18aa3, 0x748a09a0, 0x67dafa54, 0x95b17957,
        0xcba24573, 0x39c9c670, 0x2a993584, 0xd8f2b687, 0x0c38d26c, 0xfe53516f, 0xed03a29b, 0x1f682198,
        0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927, 0x96bf4dcc, 0x64d4cecf, 0x77843d3b, 0x85efbe38,
        0xdbfc821c, 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8, 0x1c661503, 0xee0d9600, 0xfd5d65f4, 0x0f36e6f7,
        0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096, 0xa65c047d, 0x5437877e, 0x4767748a, 0xb50cf789,
        0xeb1fcbad, 0x197448ae, 0x0a24bb5a, 0xf84f3859, 0x2c855cb2, 0xdeeedfb1, 0xcdbe2c45, 0x3fd5af46,
        0x7198540d, 0x83f3d70e, 0x90a324fa, 0x62c8a7f9, 0xb602c312, 0x44694011, 0x5739b3e5, 0xa55230e6,
        0xfb410cc2, 0x092a8fc1, 0x1a7a7c35, 0xe811ff36, 0x3cdb9bdd, 0xceb018de, 0xdde0eb2a, 0x2f8b6829,
        0x82f63b78, 0x709db87b, 0x63cd4b8f, 0x91a6c88c, 0x456cac67, 0xb7072f64, 0xa457dc90, 0x563c5f93,
        0x082f63b7, 0xfa44e0b4, 0xe9141340, 0x1b7f9043, 0xcfb5f4a8, 0x3dde77ab, 0x2e8e845f, 0xdce5075c,
        0x92a8fc17, 0x60c37f14, 0x73938ce0, 0x81f80fe3, 0x55326b08, 0xa759e80b, 0xb4091bff, 0x466298fc,
        0x1871a4d8, 0xea1a27db, 0xf94ad42f, 0x0b21572c, 0xdfeb33c7, 0x2d80b0c4, 0x3ed04330, 0xccbbc033,
        0xa24bb5a6, 0x502036a5, 0x4370c551, 0xb11b4652, 0x65d122b9, 0x97baa1ba, 0x84ea524e, 0x7681d14d,
        0x2892ed69, 0xdaf96e6a, 0xc9a99d9e, 0x3bc21e9d, 0xef087a76, 0x1d63f975, 0x0e330a81, 0xfc588982,
        0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d, 0x758fe5d6, 0x87e466d5, 0x94b49521, 0x66df1622,
        0x38cc2a06, 0xcaa7a905, 0xd9f75af1, 0x2b9cd9f2, 0xff56bd19, 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed,
        0xc38d26c4, 0x31e6a5c7, 0x22b65633, 0xd0ddd530, 0x0417b1db, 0xf67c32d8, 0xe52cc12c, 0x1747422f,
        0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff, 0x8ecee914, 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0,
        0xd3d3e1ab, 0x21b862a8, 0x32e8915c, 0xc083125f, 0x144976b4, 0xe622f5b7, 0xf5720643, 0x07198540,
        0x590ab964, 0xab613a67, 0xb831c993, 0x4a5a4a90, 0x9e902e7b, 0x6cfbad78, 0x7fab5e8c, 0x8dc0dd8f,
        0xe330a81a, 0x115b2b19, 0x020bd8ed, 0xf0605bee, 0x24aa3f05, 0xd6c1bc06, 0xc5914ff2, 0x37faccf1,
        0x69e9f0d5, 0x9b8273d6, 0x88d28022, 0x7ab90321, 0xae7367ca, 0x5c18e4c9, 0x4f48173d, 0xbd23943e,
        0xf36e6f75, 0x0105ec76, 0x12551f82, 0xe03e9c81, 0x34f4f86a, 0xc69f7b69, 0xd5cf889d, 0x27a40b9e,
        0x79b737ba, 0x8bdcb4b9, 0x988c474d, 0x6ae7c44e, 0xbe2da0a5, 0x4c4623a6, 0x5f16d052, 0xad7d5351,
    };
    uint32_t crc = ~0;

    for (size_t i = 0; i < size; i++)
        crc = (table[(crc ^ *pos++) & 0xff] ^ (crc >> 8));

    return ~crc;
}

static bool verify_firmware(const uint8_t *data, size_t size) {
    static const struct {
        uint32_t size;
        uint32_t crc;
    } table[] = {
        {46496, 0x57319ea5},
        {46688, 0xf0ea1b4a},
        {46208, 0xa19a5f5c},
    };
    static const size_t table_length = sizeof(table) / sizeof(*table);
    uint32_t crc = crc32c(data, size);

    for (size_t i = 0; i < table_length; i++)
        if (table[i].size == size && table[i].crc == crc)
            return true;

    output("%s: %08x", "unsupported firmware", crc);
    return false;
}

static bool upload_send(struct device *dev, const char *fn, const uint8_t *data, size_t size) {
    if (!device_enter_ymodem_mode(dev))
        return false;

    if (!device_send_metadata(dev, fn, size))
        return false;

    if (!device_send_data_stream(dev, data, size))
        return false;

    if (!device_send_metadata(dev, "", 0))
        return false;

    return true;
}

static int upload_theme(struct device *dev, const char *path) {
    // TODO: update these in refactoring for a new display
    enum {
        HIDSS_THEME_MIN_SIZE = 4096,
        HIDSS_THEME_MAX_SIZE = 4194304,
    };
    uint8_t *data = NULL;
    size_t size;
    int rv = EXIT_FAILURE;

    if (!file_get_contents(path, &data, &size, HIDSS_THEME_MIN_SIZE, HIDSS_THEME_MAX_SIZE))
        goto end;

    if (!upload_send(dev, HIDSS_THEME_FILENAME, data, size))
        goto end;

    rv = EXIT_SUCCESS;
end:
    free(data);
    return rv;
}

static int upload_firmware(struct device *dev, const char *path) {
    // TODO: update these in refactoring for a new display
    enum {
        HIDSS_FIRWMARE_MIN_SIZE = 0,
        HIDSS_FIRMWARE_MAX_SIZE = 65536,
    };
    uint8_t *data = NULL;
    size_t size;
    uint8_t buf[REPORT_BUFFER_SIZE];
    int rv = EXIT_FAILURE;

    if (!file_get_contents(path, &data, &size, HIDSS_FIRWMARE_MIN_SIZE, HIDSS_FIRMWARE_MAX_SIZE))
        goto end;

    if (!verify_firmware(data, size))
        goto end;

    if (!device_enter_boot_mode(dev, buf))
        goto end;

    if (!upload_send(dev, HIDSS_FIRMWARE_FILENAME, data, size))
        goto end;

    rv = EXIT_SUCCESS;
end:
    free(data);
    return rv;
}

void setprogname(const char *s) {
    if (memccpy(progname, s, '\0', sizeof(progname)) == NULL)
        progname[sizeof(progname) - 1] = '\0';
}

const char *getprogname(void) {
    return progname;
}

void output(const char *fmt, ...) {
    va_list args;

    fputs(progname, stdout);
    fputs(": ", stdout);

    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

    putc('\n', stdout);
}

bool strbuild_real(char * restrict dst, size_t size, char const * restrict * restrict src) {
    *dst = '\0';

    while (*src != NULL) {
        char *end;
        size_t len;

        end = memccpy(dst, *src, '\0', size);
        if (end == NULL) {
            dst[size - 1] = '\0';
            return false;
        }

        len = end - dst - 1;
        dst += len;
        size -= len;
        src++;
    }

    return true;
}

void format_bus_path(char bp[static BUS_PATH_MAX], uint8_t bus, const uint8_t *ports, size_t len) {
    int n = snprintf(bp, sizeof("000-000"), "%hhu-%hhu", bus, *ports);

    for (size_t i = 1; i < len; i++)
        n += snprintf(bp + n, sizeof(".000"), ".%hhu", ports[i]);
}

bool verify_device_ids(const char *name, uint16_t vendor_id, uint16_t product_id) {
    enum {
        VENDOR_ID = 0x0483,
        PRODUCT_ID = 0x0065,
    };

    if (vendor_id != VENDOR_ID) {
        if (name != NULL)
            output("%s: %s", "vendor id mismatch", name);
        return false;
    }

    if (product_id != PRODUCT_ID) {
        if (name != NULL)
            output("%s: %s", "product id mismatch", name);
        return false;
    }

    return true;
}

bool verify_report_desc(const char *name, const void *buf, size_t size, uint8_t report_id) {
    static const uint8_t rd[34] = {
        0x06, 0x00, 0xff, 0x09, 0x01, 0xa1, 0x01, 0x09,
        0x01, 0x15, 0x00, 0x26, 0xff, 0x00, 0x95, 0x40,
        0x75, 0x08, 0x81, 0x02, 0x09, 0x01, 0x15, 0x00,
        0x26, 0xff, 0x00, 0x95, 0x40, 0x75, 0x08, 0x91,
        0x02, 0xc0,
    };

    if (size != sizeof(rd)) {
        if (name != NULL)
            output("%s: %s", "report descriptor size mismatch", name);
        return false;
    }

    if (memcmp(buf, rd, sizeof(rd)) != 0) {
        if (name != NULL)
            output("%s: %s", "report descriptor mismatch", name);
        return false;
    }

    if (report_id != REPORT_ID) {
        if (name != NULL)
            output("%s: %s", "report id mismatch", name);
        return false;
    }

    return true;
}

bool getdatetime(struct tm *tm) {
    time_t ts;

    if (time(&ts) == (time_t) -1) {
        output("%s: %s", "time", strerror(errno));
        return false;
    }

    if (localtime_r(&ts, tm) == NULL) {
        output("%s: %s", "localtime", strerror(errno));
        return false;
    }

    return true;
}

int mode_enumerate(void) {
    struct device_info *dis = device_enumerate();

    for (struct device_info *di = dis; di != NULL; di = di->next)
        fprintf(
            stdout,
            "DevPath\t%s\n"
            "BusPath\t%s\n"
            "Vendor\t%s\n"
            "Product\t%s\n"
            "Serial\t%s\n"
            "\n",
            di->devpath,
            di->buspath,
            di->vendor,
            di->product,
            di->serial
        );

    device_enumerate_free(dis);

    return EXIT_SUCCESS;
}

int mode_command(struct device *dev) {
    char line[4096];
    uint8_t timeout = HIDSS_TIMEOUT_DEFAULT;
    uint8_t brightness = HIDSS_BRIGHTNESS_DEFAULT;
    bool failed = true;

    while (fgets(line, sizeof(line), stdin) != NULL) {
        const char *args[COMMAND_MAX_ARGS];
        size_t len;
        const char *cmd;
        bool res;

        command_parse_args(line, args, &len);

        if (len == 0) {
            output("no command");
            break;
        }

        cmd = args[0];

        if (strcmp(cmd, "widget") == 0) {
            res = command_widget(dev, args + 1, len - 1);
        } else if (strcmp(cmd, "sensor") == 0) {
            res = command_sensor(dev, args + 1, len - 1);
        } else if (strcmp(cmd, "datetime") == 0) {
            res = command_datetime(dev, args + 1, len - 1, &timeout, &brightness);
        } else if (strcmp(cmd, "exit") == 0) {
            failed = false;
            res = false;
        } else {
            output("%s: %s", "unknown command", cmd);
            res = false;
        }

        if (!res)
            break;
    }

    return (failed ? EXIT_FAILURE : EXIT_SUCCESS);
}

int mode_upload(struct device *dev, const char *upload_path) {
    char path[PATH_MAX];
    const char *base;

    strbuild(path, sizeof(path), upload_path);
    base = basename(path);

    if (strcmp(base, HIDSS_THEME_FILENAME) == 0)
        return upload_theme(dev, upload_path);

    if (strcmp(base, HIDSS_FIRMWARE_FILENAME) == 0)
        return upload_firmware(dev, upload_path);

    output("unknown file type: %s", upload_path);
    return EXIT_FAILURE;
}

int mode_model(struct device *dev) {
    uint8_t buf[REPORT_BUFFER_SIZE];

    if (!device_enter_boot_mode(dev, buf))
        return EXIT_FAILURE;

    if (!device_enter_ymodem_mode(dev))
        return EXIT_FAILURE;

    if (!device_send_metadata(dev, "", 0))
        return EXIT_FAILURE;

    fprintf(stdout, "%s\n", buf + 1);

    return EXIT_SUCCESS;
}
