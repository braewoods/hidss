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

#include "common.h"

static bool ymodem_validate_response(const uint8_t buf[static READ_REPORT_SIZE], uint8_t byte) {
    if (buf[0] != 0x06 || buf[1] != byte) {
        output("%s: %s", __func__, "unexpected response");
        return false;
    }

    return true;
}

static void ymodem_write_crc_to_block(uint8_t *buf, size_t size) {
    static const uint16_t table[256] = {
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
        0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0,
    };
    uint8_t *pos;
    uint16_t crc;

    pos = buf + 3;
    crc = 0x0000;

    for (size_t i = 0; i < size; i++) {
        crc = (table[(crc >> 8) ^ *pos++] ^ (crc << 8));
    }

    *pos++ = ((crc & 0xff00) >> 8);
    *pos++ = ((crc & 0x00ff) >> 0);
}

bool device_first(char device[static PATH_MAX]) {
    struct device_info *dis;

    dis = device_enumerate();
    if (dis == NULL) {
        return false;
    }

    strbuild(device, PATH_MAX, dis->device);

    device_enumerate_free(dis);

    return true;
}

void device_enumerate_free(struct device_info *di) {
    while (di != NULL) {
        struct device_info *next;

        next = di->next;

        free(di);

        di = next;
    }
}

bool device_send_widget(struct device *dev, const uint8_t *keys, const uint16_t *vals, size_t len) {
    // Widget Report (max of 64 bytes)
    // u8: 0x00 (report id)
    // u8: 0 to 20 (number of fields)
    // u8: key, u16be: value (field layout, may be repeated)
    // key is widget id from current theme
    // rest is null padding
    uint8_t buf[WRITE_REPORT_SIZE];
    uint8_t *pos;
    uint8_t *end;

    pos = buf;
    end = buf + sizeof(buf);

    *pos++ = REPORT_ID;
    *pos++ = 0x00;
    *pos++ = len;

    for (size_t i = 0; i < len; i++) {
        *pos++ = keys[i];
        *pos++ = ((vals[i] & 0xff00) >> 8);
        *pos++ = ((vals[i] & 0x00ff) >> 0);
    }

    memset(pos, 0x00, end - pos);

    return device_write(dev, buf);
}

bool device_send_command(struct device *dev, const char *cmd, bool add_header) {
    // Command Report (max of 64 bytes)
    // u8: 0x01 (report id) (optional in some cases)
    // u8: variable length string (command)
    // rest is null padding
    uint8_t buf[WRITE_REPORT_SIZE];
    uint8_t *pos;
    uint8_t *end;

    pos = buf;
    end = buf + sizeof(buf);

    *pos++ = REPORT_ID;

    if (add_header)
        *pos++ = 0x01;

    while (*cmd != '\0')
        *pos++ = *cmd++;

    *pos++ = '\0';

    memset(pos, 0x00, end - pos);

    return device_write(dev, buf);
}

bool device_send_sensor(struct device *dev, const uint8_t *keys, const uint16_t *vals, size_t len) {
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
    uint8_t buf[WRITE_REPORT_SIZE];
    uint8_t *pos;
    uint8_t *end;

    pos = buf;
    end = buf + sizeof(buf);

    *pos++ = REPORT_ID;
    *pos++ = 0x02;
    *pos++ = len;

    for (size_t i = 0; i < len; i++) {
        *pos++ = keys[i];
        *pos++ = ((vals[i] & 0xff00) >> 8);
        *pos++ = ((vals[i] & 0x00ff) >> 0);
    }

    memset(pos, 0x00, end - pos);

    return device_write(dev, buf);
}

bool device_send_datetime(struct device *dev, uint8_t timeout, uint8_t brightness) {
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
    uint8_t buf[WRITE_REPORT_SIZE];
    uint8_t *pos;
    uint8_t *end;
    struct tm tm;

    pos = buf;
    end = buf + sizeof(buf);

    *pos++ = REPORT_ID;
    *pos++ = 0x03;
    *pos++ = 0x01;
    *pos++ = 0x15;

    if (!getdatetime(&tm))
        return false;

    *pos++ = tm.tm_year - 100;
    *pos++ = tm.tm_mon + 1;
    *pos++ = tm.tm_mday;
    *pos++ = tm.tm_hour;
    *pos++ = tm.tm_min;
    *pos++ = tm.tm_sec;
    *pos++ = timeout;
    *pos++ = brightness;

    memset(pos, 0x00, end - pos);

    return device_write(dev, buf);
}

bool device_send_metadata(struct device *dev, const char *fn, size_t size) {
    // u8: 0x01 (128 byte data block)
    // u8: 0x00 (frame number)
    // u8: 0xff (complement of frame number)
    // u8: filename (variable length string, null terminated)
    // u8: filesize (variable length string, null terminated)
    // null padding for remainder of data block
    // u8: upper byte of CRC16 for data block
    // u8: lower byte of CRC16 for data block
    // null padding for extraneous bytes
    uint8_t block[YMODEM_128_BLOCK_SIZE];
    uint8_t *pos;
    uint8_t *data_end;
    uint8_t *block_end;
    uint8_t buf[READ_REPORT_SIZE];

    pos = block;
    data_end = block + 3 + 128;
    block_end = block + sizeof(block);

    *pos++ = 0x01;
    *pos++ = 0x00;
    *pos++ = 0xff;

    while (*fn != '\0')
        *pos++ = *fn++;

    *pos++ = '\0';

    if (size > 0)
        pos += 1 + sprintf((char *) pos, "%zu", size);

    memset(pos, 0x00, data_end - pos);

    ymodem_write_crc_to_block(block, 128);

    pos = data_end + 2;

    memset(pos, 0x00, block_end - pos);

    for (pos = block; pos < block_end; pos += REPORT_SIZE) {
        uint8_t buf[WRITE_REPORT_SIZE];

        *buf = REPORT_ID;
        memcpy(buf + 1, pos, REPORT_SIZE);

        if (!device_write(dev, buf))
            return false;
    }

    if (!device_read(dev, buf, -1))
        return false;

    return ymodem_validate_response(buf, (size == 0) ? 0x00 : 0x43);
}

bool device_send_data(struct device *dev, const uint8_t **data, size_t *size, uint8_t *frame) {
    // u8: 0x02 (1024 byte data block)
    // u8: 0x01 (frame number)
    // u8: 0xfe (complement of frame number)
    // u8: up to 1024 bytes of user data, padded with 0x1A if needed
    // u8: upper byte of CRC16 for data block
    // u8: lower byte of CRC16 for data block
    // null padding for extraneous bytes
    uint8_t block[YMODEM_1024_BLOCK_SIZE];
    uint8_t *pos;
    uint8_t *data_end;
    uint8_t *block_end;
    uint8_t buf[READ_REPORT_SIZE];

    pos = block;
    data_end = block + 3 + 1024;
    block_end = block + sizeof(block);

    *pos++ = 0x02;
    *pos++ = *frame;
    *pos++ = ~*frame;
    *frame += 1;

    if (*size >= 1024) {
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

    ymodem_write_crc_to_block(block, 1024);

    pos = data_end + 2;

    memset(pos, 0x00, block_end - pos);

    for (pos = block; pos < block_end; pos += REPORT_SIZE) {
        uint8_t buf[WRITE_REPORT_SIZE];

        *buf = REPORT_ID;
        memcpy(buf + 1, pos, REPORT_SIZE);

        if (!device_write(dev, buf))
            return false;
    }

    if (!device_read(dev, buf, -1))
        return false;

    return ymodem_validate_response(buf, (*size == 0) ? 0x00 : 0x43);
}

bool device_send_data_stream(struct device *dev, const uint8_t *data, size_t size) {
    uint8_t frame;
    size_t total;
    uint8_t buf[WRITE_REPORT_SIZE];
    uint8_t *pos;
    uint8_t *end;

    frame = 0x01;
    total = size;

    while (size > 0) {
        size_t count;
        double progress;

        if (size == total)
            fprintf(stdout, "%zu\t%zu\t%.1f%%\n", (size_t) 0, total, 0.0);

        if (!device_send_data(dev, &data, &size, &frame))
            return false;

        count = total - size;

        progress = 100.0 * count / total;

        fprintf(stdout, "%zu\t%zu\t%.1f%%\n", count, total, progress);
    }

    pos = buf;
    end = buf + sizeof(buf);

    *pos++ = REPORT_ID;
    *pos++ = 0x04;

    memset(pos, 0x00, end - pos);

    if (!device_write(dev, buf))
        return false;

    if (!device_read(dev, buf, -1))
        return false;

    return ymodem_validate_response(buf, 0x43);
}

bool device_enter_ymodem_mode(struct device *dev) {
    uint8_t buf[READ_REPORT_SIZE];

    if (!device_send_command(dev, "reset", true))
        return false;

    if (!device_send_command(dev, "ymodem", false))
        return false;

    if (!device_read(dev, buf, -1))
        return false;

    return ymodem_validate_response(buf, 0x43);
}

bool device_enter_boot_mode(struct device *dev, uint8_t buf[static READ_REPORT_SIZE]) {
    if (!device_send_command(dev, "model", true))
        return false;

    if (device_read(dev, buf, 100))
        return true;

    if (!privileges_restore())
        return false;

    if (!device_reopen(dev, 5))
        return false;

    if (!privileges_discard())
        return false;

    if (!device_send_command(dev, "model", true))
        return false;

    return device_read(dev, buf, -1);
}
