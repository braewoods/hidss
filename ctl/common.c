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

static void command_widget(struct device *dev, const char **args, size_t len) {
    uint8_t keys[HIDSS_WIDGET_FIELDS_MAX];
    uint16_t vals[HIDSS_WIDGET_FIELDS_MAX];
    size_t i;
    size_t j;

    if (len < 2 * HIDSS_WIDGET_FIELDS_MIN) {
        output("too few arguments");
        return;
    }

    if (len > 2 * HIDSS_WIDGET_FIELDS_MAX) {
        output("too many arguments");
        return;
    }

    if ((len % 2) != 0) {
        output("arguments must appear in pairs");
        return;
    }

    for (i = j = 0; i < len; j++) {
        const char *key_arg = args[i++];
        long key;
        const char *val_arg = args[i++];
        long val;

        if (!command_parse_argument(key_arg, &key, i, HIDSS_WIDGET_KEY_MIN, HIDSS_WIDGET_KEY_MAX))
            return;

        if (!command_parse_argument(val_arg, &val, i, HIDSS_WIDGET_VALUE_MIN, HIDSS_WIDGET_VALUE_MAX))
            return;

        keys[j] = key;
        vals[j] = val;
    }

    if (!device_send_widget(dev, keys, vals, j))
        return;

    output("ok");
}

static void command_sensor(struct device *dev, const char **args, size_t len) {
    uint8_t keys[HIDSS_SENSOR_FIELDS_MAX];
    uint16_t vals[HIDSS_SENSOR_FIELDS_MAX];
    size_t i;
    size_t j;

    if (len < 2 * HIDSS_SENSOR_FIELDS_MIN) {
        output("too few arguments");
        return;
    }

    if (len > 2 * HIDSS_SENSOR_FIELDS_MAX) {
        output("too many arguments");
        return;
    }

    if ((len % 2) != 0) {
        output("arguments must appear in pairs");
        return;
    }

    for (i = j = 0; i < len; j++) {
        const char *key_arg = args[i++];
        long key;
        const char *val_arg = args[i++];
        long val;

        if (!command_parse_argument(key_arg, &key, i, HIDSS_SENSOR_KEY_MIN, HIDSS_SENSOR_KEY_MAX))
            return;

        if (!command_parse_argument(val_arg, &val, i, HIDSS_SENSOR_VALUE_MIN, HIDSS_SENSOR_VALUE_MAX))
            return;

        keys[j] = key;
        vals[j] = val;
    }

    if (!device_send_sensor(dev, keys, vals, j))
        return;

    output("ok");
}

static void command_datetime(struct device *dev, const char **args, size_t len, uint8_t *timeout, uint8_t *brightness) {
    long n;
    uint8_t new_timeout;
    uint8_t new_brightness;

    if (len > 2) {
        output("too many arguments");
        return;
    }

    if (len > 0) {
        if (!command_parse_argument(args[0], &n, 1, HIDSS_TIMEOUT_MIN, HIDSS_TIMEOUT_MAX))
            return;

        new_timeout = n;
    } else {
        new_timeout = *timeout;
    }

    if (len > 1) {
        if (!command_parse_argument(args[1], &n, 2, HIDSS_BRIGHTNESS_MIN, HIDSS_BRIGHTNESS_MAX))
            return;

        new_brightness = n;
    } else {
        new_brightness = *brightness;
    }

    if (!device_send_datetime(dev, new_timeout, new_brightness))
        return;

    *timeout = new_timeout;
    *brightness = new_brightness;

    output("ok");
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
    uint8_t *data = NULL;
    size_t size;
    uint8_t buf[REPORT_BUFFER_SIZE];
    int rv = EXIT_FAILURE;

    if (!file_get_contents(path, &data, &size, HIDSS_FIRWMARE_MIN_SIZE, HIDSS_FIRMWARE_MAX_SIZE))
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

void format_bus_path(char bp[static BUS_PATH_MAX], uint8_t bus, const uint8_t ports[static BUS_PORT_MAX], size_t len) {
    int n = snprintf(bp, sizeof("000-000"), "%hhu-%hhu", bus, *ports);

    for (size_t i = 1; i < len; i++)
        n += snprintf(bp + n, sizeof(".000"), ".%hhu", ports[i]);
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

    while (fgets(line, sizeof(line), stdin) != NULL) {
        const char *args[COMMAND_MAX_ARGS];
        size_t len;
        const char *cmd;

        command_parse_args(line, args, &len);

        if (len == 0) {
            output("no command");
            continue;
        }

        cmd = args[0];

        if (strcmp(cmd, "widget") == 0) {
            command_widget(dev, args + 1, len - 1);
        } else if (strcmp(cmd, "sensor") == 0) {
            command_sensor(dev, args + 1, len - 1);
        } else if (strcmp(cmd, "datetime") == 0) {
            command_datetime(dev, args + 1, len - 1, &timeout, &brightness);
        } else if (strcmp(cmd, "exit") == 0) {
            break;
        } else {
            output("%s: %s", "unknown command", cmd);
        }
    }

    return EXIT_SUCCESS;
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
