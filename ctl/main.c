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

enum {
    MODE_UNSPECIFIED,
    MODE_ENUMERATE,
    MODE_COMMAND,
    MODE_UPLOAD,
    MODE_MODEL,
};

struct main_state {
    int exit_code;
    int mode;
    const char *upload_path;
    const char *device_path;
    struct device *device;
};

static bool parse_args(int argc, char **argv, struct main_state *ms) {
    int mode_set_count = 0;
    int opt;

    setprogname(argv[0]);
    tzset();

    if (setlocale(LC_ALL, "") == NULL) {
        output("%s: %s", "setlocale", strerror(errno));
        return false;
    }

    if (!platform_init())
        return false;

    while ((opt = getopt(argc, argv, ":ecu:md:h")) != -1) {
        switch (opt) {
            case 'e':
                ms->mode = MODE_ENUMERATE;
                mode_set_count++;
                break;

            case 'c':
                ms->mode = MODE_COMMAND;
                mode_set_count++;
                break;

            case 'u':
                ms->mode = MODE_UPLOAD;
                mode_set_count++;
                ms->upload_path = optarg;
                break;

            case 'm':
                ms->mode = MODE_MODEL;
                mode_set_count++;
                break;

            case 'd':
                ms->device_path = optarg;
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
                    "  datetime [<timeout>] [<brightness>]\n"
                    "  exit\n",
                    getprogname()
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

    if (optind < argc) {
        output("extraneous arguments found");
        return false;
    }

    if (mode_set_count == 0) {
        output("no mode requested");
        return false;
    }

    if (mode_set_count > 1) {
        output("only one mode may be requested");
        return false;
    }

    if (ms->mode == MODE_ENUMERATE && ms->device_path != NULL) {
        output("option 'e' cannot be used with option 'd'");
        return false;
    }

    if (ms->mode == MODE_UPLOAD && *ms->upload_path == '\0') {
        output("argument for 'u' must be non-empty");
        return false;
    }

    return true;
}

int main(int argc, char **argv) {
    struct main_state ms = {
        .exit_code = EXIT_FAILURE,
        .mode = MODE_UNSPECIFIED,
        .upload_path = NULL,
        .device_path = NULL,
        .device = NULL,
    };
    char path[PATH_MAX];

    if (!parse_args(argc, argv, &ms))
        goto end;

    if (ms.mode != MODE_ENUMERATE) {
        if (ms.device_path == NULL) {
            if (!device_first(path)) {
                output("non-existent device path");
                goto end;
            }
            ms.device_path = path;
        }

        ms.device = device_open(ms.device_path);
        if (ms.device == NULL)
            goto end;
    }

    if (!privileges_discard())
        goto end;

    switch (ms.mode) {
        case MODE_ENUMERATE:
            ms.exit_code = mode_enumerate();
            break;

        case MODE_COMMAND:
            ms.exit_code = mode_command(ms.device);
            break;

        case MODE_UPLOAD:
            ms.exit_code = mode_upload(ms.device, ms.upload_path);
            break;

        case MODE_MODEL:
            ms.exit_code = mode_model(ms.device);
            break;

        default:
            ms.exit_code = EXIT_FAILURE;
            break;
    }

end:
    device_close(ms.device);
    platform_fini();
    return ms.exit_code;
}
