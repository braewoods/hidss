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

struct main_state {
    const char *theme;
    const char *output;
    struct section *section;
    long rotate;
};

static bool parse_args(int argc, char **argv, struct main_state *ms) {
    int opt;
    long n;

    setprogname(argv[0]);

    while ((opt = getopt(argc, argv, ":t:o:r:")) != -1) {
        switch (opt) {
            case 't':
                ms->theme = optarg;
                break;

            case 'o':
                ms->output = optarg;
                break;

            case 'r':
                if (!strtolong(optarg, &n, 10)) {
                    output("argument for '%c' must be an integer", opt);
                    return false;
                }
                switch (n) {
                    case 0:
                        ms->rotate = HIDSS_WIDGET_ROTATE_0;
                        break;
                    case 90:
                        ms->rotate = HIDSS_WIDGET_ROTATE_90;
                        break;
                    case 180:
                        ms->rotate = HIDSS_WIDGET_ROTATE_180;
                        break;
                    case 270:
                        ms->rotate = HIDSS_WIDGET_ROTATE_270;
                        break;
                    default:
                        output("argument for '%c' must be one of: 0, 90, 180, or 270", opt);
                        return false;
                }
                break;

            case ':':
                output("missing argument for '%c'", optopt);
                return false;

            case '?':
                output("unknown option '%c'", optopt);
                return false;
        }
    }

    if (ms->theme == NULL) {
        output("argument 't' must be specified");
        return false;
    }

    // TODO: check the filename of output?
    if (ms->output == NULL) {
        output("argument 'o' must be specified");
        return false;
    }

    return true;
}

int main(int argc, char **argv) {
    struct main_state ms = {
        .theme = NULL,
        .output = NULL,
        .section = NULL,
        .rotate = HIDSS_WIDGET_ROTATE_0,
    };
    int ec = EXIT_FAILURE;

    if (!parse_args(argc, argv, &ms))
        goto end;

    if (!section_parse(ms.theme, ms.rotate, &ms.section))
        goto end;

    if (!output_image(ms.output, ms.section, ms.rotate))
        goto end;

    ec = EXIT_SUCCESS;

end:
    section_free(ms.section);
    return ec;
}
