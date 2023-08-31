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
    PROGNAME_MAX = 256,
};

static char progname[PROGNAME_MAX];

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
