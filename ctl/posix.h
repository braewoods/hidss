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

#ifndef _POSIX_H_
#define _POSIX_H_

#include "common.h"
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ioctl.h>

static inline bool is_hidraw_device(const char *s) {
    size_t n;

    if (strncmp(s, "hidraw", 6) != 0)
        return false;

    n = digspn(s += 6);
    if (n == 0)
        return false;

    s += n;
    return (*s == '\0');
}

static inline bool is_bus_path(const char *s) {
    size_t n;

    n = digspn(s);
    if (n == 0)
        return false;

    s += n;
    if (*s != '-')
        return false;

    n = digspn(s += 1);
    if (n == 0)
        return false;

    for (s += n; *s == '.'; s += n) {
        n = digspn(s += 1);

        if (n == 0)
            return false;
    }

    return (*s == '\0');
}

static inline bool is_usb_device(const char *s) {
    size_t n;

    if (strncmp(s, "usb", 3) != 0)
        return false;

    n = digspn(s += 3);
    if (n == 0)
        return false;

    s += n;
    return (*s == '\0');
}

static inline bool is_uhidev_device(const char *s) {
    size_t n;

    if (strncmp(s, "uhidev", 6) != 0)
        return false;

    n = digspn(s += 6);
    if (n == 0)
        return false;

    s += n;
    return (*s == '\0');
}

static inline bool is_uhid_device(const char *s) {
    size_t n;

    if (strncmp(s, "uhid", 4) != 0)
        return false;

    n = digspn(s += 4);
    if (n == 0)
        return false;

    s += n;
    return (*s == '\0');
}
#endif
