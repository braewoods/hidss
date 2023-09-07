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

#include "posix.h"

#if defined(__linux__)
enum {
    HID_WRITE_SKIP = 0,
    HID_READ_SKIP = 1,
};
#else
enum {
    HID_WRITE_SKIP = 1,
    HID_READ_SKIP = 1,
};
#endif

static uid_t initial_uid;
static uid_t initial_euid;

bool platform_init(void) {
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        output("%s: %s", "signal", strerror(errno));
        return false;
    }

    initial_uid = getuid();
    initial_euid = geteuid();

    return true;
}

void platform_fini(void) {

}

bool privileges_discard(void) {
    if (seteuid(initial_uid) == -1) {
        output("%s: %s", "seteuid", strerror(errno));
        return false;
    }

    return true;
}

bool privileges_restore(void) {
    if (seteuid(initial_euid) == -1) {
        output("%s: %s", "seteuid", strerror(errno));
        return false;
    }

    return true;
}

bool file_get_contents(const char *path, uint8_t **data, size_t *size, long low, long high) {
    int fd = -1;
    struct stat st;
    uint8_t *buf = NULL;
    bool rv = false;
    ssize_t n;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        output("%s: %s: %s", "open", strerror(errno), path);
        goto end;
    }

    if (fstat(fd, &st) == -1) {
        output("%s: %s: %s", "fstat", strerror(errno), path);
        goto end;
    }

    if (!inrange(st.st_size, low, high)) {
        output("size of %s not in range of %ld to %ld", path, low, high);
        goto end;
    }

    buf = alloc(uint8_t, st.st_size);
    if (buf == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "uint8_t");
        goto end;
    }

    n = read(fd, buf, st.st_size);
    if (n == -1) {
        output("%s: %s: %s", "read", strerror(errno), path);
        goto end;
    }

    if (n != st.st_size) {
        output("%s: %s: %s", "read", "short read", path);
        goto end;
    }

    *data = buf;
    *size = st.st_size;
    rv = true;

end:
    if (!rv)
        free(buf);
    if (fd != -1)
        close(fd);
    return rv;
}

#if !defined(__APPLE__)
void device_close(struct device *dev) {
    if (dev == NULL)
        return;

    if (dev->fd != -1)
        close(dev->fd);

    free(dev);
}

bool device_reopen(struct device *dev, time_t delay) {
    struct timespec req;
    struct timespec rem;
    struct device *new_dev;

    if (dev->fd != -1) {
        close(dev->fd);
        dev->fd = -1;
    }

    req.tv_sec = delay;
    req.tv_nsec = 0;

    while (nanosleep(&req, &rem) == -1)
        req = rem;

    new_dev = device_open(dev->name);
    if (new_dev == NULL) {
        output("%s: %s", "failed to reopen device", dev->name);
        return false;
    }

    memcpy(dev, new_dev, sizeof(*dev));
    free(new_dev);
    return true;
}

bool device_write(struct device *dev, const uint8_t buf[static REPORT_BUFFER_SIZE]) {
    ssize_t n = write(dev->fd, buf + HID_WRITE_SKIP, REPORT_BUFFER_SIZE - HID_WRITE_SKIP);

    if (n == -1) {
        output("%s: %s: %s", "write", strerror(errno), dev->name);
        return false;
    }

    if (n != REPORT_BUFFER_SIZE - HID_WRITE_SKIP) {
        output("%s: %s: %s", "write", "short packet", dev->name);
        return false;
    }

    return true;
}

bool device_read(struct device *dev, uint8_t buf[static REPORT_BUFFER_SIZE], int to) {
    int res;
    struct pollfd fds;
    ssize_t n;

    fds.fd = dev->fd;
    fds.events = POLLIN;

    res = poll(&fds, 1, to);
    if (res == -1) {
        output("%s: %s: %s", "poll", strerror(errno), dev->name);
        return false;
    }

    if (res == 0)
        return false;

    *buf = REPORT_ID;
    n = read(dev->fd, buf + HID_READ_SKIP, REPORT_BUFFER_SIZE - HID_READ_SKIP);
    if (n == -1) {
        output("%s: %s: %s", "read", strerror(errno), dev->name);
        return false;
    }

    if (n != REPORT_BUFFER_SIZE - HID_READ_SKIP) {
        output("%s: %s: %s", "read", "short packet", dev->name);
        return false;
    }

    return true;
}
#endif
