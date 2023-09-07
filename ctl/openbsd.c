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
#include <dev/usb/usb.h>
#include <dev/usb/usbhid.h>

struct device {
    int fd;
    char name[16];
};

static bool check_device_info(int fd, const char *name, bool print) {
    struct usb_device_info udi;

    if (ioctl(fd, USB_GET_DEVICEINFO, &udi) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_DEVICEINFO)", strerror(errno), name);
        return false;
    }

    if (!verify_device_ids(print ? name : NULL, udi.udi_vendorNo, udi.udi_productNo))
        return false;

    return true;
}

static bool check_report_desc(int fd, const char *name, bool print) {
    struct usb_ctl_report_desc ucrd;
    int report_id;

    if (ioctl(fd, USB_GET_REPORT_DESC, &ucrd) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_REPORT_DESC)", strerror(errno), name);
        return false;
    }

    if (ioctl(fd, USB_GET_REPORT_ID, &report_id) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_REPORT_ID)", strerror(errno), name);
        return false;
    }

    if (!verify_report_desc(print ? name : NULL, ucrd.ucrd_data, ucrd.ucrd_size, report_id))
        return false;

    return true;
}

static struct device_info *create_device_info(int fd, const char *name) {
    struct usb_device_info udi;
    struct device_info *di;

    if (ioctl(fd, USB_GET_DEVICEINFO, &udi) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_DEVICEINFO)", strerror(errno), name);
        return NULL;
    }

    di = alloc(struct device_info, 1);
    if (di == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "struct device_info");
        return NULL;
    }

    memset(di, 0, sizeof(*di));

    strbuild(di->devpath, sizeof(di->devpath), name);
    format_bus_path(di->buspath, udi.udi_bus, &udi.udi_port, 1);
    strbuild(di->vendor, sizeof(di->vendor), udi.udi_vendor);
    strbuild(di->product, sizeof(di->product), udi.udi_product);
    strbuild(di->serial, sizeof(di->serial), udi.udi_serial);

    return di;
}

struct device_info *device_enumerate(void) {
    DIR *dir;
    struct dirent *d;
    struct device_info *root = NULL;
    struct device_info *end = NULL;

    dir = opendir("/dev");
    if (dir == NULL) {
        output("%s: %s: %s", "opendir", strerror(errno), "/dev");
        return NULL;
    }

    while ((d = readdir(dir)) != NULL) {
        const char *name = d->d_name;
        int fd;
        struct device_info *di;

        if (!is_uhid_device(name))
            continue;

        fd = openat(dirfd(dir), name, O_RDONLY | O_CLOEXEC);
        if (fd == -1)
            continue;

        if (!check_device_info(fd, name, false))
            goto close_fd;

        if (!check_report_desc(fd, name, false))
            goto close_fd;

        di = create_device_info(fd, name);
        if (di == NULL)
            goto close_fd;

        if (root == NULL) {
            root = di;
            end = di;
        } else {
            end->next = di;
            end = di;
        }

close_fd:
        close(fd);
    }

    closedir(dir);
    return root;
}

struct device *device_open(const char *name) {
    char path[PATH_MAX];
    int fd = -1;
    struct device *dev = NULL;

    if (!is_uhid_device(name)) {
        output("%s: %s", "not a uhid device", name);
        goto end;
    }

    strbuild(path, sizeof(path), "/dev/", name);
    fd = open(path, O_RDWR | O_CLOEXEC);

    if (fd == -1) {
        output("%s: %s: %s", "open", strerror(errno), name);
        goto end;
    }

    if (!check_device_info(fd, name, true))
        goto end;

    if (!check_report_desc(fd, name, true))
        goto end;

    dev = alloc(struct device, 1);
    if (dev == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "struct device");
        goto end;
    }

    dev->fd = fd;
    strbuild(dev->name, sizeof(dev->name), name);

end:
    if (dev == NULL && fd != -1)
        close(fd);
    return dev;
}

void device_close(struct device *dev) {
    if (dev == NULL)
        return;

    if (dev->fd != -1)
        close(dev->fd);

    free(dev);
}

bool device_reopen(struct device *dev, unsigned int delay) {
    struct device *new_dev;

    if (dev->fd != -1) {
        close(dev->fd);
        dev->fd = -1;
    }

    while (delay != 0)
        delay = sleep(delay);

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
    ssize_t n = write(dev->fd, buf + 1, REPORT_BUFFER_SIZE - 1);

    if (n == -1) {
        output("%s: %s: %s", "write", strerror(errno), dev->name);
        return false;
    }

    if (n != REPORT_BUFFER_SIZE - 1) {
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
    n = read(dev->fd, buf + 1, REPORT_BUFFER_SIZE - 1);
    if (n == -1) {
        output("%s: %s: %s", "read", strerror(errno), dev->name);
        return false;
    }

    if (n != REPORT_BUFFER_SIZE - 1) {
        output("%s: %s: %s", "read", "short packet", dev->name);
        return false;
    }

    return true;
}
