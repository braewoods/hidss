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
#include <libudev.h>
#include <linux/hidraw.h>
#include <linux/input.h>

struct device {
    int fd;
    char name[16];
};

static bool sysfs_check_device_info(const char *path) {
    char path2[PATH_MAX];
    int fd;
    char data[4096];
    ssize_t n;
    char *pos = data;
    char *line;
    char *id = NULL;
    char *bustype;
    char *vendor;
    char *product;
    unsigned long bustype_num;
    unsigned long vendor_id;
    unsigned long product_id;

    strbuild(path2, sizeof(path2), path, "/device/uevent");

    fd = open(path2, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        output("%s: %s: %s", "open", strerror(errno), path2);
        return false;
    }

    n = read(fd, data, sizeof(data));
    close(fd);
    if (n == -1) {
        output("%s: %s: %s", "read", strerror(errno), path2);
        return false;
    }

    if (n == sizeof(data)) {
        output("%s: %s: %s", __func__, "buffer overflow", path2);
        return false;
    }

    data[n] = '\0';

    while ((line = strsep(&pos, "\n")) != NULL) {
        char *pos2 = line;
        char *key;
        char *val;

        key = strsep(&pos2, "=");
        if (key == NULL)
            continue;

        val = strsep(&pos2, "\n");
        if (val == NULL)
            continue;

        if (strcmp(key, "HID_ID") != 0)
            continue;

        id = val;
        break;
    }

    if (id == NULL)
        return false;

    pos = id;

    bustype = strsep(&pos, ":");
    if (bustype == NULL)
        return false;

    vendor = strsep(&pos, ":");
    if (vendor == NULL)
        return false;

    product = strsep(&pos, "");
    if (product == NULL)
        return false;

    if (!strtoulong(bustype, &bustype_num, 16))
        return false;

    if (!strtoulong(vendor, &vendor_id, 16))
        return false;

    if (!strtoulong(product, &product_id, 16))
        return false;

    if (bustype_num != BUS_USB)
        return false;

    if (vendor_id != VENDOR_ID)
        return false;

    if (product_id != PRODUCT_ID)
        return false;

    return true;
}

static bool sysfs_check_report_descriptor(const char *path) {
    char path2[PATH_MAX];
    int fd;
    uint8_t rd[HID_MAX_DESCRIPTOR_SIZE];
    ssize_t n;

    strbuild(path2, sizeof(path2), path, "/device/report_descriptor");

    fd = open(path2, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        output("%s: %s: %s", "open", strerror(errno), path2);
        return false;
    }

    n = read(fd, rd, sizeof(rd));
    close(fd);
    if (n == -1) {
        output("%s: %s: %s", "read", strerror(errno), path2);
        return false;
    }

    if (n != REPORT_DESCRIPTOR_SIZE)
        return false;

    if (memcmp(rd, REPORT_DESCRIPTOR, n) != 0)
        return false;

    return true;
}

static struct device_info *sysfs_create_device_info(struct udev_device *hidraw) {
    struct udev_device *usb;
    struct device_info *di;
    const char *str;

    usb = udev_device_get_parent_with_subsystem_devtype(hidraw, "usb", "usb_device");
    if (usb == NULL) {
        output("%s: %s", "udev_device_get_parent_with_subsystem_devtype", "unknown failure");
        return NULL;
    }

    di = alloc(struct device_info, 1);
    if (di == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "struct device_info");
        return NULL;
    }

    memset(di, 0, sizeof(*di));

    str = udev_device_get_sysname(hidraw);
    if (str != NULL)
        strbuild(di->devpath, sizeof(di->devpath), str);

    str = udev_device_get_sysname(usb);
    if (str != NULL)
        strbuild(di->buspath, sizeof(di->buspath), str);

    str = udev_device_get_sysattr_value(usb, "manufacturer");
    if (str != NULL)
        strbuild(di->vendor, sizeof(di->vendor), str);

    str = udev_device_get_sysattr_value(usb, "product");
    if (str != NULL)
        strbuild(di->product, sizeof(di->product), str);

    str = udev_device_get_sysattr_value(usb, "serial");
    if (str != NULL)
        strbuild(di->serial, sizeof(di->serial), str);

    return di;
}

static bool hidraw_check_device_info(int fd, const char *name) {
    struct hidraw_devinfo di;

    if (ioctl(fd, HIDIOCGRAWINFO, &di) == -1) {
        output("%s: %s: %s", "ioctl (HIDIOCGRAWINFO)", strerror(errno), name);
        return false;
    }

    if (di.bustype != BUS_USB) {
        output("%s: %s", "bus type mismatch", name);
        return false;
    }

    if (di.vendor != VENDOR_ID) {
        output("%s: %s", "vendor id mismatch", name);
        return false;
    }

    if (di.product != PRODUCT_ID) {
        output("%s: %s", "product id mismatch", name);
        return false;
    }

    return true;
}

static bool hidraw_check_report_descriptor(int fd, const char *name) {
    int size;
    struct hidraw_report_descriptor rd;

    if (ioctl(fd, HIDIOCGRDESCSIZE, &size) == -1) {
        output("%s: %s: %s", "ioctl (HIDIOCGRDESCSIZE)", strerror(errno), name);
        return false;
    }

    if (size != REPORT_DESCRIPTOR_SIZE) {
        output("%s: %s", "report descriptor size mismatch", name);
        return false;
    }

    rd.size = size;

    if (ioctl(fd, HIDIOCGRDESC, &rd) == 1) {
        output("%s: %s: %s", "ioctl (HIDIOCGRDESC)", strerror(errno), name);
        return false;
    }

    if (memcmp(rd.value, REPORT_DESCRIPTOR, rd.size) != 0) {
        output("%s: %s", "report descriptor mismatch", name);
        return false;
    }

    return true;
}

struct device_info *device_enumerate(void) {
    struct udev *udev;
    struct udev_enumerate *enumerator;
    struct udev_list_entry *device_paths;
    struct udev_list_entry *device_path;
    struct device_info *root;
    struct device_info *end;

    udev = udev_new();
    if (udev == NULL) {
        output("%s: %s", "udev_new", "unknown failure");
        goto err_0;
    }

    enumerator = udev_enumerate_new(udev);
    if (enumerator == NULL) {
        output("%s: %s", "udev_enumerate_new", "unknown failure");
        goto err_1;
    }

    if (udev_enumerate_add_match_subsystem(enumerator, "hidraw") < 0) {
        output("%s: %s", "udev_enumerate_add_match_subsystem", "unknown failure");
        goto err_2;
    }

    if (udev_enumerate_scan_devices(enumerator) < 0) {
        output("%s: %s", "udev_enumerate_scan_devices", "unknown failure");
        goto err_2;
    }

    device_paths = udev_enumerate_get_list_entry(enumerator);
    root = end = NULL;

    udev_list_entry_foreach(device_path, device_paths) {
        const char *path;
        struct udev_device *hidraw;
        struct device_info *di;

        path = udev_list_entry_get_name(device_path);
        if (path == NULL) {
            output("%s: %s", "udev_list_entry_get_name", "unknown failure");
            continue;
        }

        if (!sysfs_check_device_info(path))
            continue;

        if (!sysfs_check_report_descriptor(path))
            continue;

        hidraw = udev_device_new_from_syspath(udev, path);
        if (hidraw == NULL) {
            output("%s: %s", "udev_device_new_from_syspath", "unknown failure");
            continue;
        }

        di = sysfs_create_device_info(hidraw);
        if (di == NULL) {
            udev_device_unref(hidraw);
            continue;
        }

        if (root == NULL) {
            root = end = di;
        } else {
            end->next = di;
            end = di;
        }

        udev_device_unref(hidraw);
    }

    udev_enumerate_unref(enumerator);

    udev_unref(udev);

    return root;

err_2:
    udev_enumerate_unref(enumerator);
err_1:
    udev_unref(udev);
err_0:
    return NULL;
}

struct device *device_open(const char *name) {
    char path[PATH_MAX];
    int fd;
    struct device *dev;

    if (!is_hidraw_device(name)) {
        output("%s: %s", "not a hidraw device", name);
        goto err_0;
    }

    strbuild(path, sizeof(path), "/dev/", name);

    fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd == -1) {
        output("%s: %s: %s", "open", strerror(errno), name);
        goto err_0;
    }

    if (!hidraw_check_device_info(fd, name))
        goto err_1;

    if (!hidraw_check_report_descriptor(fd, name))
        goto err_1;

    if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
        output("%s: %s: %s", "flock", strerror(errno), name);
        goto err_1;
    }

    dev = alloc(struct device, 1);
    if (dev == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "struct device");
        goto err_1;
    }

    dev->fd = fd;
    strbuild(dev->name, sizeof(dev->name), name);

    return dev;

err_1:
    close(fd);
err_0:
    return NULL;
}

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
    ssize_t n;

    n = write(dev->fd, buf, REPORT_BUFFER_SIZE);
    if (n == -1) {
        output("%s: %s: %s", "write", strerror(errno), dev->name);
        return false;
    }

    if (n != REPORT_BUFFER_SIZE) {
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

    if (res == 0) {
        return false;
    }

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
