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
#include <linux/hidraw.h>
#include <linux/input.h>

#define HIDRAW_SYSFS "/sys/class/hidraw"

struct device {
    int fd;
    char name[16];
};

static ssize_t sysfs_read_field(const char *path, void *buf, size_t size, bool print) {
    int fd;
    ssize_t n;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        if (print)
            output("%s: %s: %s", "open", strerror(errno), path);
        return -1;
    }

    n = read(fd, buf, size);
    close(fd);
    if (n == -1) {
        if (print)
            output("%s: %s: %s", "read", strerror(errno), path);
        return -1;
    }

    return n;
}

static bool sysfs_read_line(const char *base, const char *field, char *buf, size_t size) {
    char path[PATH_MAX];
    ssize_t n;

    strbuild(path, sizeof(path), base, "/", field);
    n = sysfs_read_field(path, buf, size, false);
    if (n == -1)
        return false;

    buf[n - 1] = '\0';
    return true;
}

static char *uevent_get_field(char *data, const char *name) {
    char *ctx = NULL;
    char *field = NULL;

    for (
        char *line = strtok_r(data, "\n", &ctx);
        line != NULL;
        line = strtok_r(NULL, "\n", &ctx)
    ) {
        char *ctx2 = NULL;
        char *key;
        char *val;

        key = strtok_r(line, "=", &ctx2);
        if (key == NULL)
            continue;

        val = strtok_r(NULL, "", &ctx2);
        if (val == NULL)
            continue;

        if (strcmp(key, name) != 0)
            continue;

        field = val;
        break;
    }

    return field;
}

static bool uevent_check_hid_id(char *hid_id) {
    char *ctx = NULL;
    char *bustype;
    char *vendor;
    char *product;
    long bustype_n;
    long vendor_n;
    long product_n;

    bustype = strtok_r(hid_id, ":", &ctx);
    if (bustype == NULL)
        return false;

    vendor = strtok_r(NULL, ":", &ctx);
    if (vendor == NULL)
        return false;

    product = strtok_r(NULL, "", &ctx);
    if (product == NULL)
        return false;

    if (!strtolong(bustype, &bustype_n, 16))
        return false;

    if (!strtolong(vendor, &vendor_n, 16))
        return false;

    if (!strtolong(product, &product_n, 16))
        return false;

    if (bustype_n != BUS_USB)
        return false;

    if (!verify_device_ids(NULL, vendor_n, product_n))
        return false;

    return true;
}

static bool sysfs_check_device_info(const char *name) {
    char path[PATH_MAX];
    char buf[4096];
    ssize_t n;
    char *hid_id;

    strbuild(path, sizeof(path), HIDRAW_SYSFS, "/", name, "/device/uevent");
    n = sysfs_read_field(path, buf, sizeof(buf), true);

    if (n == sizeof(buf)) {
        output("%s: %s: %s", __func__, "buffer truncation", path);
        return false;
    }

    buf[n] = '\0';

    hid_id = uevent_get_field(buf, "HID_ID");
    if (hid_id == NULL)
        return false;

    if (!uevent_check_hid_id(hid_id))
        return false;

    return true;
}

static bool sysfs_check_report_descriptor(const char *name) {
    char path[PATH_MAX];
    uint8_t rd[HID_MAX_DESCRIPTOR_SIZE];
    ssize_t n;

    strbuild(path, sizeof(path), HIDRAW_SYSFS, "/", name, "/device/report_descriptor");
    n = sysfs_read_field(path, rd, sizeof(rd), true);

    if (!verify_report_descriptor(NULL, rd, n, REPORT_ID))
        return false;

    return true;
}

static struct device_info *sysfs_create_device_info(const char *name) {
    char tmp[PATH_MAX];
    char path[PATH_MAX];
    char *s;
    struct device_info *di;
    char buf[4096];

    strbuild(tmp, sizeof(tmp), HIDRAW_SYSFS, "/", name);
    if (realpath(tmp, path) == NULL) {
        output("%s: %s: %s", "realpath", strerror(errno), tmp);
        return NULL;
    }

    while ((s = strrchr(path, '/')) != NULL) {
        if (is_bus_path(s + 1))
            break;

        *s = '\0';
    }

    if (s == NULL) {
        output("%s: %s: %s", __func__, "failed to find usb parent", tmp);
        return NULL;
    }

    di = alloc(struct device_info, 1);
    if (di == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "struct device_info");
        return NULL;
    }

    memset(di, 0, sizeof(*di));

    strbuild(di->devpath, sizeof(di->devpath), name);
    strbuild(di->buspath, sizeof(di->buspath), s + 1);

    if (sysfs_read_line(path, "manufacturer", buf, sizeof(buf)))
        strbuild(di->vendor, sizeof(di->vendor), buf);

    if (sysfs_read_line(path, "product", buf, sizeof(buf)))
        strbuild(di->product, sizeof(di->product), buf);

    if (sysfs_read_line(path, "serial", buf, sizeof(buf)))
        strbuild(di->serial, sizeof(di->serial), buf);

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

    if (!verify_device_ids(name, di.vendor, di.product))
        return false;

    return true;
}

static bool hidraw_check_report_descriptor(int fd, const char *name) {
    int size;
    struct hidraw_report_descriptor rd;

    if (ioctl(fd, HIDIOCGRDESCSIZE, &size) == -1) {
        output("%s: %s: %s", "ioctl (HIDIOCGRDESCSIZE)", strerror(errno), name);
        return false;
    }

    rd.size = size;

    if (ioctl(fd, HIDIOCGRDESC, &rd) == 1) {
        output("%s: %s: %s", "ioctl (HIDIOCGRDESC)", strerror(errno), name);
        return false;
    }

    if (!verify_report_descriptor(name, rd.value, rd.size, REPORT_ID))
        return false;

    return true;
}

struct device_info *device_enumerate(void) {
    DIR *dir;
    struct dirent *d;
    struct device_info *root = NULL;
    struct device_info *end = NULL;

    dir = opendir(HIDRAW_SYSFS);
    if (dir == NULL) {
        output("%s: %s: %s", "opendir", strerror(errno), HIDRAW_SYSFS);
        return NULL;
    }

    while ((d = readdir(dir)) != NULL) {
        struct device_info *di;

        if (!is_hidraw_device(d->d_name))
            continue;

        if (!sysfs_check_device_info(d->d_name))
            continue;

        if (!sysfs_check_report_descriptor(d->d_name))
            continue;

        di = sysfs_create_device_info(d->d_name);
        if (di == NULL)
            continue;

        if (root == NULL) {
            root = di;
            end = di;
        } else {
            end->next = di;
            end = di;
        }
    }

    closedir(dir);
    return root;
}

struct device *device_open(const char *name) {
    char path[PATH_MAX];
    int fd = -1;
    struct device *dev = NULL;

    if (!is_hidraw_device(name)) {
        output("%s: %s", "not a hidraw device", name);
        goto end;
    }

    strbuild(path, sizeof(path), "/dev/", name);
    fd = open(path, O_RDWR | O_CLOEXEC);

    if (fd == -1) {
        output("%s: %s: %s", "open", strerror(errno), name);
        goto end;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
        output("%s: %s: %s", "flock", strerror(errno), name);
        goto end;
    }

    if (!hidraw_check_device_info(fd, name))
        goto end;

    if (!hidraw_check_report_descriptor(fd, name))
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
    ssize_t n = write(dev->fd, buf, REPORT_BUFFER_SIZE);

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
