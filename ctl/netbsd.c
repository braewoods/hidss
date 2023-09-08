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

#include "uhidraw.h"
#include <dev/usb/usb.h>
#include <dev/usb/usbhid.h>

static size_t walk_usb_tree(int fd, uint8_t addr, uint8_t key, uint8_t ports[static BUS_PORT_MAX], size_t len) {
    struct usb_device_info udi;

    if (len == BUS_PORT_MAX)
        return 0;

    if (addr == key)
        return len;

    udi.udi_addr = addr;

    if (ioctl(fd, USB_DEVICEINFO, &udi) == -1)
        return 0;

    for (int port = 0; port < udi.udi_nports; port++) {
        uint8_t addr;
        size_t n;

        addr = udi.udi_ports[port];
        if (addr >= USB_MAX_DEVICES)
            continue;

        ports[len] = port + 1;

        n = walk_usb_tree(fd, addr, key, ports, len + 1);
        if (n != 0)
            return n;
    }

    return 0;
}

static bool get_bus_path(const struct usb_device_info *udi, uint8_t ports[static BUS_PORT_MAX], size_t *len) {
    char path[PATH_MAX];
    int fd;

    snprintf(path, sizeof(path), "/dev/usb%hhu", udi->udi_bus);
    fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd == -1) {
        output("%s: %s: %s", "open", strerror(errno), path);
        return false;
    }

    *len = walk_usb_tree(fd, 0, udi->udi_addr, ports, 0);
    close(fd);

    return (*len != 0);
}

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
    uint8_t ports[BUS_PORT_MAX];
    size_t len;
    struct device_info *di;

    if (ioctl(fd, USB_GET_DEVICEINFO, &udi) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_DEVICEINFO)", strerror(errno), name);
        return NULL;
    }

    if (!get_bus_path(&udi, ports, &len))
        return NULL;

    di = alloc(struct device_info, 1);
    if (di == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "struct device_info");
        return NULL;
    }

    memset(di, 0, sizeof(*di));

    strbuild(di->devpath, sizeof(di->devpath), name);
    format_bus_path(di->buspath, udi.udi_bus, ports, len);
    strbuild(di->vendor, sizeof(di->vendor), udi.udi_vendor);
    strbuild(di->product, sizeof(di->product), udi.udi_product);
    strbuild(di->serial, sizeof(di->serial), udi.udi_serial);

    return di;
}

static bool hid_set_raw(int fd, const char *name) {
    int raw = true;

    if (ioctl(fd, USB_HID_SET_RAW, &raw) == -1) {
        output("%s: %s: %s", "ioctl (HID_SET_RAW)", strerror(errno), name);
        return false;
    }

    return true;
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

    if (!hid_set_raw(fd, name))
        goto end;

    dev = uhidraw_create_device(fd, 1, name);

end:
    if (dev == NULL && fd != -1)
        close(fd);
    return dev;
}
