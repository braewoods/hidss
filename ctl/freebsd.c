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
#include <sys/sysctl.h>
#include <dev/hid/hidraw.h>
#include <dev/evdev/input.h>
#include <dev/usb/usb_ioctl.h>
#include <dev/usb/usbhid.h>

enum {
    DEVICE_UNKNOWN = -1,
    DEVICE_HIDRAW,
    DEVICE_UHID,
};

static int get_device_type(const char *name) {
    if (is_hidraw_device(name))
        return DEVICE_HIDRAW;

    if (is_uhid_device(name))
        return DEVICE_UHID;

    return DEVICE_UNKNOWN;
}

static bool hidraw_check_device_info(int fd, const char *name, bool print) {
    struct hidraw_devinfo di;

    if (ioctl(fd, HIDIOCGRAWINFO, &di) == -1) {
        output("%s: %s: %s", "ioctl (HIDIOCGRAWINFO)", strerror(errno), name);
        return false;
    }

    if (di.bustype != BUS_USB) {
        output("%s: %s", "bus type mismatch", name);
        return false;
    }

    if (!verify_device_ids(print ? name : NULL, di.vendor, di.product))
        return false;

    return true;
}

static bool uhid_check_device_info(int fd, const char *name, bool print) {
    struct usb_device_info udi;

    if (ioctl(fd, USB_GET_DEVICEINFO, &udi) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_DEVICEINFO)", strerror(errno), name);
        return false;
    }

    if (!verify_device_ids(print ? name : NULL, udi.udi_vendorNo, udi.udi_productNo))
        return false;

    return true;
}

static bool check_device_info(int type, int fd, const char *name, bool print) {
    static bool (* const table[2]) (int, const char *, bool) = {
        [DEVICE_HIDRAW] = hidraw_check_device_info,
        [DEVICE_UHID] = uhid_check_device_info,
    };

    return table[type](fd, name, print);
}

static bool hidraw_check_report_desc(int fd, const char *name, bool print) {
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

    if (!verify_report_desc(print ? name : NULL, rd.value, rd.size, REPORT_ID))
        return false;

    return true;
}

static bool uhid_check_report_desc(int fd, const char *name, bool print) {
    uint8_t buf[HID_MAX_DESCRIPTOR_SIZE];
    struct usb_gen_descriptor ugd;

    ugd.ugd_data = buf;
    ugd.ugd_maxlen = sizeof(buf);

    if (ioctl(fd, USB_GET_REPORT_DESC, &ugd) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_REPORT_DESC)", strerror(errno), name);
        return false;
    }

    if (!verify_report_desc(print ? name : NULL, ugd.ugd_data, ugd.ugd_actlen, REPORT_ID))
        return false;

    return true;
}

static bool check_report_desc(int type, int fd, const char *name, bool print) {
    static bool (* const table[2]) (int, const char *, bool) = {
        [DEVICE_HIDRAW] = hidraw_check_report_desc,
        [DEVICE_UHID] = uhid_check_report_desc,
    };

    return table[type](fd, name, print);
}

static char *extract_field(char *str, const char *name) {
    char *ctx = NULL;

    for (
        char *field = strtok_r(str, " ", &ctx);
        field != NULL;
        field = strtok_r(NULL, " ", &ctx)
    ) {
        char *ctx2 = NULL;
        char *key;
        char *val;

        key = strtok_r(field, "=", &ctx2);
        if (key == NULL)
            continue;

        val = strtok_r(NULL, "", &ctx2);
        if (val == NULL)
            continue;

        if (strcmp(key, name) != 0)
            continue;

        return val;
    }

    return NULL;
}

static bool find_uhub_direct_descendant(const char *dev, char buf[static DEVNAME_MAX]) {
    char data[DEVNAME_MAX];

    strbuild(data, sizeof(data), dev);

    do {
        char name[64];
        size_t len = DEVNAME_MAX - 1;
        int off;

        strbuild(buf, DEVNAME_MAX, data);

        off = digcspn(data);
        snprintf(
            name,
            sizeof(name),
            "dev.%.*s.%s.%%parent",
            off,
            data,
            data + off
        );

        if (sysctlbyname(name, data, &len, NULL, 0) == -1) {
            output("%s: %s: %s", "sysctlbyname", strerror(errno), name);
            return false;
        }

        data[len] = '\0';
    } while(!is_uhub_device(data));

    return true;
}

static bool find_ugen(const char *dev, char buf[static DEVNAME_MAX]) {
    char par[DEVNAME_MAX];
    char name[64];
    char data[128];
    int off;
    size_t len = sizeof(data) - 1;
    char *ugen;

    if (!find_uhub_direct_descendant(dev, par))
        return false;

    off = digcspn(par);
    snprintf(
        name,
        sizeof(name),
        "dev.%.*s.%s.%%location",
        off,
        par,
        par + off
    );

    if (sysctlbyname(name, data, &len, NULL, 0) == -1) {
        output("%s: %s: %s", "sysctlbyname", strerror(errno), name);
        return false;
    }

    data[len] = '\0';

    ugen = extract_field(data, "ugen");
    if (ugen == NULL) {
        output("%s: %s", "corrupted %location data", name);
        return false;
    }

    strbuild(buf, DEVNAME_MAX, ugen);
    return true;
}

static bool open_ugen(const char *name, int *out) {
    char path[PATH_MAX];
    int fd;

    strbuild(path, sizeof(path), "/dev/", name);
    fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd == -1) {
        output("%s: %s: %s", "open", strerror(errno), name);
        return false;
    }

    *out = fd;
    return true;
}

static bool get_ugen_device_info(int fd, const char *name, struct usb_device_info *udi) {
    if (ioctl(fd, USB_GET_DEVICEINFO, udi) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_DEVICEINFO)", strerror(errno), name);
        return false;
    }

    return true;
}

static bool get_ugen_bus_path(int fd, const char *name, uint8_t ports[static BUS_PORT_MAX], size_t *len) {
    struct usb_device_port_path udp;

    if (ioctl(fd, USB_GET_DEV_PORT_PATH, &udp) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_DEV_PORT_PATH)", strerror(errno), name);
        return false;
    }

    memcpy(ports, udp.udp_port_no, udp.udp_port_level);
    *len = udp.udp_port_level;
    return true;
}

static struct device_info *create_device_info(const char *name) {
    char ugen[DEVNAME_MAX];
    int fd;
    struct usb_device_info udi;
    uint8_t ports[BUS_PORT_MAX];
    size_t len;
    bool valid_udi;
    bool valid_bp;
    struct device_info *di;

    if (!find_ugen(name, ugen))
        return NULL;

    if (!open_ugen(ugen, &fd))
        return NULL;

    valid_udi = get_ugen_device_info(fd, ugen, &udi);
    valid_bp = get_ugen_bus_path(fd, ugen, ports, &len);
    close(fd);

    if (!valid_udi || !valid_bp)
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
        int type;
        int fd;
        struct device_info *di;

        type = get_device_type(name);
        if (type == DEVICE_UNKNOWN)
            continue;

        fd = openat(dirfd(dir), name, O_RDONLY | O_CLOEXEC);
        if (fd == -1)
            continue;

        if (!check_device_info(type, fd, name, false))
            goto close_fd;

        if (!check_report_desc(type, fd, name, false))
            goto close_fd;

        di = create_device_info(name);
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
    int type;
    char path[PATH_MAX];
    int fd = -1;
    struct device *dev = NULL;

    type = get_device_type(name);
    if (type == DEVICE_UNKNOWN) {
        output("%s: %s", "not a hidraw or uhid device", name);
        goto end;
    }

    strbuild(path, sizeof(path), "/dev/", name);
    fd = open(path, O_RDWR | O_CLOEXEC);

    if (fd == -1) {
        output("%s: %s: %s", "open", strerror(errno), name);
        goto end;
    }

    if (!check_device_info(type, fd, name, true))
        goto end;

    if (!check_report_desc(type, fd, name, true))
        goto end;

    dev = uhidraw_create_device(fd, type, name);

end:
    if (dev == NULL && fd != -1)
        close(fd);
    return dev;
}
