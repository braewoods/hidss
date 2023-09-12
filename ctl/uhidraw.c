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
#include <linux/hidraw.h>
#include <linux/input.h>
#define HAVE_HIDRAW
#elif defined(__NetBSD__)
#include <dev/usb/usb.h>
#include <dev/usb/usbhid.h>
#define HAVE_UHID
#define HAVE_UHID_DEVICE_INFO
#define HAVE_UHID_REPORT_DESC 1
#elif defined(__OpenBSD__)
#include <dev/usb/usb.h>
#include <dev/usb/usbhid.h>
#define HAVE_UHID
#define HAVE_UHID_DEVICE_INFO
#define HAVE_UHID_REPORT_DESC 1
#elif defined(__FreeBSD__)
#include <sys/sysctl.h>
#include <dev/hid/hidraw.h>
#include <dev/evdev/input.h>
#include <dev/usb/usb_ioctl.h>
#include <dev/usb/usbhid.h>
#define HAVE_UGEN
#define HAVE_HIDRAW
#define HAVE_UHID
#define HAVE_UHID_DEVICE_INFO
#define HAVE_UHID_REPORT_DESC 2
#elif defined(__DragonFly__)
#include <sys/sysctl.h>
#include <bus/u4b/usb_ioctl.h>
#include <bus/u4b/usbhid.h>
#define HAVE_UGEN
#define HAVE_UGEN_DEVICE_INFO
#define HAVE_UHID
#define HAVE_UHID_REPORT_DESC 2
#endif

enum {
    DEVICE_UNKNOWN = -1,
    DEVICE_HIDRAW,
    DEVICE_UHID,
};

enum {
    DEVNAME_MAX = 16,
};

struct device {
    int fd;
    int ws;
    char name[DEVNAME_MAX];
};

#if defined(HAVE_HIDRAW)
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
#endif

#if defined(HAVE_UHID)
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

static int get_device_type(const char *name) {
#if defined(HAVE_HIDRAW)
    if (is_hidraw_device(name))
        return DEVICE_HIDRAW;
#endif

#if defined(HAVE_UHID)
    if (is_uhid_device(name))
        return DEVICE_UHID;
#endif

    return DEVICE_UNKNOWN;
}

#if defined(__linux__)
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

static ssize_t sysfs_read_field(const char *path, void *buf, size_t size) {
    int fd = -1;
    ssize_t n = -1;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd == -1)
        goto end;

    n = read(fd, buf, size);
    if (n == -1)
        goto end;

end:
    if (fd != -1)
        close(fd);
    return n;
}

static bool sysfs_read_line(const char *base, const char *field, char *buf, size_t size) {
    char path[PATH_MAX];
    ssize_t n;

    strbuild(path, sizeof(path), base, "/", field);
    n = sysfs_read_field(path, buf, size);
    if (n == -1)
        return false;

    buf[n - 1] = '\0';
    return true;
}

static bool fill_device_info(int unused, const char *name, struct device_info *di) {
    char tmp[PATH_MAX];
    char path[PATH_MAX];
    char *s;
    char buf[USB_STRING_MAX];

    (void) unused;

    strbuild(tmp, sizeof(tmp), "/sys/class/hidraw/", name);
    if (realpath(tmp, path) == NULL) {
        output("%s: %s: %s", "realpath", strerror(errno), name);
        return false;
    }

    while ((s = strrchr(path, '/')) != NULL) {
        if (is_bus_path(s + 1))
            break;

        *s = '\0';
    }

    if (s == NULL) {
        output("%s: %s: %s", __func__, "failed to find usb parent", name);
        return false;
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

    return true;
}
#endif

#if defined(HAVE_UHID)
static struct device_info *fill_usb_device_info(struct device_info *di, const char *name, const struct usb_device_info *udi, const uint8_t *ports, size_t len) {
    memset(di, 0, sizeof(*di));

    strbuild(di->devpath, sizeof(di->devpath), name);
    format_bus_path(di->buspath, udi->udi_bus, ports, len);
    strbuild(di->vendor, sizeof(di->vendor), udi->udi_vendor);
    strbuild(di->product, sizeof(di->product), udi->udi_product);
    strbuild(di->serial, sizeof(di->serial), udi->udi_serial);

    return di;
}
#endif

#if defined(__NetBSD__)
static size_t netbsd_walk_usb_tree(int fd, uint8_t addr, uint8_t key, uint8_t ports[static BUS_PORT_MAX], size_t len) {
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

        n = netbsd_walk_usb_tree(fd, addr, key, ports, len + 1);
        if (n != 0)
            return n;
    }

    return 0;
}

static bool netbsd_get_bus_path(const struct usb_device_info *udi, uint8_t ports[static BUS_PORT_MAX], size_t *len) {
    char path[PATH_MAX];
    int fd;

    snprintf(path, sizeof(path), "/dev/usb%hhu", udi->udi_bus);
    fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd == -1) {
        output("%s: %s: %s", "open", strerror(errno), path);
        return false;
    }

    for (size_t i = 0; i < USB_MAX_DEVICES; i++) {
        *len = netbsd_walk_usb_tree(fd, i, udi->udi_addr, ports, 0);

        if (*len != 0)
            break;
    }

    close(fd);

    return (*len != 0);
}

static bool netbsd_enable_raw(int fd, const char *name) {
    int raw = true;

    if (ioctl(fd, USB_HID_SET_RAW, &raw) == -1) {
        output("%s: %s: %s", "ioctl (HID_SET_RAW)", strerror(errno), name);
        return false;
    }

    return true;
}
#endif

#if defined(HAVE_UGEN)
static inline bool is_uhub_device(const char *s) {
    size_t n;

    if (strncmp(s, "uhub", 4) != 0)
        return false;

    n = digspn(s += 4);
    if (n == 0)
        return false;

    s += n;
    return (*s == '\0');
}

static char *ugen_extract_field(char *str, const char *name) {
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

static bool ugen_find_uhub_descendant(const char *dev, char buf[static DEVNAME_MAX]) {
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

static bool ugen_find_data(const char *dev, char buf[static DEVNAME_MAX]) {
    char par[DEVNAME_MAX];
    char name[64];
    char data[128];
    int off;
    size_t len = sizeof(data) - 1;
    char *ugen;

    if (!ugen_find_uhub_descendant(dev, par))
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

    ugen = ugen_extract_field(data, "ugen");
    if (ugen == NULL) {
        output("%s: %s", "corrupted %location data", name);
        return false;
    }

    strbuild(buf, DEVNAME_MAX, ugen);
    return true;
}

static bool ugen_open_device(const char *name, int *out) {
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

static bool ugen_get_device_info(int fd, const char *name, struct usb_device_info *udi) {
    if (ioctl(fd, USB_GET_DEVICEINFO, udi) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_DEVICEINFO)", strerror(errno), name);
        return false;
    }

    return true;
}

static bool ugen_get_bus_path(int fd, const char *name, uint8_t ports[static BUS_PORT_MAX], size_t *len) {
    struct usb_device_port_path udp;

    if (ioctl(fd, USB_GET_DEV_PORT_PATH, &udp) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_DEV_PORT_PATH)", strerror(errno), name);
        return false;
    }

    memcpy(ports, udp.udp_port_no, udp.udp_port_level);
    *len = udp.udp_port_level;
    return true;
}

#if defined(HAVE_UGEN_DEVICE_INFO)
static bool ugen_check_device_info(int unused, const char *name, bool print) {
    char ugen[DEVNAME_MAX];
    int fd;
    struct usb_device_info udi;
    bool valid_udi;

    (void) unused;

    if (!ugen_find_data(name, ugen))
        return false;

    if (!ugen_open_device(ugen, &fd))
        return false;

    valid_udi = ugen_get_device_info(fd, ugen, &udi);
    close(fd);

    if (!valid_udi)
        return false;

    if (!verify_device_ids(print ? name : NULL, udi.udi_vendorNo, udi.udi_productNo))
        return false;

    return true;
}
#endif

static bool fill_device_info(int unused, const char *name, struct device_info *di) {
    char ugen[DEVNAME_MAX];
    int fd;
    struct usb_device_info udi;
    uint8_t ports[BUS_PORT_MAX];
    size_t len;
    bool valid_udi;
    bool valid_bp;

    (void) unused;

    if (!ugen_find_data(name, ugen))
        return false;

    if (!ugen_open_device(ugen, &fd))
        return false;

    valid_udi = ugen_get_device_info(fd, ugen, &udi);
    valid_bp = ugen_get_bus_path(fd, ugen, ports, &len);
    close(fd);

    if (!valid_udi || !valid_bp)
        return false;

    return fill_usb_device_info(di, name, &udi, ports, len);
}
#endif

#if defined(HAVE_HIDRAW)
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
#endif

#if defined(HAVE_UHID_DEVICE_INFO)
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
#endif

#if defined(HAVE_UHID_REPORT_DESC)

#if HAVE_UHID_REPORT_DESC == 1
static bool uhid_check_report_desc(int fd, const char *name, bool print) {
    struct usb_ctl_report_desc ucrd;

    if (ioctl(fd, USB_GET_REPORT_DESC, &ucrd) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_REPORT_DESC)", strerror(errno), name);
        return false;
    }

    if (!verify_report_desc(print ? name : NULL, ucrd.ucrd_data, ucrd.ucrd_size, REPORT_ID))
        return false;

    return true;
}
#endif

#if HAVE_UHID_REPORT_DESC == 2
static bool uhid_check_report_desc(int fd, const char *name, bool print) {
    uint8_t buf[4096];
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
#endif

#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
static bool fill_device_info(int fd, const char *name, struct device_info *di) {
    struct usb_device_info udi;
    uint8_t ports[BUS_PORT_MAX];
    size_t len;

    if (ioctl(fd, USB_GET_DEVICEINFO, &udi) == -1) {
        output("%s: %s: %s", "ioctl (USB_GET_DEVICEINFO)", strerror(errno), name);
        return false;
    }

#if defined(__NetBSD__)
    if (!netbsd_get_bus_path(&udi, ports, &len))
        return false;
#endif

#if defined(__OpenBSD__)
    *ports = udi.udi_port;
    len = 1;
#endif

    return fill_usb_device_info(di, name, &udi, ports, len);
}
#endif

static bool check_device_info(int type, int fd, const char *name, bool print) {
#if defined(HAVE_HIDRAW)
    if (type == DEVICE_HIDRAW)
        return hidraw_check_device_info(fd, name, print);
#endif

#if defined(HAVE_UGEN_DEVICE_INFO)
    if (type == DEVICE_UHID)
        return ugen_check_device_info(fd, name, print);
#endif

#if defined(HAVE_UHID_DEVICE_INFO)
    if (type == DEVICE_UHID)
        return uhid_check_device_info(fd, name, print);
#endif

    return false;
}

static bool check_report_desc(int type, int fd, const char *name, bool print) {
#if defined(HAVE_HIDRAW)
    if (type == DEVICE_HIDRAW)
        return hidraw_check_report_desc(fd, name, print);
#endif

#if defined(HAVE_UHID_REPORT_DESC)
    if (type == DEVICE_UHID)
        return uhid_check_report_desc(fd, name, print);
#endif

    return false;
}

static struct device_info *create_device_info(int fd, const char *name) {
    struct device_info *di = alloc(struct device_info, 1);

    if (di == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "struct device_info");
        return NULL;
    }

    if (!fill_device_info(fd, name, di)) {
        free(di);
        return NULL;
    }

    return di;
}

static struct device *create_device(int fd, int ws, const char *name) {
    struct device *dev;

    dev = alloc(struct device, 1);
    if (dev == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "struct device");
        return NULL;
    }

    memset(dev, 0, sizeof(*dev));

    dev->fd = fd;
    dev->ws = ws;
    strbuild(dev->name, sizeof(dev->name), name);

    return dev;
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

#if defined(__linux__)
        if (flock(fd, LOCK_EX | LOCK_NB) == -1)
            goto close_fd;
#endif

        if (!check_device_info(type, fd, name, false))
            goto close_fd;

        if (!check_report_desc(type, fd, name, false))
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
    int type;
    char path[PATH_MAX];
    int fd = -1;
    struct device *dev = NULL;

    type = get_device_type(name);
    if (type == DEVICE_UNKNOWN) {
        output("%s: %s", "not a supported device", name);
        goto end;
    }

    strbuild(path, sizeof(path), "/dev/", name);
    fd = open(path, O_RDWR | O_CLOEXEC);

    if (fd == -1) {
        output("%s: %s: %s", "open", strerror(errno), name);
        goto end;
    }

#if defined(__linux__)
    if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
        output("%s: %s: %s", "flock", strerror(errno), name);
        goto end;
    }
#endif

    if (!check_device_info(type, fd, name, true))
        goto end;

    if (!check_report_desc(type, fd, name, true))
        goto end;

#if defined(__NetBSD__)
    if (!netbsd_enable_raw(fd, name))
        goto end;
#endif

    dev = create_device(fd, type, name);

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
    ssize_t n = write(dev->fd, buf + dev->ws, REPORT_BUFFER_SIZE - dev->ws);

    if (n == -1) {
        output("%s: %s: %s", "write", strerror(errno), dev->name);
        return false;
    }

    if (n != REPORT_BUFFER_SIZE - dev->ws) {
        output("%s: %s: %s", "write", "short packet", dev->name);
        return false;
    }

    return true;
}

bool device_read(struct device *dev, uint8_t buf[static REPORT_BUFFER_SIZE], int to, bool print) {
    ssize_t n;

    if (to >= 0) {
        struct pollfd fds;
        int res;

        fds.fd = dev->fd;
        fds.events = POLLIN;

        res = poll(&fds, 1, to);
        if (res == -1) {
            output("%s: %s: %s", "poll", strerror(errno), dev->name);
            return false;
        }

        if (res == 0) {
            if (print)
                output("%s: %s: %s", "poll", "timeout has elapsed", dev->name);
            return false;
        }
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
