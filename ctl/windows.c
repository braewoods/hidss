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

#include "common.h"
#include <wtypesbase.h>
#include <hidsdi.h>
#include <cfgmgr32.h>

#define ENUM_TABLE_ENTRY(A) [A]=#A

#if !defined(_UCRT)
#error "Only UCRT toolchains are supported."
#endif

struct device {
    HANDLE handle;
    OVERLAPPED read;
    OVERLAPPED write;
    char path[DEV_PATH_MAX];
};

static const char *strerror_windows(DWORD err) {
    static char msg_cs[4096];
    DWORD res;
    char *s;

    res = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        msg_cs,
        sizeof(msg_cs),
        NULL
    );

    if (res == 0)
        *msg_cs = '\0';

    s = strchr(msg_cs, '\r');
    if (s != NULL)
        *s = '\0';

    s = strchr(msg_cs, '\n');
    if (s != NULL)
        *s = '\0';

    return msg_cs;
}

static inline const char *strerror_win(void) {
    return strerror_windows(GetLastError());
}

static inline const char *strerror_cm(CONFIGRET cr) {
    static const char *table[NUM_CR_RESULTS] = {
        ENUM_TABLE_ENTRY(CR_SUCCESS),
        ENUM_TABLE_ENTRY(CR_DEFAULT),
        ENUM_TABLE_ENTRY(CR_OUT_OF_MEMORY),
        ENUM_TABLE_ENTRY(CR_INVALID_POINTER),
        ENUM_TABLE_ENTRY(CR_INVALID_FLAG),
        ENUM_TABLE_ENTRY(CR_INVALID_DEVNODE),
        ENUM_TABLE_ENTRY(CR_INVALID_RES_DES),
        ENUM_TABLE_ENTRY(CR_INVALID_LOG_CONF),
        ENUM_TABLE_ENTRY(CR_INVALID_ARBITRATOR),
        ENUM_TABLE_ENTRY(CR_INVALID_NODELIST),
        ENUM_TABLE_ENTRY(CR_DEVNODE_HAS_REQS),
        ENUM_TABLE_ENTRY(CR_INVALID_RESOURCEID),
        ENUM_TABLE_ENTRY(CR_DLVXD_NOT_FOUND),
        ENUM_TABLE_ENTRY(CR_NO_SUCH_DEVNODE),
        ENUM_TABLE_ENTRY(CR_NO_MORE_LOG_CONF),
        ENUM_TABLE_ENTRY(CR_NO_MORE_RES_DES),
        ENUM_TABLE_ENTRY(CR_ALREADY_SUCH_DEVNODE),
        ENUM_TABLE_ENTRY(CR_INVALID_RANGE_LIST),
        ENUM_TABLE_ENTRY(CR_INVALID_RANGE),
        ENUM_TABLE_ENTRY(CR_FAILURE),
        ENUM_TABLE_ENTRY(CR_NO_SUCH_LOGICAL_DEV),
        ENUM_TABLE_ENTRY(CR_CREATE_BLOCKED),
        ENUM_TABLE_ENTRY(CR_NOT_SYSTEM_VM),
        ENUM_TABLE_ENTRY(CR_REMOVE_VETOED),
        ENUM_TABLE_ENTRY(CR_APM_VETOED),
        ENUM_TABLE_ENTRY(CR_INVALID_LOAD_TYPE),
        ENUM_TABLE_ENTRY(CR_BUFFER_SMALL),
        ENUM_TABLE_ENTRY(CR_NO_ARBITRATOR),
        ENUM_TABLE_ENTRY(CR_NO_REGISTRY_HANDLE),
        ENUM_TABLE_ENTRY(CR_REGISTRY_ERROR),
        ENUM_TABLE_ENTRY(CR_INVALID_DEVICE_ID),
        ENUM_TABLE_ENTRY(CR_INVALID_DATA),
        ENUM_TABLE_ENTRY(CR_INVALID_API),
        ENUM_TABLE_ENTRY(CR_DEVLOADER_NOT_READY),
        ENUM_TABLE_ENTRY(CR_NEED_RESTART),
        ENUM_TABLE_ENTRY(CR_NO_MORE_HW_PROFILES),
        ENUM_TABLE_ENTRY(CR_DEVICE_NOT_THERE),
        ENUM_TABLE_ENTRY(CR_NO_SUCH_VALUE),
        ENUM_TABLE_ENTRY(CR_WRONG_TYPE),
        ENUM_TABLE_ENTRY(CR_INVALID_PRIORITY),
        ENUM_TABLE_ENTRY(CR_NOT_DISABLEABLE),
        ENUM_TABLE_ENTRY(CR_FREE_RESOURCES),
        ENUM_TABLE_ENTRY(CR_QUERY_VETOED),
        ENUM_TABLE_ENTRY(CR_CANT_SHARE_IRQ),
        ENUM_TABLE_ENTRY(CR_NO_DEPENDENT),
        ENUM_TABLE_ENTRY(CR_SAME_RESOURCES),
        ENUM_TABLE_ENTRY(CR_NO_SUCH_REGISTRY_KEY),
        ENUM_TABLE_ENTRY(CR_INVALID_MACHINENAME),
        ENUM_TABLE_ENTRY(CR_REMOTE_COMM_FAILURE),
        ENUM_TABLE_ENTRY(CR_MACHINE_UNAVAILABLE),
        ENUM_TABLE_ENTRY(CR_NO_CM_SERVICES),
        ENUM_TABLE_ENTRY(CR_ACCESS_DENIED),
        ENUM_TABLE_ENTRY(CR_CALL_NOT_IMPLEMENTED),
        ENUM_TABLE_ENTRY(CR_INVALID_PROPERTY),
        ENUM_TABLE_ENTRY(CR_DEVICE_INTERFACE_ACTIVE),
        ENUM_TABLE_ENTRY(CR_NO_SUCH_DEVICE_INTERFACE),
        ENUM_TABLE_ENTRY(CR_INVALID_REFERENCE_STRING),
        ENUM_TABLE_ENTRY(CR_INVALID_CONFLICT_LIST),
        ENUM_TABLE_ENTRY(CR_INVALID_INDEX),
        ENUM_TABLE_ENTRY(CR_INVALID_STRUCTURE_SIZE),
    };
    return table[cr];
}

static inline bool utf16_to_utf8(const wchar_t *wcs, char *cs, size_t len) {
    int res = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS | WC_NO_BEST_FIT_CHARS,
        wcs,
        -1,
        cs,
        len,
        NULL,
        NULL
    );
    return (res != 0);
}

static char *get_device_interface_list(void) {
    GUID guid;
    char *dil = NULL;
    bool done = false;

    HidD_GetHidGuid(&guid);

    while (!done) {
        ULONG len;
        CONFIGRET cr;

        cr = CM_Get_Device_Interface_List_SizeA(
            &len,
            &guid,
            NULL,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT
        );

        if (cr != CR_SUCCESS) {
            output("%s: %s", "CM_Get_Device_Interface_List_Size", strerror_cm(cr));
            goto end;
        }

        dil = redim(dil, char, len);
        if (dil == NULL) {
            output("%s: %s: %s", "alloc", strerror(errno), "char");
            goto end;
        }

        cr = CM_Get_Device_Interface_ListA(
            &guid,
            NULL,
            dil,
            len,
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT
        );

        if (cr == CR_BUFFER_SMALL)
            continue;

        if (cr != CR_SUCCESS) {
            output("%s: %s", "CM_Get_Device_Interface_List", strerror_cm(cr));
            goto end;
        }

        done = true;
    }

end:
    if (!done) {
        free(dil);
        dil = NULL;
    }
    return dil;
}

static bool check_device_info(HANDLE handle, const char *path) {
    bool rv = false;
    HIDD_ATTRIBUTES attr;
    PHIDP_PREPARSED_DATA data = NULL;
    HIDP_CAPS cap;

    attr.Size = sizeof(HIDD_ATTRIBUTES);

    if (!HidD_GetAttributes(handle, &attr)) {
        if (path != NULL)
            output("%s: %s: %s", "HidD_GetAttributes", strerror_win(), path);
        goto end;
    }

    if (attr.VendorID != VENDOR_ID) {
        if (path != NULL)
            output("%s: %s", "vendor id mismatch", path);
        goto end;
    }

    if (attr.ProductID != PRODUCT_ID) {
        if (path != NULL)
            output("%s: %s", "product id mismatch", path);
        goto end;
    }

    if (!HidD_GetPreparsedData(handle, &data)) {
        if (path != NULL)
            output("%s: %s: %s", "HidD_GetPreparsedData", strerror_win(), path);
        goto end;
    }

    if (!HidP_GetCaps(data, &cap)) {
        if (path != NULL)
            output("%s: %s: %s", "HidP_GetCaps", strerror_win(), path);
        goto end;
    }

    if (cap.UsagePage != USAGE_PAGE_ID) {
        if (path != NULL)
            output("%s: %s", "usage page id mismatch", path);
        goto end;
    }

    if (cap.Usage != USAGE_ID) {
        if (path != NULL)
            output("%s: %s", "usage id mismatch", path);
        goto end;
    }

    if (cap.InputReportByteLength != REPORT_BUFFER_SIZE) {
        if (path != NULL)
            output("%s: %s", "input report size mismatch", path);
        goto end;
    }

    if (cap.OutputReportByteLength != REPORT_BUFFER_SIZE) {
        if (path != NULL)
            output("%s: %s", "output report size mismatch", path);
        goto end;
    }

    if (cap.FeatureReportByteLength != 0) {
        if (path != NULL)
            output("%s: %s", "feature report size mismatch", path);
        goto end;
    }

    rv = true;
end:
    if (data != NULL)
        HidD_FreePreparsedData(data);
    return rv;
}

static struct device_info *create_device_info(HANDLE handle, const char *path) {
    struct device_info *di = NULL;
    wchar_t buf[USB_STRING_MAX];
    bool done = false;

    di = alloc(struct device_info, 1);
    if (di == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "struct device_info");
        goto end;
    }

    memset(di, 0, sizeof(*di));

    strbuild(di->devpath, sizeof(di->devpath), path);

    if (!HidD_GetManufacturerString(handle, buf, sizeof(buf))) {
        output("%s: %s", "HidD_GetManufacturerString", strerror_win());
        goto end;
    }

    if (!utf16_to_utf8(buf, di->vendor, sizeof(di->vendor))) {
        output("%s: %s", "WideCharToMultiByte", strerror_win());
        goto end;
    }

    if (!HidD_GetProductString(handle, buf, sizeof(buf))) {
        output("%s: %s", "HidD_GetProductString", strerror_win());
        goto end;
    }

    if (!utf16_to_utf8(buf, di->product, sizeof(di->product))) {
        output("%s: %s", "WideCharToMultiByte", strerror_win());
        goto end;
    }

    if (!HidD_GetSerialNumberString(handle, buf, sizeof(buf))) {
        output("%s: %s", "HidD_GetSerialNumberString", strerror_win());
        goto end;
    }

    if (!utf16_to_utf8(buf, di->serial, sizeof(di->serial))) {
        output("%s: %s", "WideCharToMultiByte", strerror_win());
        goto end;
    }

    done = true;

end:
    if (!done) {
        free(di);
        di = NULL;
    }
    return di;
}

bool platform_init(void) {
    return true;
}

void platform_fini(void) {

}

bool privileges_discard(void) {
    return true;
}

bool privileges_restore(void) {
    return true;
}

bool file_get_contents(const char *path, uint8_t **data, size_t *size, long low, long high) {
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD fs_low;
    DWORD fs_high;
    uint8_t *buf = NULL;
    DWORD n;
    bool rv = false;

    file = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (file == INVALID_HANDLE_VALUE) {
        output("%s: %s: %s", "CreateFile", strerror_win(), path);
        goto end;
    }

    fs_low = GetFileSize(file, &fs_high);
    if (fs_low == INVALID_FILE_SIZE) {
        output("%s: %s: %s", "GetFileSize", strerror_win(), path);
        goto end;
    }

    if (fs_high != 0 || !inrange(fs_low, low, high)) {
        output("size of %s not in range of %ld to %ld", path, low, high);
        goto end;
    }

    buf = alloc(uint8_t, fs_low);
    if (buf == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "uint8_t");
        goto end;
    }

    if (!ReadFile(file, buf, fs_low, &n, NULL)) {
        output("%s: %s: %s", "ReadFile", strerror_win(), path);
        goto end;
    }

    if (n != fs_low) {
        output("%s: %s: %s", "ReadFile", "short read", path);
        goto end;
    }

    *data = buf;
    *size = fs_low;
    rv = true;

end:
    if (!rv)
        free(buf);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    return rv;
}

struct device_info *device_enumerate(void) {
    char *dil;
    struct device_info *root = NULL;
    struct device_info *end = NULL;

    dil = get_device_interface_list();
    if (dil == NULL)
        return NULL;

    for (const char *di = dil; *di != '\0'; di += 1 + strlen(di)) {
        HANDLE handle;
        struct device_info *dip;

        handle = CreateFileA(
            di,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (handle == INVALID_HANDLE_VALUE)
            continue;

        if (!check_device_info(handle, NULL))
            goto close_handle;

        dip = create_device_info(handle, di);
        if (dip == NULL)
            goto close_handle;

        if (root == NULL) {
            root = end = dip;
        } else {
            end->next = dip;
            end = dip;
        }

close_handle:
        CloseHandle(handle);
    }

    free(dil);
    return root;
}

struct device *device_open(const char *path) {
    HANDLE handle = INVALID_HANDLE_VALUE;
    HANDLE read = NULL;
    HANDLE write = NULL;
    struct device *dev = NULL;
    bool done = false;

    handle = CreateFileA(
        path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (handle == INVALID_HANDLE_VALUE) {
        output("%s: %s: %s", "CreateFile", strerror_win(), path);
        goto end;
    }

    if (!check_device_info(handle, path))
        goto end;

    read = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (read == NULL) {
        output("%s: %s: %s", "CreateEvent", strerror_win(), path);
        goto end;
    }

    write = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (write == NULL) {
        output("%s: %s: %s", "CreateEvent", strerror_win(), path);
        goto end;
    }

    dev = alloc(struct device, 1);
    if (dev == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "struct device");
        goto end;
    }

    memset(dev, 0, sizeof(*dev));
    dev->handle = handle;
    dev->read.hEvent = read;
    dev->write.hEvent = write;
    strbuild(dev->path, sizeof(dev->path), path);

    done = true;

end:
    if (!done) {
        if (handle != INVALID_HANDLE_VALUE)
            CloseHandle(handle);
        if (read != NULL)
            CloseHandle(read);
        if (write != NULL)
            CloseHandle(write);
        free(dev);
    }
    return dev;
}

void device_close(struct device *dev) {
    if (dev == NULL)
        return;

    if (dev->handle != INVALID_HANDLE_VALUE) {
        CancelIo(dev->handle);
        CloseHandle(dev->handle);
    }

    if (dev->read.hEvent != INVALID_HANDLE_VALUE)
        CloseHandle(dev->read.hEvent);

    if (dev->write.hEvent != INVALID_HANDLE_VALUE)
        CloseHandle(dev->write.hEvent);

    free(dev);
}

bool device_reopen(struct device *dev, time_t delay) {
    struct device *new_dev;

    if (dev->handle != INVALID_HANDLE_VALUE) {
        CancelIo(dev->handle);
        CloseHandle(dev->handle);
        dev->handle = INVALID_HANDLE_VALUE;
    }

    if (dev->read.hEvent != INVALID_HANDLE_VALUE) {
        CloseHandle(dev->read.hEvent);
        dev->read.hEvent = INVALID_HANDLE_VALUE;
    }

    if (dev->write.hEvent != INVALID_HANDLE_VALUE) {
        CloseHandle(dev->write.hEvent);
        dev->write.hEvent = INVALID_HANDLE_VALUE;
    }

    Sleep(delay * 1000);

    new_dev = device_open(dev->path);
    if (new_dev == NULL) {
        output("%s: %s", "failed to reopen device", dev->path);
        return false;
    }

    memcpy(dev, new_dev, sizeof(*dev));
    free(new_dev);
    return false;
}

bool device_write(struct device *dev, const uint8_t buf[static REPORT_BUFFER_SIZE]) {
    DWORD len;
    bool rv = false;

    if (WriteFile(dev->handle, buf, REPORT_BUFFER_SIZE, &len, &dev->write)) {
        goto check_len;
    }

    if (GetLastError() != ERROR_IO_PENDING) {
        output("%s: %s: %s", "WriteFile", strerror_win(), dev->path);
        goto end;
    }

    if (!GetOverlappedResult(dev->handle, &dev->write, &len, TRUE)) {
        output("%s: %s: %s", "GetOverlappedResult", strerror_win(), dev->path);
        goto end;
    }

check_len:
    if (len != REPORT_BUFFER_SIZE) {
        output("%s: %s: %s", "WriteFile", "short packet", dev->path);
        goto end;
    }

    rv = true;

end:
    if (!rv)
        CancelIo(dev->handle);
    return rv;
}

bool device_read(struct device *dev, uint8_t buf[static REPORT_BUFFER_SIZE], int to) {
    DWORD len;
    bool rv = false;

    if (ReadFile(dev->handle, buf, REPORT_BUFFER_SIZE, &len, &dev->read)) {
        goto check_len;
    }

    if (GetLastError() != ERROR_IO_PENDING) {
        output("%s: %s: %s", "ReadFile", strerror_win(), dev->path);
        goto end;
    }

    switch (WaitForSingleObject(dev->read.hEvent, to)) {
        case WAIT_FAILED:
            output("%s: %s: %s", "WaitForSingleObject", strerror_win(), dev->path);
        case WAIT_TIMEOUT:
            goto end;
        case WAIT_OBJECT_0:
            break;
    }

    if (!GetOverlappedResult(dev->handle, &dev->read, &len, TRUE)) {
        output("%s: %s: %s", "GetOverlappedResult", strerror_win(), dev->path);
        goto end;
    }

check_len:
    if (len != REPORT_BUFFER_SIZE) {
        output("%s: %s: %s", "ReadFile", "short packet", dev->path);
        goto end;
    }

    rv = true;

end:
    if (!rv)
        CancelIo(dev->handle);
    return rv;
}
