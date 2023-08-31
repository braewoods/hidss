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

struct device {
    HANDLE handle;
    OVERLAPPED read_ol;
    OVERLAPPED write_ol;
    char path[256];
};

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

static inline bool utf8_to_utf16(const char *cs, wchar_t *wcs, size_t len) {
    int res = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        cs,
        -1,
        wcs,
        len
    );
    return (res != 0);
}

static const char *strerror_win32(DWORD err) {
    DWORD res;
    wchar_t msg_wcs[1024];
    static char msg_cs[1024];

    res = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        msg_wcs,
        sizeof(msg_wcs),
        NULL
    );

    if (res == 0 || !utf16_to_utf8(msg_wcs, msg_cs, sizeof(msg_cs)))
        *msg_cs = '\0';

    return msg_cs;
}

static inline void safe_close_handle(HANDLE *handle) {
    if (*handle != INVALID_HANDLE_VALUE) {
        CloseHandle(*handle);
        *handle = INVALID_HANDLE_VALUE;
    }
}

static bool hid_check_device_info(HANDLE handle, const char *path) {
    bool rv = false;
    HIDD_ATTRIBUTES attr;
    PHIDP_PREPARSED_DATA data = NULL;
    HIDP_CAPS cap;

    attr.Size = sizeof(HIDD_ATTRIBUTES);

    if (!HidD_GetAttributes(handle, &attr)) {
        if (path != NULL)
            output("%s: %s: %s", "HidD_GetAttributes", strerror_win32(GetLastError()), path);
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
            output("%s: %s: %s", "HidD_GetPreparsedData", strerror_win32(GetLastError()), path);
        goto end;
    }

    if (!HidP_GetCaps(data, &cap)) {
        if (path != NULL)
            output("%s: %s: %s", "HidP_GetCaps", strerror_win32(GetLastError()), path);
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

static struct device_info *hid_create_device_info(HANDLE handle, const wchar_t *path) {
    struct device_info *di;
    wchar_t buf[256];

    di = alloc(struct device_info, 1);
    if (di == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "struct device_info");
        goto err_0;
    }

    memset(di, 0, sizeof(*di));

    if (!utf16_to_utf8(path, di->devpath, sizeof(di->devpath))) {
        output("%s: %s", "utf16_to_utf8", strerror_win32(GetLastError()));
        goto err_1;
    }

    if (!HidD_GetManufacturerString(handle, buf, sizeof(buf))) {
        output("%s: %s", "HidD_GetManufacturerString", strerror_win32(GetLastError()));
        goto err_1;
    }

    if (!utf16_to_utf8(buf, di->vendor, sizeof(di->vendor))) {
        output("%s: %s", "utf16_to_utf8", strerror_win32(GetLastError()));
        goto err_1;
    }

    if (!HidD_GetProductString(handle, buf, sizeof(buf))) {
        output("%s: %s", "HidD_GetProductString", strerror_win32(GetLastError()));
        goto err_1;
    }

    if (!utf16_to_utf8(buf, di->product, sizeof(di->product))) {
        output("%s: %s", "utf16_to_utf8", strerror_win32(GetLastError()));
        goto err_1;
    }

    if (!HidD_GetSerialNumberString(handle, buf, sizeof(buf))) {
        output("%s: %s", "HidD_GetSerialNumberString", strerror_win32(GetLastError()));
        goto err_1;
    }

    if (!utf16_to_utf8(buf, di->serial, sizeof(di->serial))) {
        output("%s: %s", "utf16_to_utf8", strerror_win32(GetLastError()));
        goto err_1;
    }

    return di;

err_1:
    free(di);
err_0:
    return NULL;
}

bool platform_init(void) {
    tzset();

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

struct device_info *device_enumerate(void) {
    GUID hid_guid;
    ULONG len;
    wchar_t *di_list = NULL;
    struct device_info *root = NULL;
    struct device_info *end = NULL;

    HidD_GetHidGuid(&hid_guid);

    while (true) {
        CONFIGRET cr;

        cr = CM_Get_Device_Interface_List_SizeW(&len, &hid_guid, NULL, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
        if (cr != CR_SUCCESS) {
            output("%s: %s", "CM_Get_Device_Interface_List_SizeW", strerror_win32(GetLastError()));
            goto err_0;
        }

        di_list = redim(di_list, wchar_t, len);
        if (di_list == NULL) {
            output("%s: %s: %s", "alloc", strerror(errno), "wchar_t");
            goto err_0;
        }

        cr = CM_Get_Device_Interface_ListW(&hid_guid, NULL, di_list, len, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
        if (cr != CR_SUCCESS) {
            if (cr == CR_BUFFER_SMALL)
                continue;
            output("%s: %s", "CM_Get_Device_Interface_ListW", strerror_win32(GetLastError()));
            goto err_0;
        }

        break;
    }

    for (const wchar_t *di = di_list; *di != '\0'; di += wcslen(di) + 1) {
        HANDLE handle;
        struct device_info *dip;

        handle = CreateFileW(
            di,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (handle == INVALID_HANDLE_VALUE) {
            continue;
        }

        if (!hid_check_device_info(handle, NULL)) {
            CloseHandle(handle);
            continue;
        }

        dip = hid_create_device_info(handle, di);
        if (dip == NULL) {
            CloseHandle(handle);
            continue;
        }

        if (root == NULL) {
            root = end = dip;
        } else {
            end->next = dip;
            end = dip;
        }

        CloseHandle(handle);
    }

    free(di_list);
    return root;

err_0:
    free(di_list);
    return NULL;
}

struct device *device_open(const char *path_cs) {
    wchar_t path_wcs[256];
    HANDLE handle;
    struct device *dev;
    HANDLE read_ev;
    HANDLE write_ev;

    if (!utf8_to_utf16(path_cs, path_wcs, sizeof(path_wcs))) {
        output("%s: %s", "utf8_to_utf16", strerror_win32(GetLastError()));
        goto err_0;
    }

    handle = CreateFileW(
        path_wcs,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (handle == INVALID_HANDLE_VALUE) {
        output("%s: %s: %s", "CreateFileW", strerror_win32(GetLastError()), path_cs);
        goto err_0;
    }

    if (!hid_check_device_info(handle, path_cs))
        goto err_1;

    read_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (read_ev == NULL) {
        output("%s: %s: %s", "CreateEventW", strerror_win32(GetLastError()), path_cs);
        goto err_1;
    }

    write_ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (write_ev == NULL) {
        output("%s: %s: %s", "CreateEventW", strerror_win32(GetLastError()), path_cs);
        goto err_2;
    }

    dev = alloc(struct device, 1);
    if (dev == NULL) {
        output("%s: %s: %s", "alloc", strerror(errno), "struct device");
        goto err_3;
    }

    dev->handle = handle;
    memset(&dev->read_ol, 0, sizeof(dev->read_ol));
    dev->read_ol.hEvent = read_ev;
    memset(&dev->write_ol, 0, sizeof(dev->write_ol));
    dev->write_ol.hEvent = write_ev;
    strbuild(dev->path, sizeof(dev->path), path_cs);

    return dev;

err_3:
    CloseHandle(write_ev);
err_2:
    CloseHandle(read_ev);
err_1:
    CloseHandle(handle);
err_0:
    return NULL;
}

void device_close(struct device *dev) {
    if (dev == NULL)
        return;

    CancelIo(dev->handle);

    safe_close_handle(&dev->write_ol.hEvent);
    safe_close_handle(&dev->read_ol.hEvent);
    safe_close_handle(&dev->handle);

    free(dev);
}

bool device_reopen(struct device *dev, time_t delay) {
    struct device *new_dev;

    CancelIo(dev->handle);

    safe_close_handle(&dev->write_ol.hEvent);
    safe_close_handle(&dev->read_ol.hEvent);
    safe_close_handle(&dev->handle);

    Sleep(delay * 1000);

    new_dev = device_open(dev->path);
    if (new_dev == NULL) {
        output("%s: %s", "failed to reopen device", dev->path);
        return false;
    }

    memcpy(dev, new_dev, sizeof(*dev));
    free(new_dev);
    return true;
}

bool device_write(struct device *dev, const uint8_t buf[static REPORT_BUFFER_SIZE]) {
    DWORD n;

    WriteFile(dev->handle, buf, REPORT_BUFFER_SIZE, &n, &dev->write_ol);

    if (GetLastError() != ERROR_IO_PENDING) {
        output("%s: %s: %s", "WriteFile", strerror_win32(GetLastError()), dev->path);
        goto err;
    }

    if (!GetOverlappedResult(dev->handle, &dev->write_ol, &n, TRUE)) {
        output("%s: %s: %s", "GetOverlappedResult", strerror_win32(GetLastError()), dev->path);
        goto err;
    }

    if (n != REPORT_BUFFER_SIZE) {
        output("%s: %s: %s", "WriteFile", "short packet", dev->path);
        goto err;
    }

    return true;

err:
    CancelIo(dev->handle);
    return false;
}

bool device_read(struct device *dev, uint8_t buf[static REPORT_BUFFER_SIZE], int to) {
    DWORD n;
    DWORD res;

    ReadFile(dev->handle, buf, REPORT_BUFFER_SIZE, &n, &dev->read_ol);

    if (GetLastError() != ERROR_IO_PENDING) {
        output("%s: %s: %s", "ReadFile", strerror_win32(GetLastError()), dev->path);
        goto err;
    }

    res = WaitForSingleObject(dev->read_ol.hEvent, to);
    if (res == WAIT_FAILED) {
        output("%s: %s: %s", "WaitForSingleObject", strerror_win32(GetLastError()), dev->path);
        goto err;
    }

    if (res == WAIT_TIMEOUT) {
        goto err;
    }

    if (!GetOverlappedResult(dev->handle, &dev->read_ol, &n, TRUE)) {
        output("%s: %s: %s", "GetOverlappedResult", strerror_win32(GetLastError()), dev->path);
        goto err;
    }

    if (n != REPORT_BUFFER_SIZE) {
        output("%s: %s: %s", "ReadFile", "short packet", dev->path);
        goto err;
    }

    return true;

err:
    CancelIo(dev->handle);
    return false;
}
