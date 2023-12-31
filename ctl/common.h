// Copyright (c) 2024 James Buren
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

#ifndef _COMMON_H_
#define _COMMON_H_

#if defined(__linux__)
#define _GNU_SOURCE
#elif defined(__MINGW32__)
#define WINVER _WIN32_WINNT_WIN10
#define _POSIX_C_SOURCE 200809L
#define tzset _tzset
#define memccpy _memccpy
#endif

#if defined(__clang__)
#define FORMAT_PRINTF printf
#else
#define FORMAT_PRINTF gnu_printf
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <locale.h>
#include <limits.h>
#include <getopt.h>
#include <libgen.h>
#include <errno.h>
#include "hidss.h"

#define alloc(T,N) ((T*)malloc(sizeof(T[N])))
#define redim(P,T,N) ((T*)realloc(P,sizeof(T[N])))
#define strbuild(A,B,...) strbuild_real(A,B,(const char *[]){__VA_ARGS__,NULL})

enum {
    REPORT_ID = 0,
    REPORT_SIZE = 64,
    REPORT_BUFFER_SIZE = REPORT_SIZE + 1,
    DEV_PATH_MAX = 256,
    BUS_PATH_MAX = 128,
    USB_STRING_MAX = 256,
    BUS_PORT_MAX = 32,
};

struct device_info {
    struct device_info *next;
    char devpath[DEV_PATH_MAX];
    char buspath[BUS_PATH_MAX];
    char vendor[USB_STRING_MAX];
    char product[USB_STRING_MAX];
    char serial[USB_STRING_MAX];
};

struct device;

static inline bool strtolong(const char *s, long *n, int b) {
    char *e;

    errno = 0;
    *n = strtol(s, &e, b);

    return (errno == 0 && s != e && *e == '\0');
}

static inline bool inrange(long n, long l, long h) {
    return (n >= l && n <= h);
}

static inline size_t digspn(const char *s) {
    const char *e = s;

    while (isdigit(*e))
        e++;

    return (e - s);
}

static inline size_t digcspn(const char *s) {
    const char *e = s;

    while (*e != '\0' && !isdigit(*e))
        e++;

    return (e - s);
}

static inline size_t xdigspn(const char *s) {
    const char *e = s;

    while (isxdigit(*e))
        e++;

    return (e - s);
}

static inline size_t xdigcspn(const char *s) {
    const char *e = s;

    while (*e != '\0' && !isxdigit(*e))
        e++;

    return (e - s);
}

void setprogname(const char *);
const char *getprogname(void);
void output(const char *, ...) __attribute__((format(FORMAT_PRINTF, 1, 2)));
bool strbuild_real(char * restrict, size_t, char const * restrict * restrict);
void format_bus_path(char [static BUS_PATH_MAX], uint8_t, const uint8_t *, size_t);
bool verify_device_ids(const char *, uint16_t, uint16_t);
bool verify_report_desc(const char *, const void *, size_t, uint8_t);
bool getdatetime(struct tm *);
int mode_enumerate(void);
int mode_command(struct device *);
int mode_upload(struct device *, const char *);
int mode_model(struct device *);

bool device_first(char device[static PATH_MAX]);
void device_enumerate_free(struct device_info *);
bool device_send_widget(struct device *, const uint8_t *, const uint16_t *, size_t);
bool device_send_command(struct device *, const char *, bool);
bool device_send_sensor(struct device *, const uint8_t *, const uint16_t *, size_t);
bool device_send_datetime(struct device *, uint8_t, uint8_t);
bool device_send_metadata(struct device *, const char *, size_t);
bool device_send_data(struct device *, const uint8_t **, size_t *, uint8_t *);
bool device_send_data_stream(struct device *, const uint8_t *, size_t);
bool device_enter_ymodem_mode(struct device *);
bool device_enter_boot_mode(struct device *, uint8_t [static REPORT_BUFFER_SIZE]);

bool platform_init(void);
void platform_fini(void);
bool privileges_discard(void);
bool privileges_restore(void);
bool file_get_contents(const char *, uint8_t **, size_t *, long, long);
struct device_info *device_enumerate(void);
struct device *device_open(const char *);
void device_close(struct device *);
bool device_reopen(struct device *, unsigned int);
bool device_write(struct device *, const uint8_t [static REPORT_BUFFER_SIZE]);
bool device_read(struct device *, uint8_t [static REPORT_BUFFER_SIZE], int, bool);
#endif
