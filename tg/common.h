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
#include <ctype.h>
#include <limits.h>
#include <getopt.h>
#include <errno.h>
#include <ini.h>
#include <gd.h>
#include "hidss.h"

#define alloc(T,N) ((T*)malloc(sizeof(T[N])))
#define redim(P,T,N) ((T*)realloc(P,sizeof(T[N])))
#define strbuild(A,B,...) strbuild_real(A,B,(const char *[]){__VA_ARGS__,NULL})

enum {
    SECTION_UNKNOWN,
    SECTION_SPLASH,
    SECTION_BACKGROUND,
};

struct image_list {
    struct image_list *next;
    gdImage *image;
};

struct splash {
    char *image;
    struct image_list *images;
    uint32_t color;
    uint16_t width;
    uint16_t height;
    uint16_t delay;
    uint16_t total;
    bool color_set;
    bool delay_set;
    bool total_set;
};

struct background {
    char *image;
    struct image_list *images;
    uint32_t color;
    uint16_t width;
    uint16_t height;
    uint16_t delay;
    bool color_set;
    bool width_set;
    bool height_set;
    bool delay_set;
};

struct section {
    struct section *next;
    int type;
    int line;
    union {
        struct splash splash;
        struct background background;
    };
};

static inline bool strtolong(const char *s, long *n, int b) {
    char *e;

    errno = 0;
    *n = strtol(s, &e, b);

    return (errno == 0 && s != e && *e == '\0');
}

static inline bool inrange(long n, long l, long h) {
    return (n >= l && n <= h);
}

static inline long minlong(long a, long b) {
    return (a < b) ? a : b;
}

static inline long maxlong(long a, long b) {
    return (a > b) ? a : b;
}

static inline long powlong(long base, long n) {
    if (n == 0)
        return 1;

    return base * powlong(base, n - 1);
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

static inline bool is_rgb888(const char *s) {
    const char *e = s;

    while (isxdigit(*e))
        e++;

    return ((e - s) == 6) && (*e == '\0');
}

static inline const char *file_extension(const char *s) {
    const char *ext = strrchr(s, '.');

    return (ext == NULL) ? NULL : (ext + 1);
}

static inline uint16_t rgb888_to_rgb565(uint32_t p) {
    uint32_t r = (p & 0xff0000) >> 16;
    uint32_t g = (p & 0x00ff00) >>  8;
    uint32_t b = (p & 0x0000ff) >>  0;
    uint16_t rgb = (r << 11) | (g << 5) | (b << 0);
    return rgb;
}

void setprogname(const char *);
const char *getprogname(void);
void output(const char *, ...) __attribute__((format(FORMAT_PRINTF, 1, 2)));
bool strbuild_real(char * restrict, size_t, char const * restrict * restrict);

struct image_list *image_list_open(const char *, const char *);
size_t image_list_frames(const struct image_list *);
bool image_list_has_alpha(const struct image_list *);
bool image_list_to_rgb_565(const struct image_list *, size_t *, uint8_t **, size_t *);
bool image_list_to_argb_565(const struct image_list *, size_t *, uint8_t **, size_t *);
bool image_list_convert(const struct image_list *, size_t *, bool *, uint8_t **, size_t *);
void image_list_free(struct image_list *);

bool section_parse(const char *dir, long rotate, struct section **out);
void section_free(struct section *);

bool output_image(const char *, struct section *, long);
#endif
