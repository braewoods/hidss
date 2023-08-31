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

#ifndef _HIDSS_H_
#define _HIDSS_H_

#include <stdbool.h>
#include <stdint.h>

#define HIDSS_WIDGET_ASSERT_SIZE(T) _Static_assert(sizeof(T)==HIDSS_WIDGET_SIZE,#T" failed size assertion")

#define HIDSS_THEME_FILENAME "img.dat"
#define HIDSS_FIRMWARE_FILENAME "update.bin"

enum {
    HIDSS_SENSOR_NONE,
    HIDSS_SENSOR_CPU_TEMPERATURE,
    HIDSS_SENSOR_CPU_CLOCK,
    HIDSS_SENSOR_CPU_USAGE,
    HIDSS_SENSOR_CPU_FAN,
    HIDSS_SENSOR_GPU_TEMPERATURE,
    HIDSS_SENSOR_GPU_CLOCK,
    HIDSS_SENSOR_GPU_USAGE,
    HIDSS_SENSOR_GPU_MEMORY_CLOCK,
    HIDSS_SENSOR_GPU_MEMORY_USAGE,
    HIDSS_SENSOR_RAM_USED,
    HIDSS_SENSOR_RAM_AVAILABLE,
    HIDSS_SENSOR_RAM_USAGE,
    HIDSS_SENSOR_DISK_TEMPERATURE,
    HIDSS_SENSOR_DISK_TOTAL,
    HIDSS_SENSOR_DISK_USED,
    HIDSS_SENSOR_DISK_AVAILABLE,
    HIDSS_SENSOR_DISK_USAGE,
    HIDSS_SENSOR_NETWORK_UPLOAD,
    HIDSS_SENSOR_NETWORK_DOWNLOAD,
    HIDSS_SENSOR_SOUND_VOLUME,
};

enum {
    HIDSS_WIDGET_FIELDS_MIN = 1,
    HIDSS_WIDGET_FIELDS_MAX = 20,
    HIDSS_WIDGET_KEY_MIN = 1,
    HIDSS_WIDGET_KEY_MAX = 255,
    HIDSS_WIDGET_VALUE_MIN = 0,
    HIDSS_WIDGET_VALUE_MAX = 65535,
    HIDSS_SENSOR_FIELDS_MIN = 1,
    HIDSS_SENSOR_FIELDS_MAX = 20,
    HIDSS_SENSOR_KEY_MIN = 1,
    HIDSS_SENSOR_KEY_MAX = 20,
    HIDSS_SENSOR_VALUE_MIN = -32768,
    HIDSS_SENSOR_VALUE_MAX = 32767,
    HIDSS_TIMEOUT_MIN = 0,
    HIDSS_TIMEOUT_MAX = 255,
    HIDSS_TIMEOUT_DEFAULT = 0,
    HIDSS_BRIGHTNESS_MIN = 1,
    HIDSS_BRIGHTNESS_MAX = 100,
    HIDSS_BRIGHTNESS_DEFAULT = 80,
};

enum {
    HIDSS_WIDGET_SIZE = 64,
    HIDSS_WIDGET_MAX = 64,
    HIDSS_WIDGET_BLOCK_SIZE = HIDSS_WIDGET_SIZE * HIDSS_WIDGET_MAX,
    HIDSS_WIDGET_ROTATE = 0x96,
    HIDSS_WIDGET_SPLASH = 0x94,
    HIDSS_WIDGET_BACKGROUND = 0x81,
    HIDSS_WIDGET_IMAGE = 0x84,
};

enum {
    HIDSS_WIDGET_ROTATE_0,
    HIDSS_WIDGET_ROTATE_90,
    HIDSS_WIDGET_ROTATE_180,
    HIDSS_WIDGET_ROTATE_270,
};

struct hidss_widget {
    uint8_t type;
    uint8_t padding[HIDSS_WIDGET_SIZE - 1];
} __attribute__((packed));

struct hidss_widget_rotate {
    uint8_t type;
    uint8_t rotate;
    uint8_t padding[HIDSS_WIDGET_SIZE - 2];
} __attribute__((packed));

struct hidss_widget_splash {
    uint8_t type;
    uint8_t widget_id;
    uint8_t sensor_id;
    uint16_t x;
    uint16_t y;
    uint16_t width;
    uint16_t height;
    uint32_t offset;
    uint8_t frames;
    uint16_t total;
    uint16_t delay;
    uint16_t color;
    uint8_t padding[HIDSS_WIDGET_SIZE - 22];
} __attribute__((packed));

struct hidss_widget_background {
    uint8_t type;
    uint8_t widget_id;
    uint8_t sensor_id;
    uint16_t x;
    uint16_t y;
    uint16_t width;
    uint16_t height;
    uint8_t is_color;
    uint16_t color;
    uint32_t offset;
    uint8_t frames;
    uint8_t has_alpha;
    uint16_t delay;
    uint8_t padding[HIDSS_WIDGET_SIZE - 22];
} __attribute__((packed));

struct hidss_widget_image {
    uint8_t type;
    uint8_t widget_id;
    uint8_t sensor_id;
    uint16_t x;
    uint16_t y;
    uint16_t width;
    uint16_t height;
    uint32_t offset;
    uint8_t frames;
    uint8_t has_alpha;
    uint16_t delay;
    uint8_t padding[HIDSS_WIDGET_SIZE - 19];
} __attribute__((packed));

HIDSS_WIDGET_ASSERT_SIZE(struct hidss_widget);
HIDSS_WIDGET_ASSERT_SIZE(struct hidss_widget_rotate);
HIDSS_WIDGET_ASSERT_SIZE(struct hidss_widget_splash);
HIDSS_WIDGET_ASSERT_SIZE(struct hidss_widget_background);
HIDSS_WIDGET_ASSERT_SIZE(struct hidss_widget_image);

static inline uint16_t hidss_widget_swap_16(uint16_t n) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return n;
#else
    return __builtin_bswap16(n);
#endif
}

static inline uint32_t hidss_widget_swap_32(uint32_t n) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return n;
#else
    return __builtin_bswap32(n);
#endif
}

static inline void hidss_widget_splash_swap(struct hidss_widget_splash *w) {
    w->x = hidss_widget_swap_16(w->x);
    w->y = hidss_widget_swap_16(w->y);
    w->width = hidss_widget_swap_16(w->width);
    w->height = hidss_widget_swap_16(w->height);
    w->offset = hidss_widget_swap_32(w->offset);
    w->total = hidss_widget_swap_16(w->total);
    w->delay = hidss_widget_swap_16(w->delay);
    w->color = hidss_widget_swap_16(w->color);
}

static inline void hidss_widget_background_swap(struct hidss_widget_background *w) {
    w->x = hidss_widget_swap_16(w->x);
    w->y = hidss_widget_swap_16(w->y);
    w->width = hidss_widget_swap_16(w->width);
    w->height = hidss_widget_swap_16(w->height);
    w->color = hidss_widget_swap_16(w->color);
    w->offset = hidss_widget_swap_32(w->offset);
    w->delay = hidss_widget_swap_16(w->delay);
}

static inline void hidss_widget_image_swap(struct hidss_widget_image *w) {
    w->x = hidss_widget_swap_16(w->x);
    w->y = hidss_widget_swap_16(w->y);
    w->width = hidss_widget_swap_16(w->width);
    w->height = hidss_widget_swap_16(w->height);
    w->offset = hidss_widget_swap_32(w->offset);
    w->delay = hidss_widget_swap_16(w->delay);
}
#endif
