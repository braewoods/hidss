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

#ifndef _HIDSS_H_
#define _HIDSS_H_

#include <stdbool.h>
#include <stdint.h>

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
    HIDSS_THEME_MIN_SIZE = 4096,
    HIDSS_THEME_MAX_SIZE = 4194304,
    HIDSS_FIRWMARE_MIN_SIZE = 0,
    HIDSS_FIRMWARE_MAX_SIZE = 65536,
    HIDSS_LANDSCAPE_WIDTH = 480,
    HIDSS_LANDSCAPE_HEIGHT = 320,
    HIDSS_PORTRAIT_WIDTH = 320,
    HIDSS_PORTRAIT_HEIGHT = 480,
};

static inline bool hidss_screen_verify_dimensions(uint16_t width, uint16_t height) {
    if (width == HIDSS_LANDSCAPE_WIDTH && height == HIDSS_LANDSCAPE_HEIGHT)
        return true;

    if (width == HIDSS_PORTRAIT_WIDTH && height == HIDSS_PORTRAIT_HEIGHT)
        return true;

    return false;
}

static inline bool hidss_screen_is_landscape(uint16_t width, uint16_t height) {
    return (width > height);
}

static inline bool hidss_screen_is_portrait(uint16_t width, uint16_t height) {
    return (width < height);
}
#endif
