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

#include "common.h"

enum {
    IMAGE_FULL_SIZE = 1 << 22,
    IMAGE_DATA_OFFSET = HIDSS_WIDGET_BLOCK_SIZE,
    IMAGE_DATA_SIZE = IMAGE_FULL_SIZE - IMAGE_DATA_OFFSET,
};

static void find_unique_sections(struct section *root, struct splash **sp, struct background **bg) {
    for (struct section *node = root; node != NULL; node = node->next)
        switch (node->type) {
            case SECTION_SPLASH:
                *sp = &node->splash;
                break;

            case SECTION_BACKGROUND:
                *bg = &node->background;
                break;
        }
}

static size_t find_data_offset(uint8_t *buf, size_t *buf_len, const uint8_t *dat, size_t dat_len) {
    uint8_t *ptr;
    size_t len;

    if (*buf_len > 0) {
        ptr = memmem(buf, *buf_len, dat, dat_len);
        if (ptr != NULL)
            return (ptr - buf) + IMAGE_DATA_OFFSET;
    }

    len = *buf_len + dat_len;
    if (len > IMAGE_DATA_SIZE) {
        output("image buffer overflow by %zu bytes", len - IMAGE_DATA_SIZE);
        return -1;
    }

    ptr = buf + *buf_len;
    memcpy(ptr, dat, dat_len);

    *buf_len = len;
    return (ptr - buf) + IMAGE_DATA_OFFSET;
}

static void widget_rotate_write(void *widget, long rotate) {
    struct hidss_widget_rotate *w = widget;

    w->type = HIDSS_WIDGET_ROTATE;
    w->rotate = rotate;

    memset(w->padding, 0x00, sizeof(w->padding));
}

static bool widget_splash_write(void *widget, struct splash *sp, uint8_t *buf, size_t *buf_len) {
    struct hidss_widget_splash *w = widget;
    size_t frames;
    uint8_t *dat;
    size_t dat_len;
    size_t offset;

    if (!image_list_to_rgb_565(sp->images, &frames, &dat, &dat_len))
        return false;

    offset = find_data_offset(buf, buf_len, dat, dat_len);
    free(dat);

    if (offset == (size_t) -1)
        return false;

    w->type = HIDSS_WIDGET_SPLASH;
    w->widget_id = 0;
    w->sensor_id = 0;
    w->x = 0;
    w->y = 0;
    w->width = sp->width;
    w->height = sp->height;
    w->offset = offset;
    w->frames = frames;
    w->total = sp->total;
    w->delay = sp->delay;
    w->color = rgb888_to_rgb565(sp->color);

    memset(w->padding, 0x00, sizeof(w->padding));
    hidss_widget_splash_swap(w);
    return true;
}

static bool widget_background_write(void *widget, struct background *bg, uint8_t *buf, size_t *buf_len) {
    struct hidss_widget_background *w = widget;
    size_t frames;
    uint8_t *dat;
    size_t dat_len;
    size_t offset;
    bool is_color;

    if (bg->images != NULL) {
        if (!image_list_to_rgb_565(bg->images, &frames, &dat, &dat_len))
            return false;

        offset = find_data_offset(buf, buf_len, dat, dat_len);
        free(dat);

        if (offset == (size_t) -1)
            return false;

        is_color = false;
    } else {
        frames = 0;
        offset = 0;
        is_color = true;
    }

    w->type = HIDSS_WIDGET_BACKGROUND;
    w->widget_id = 0;
    w->sensor_id = 0;
    w->x = 0;
    w->y = 0;
    w->width = bg->width;
    w->height = bg->height;
    w->color = rgb888_to_rgb565(bg->color);
    w->delay = bg->delay;
    w->is_color = is_color;
    w->offset = offset;
    w->frames = frames;
    w->has_alpha = false;

    memset(w->padding, 0x00, sizeof(w->padding));
    hidss_widget_background_swap(w);
    return true;
}

static size_t format_image(uint8_t *ptr, struct section *root, long rotate) {
    struct splash *sp = NULL;
    struct background *bg = NULL;
    uint8_t *pos = ptr;
    uint8_t *end = ptr + IMAGE_DATA_OFFSET;
    size_t len = 0;
    bool res;

    find_unique_sections(root, &sp, &bg);

    widget_rotate_write(pos, rotate);
    pos += HIDSS_WIDGET_SIZE;

    if (sp != NULL) {
        res = widget_splash_write(pos, sp, end, &len);
        pos += HIDSS_WIDGET_SIZE;

        if (!res)
            return -1;
    }

    res = widget_background_write(pos, bg, end, &len);
    pos += HIDSS_WIDGET_SIZE;

    if (!res)
        return -1;

    memset(pos, 0x00, end - pos);
    return (IMAGE_DATA_OFFSET + len);
}

static bool write_image(const char *path, const uint8_t *ptr, size_t len) {
    FILE *file = NULL;
    bool rv = false;

    file = fopen(path, "wb");
    if (file == NULL) {
        output("%s: %s: %s", "fopen", strerror(errno), path);
        goto end;
    }

    if (fwrite(ptr, sizeof(uint8_t), len, file) != len) {
        output("%s: %s: %s", "fwrite", strerror(errno), path);
        goto end;
    }

    if (fflush(file) == EOF) {
        output("%s: %s: %s", "fflush", strerror(errno), path);
        goto end;
    }

    rv = true;

end:
    if (file != NULL)
        fclose(file);
    return rv;
}

bool output_image(const char *path, struct section *root, long rotate) {
    uint8_t *ptr = NULL;
    size_t len;
    bool rv = false;

    ptr = alloc(uint8_t, IMAGE_FULL_SIZE);
    if (ptr == NULL) {
        output("%s: %s: %s", "malloc", strerror(errno), "uint8_t");
        goto end;
    }

    len = format_image(ptr, root, rotate);
    if (len == (size_t) -1)
        goto end;

    if (!write_image(path, ptr, len))
        goto end;

    rv = true;

end:
    free(ptr);
    return rv;
}
