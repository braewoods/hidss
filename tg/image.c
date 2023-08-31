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
    FN_MAX = 64,
    NUM_MAX = 4,
    EXT_MAX = 8,
};

static size_t size_image(const gdImage *img) {
    return gdImageSX(img) * gdImageSY(img);
}

static size_t size_alpha_image(const gdImage *img) {
    return 1 * size_image(img);
}

static size_t size_rgb_565(const gdImage *img) {
    return 2 * size_image(img);
}

static size_t size_argb_565(const gdImage *img) {
    return 3 * size_image(img);
}

static bool parse_filename(const char *s, char fn[static FN_MAX], char num[static NUM_MAX], char ext[static EXT_MAX]) {
    const char *e;
    size_t n;
    const char *start;
    const char *middle;
    const char *end;

    start = e = s;
    n = digcspn(e);
    if (e[n] == '\0')
        return false;

    middle = e += n;
    n = digspn(e);
    if (e[n] == '\0')
        return false;

    end = e += n;
    e += strlen(e);

    n = minlong(middle - start, FN_MAX - 1);
    memcpy(fn, start, n);
    fn[n] = '\0';

    n = minlong(end - middle, NUM_MAX - 1);
    memcpy(num, middle, n);
    num[n] = '\0';

    n = minlong(e - end, EXT_MAX - 1);
    memcpy(ext, end, n);
    ext[n] = '\0';

    return true;
}

static gdImage *run_loader(const char *path, FILE *file) {
    static const struct {
        const char ext[8];
        gdImage *(*func) (FILE *);
    } table[] = {
        //{"avif", gdImageCreateFromAvif},
        { "bmp",  gdImageCreateFromBmp},
        { "gif",  gdImageCreateFromGif},
        //{"heic", gdImageCreateFromHeif},
        //{"heix", gdImageCreateFromHeif},
        {"jpeg", gdImageCreateFromJpeg},
        { "jpg", gdImageCreateFromJpeg},
        { "png",  gdImageCreateFromPng},
        { "tga",  gdImageCreateFromTga},
        { "tif", gdImageCreateFromTiff},
        {"tiff", gdImageCreateFromTiff},
        {"webp", gdImageCreateFromWebp},
    };
    static const size_t table_length = sizeof(table) / sizeof(*table);
    const char *ext = file_extension(path);

    if (ext == NULL) {
        output("%s: %s", "no file extension", path);
        return NULL;
    }

    for (size_t i = 0; i < table_length; i++)
        if (strcasecmp(ext, table[i].ext) == 0)
            return table[i].func(file);

    output("%s: %s: %s", "unsupported file extension", ext, path);
    return NULL;
}

static struct image_list *create_image_list(gdImage *img) {
    struct image_list *il = alloc(struct image_list, 1);

    if (il == NULL) {
        output("%s: %s: %s", "malloc", strerror(errno), "struct image_list");
        return NULL;
    }

    memset(il, 0, sizeof(*il));
    il->image = img;
    return il;
}

static int open_image(const char *path, struct image_list **out, bool first) {
    FILE *file;
    gdImage *img;
    struct image_list *il;

    file = fopen(path, "rb");
    if (file == NULL) {
        if (!first && errno == ENOENT)
            return 0;
        output("%s: %s: %s", "fopen", strerror(errno), path);
        return -1;
    }

    img = run_loader(path, file);
    fclose(file);
    if (img == NULL) {
        output("%s: %s", "failed to load image", path);
        return -1;
    }

    if (!gdImagePaletteToTrueColor(img)) {
        output("failed to convert image to true color: %s", path);
        gdImageDestroy(img);
        return -1;
    }

    il = create_image_list(img);
    if (il == NULL) {
        gdImageDestroy(img);
        return -1;
    }

    *out = il;
    return 1;
}

static bool has_alpha_mask(const gdImage *img) {
    for (int sy = 0; sy < gdImageSY(img); sy++) {
        for (int sx = 0; sx < gdImageSX(img); sx++) {
            int pix = gdImageTrueColorPixel(img, sx, sy);

            if (gdTrueColorGetAlpha(pix) != gdAlphaOpaque)
                return true;
        }
    }

    return false;
}

static bool to_rgb_565(const gdImage *img, uint8_t **buf, size_t *len, size_t *cap) {
    int end_sx = gdImageSX(img);
    int end_sy = gdImageSY(img);
    size_t rgb_size = size_rgb_565(img);
    size_t size = rgb_size;
    uint8_t *rgb_pos = *buf;

    if (*cap < size) {
        output("image conversion buffer overflow: %s", __func__);
        return false;
    }

    for (int sy = 0; sy < end_sy; sy++) {
        for (int sx = 0; sx < end_sx; sx++) {
            int pix = gdImageTrueColorPixel(img, sx, sy);
            int red = gdTrueColorGetRed(pix) >> 3;
            int green = gdTrueColorGetGreen(pix) >> 2;
            int blue = gdTrueColorGetBlue(pix) >> 3;
            int rgb = (red << 11) | (green << 5) | (blue << 0);

            *rgb_pos++ = (rgb & 0x00ff) >> 0;
            *rgb_pos++ = (rgb & 0xff00) >> 8;
        }
    }

    *buf += size;
    *len += size;
    *cap -= size;
    return true;
}

static bool to_argb_565(const gdImage *img, uint8_t **buf, size_t *len, size_t *cap) {
    int end_sx = gdImageSX(img);
    int end_sy = gdImageSY(img);
    size_t alpha_size = size_alpha_image(img);
    size_t rgb_size = size_rgb_565(img);
    size_t size = alpha_size + rgb_size;
    uint8_t *alpha_pos = *buf;
    uint8_t *rgb_pos = *buf + alpha_size;

    if (*cap < size) {
        output("image conversion buffer overflow: %s", __func__);
        return false;
    }

    for (int sy = 0; sy < end_sy; sy++) {
        for (int sx = 0; sx < end_sx; sx++) {
            int pix = gdImageTrueColorPixel(img, sx, sy);
            int alpha = gdTrueColorGetAlpha(pix);
            int red = gdTrueColorGetRed(pix) >> 3;
            int green = gdTrueColorGetGreen(pix) >> 2;
            int blue = gdTrueColorGetBlue(pix) >> 3;
            int rgb = (red << 11) | (green << 5) | (blue << 0);

            *alpha_pos++ = 255 - ((alpha << 1) + (alpha >> 6));
            *rgb_pos++ = (rgb & 0x00ff) >> 0;
            *rgb_pos++ = (rgb & 0xff00) >> 8;
        }
    }

    *buf += size;
    *len += size;
    *cap -= size;
    return true;
}

struct image_list *image_list_open(const char *dir, const char *file) {
    static const char subdir[] = "/img/";
    char path[PATH_MAX];
    struct image_list *root;
    char fn[FN_MAX];
    char num[NUM_MAX];
    char ext[EXT_MAX];
    int i;
    int width;
    int max;
    int sx;
    int sy;
    struct image_list *end;

    strbuild(path, sizeof(path), dir, subdir, file);
    if (open_image(path, &root, true) == -1)
        return NULL;

    if (!parse_filename(file, fn, num, ext))
        return root;

    i = atol(num);
    width = strlen(num);
    max = powlong(10, width);
    sx = gdImageSX(root->image);
    sy = gdImageSY(root->image);
    end = root;

    for (i++; i < max; i++) {
        struct image_list *il;
        int res;

        snprintf(
            path,
            sizeof(path),
            "%s%s%s%0*d%s",
            dir,
            subdir,
            fn,
            width,
            i,
            ext
        );

        res = open_image(path, &il, false);
        if (res == -1) {
            image_list_free(root);
            return NULL;
        }

        if (res == 0)
            break;

        if (gdImageSX(il->image) != sx || gdImageSY(il->image) != sy) {
            output("image must have dimensions %dx%d: %s", sx, sy, path);
            image_list_free(root);
            return NULL;
        }

        end->next = il;
        end = il;
    }

    return root;
}

size_t image_list_frames(const struct image_list *il) {
    size_t n = 0;

    while (il != NULL) {
        n++;
        il = il->next;
    }

    return n;
}

bool image_list_has_alpha(const struct image_list *il) {
    while (il != NULL) {
        if (has_alpha_mask(il->image))
            return true;

        il = il->next;
    }

    return false;
}

bool image_list_to_rgb_565(const struct image_list *il, size_t *out_frames, uint8_t **out_buf, size_t *out_size) {
    size_t len = 0;
    size_t frames = image_list_frames(il);
    size_t size = frames * size_rgb_565(il->image);
    uint8_t *buf = alloc(uint8_t, size);
    uint8_t *ptr = buf;

    if (ptr == NULL) {
        output("%s: %s: %s", "malloc", strerror(errno), "uint8_t");
        return false;
    }

    while (il != NULL) {
        if (!to_rgb_565(il->image, &ptr, &len, &size))
            return false;

        il = il->next;
    }

    *out_frames = frames;
    *out_buf = buf;
    *out_size = len;
    return true;
}

bool image_list_to_argb_565(const struct image_list *il, size_t *out_frames, uint8_t **out_buf, size_t *out_size) {
    size_t len = 0;
    size_t frames = image_list_frames(il);
    size_t size = frames * size_argb_565(il->image);
    uint8_t *buf = alloc(uint8_t, size);
    uint8_t *ptr = buf;

    if (ptr == NULL) {
        output("%s: %s: %s", "malloc", strerror(errno), "uint8_t");
        return false;
    }

    while (il != NULL) {
        if (!to_argb_565(il->image, &ptr, &len, &size))
            return false;

        il = il->next;
    }

    *out_frames = frames;
    *out_buf = buf;
    *out_size = len;
    return true;
}

bool image_list_convert(const struct image_list *il, size_t *out_frames, bool *out_has_alpha, uint8_t **out_buf, size_t *out_size) {
    bool has_alpha = image_list_has_alpha(il);

    *out_has_alpha = has_alpha;

    if (has_alpha)
        return image_list_to_argb_565(il, out_frames, out_buf, out_size);

    return image_list_to_rgb_565(il, out_frames, out_buf, out_size);
}

void image_list_free(struct image_list *il) {
    while (il != NULL) {
        struct image_list *next = il->next;
        if (il->image != NULL)
            gdImageDestroy(il->image);
        free(il);
        il = next;
    }
}
