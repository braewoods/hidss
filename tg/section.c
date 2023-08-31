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
    MAX_SECTIONS = HIDSS_WIDGET_MAX - 1,
};

struct context {
    struct section *root;
    struct section *end;
};

static bool section_to_type(const char *section, int *type) {
    static const struct {
        const char *name;
        int type;
    } table[] = {
        {    "splash",     SECTION_SPLASH},
        {"background", SECTION_BACKGROUND},
    };
    static const size_t table_length = sizeof(table) / sizeof(*table);

    *type = SECTION_UNKNOWN;

    for (size_t i = 0; i < table_length; i++)
        if (strcmp(table[i].name, section) == 0) {
            *type = table[i].type;
            break;
        }

    return (*type != SECTION_UNKNOWN);
}

static const char *type_to_section(int type) {
    static const char *table[] = {
        [SECTION_UNKNOWN]    =    "unknown",
        [SECTION_SPLASH]     =     "splash",
        [SECTION_BACKGROUND] = "background",
    };
    static const size_t table_length = sizeof(table) / sizeof(*table);

    if (type < 0 || type >= (int) table_length)
        return "unknown";

    return table[type];
}

static bool parse_rgb888(const char *name, const char *value, long *n) {
    const long low = 0x000000;
    const long high = 0xffffff;

    if (!is_rgb888(value) || !strtolong(value, n, 16) || !inrange(*n, low, high)) {
        output("%s must be an RGB hexadecimal string", name);
        return false;
    }

    return true;
}

static bool parse_str(const char *name, const char *value, char **out) {
    char *str;

    if (*value == '\0') {
        output("%s must be a non-empty string", name);
        return false;
    }

    str = strdup(value);
    if (str == NULL) {
        output("%s: %s", "strdup", strerror(errno));
        return false;
    }

    free(*out);
    *out = str;
    return true;
}

static bool parse_u16(const char *name, const char *value, long *n) {
    const long low = 0x0000;
    const long high = 0xffff;

    if (!strtolong(value, n, 0)) {
        output("%s must be an integer", name);
        return false;
    }

    if (!inrange(*n, low, high)) {
        output("%s must be between %ld and %ld", name, low, high);
        return false;
    }

    return true;
}

static bool parse_u16_nonzero(const char *name, const char *value, long *n) {
    const long low = 0x0001;
    const long high = 0xffff;

    if (!strtolong(value, n, 0)) {
        output("%s must be an integer", name);
        return false;
    }

    if (!inrange(*n, low, high)) {
        output("%s must be between %ld and %ld", name, low, high);
        return false;
    }

    return true;
}

static bool check_field_is_set(const char *field, bool is_set) {
    if (!is_set) {
        output("field %s must be set", field);
        return false;
    }

    return true;
}

static bool check_field_is_unset(const char *field, bool is_set) {
    if (is_set) {
        output("field %s must be left unset", field);
        return false;
    }

    return true;
}

static bool handle_splash_section(struct splash *sp, const char *name, const char *value) {
    long n;

    if (strcmp(name, "image") == 0) {
        if (!parse_str(name, value, &sp->image))
            return false;

        return true;
    }

    if (strcmp(name, "color") == 0) {
        if (!parse_rgb888(name, value, &n))
            return false;

        sp->color = n;
        sp->color_set = true;
        return true;
    }

    if (strcmp(name, "delay") == 0) {
        if (!parse_u16_nonzero(name, value, &n))
            return false;

        sp->delay = n;
        sp->delay_set = true;
        return true;
    }

    if (strcmp(name, "total") == 0) {
        if (!parse_u16_nonzero(name, value, &n))
            return false;

        sp->total = n;
        sp->total_set = true;
        return true;
    }

    return false;
}

static bool handle_background_section(struct background *bg, const char *name, const char *value) {
    long n;

    if (strcmp(name, "image") == 0) {
        if (!parse_str(name, value, &bg->image))
            return false;

        return true;
    }

    if (strcmp(name, "color") == 0) {
        if (!parse_rgb888(name, value, &n))
            return false;

        bg->color = n;
        bg->color_set = true;
        return true;
    }

    if (strcmp(name, "width") == 0) {
        if (!parse_u16_nonzero(name, value, &n))
            return false;

        bg->width = n;
        bg->width_set = true;
        return true;
    }

    if (strcmp(name, "height") == 0) {
        if (!parse_u16_nonzero(name, value, &n))
            return false;

        bg->height = n;
        bg->height_set = true;
        return true;
    }

    if (strcmp(name, "delay") == 0) {
        if (!parse_u16_nonzero(name, value, &n))
            return false;

        bg->delay = n;
        bg->delay_set = true;
        return true;
    }

    output("%s: %s", "encountered unknown field", name);
    return false;
}

static bool validate_splash(struct splash *sp, const char *dir) {
    struct image_list *il;

    if (!check_field_is_set("image", sp->image != NULL))
        return false;

    il = image_list_open(dir, sp->image);
    if (il == NULL)
        return false;

    if (il->next == NULL) {
        if (!check_field_is_unset("delay", sp->delay_set)) {
            image_list_free(il);
            return false;
        }
    } else {
        if (!check_field_is_set("delay", sp->delay_set)) {
            image_list_free(il);
            return false;
        }
    }

    if (image_list_has_alpha(il)) {
        output("splash images may not have an alpha channel");
        image_list_free(il);
        return false;
    }

    sp->images = il;
    sp->width = gdImageSX(il->image);
    sp->height = gdImageSY(il->image);
    return true;
}

static bool validate_background(struct background *bg, const char *dir) {
    struct image_list *il;

    if (bg->image == NULL) {
        if (!check_field_is_set("color", bg->color_set))
            return false;

        if (!check_field_is_set("width", bg->width_set))
            return false;

        if (!check_field_is_set("height", bg->height_set))
            return false;

        if (!check_field_is_unset("delay", bg->delay_set))
            return false;

        return true;
    }

    if (!check_field_is_unset("color", bg->color_set))
        return false;

    if (!check_field_is_unset("width", bg->width_set))
        return false;

    if (!check_field_is_unset("height", bg->height_set))
        return false;

    il = image_list_open(dir, bg->image);
    if (il == NULL)
        return false;

    if (il->next == NULL) {
        if (!check_field_is_unset("delay", bg->delay_set)) {
            image_list_free(il);
            return false;
        }
    } else {
        if (!check_field_is_set("delay", bg->delay_set)) {
            image_list_free(il);
            return false;
        }
    }

    if (image_list_has_alpha(il)) {
        output("background images may not have an alpha channel");
        image_list_free(il);
        return false;
    }

    bg->images = il;
    bg->width = gdImageSX(il->image);
    bg->height = gdImageSY(il->image);
    return true;
}

static bool handle_new_section(struct context *ctx, const char *section, int line) {
    int type;
    struct section *node;

    if (!section_to_type(section, &type)) {
        output("%s: %s", "encountered unknown section", section);
        return false;
    }

    node = alloc(struct section, 1);
    if (node == NULL) {
        output("%s: %s: %s", "malloc", strerror(errno), "struct section");
        return false;
    }

    memset(node, 0, sizeof(*node));
    node->type = type;
    node->line = line;

    if (ctx->root == NULL) {
        ctx->root = node;
        ctx->end = node;
    } else {
        ctx->end->next = node;
        ctx->end = node;
    }

    return true;
}

static int callback(void *user, const char *section, const char *name, const char *value, int line) {
    struct context *ctx = user;
    struct section *node = ctx->end;

    if (*section == '\0') {
        output("%s must have a name", (node == NULL) ? "first section" : "section");
        return false;
    }

    if (name == NULL && value == NULL)
        return handle_new_section(ctx, section, line);

    switch (node->type) {
        case SECTION_SPLASH:
            return handle_splash_section(&node->splash, name, value);

        case SECTION_BACKGROUND:
            return handle_background_section(&node->background, name, value);

        default:
            output("unhandled section type");
            return false;
    }
}

static bool validate_sections(struct section *root, const char *path, const char *dir, long rotate) {
    struct splash *sp = NULL;
    struct background *bg = NULL;
    size_t count = 0;
    size_t sp_count = 0;
    size_t bg_count = 0;

    if (root == NULL) {
        output("%s: %s", "empty theme", path);
        return false;
    }

    for (struct section *node = root; node != NULL; node = node->next) {
        bool rv;

        count++;

        switch (node->type) {
            case SECTION_SPLASH:
                sp = &node->splash;
                sp_count++;
                rv = validate_splash(sp, dir);
                break;

            case SECTION_BACKGROUND:
                bg = &node->background;
                bg_count++;
                rv = validate_background(bg, dir);
                break;
        }

        if (!rv) {
            output(
                "error while validating section %s at line %d: %s",
                type_to_section(node->type),
                node->line,
                path
            );
            return false;
        }
    }

    // TODO: bounds check all widgets against background
    if (count > MAX_SECTIONS) {
        output("number of sections exceeds the limit by %zu: %s", count - MAX_SECTIONS, path);
        return false;
    }

    if (sp_count > 1) {
        output("%s: %s", "theme can only have one splash section", path);
        return false;
    }

    if (bg_count == 0) {
        output("%s: %s", "theme must have a background section", path);
        return false;
    }

    if (bg_count > 1) {
        output("%s: %s", "theme can only have one background section", path);
        return false;
    }

    if (sp != NULL) {
        if (sp->width != bg->width) {
            output(
                "width mismatch between splash (%d) and background (%d)",
                sp->width,
                bg->width
            );
            return false;
        }

        if (sp->height != bg->height) {
            output(
                "height mismatch between splash (%d) and background (%d)",
                sp->height,
                bg->height
            );
            return false;
        }
    }

    switch (rotate) {
        case HIDSS_WIDGET_ROTATE_90:
        case HIDSS_WIDGET_ROTATE_270:
            if (bg->width != bg->height) {
                output(
                    "%s: %s",
                    "rotate of 90 or 270 degrees only supported for square themes",
                    path
                );
                return false;
            }
            break;
    }

    return true;
}

bool section_parse(const char *dir, long rotate, struct section **out) {
    char path[PATH_MAX];
    struct context ctx;
    int res;
    bool rv = false;

    strbuild(path, sizeof(path), dir, "/theme.ini");
    memset(&ctx, 0, sizeof(ctx));

    res = ini_parse(path, callback, &ctx);
    switch (res) {
        case 0:
            break;

        case -1:
            output("%s: %s: %s", "fopen", strerror(errno), path);
            goto end;

        case -2:
            output("%s: %s: %s", "malloc", strerror(errno), path);
            goto end;

        default:
            output("error while parsing line %d: %s", res, path);
            goto end;
    }

    if (!validate_sections(ctx.root, path, dir, rotate))
        goto end;

    *out = ctx.root;
    rv = true;

end:
    if (!rv)
        section_free(ctx.root);
    return rv;
}

void section_free(struct section *section) {
    while (section != NULL) {
        struct section *next = section->next;
        struct splash *sp;
        struct background *bg;

        switch (section->type) {
            case SECTION_SPLASH:
                sp = &section->splash;
                free(sp->image);
                image_list_free(sp->images);
                break;

            case SECTION_BACKGROUND:
                bg = &section->background;
                free(bg->image);
                image_list_free(bg->images);
                break;
        }

        free(section);
        section = next;
    }
}
