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

static uid_t initial_uid;
static uid_t initial_euid;

DIR *opendirat(DIR *par, const char *path) {
    int fd;
    DIR *dir;

    fd = openat(dirfd(par), path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd == -1)
        goto err_0;

    dir = fdopendir(fd);
    if (dir == NULL)
        goto err_1;

    return dir;

err_1:
    close(fd);
err_0:
    return NULL;
}

bool platform_init(void) {
    void (*sig) (int);

    sig = signal(SIGPIPE, SIG_IGN);
    if (sig == SIG_ERR) {
        output("%s: %s", "signal", strerror(errno));
        return false;
    }

    tzset();

    initial_uid = getuid();
    initial_euid = geteuid();

    return true;
}

void platform_fini(void) {

}

bool privileges_discard(void) {
    int res;

    res = seteuid(initial_uid);
    if (res == -1) {
        output("%s: %s", "seteuid", strerror(errno));
        return false;
    }

    return true;
}

bool privileges_restore(void) {
    int res;

    res = seteuid(initial_euid);
    if (res == -1) {
        output("%s: %s", "seteuid", strerror(errno));
        return false;
    }

    return true;
}
