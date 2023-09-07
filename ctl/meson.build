# Copyright (c) 2023 James Buren
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

ctl = 'hidss-ctl'

ctl_srcs = [
    'main.c',
    'common.c',
    'device.c',
]

ctl_incs = [
    inc,
]

ctl_deps = []

if sys == 'linux'
    ctl_srcs += [
        'posix.c',
        'linux.c',
    ]
elif sys == 'openbsd'
    ctl_srcs += [
        'posix.c',
        'openbsd.c',
    ]
elif sys == 'windows'
    ctl_srcs += [
        'windows.c',
        win.compile_resources('windows.rc'),
    ]
    ctl_deps += [
        cc.find_library('hid', static: true),
        cc.find_library('cfgmgr32', static: true),
    ]
endif

executable(
    ctl,
    sources: ctl_srcs,
    include_directories: ctl_incs,
    dependencies: ctl_deps,
    install: true,
    install_mode: ['rwsr-xr-x', 0, 0],
)
