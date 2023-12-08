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

project(
    'hidss',
    'c',
    version: '0.1',
    license: 'MIT',
    subproject_dir: 'dep',
    default_options: [
        'warning_level=3',
        'c_std=gnu11',
        'buildtype=debugoptimized',
    ],
)

cc = meson.get_compiler('c')
inc = include_directories('inc')
sys = target_machine.system()
win = import('windows')

inih_proj = subproject(
    'inih',
    default_options: [
        'distro_install=false',
        'with_INIReader=false',
        'multi-line_entries=false',
        'utf-8_bom=false',
        'inline_comments=false',
        'inline_comment_prefix=;',
        'start-of-line_comment_prefix=;#',
        'allow_no_value=false',
        'stop_on_first_error=true',
        'report_line_numbers=true',
        'call_handler_on_new_section=true',
        'use_heap=false',
        'max_line_length=4096',
        'initial_malloc_size=4096',
        'allow_realloc=false',
    ],
)
inih_dep = inih_proj.get_variable('inih_dep')

subdir('inc')
subdir('ctl')
