/* Copyright (C) 2011 by Valentin Ochs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/*
 Copyright (c) 2022 - 2023 Intel Corporation
 SPDX-License-Identifier: Apache-2.0
*/

#include <stdlib.h>
#include <limits.h>
#include <errno.h>

extern void *__fw_malloc(size_t n);
static void *__simple_malloc(size_t n)
{
  return __fw_malloc(n);
}

weak_alias(__simple_malloc, __libc_malloc_impl);

void *__libc_malloc(size_t n)
{
  return __libc_malloc_impl(n);
}

static void *default_malloc(size_t n)
{
  return __libc_malloc_impl(n);
}

weak_alias(default_malloc, malloc);
