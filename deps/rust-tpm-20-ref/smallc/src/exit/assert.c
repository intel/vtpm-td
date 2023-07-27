/*
 Copyright (c) 2022 - 2023 Intel Corporation
 SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <stdlib.h>

void __assert_fail(const char *expr, const char *file, int line, const char *func)
{
  printf("Assertion failed: %s (%s: %s: %d)\n", expr, file, func, line);
  abort();
}
