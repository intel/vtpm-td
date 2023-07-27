/*
 Copyright (c) 2022 - 2023 Intel Corporation
 SPDX-License-Identifier: Apache-2.0
*/

#include <stdlib.h>

extern void *__fw_malloc(size_t n);

void *malloc(size_t n)
{
  return __fw_malloc(n);
}
