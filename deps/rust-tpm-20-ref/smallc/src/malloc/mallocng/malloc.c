/*
 Copyright (c) 2022 - 2023 Intel Corporation
 SPDX-License-Identifier: Apache-2.0
*/

#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

#include "meta.h"

extern void *__fw_malloc(size_t n);

void *malloc(size_t n)
{
	return __fw_malloc(n);
}
