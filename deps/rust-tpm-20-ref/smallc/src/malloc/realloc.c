/*
 Copyright (c) 2022 - 2023 Intel Corporation
 SPDX-License-Identifier: Apache-2.0
*/

#include <stdlib.h>

extern void *__fw_realloc(void *p, size_t n);

void *realloc(void *p, size_t n)
{
	return __fw_realloc(p, n);
}
