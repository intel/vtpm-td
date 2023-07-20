/*
 Copyright (c) 2022 - 2023 Intel Corporation
 SPDX-License-Identifier: Apache-2.0
*/

// #define _BSD_SOURCE
#include <stdlib.h>
#include <sys/mman.h>

#include "meta.h"

extern __fw_free(void *p);

void free(void *p)
{
	__fw_free(p);
}
