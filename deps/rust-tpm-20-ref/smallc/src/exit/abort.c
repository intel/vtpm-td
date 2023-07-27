/*
 Copyright (c) 2022 - 2023 Intel Corporation
 SPDX-License-Identifier: Apache-2.0
*/

#include <stdlib.h>

extern void __fw_abort();

void abort(void)
{
  __fw_abort();
}