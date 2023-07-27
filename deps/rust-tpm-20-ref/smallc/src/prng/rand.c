/*
 Copyright (c) 2022 - 2023 Intel Corporation
 SPDX-License-Identifier: Apache-2.0
*/

#include <stdlib.h>
#include <stdint.h>

extern uint32_t __fw_rdrand32(void);

void srand(unsigned s)
{
}

int rand(void)
{
  return (int)__fw_rdrand32();
}
