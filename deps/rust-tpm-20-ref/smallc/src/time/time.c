/*
   Copyright (c) 2022 - 2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

#include <time.h>

extern time_t __fw_sys_time();

time_t time(time_t *t)
{

  time_t current_time = 0;
  current_time = __fw_sys_time();
  if (t != NULL)
  {
    *t = current_time;
  }
  return current_time;
}
