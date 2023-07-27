/*
 Copyright (c) 2022 - 2023 Intel Corporation
 SPDX-License-Identifier: Apache-2.0
*/

#include <stdio.h>
#include <stdarg.h>

extern void __fw_debug_msg(char *, int);

int printf(const char *restrict fmt, ...)
{
#ifndef _PRINTF_BUF_SIZE_
#define _PRINTF_BUF_SIZE_ 512
#endif
  char buf[_PRINTF_BUF_SIZE_] = {0};
  int len = 0;
  va_list args;
  va_start(args, fmt);
  len = vsnprintf(buf, _PRINTF_BUF_SIZE_, fmt, args);
  va_end(args);
  __fw_debug_msg(buf, len);
  return len;
#undef _PRINTF_BUF_SIZE_
}
