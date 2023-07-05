#ifndef _ASSERT_H_
#define _ASSERT_H_

#define assert(x) ((void)((x) || (__assert_fail(#x, __FILE__, __LINE__, __func__), 0)))

void __assert_fail(const char *, const char *, int, const char *);

#endif
