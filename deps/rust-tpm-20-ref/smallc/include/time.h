#ifndef _TIME_H_
#define _TIME_H_

#include <stddef.h>

#ifndef _use_time_t
#define _use_time_t
typedef size_t time_t;
#endif // _use_time_t

struct tm
{
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
	long __tm_gmtoff;
	const char *__tm_zone;
};

time_t time(time_t *);
struct tm *gmtime(const time_t *);

#endif //_TIME_H
