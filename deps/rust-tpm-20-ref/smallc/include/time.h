#ifndef _TIME_H_
#define _TIME_H_

#include <stddef.h>

#ifndef _use_time_t
#define _use_time_t
typedef signed long time_t;
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

struct timeval 
{
	long tv_sec;      /* time value, in seconds */
	long tv_usec;     /* time value, in microseconds */
};
struct timezone 
{
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	    /* type of dst correction */
};

time_t time(time_t *);
struct tm *gmtime(const time_t *);
int gettimeofday ( struct timeval *tv , struct timezone *tz );

#endif //_TIME_H
