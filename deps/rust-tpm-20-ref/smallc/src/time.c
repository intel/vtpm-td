#include <time.h>
#include <errno.h>

const char __utc[] = "UTC";

extern time_t __fw_sys_time();

time_t time(time_t *t)
{

	time_t current_time = 0;
	current_time = __fw_sys_time();
	if (t != NULL)
	{
		*t = current_time;
	}
	return (time_t)__fw_sys_time();
}

extern int __secs_to_tm(long long t, struct tm *tm);

struct tm *gmtime(const time_t *t)
{
	static struct tm tm;
	if (__secs_to_tm(*t, &tm) < 0)
	{
		errno = EOVERFLOW;
		return 0;
	}
	tm.tm_isdst = 0;
	tm.__tm_gmtoff = 0;
	tm.__tm_zone = __utc;
	return &tm;
}
