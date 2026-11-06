/* An LD_PRELOAD shim for tests/test-cli.sh: the wall clock runs
 * $FAKE_OFFSET_US microseconds ahead (or behind), so a test can put
 * local midnight a second or two into a run.  Only the real-time clock
 * moves; the monotonic clock that drives timers is left alone.  Built
 * by the test:
 *
 *   cc -shared -fPIC -o fake-clock.so tests/fake-clock.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

static int (*real_clock_gettime) (clockid_t, struct timespec *);

static long long
offset_us (void)
{
	const char *v = getenv ("FAKE_OFFSET_US");

	return v != NULL ? strtoll (v, NULL, 10) : 0;
}

static int
now (clockid_t id, struct timespec *ts)
{
	if (real_clock_gettime == NULL)
		real_clock_gettime = (int (*) (clockid_t, struct timespec *))
		                     dlsym (RTLD_NEXT, "clock_gettime");
	return real_clock_gettime (id, ts);
}

int
clock_gettime (clockid_t id, struct timespec *ts)
{
	int r = now (id, ts);

	if (r == 0 && (id == CLOCK_REALTIME || id == CLOCK_REALTIME_COARSE)) {
		long long ns = (long long) ts->tv_sec * 1000000000LL +
		               ts->tv_nsec + offset_us () * 1000LL;

		ts->tv_sec = (time_t) (ns / 1000000000LL);
		ts->tv_nsec = (long) (ns % 1000000000LL);
	}
	return r;
}

int
gettimeofday (struct timeval *tv, void *tz)
{
	struct timespec ts;

	(void) tz;
	if (tv == NULL)
		return 0;
	clock_gettime (CLOCK_REALTIME, &ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec / 1000;
	return 0;
}

time_t
time (time_t *t)
{
	struct timespec ts;

	clock_gettime (CLOCK_REALTIME, &ts);
	if (t != NULL)
		*t = ts.tv_sec;
	return ts.tv_sec;
}
