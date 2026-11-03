/* An LD_PRELOAD shim for tests/geodb-fixtures.py: libloc's writer stamps
 * a database with time(NULL); this answers $FAKE_TIME instead, so that
 * every fixture has a fixed creation time.  Built by tests/test-geodb.sh:
 *
 *   cc -shared -fPIC -o faketime.so tests/geodb-faketime.c
 */
#include <stdlib.h>
#include <time.h>

time_t
time (time_t *t)
{
	const char *v = getenv ("FAKE_TIME");
	time_t r = v != NULL ? (time_t) strtoll (v, NULL, 10) : 0;

	if (t != NULL)
		*t = r;
	return r;
}
