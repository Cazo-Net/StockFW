/* Stand-in netsh.exe for the transactional-apply regression test.
 *
 * Writes every invocation to $STOCKFW_FAKE_NETSH_LOG (one line per run,
 * the full command line as space-separated words).  Exits 0 unless
 * $STOCKFW_FAKE_NETSH_FAIL_N is set and this is the Nth invocation, in
 * which case it exits 1 and prints the elevation error phrase to stderr
 * so netsh_needs_elevation() fires.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main (int argc, char **argv)
{
  static int n = 0;
  const char *log = getenv ("STOCKFW_FAKE_NETSH_LOG");
  const char *fail_n = getenv ("STOCKFW_FAKE_NETSH_FAIL_N");
  int fail_at = fail_n != NULL ? atoi (fail_n) : 0;
  FILE *f;
  int i;

  n++;

  if (log != NULL && *log != '\0') {
    f = fopen (log, "ab");
    if (f != NULL) {
      for (i = 1; i < argc; i++) {
        fputs (argv[i], f);
        fputc (i + 1 < argc ? ' ' : '\n', f);
      }
      fclose (f);
    }
  }

  if (fail_at > 0 && n == fail_at) {
    fprintf (stderr, "The requested operation requires elevation\n");
    return 1;
  }

  return 0;
}
