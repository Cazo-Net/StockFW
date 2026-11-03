/* The dashboard's credential rules (src/cli/fs-dash-auth.c, docs
 * 15.3.2) on a clock this test moves: launch codes (one use, 120 s,
 * the launch file removed), session keys (reads for 12 h, writes only
 * within 15 minutes of the last one, at most 4), a reused code ending
 * every session.  Built by tests/test-dashboard.sh as fs-dash-auth-test.
 */
#include "cli/fs-dash-auth.h"

#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static gint64 now_s;
static guint fails, checks;

static gint64
test_clock (gpointer data)
{
	return now_s;
}

#define CHECK(cond, what) do { \
	checks++; \
	if (cond) printf ("ok:   %s\n", what); \
	else { printf ("FAIL: %s\n", what); fails++; } \
} while (0)

static gchar *
redeem (FsDashAuth *auth, const gchar *code, FsDashRedeem *r)
{
	gchar *key = NULL;

	*r = fs_dash_auth_redeem (auth, code, FS_DASH_VIA_LOCAL, &key);
	return key;
}

static gboolean
is_hex (const gchar *s, gsize len)
{
	if (s == NULL || strlen (s) != len)
		return FALSE;
	for (gsize i = 0; i < len; i++)
		if (!g_ascii_isxdigit (s[i]))
			return FALSE;
	return TRUE;
}

int
main (void)
{
	FsDashAuth *auth = fs_dash_auth_new ();
	gchar *dir = g_dir_make_tmp ("dash-auth-XXXXXX", NULL);
	const gchar *file = NULL;
	gchar *code, *key, *key2, *keys[5];
	FsDashRedeem r;
	struct stat st;
	gint64 created;

	g_assert (auth != NULL && dir != NULL);
	fs_dash_auth_set_clock (auth, test_clock, NULL);
	fs_dash_auth_set_user (auth, geteuid (), getegid (), dir);
	now_s = 1000;

	CHECK (strlen (fs_dash_auth_fingerprint (auth)) == 14 &&
	       fs_dash_auth_fingerprint (auth)[4] == '-',
	       "the fingerprint reads XXXX-XXXX-XXXX");

	/* ---------------------------------------------------- codes */
	code = g_strdup (fs_dash_auth_issue (auth, 8080, &file));
	CHECK (is_hex (code, 32), "a code is 32 hex characters (128 bits)");
	CHECK (file != NULL && stat (file, &st) == 0 &&
	       (st.st_mode & 0777) == 0600,
	       "its launch file is 0600");
	{
		gchar *d = g_path_get_dirname (file);
		gchar *text = NULL;

		CHECK (stat (d, &st) == 0 && (st.st_mode & 0777) == 0700,
		       "  ...in a 0700 directory of its own");
		CHECK (g_file_get_contents (file, &text, NULL, NULL) &&
		       strstr (text, "http://127.0.0.1:8080/#code=") != NULL &&
		       strstr (text, code) != NULL,
		       "  ...and sends the browser to 127.0.0.1:PORT/#code=");
		g_free (text);
		g_free (d);
	}
	{
		gchar *f = g_strdup (file);

		now_s += 120;
		fs_dash_auth_tick (auth);
		CHECK (g_file_test (f, G_FILE_TEST_EXISTS),
		       "the launch file is still there 120 s on");
		now_s += 1;
		fs_dash_auth_tick (auth);
		CHECK (!g_file_test (f, G_FILE_TEST_EXISTS),
		       "  ...and gone at 121 s, with no request at all (T12)");
		g_free (f);
	}
	key = redeem (auth, code, &r);
	CHECK (r == FS_DASH_REDEEM_EXPIRED && key == NULL,
	       "a code used at 121 s is refused as expired (410)");
	g_free (code);

	code = g_strdup (fs_dash_auth_issue (auth, 8080, &file));
	now_s += 120;
	key = redeem (auth, code, &r);
	created = now_s;
	CHECK (r == FS_DASH_REDEEM_OK && is_hex (key, 64),
	       "a code used at 120 s gives a 64-hex session key (256 bits)");
	CHECK (file == NULL || !g_file_test (file, G_FILE_TEST_EXISTS),
	       "  ...and its launch file is deleted when it is used");

	/* ------------------------------------------------- sessions */
	CHECK (fs_dash_auth_check (auth, key, FALSE) == FS_DASH_SESSION_OK &&
	       fs_dash_auth_check (auth, key, TRUE) == FS_DASH_SESSION_OK,
	       "a new session may read and write");
	now_s += 15 * 60;
	CHECK (fs_dash_auth_check (auth, key, TRUE) == FS_DASH_SESSION_OK,
	       "  ...and still write 15 minutes after the code");
	now_s += 1;
	CHECK (fs_dash_auth_check (auth, key, TRUE) ==
	       FS_DASH_SESSION_WRITE_STALE,
	       "15 min 1 s without a write: a write needs a fresh link (E7)");
	CHECK (fs_dash_auth_check (auth, key, FALSE) == FS_DASH_SESSION_OK,
	       "  ...while reads go on");
	{
		gchar *c2 = g_strdup (fs_dash_auth_issue (auth, 8080, NULL));

		key2 = redeem (auth, c2, &r);
		CHECK (r == FS_DASH_REDEEM_OK &&
		       fs_dash_auth_check (auth, key2, TRUE) == FS_DASH_SESSION_OK,
		       "  ...and a fresh link gives a session that may write");
		/* The write comes 10 minutes into the session; the check
		 * is 20 minutes in, past the first 15 minutes and 10 after
		 * the write.  (Review of PR 2: a write at once and a check
		 * 14 minutes later passed with no restart at all.) */
		now_s += 10 * 60;
		fs_dash_auth_note_write (auth, key2);
		now_s += 10 * 60;
		CHECK (fs_dash_auth_check (auth, key2, TRUE) == FS_DASH_SESSION_OK,
		       "a write starts the 15 minutes again");
		now_s += 5 * 60 + 1;
		CHECK (fs_dash_auth_check (auth, key2, TRUE) ==
		       FS_DASH_SESSION_WRITE_STALE,
		       "  ...and 15 min 1 s after that write, a write needs a fresh link");
		fs_dash_auth_end (auth, key2);
		CHECK (fs_dash_auth_check (auth, key2, FALSE) == FS_DASH_SESSION_NONE,
		       "an ended session is refused (401)");
		g_free (c2);
		g_free (key2);
	}

	/* Reads: 12 h from the code. */
	now_s = created + 12 * 3600;
	CHECK (fs_dash_auth_check (auth, key, FALSE) == FS_DASH_SESSION_OK,
	       "a session still reads 12 h after its code");
	now_s += 1;
	CHECK (fs_dash_auth_check (auth, key, FALSE) == FS_DASH_SESSION_NONE &&
	       fs_dash_auth_n_sessions (auth) == 0,
	       "  ...and is gone 1 s later (12 h read lifetime)");
	g_free (key);

	/* ---------------------------------------------------- reuse */
	code = g_strdup (fs_dash_auth_issue (auth, 8080, NULL));
	key = redeem (auth, code, &r);
	{
		gchar *c2 = g_strdup (fs_dash_auth_issue (auth, 8080, NULL));

		key2 = redeem (auth, c2, &r);
		g_free (c2);
	}
	CHECK (fs_dash_auth_n_sessions (auth) == 2, "two links, two sessions");
	g_free (redeem (auth, code, &r));
	CHECK (r == FS_DASH_REDEEM_REUSED, "a code used twice is refused (410)");
	CHECK (fs_dash_auth_n_sessions (auth) == 0 &&
	       fs_dash_auth_check (auth, key, FALSE) == FS_DASH_SESSION_NONE &&
	       fs_dash_auth_check (auth, key2, FALSE) == FS_DASH_SESSION_NONE,
	       "  ...and every session ends, not only its own (T9)");
	g_free (code);
	g_free (key);
	g_free (key2);

	g_free (redeem (auth, "0123456789abcdef0123456789abcdef", &r));
	CHECK (r == FS_DASH_REDEEM_UNKNOWN, "a code never issued is 401");
	g_free (redeem (auth, "0123456789ABCDEF0123456789ABCDEF", &r));
	CHECK (r == FS_DASH_REDEEM_UNKNOWN, "  ...and so is upper-case or "
	       "malformed input");

	/* ------------------------------------------------- the caps */
	for (guint i = 0; i < 5; i++) {
		gchar *c = g_strdup (fs_dash_auth_issue (auth, 8080, NULL));

		keys[i] = redeem (auth, c, &r);
		g_free (c);
	}
	CHECK (fs_dash_auth_n_sessions (auth) == 4 &&
	       fs_dash_auth_check (auth, keys[0], FALSE) == FS_DASH_SESSION_NONE &&
	       fs_dash_auth_check (auth, keys[4], FALSE) == FS_DASH_SESSION_OK,
	       "at most 4 sessions: a fifth ends the oldest");
	for (guint i = 0; i < 5; i++)
		g_free (keys[i]);

	code = g_strdup (fs_dash_auth_issue (auth, 8080, NULL));
	for (guint i = 0; i < FS_DASH_MAX_CODES; i++)
		fs_dash_auth_issue (auth, 8080, NULL);
	g_free (redeem (auth, code, &r));
	CHECK (r == FS_DASH_REDEEM_EXPIRED,
	       "at most 8 codes wait: a ninth ends the oldest");
	g_free (code);

	fs_dash_auth_free (auth);
	{
		GDir *d = g_dir_open (dir, 0, NULL);
		gboolean empty = d != NULL && g_dir_read_name (d) == NULL;

		if (d != NULL)
			g_dir_close (d);
		CHECK (empty, "nothing is left in the runtime directory at the end");
	}
	g_rmdir (dir);
	g_free (dir);

	printf ("\n%u checks, %u failed\n", checks, fails);
	return fails == 0 ? 0 : 1;
}
