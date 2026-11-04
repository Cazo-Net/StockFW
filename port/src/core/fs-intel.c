/*---[ fs-intel.c ]------------------------------------------------------
 * The threat-intel engine.  See fs-intel.h and docs/1.0.7-threat-
 * intel-design.md, section 6.
 *
 * Layout of this file:
 *
 *   helpers      small text, number and 128-bit helpers
 *   audit        one escaped line per attempt [S17.1]
 *   store        the directory check [S2.1-2] and every file
 *                operation through a directory descriptor [S2.3]
 *   config       intel.conf
 *   state        <id>.state, <id>.list, applied.state
 *   update       fetch, parse, judge, store [S14, S15, S12]
 *   build        config + store + host -> rule set (6.4)
 *   gate         fs_intel_apply_safe, suspend, resume (6.5)
 *   honest state fs_intel_state, counters (6.6)
 *   lookup       one address (6.8)
 *
 * The store is Linux's /var/lib/stockfw/intel and, since Round 3,
 * Windows' %ProgramData%\StockFW\intel (core/fs-winstore.c, which does
 * the file operations there); on any other platform every call that
 * needs it fails with FS_INTEL_ERR_UNSUPPORTED, while the in-memory
 * parts (the config structure, the build from a given host, lookups'
 * sentence) still compile and work.
 *
 * Order of writes, so a crash between two steps never leaves a state
 * that lies: a new copy's <id>.list is written before its <id>.state,
 * and the state records the digest of the list it describes; a list
 * that does not match its state is never reported "unchanged" (the
 * next update stores the copy again).  applied.state is written only
 * after the kernel holds the new table, so a crash in between reads as
 * "differs", never as "enforced".
 *
 * Secrets: while curl runs, its argv -- the feed's URL and the proxy --
 * is readable by every local user in /proc/<pid>/cmdline.  The catalog
 * URLs carry none, intel.conf refuses a proxy with "user:password@",
 * and the URL rule refuses "user@" in a feed URL; a custom feed URL
 * may still carry a key in its query string (the design allows it for
 * paid feeds), and that key is visible there for the length of a
 * download.  Round 1 documents this rather than hiding it.
 *--------------------------------------------------------------------*/

#ifdef __linux__
#define _GNU_SOURCE
#endif

#include "core/fs-intel.h"
#include "core/fs-audit.h"
#include "core/fs-fetch.h"
#include "core/fs-i18n.h"
#ifdef G_OS_WIN32
#include "core/fs-winstore.h"
#endif

#include <gio/gio.h>   /* G_IO_ERROR: the backends' error domain */
#include <string.h>

#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

/* CMake defines FS_VERSION for every target; tests/test-core.sh compiles
 * every file of src/core by hand without it. */
#ifndef FS_VERSION
#define FS_VERSION "dev"
#endif

#define STORE_PARENT      "/var/lib/stockfw"
#define STORE_DEFAULT     "/var/lib/stockfw/intel"
#define CONF_NAME         "intel.conf"
#define APPLIED_NAME      "applied.state"

/* Where the rules live, in the platform's words, for the sentences the
 * state and the outcomes give: nftables in the kernel on Linux, Windows
 * Firewall rules on Windows (which keeps them across a restart, so a
 * restart is no reason they are gone there).  The CLI that the consent
 * text names is built on Linux only. */
#ifdef G_OS_WIN32
#define FS_INTEL_WHERE       "Windows Firewall"
#define FS_INTEL_WHERE_CAP   "Windows Firewall"
#define FS_INTEL_GONE_WHY    "removed by another program or by hand"
#define FS_INTEL_EXCEPT_CLI  ""
#else
#define FS_INTEL_WHERE       "the kernel"
#define FS_INTEL_WHERE_CAP   "The kernel"
#define FS_INTEL_GONE_WHY    "after a restart, or removed by another program"
#define FS_INTEL_EXCEPT_CLI  ", or run \"sudo stockfw intel except <address>\""
#endif
#define LOCK_NAME         "engine.lock"

/* Read caps per file kind: our own files are small, and a file that
 * grew past its cap was not written by us. */
#define CONF_MAX          (1024u * 1024u)
#define STATE_MAX         (256u * 1024u)
#define APPLIED_MAX       (1024u * 1024u)
#define LIST_MAX          FS_FEED_MAX_BYTES

/* A stored list holds the pieces of at most FS_FEED_MAX_ENTRIES
 * entries; the protected ranges can split an entry in two, a few dozen
 * times at most. */
#define LIST_MAX_INTERVALS (FS_FEED_MAX_ENTRIES + 256u)

/* The default downloader's whole-transfer limit. */
#define FETCH_TIMEOUT_S   120u

/* A custom feed is due once a day. */
#define CUSTOM_INTERVAL_H 24u

/* A copy is stale after this many update intervals [S12.3]. */
#define STALE_INTERVALS   7

/* A content date further ahead than this is refused: once stored it
 * would make every honest later copy a ROLLBACK (fs_feed_judge has no
 * clock), and a stored date this far ahead is forgotten for the same
 * reason (the clock was put back, or the state was edited). */
#define FUTURE_SLACK_S    (24 * 3600)

/* An attempt dated further ahead than this means the clock went back:
 * the schedule restarts instead of waiting for the clock to catch up. */
#define CLOCK_SLACK_S     300

/* The audit keeps external text to its first line and this many bytes
 * [S17.1]. */
#define AUDIT_TEXT_MAX    1024u

/* Notes name at most this many addresses per kind. */
#define NOTE_ADDRS        3u

G_DEFINE_QUARK (fs-intel-error-quark, fs_intel_error)

/* ============================================================ helpers */

static gchar *
sha256_hex (const void *data, gsize len)
{
	return g_compute_checksum_for_data (G_CHECKSUM_SHA256, data, len);
}

/* "1,234,567": counts in sentences. */
static gchar *
grouped (guint64 v)
{
	gchar *digits = g_strdup_printf ("%" G_GUINT64_FORMAT, v);
	gsize n = strlen (digits);
	GString *out = g_string_new (NULL);

	for (gsize i = 0; i < n; i++) {
		if (i > 0 && (n - i) % 3 == 0)
			g_string_append_c (out, ',');
		g_string_append_c (out, digits[i]);
	}
	g_free (digits);
	return g_string_free (out, FALSE);
}

/* The first line of `text', at most `max' bytes, cut on a UTF-8
 * character boundary.  Tool output and error messages pass through
 * this before they reach a note, a state file or the audit. */
static gchar *
first_line (const gchar *text, gsize max)
{
	const gchar *end;
	gsize n;

	if (text == NULL)
		return g_strdup ("");
	end = text + strcspn (text, "\r\n");
	n = (gsize) (end - text);
	if (n > max) {
		n = max;
		while (n > 0 && ((guchar) text[n] & 0xC0) == 0x80)
			n--;
	}
	return g_strndup (text, n);
}

/* Every surface that reaches a platform without the threat-intel slots
 * says this (design 13.10): blocklists and location rules alike. */
static const gchar *
unsupported_text (void)
{
	/* Where it is used, neither works: a platform without a store or
	 * a backend without the threat-intel slots. */
	return _("Blocklists and country or network-owner blocking are not "
	         "available on this platform yet.");
}

/* Country and network-owner blocking reads IPFire's location database
 * into nftables sets: Linux only.  Windows enforces the blocklists
 * (Round 3) but not this. */
const gchar *
fs_intel_geo_unsupported_text (void)
{
#ifdef G_OS_WIN32
	return _("Blocking by country or network owner is not supported on "
	         "Windows in this version. Blocklists are.");
#else
	return _("Blocking by country or network owner is not supported on "
	         "this platform.");
#endif
}

/* ---- NAT64 -------------------------------------------------------- */

/* 64:ff9b::/96, the NAT64 well-known prefix [N9, S7.3]. */
#define NAT64_HI G_GUINT64_CONSTANT (0x0064ff9b00000000)

static gboolean
nat64_embedded (FsU128 a, guint32 *v4)
{
	if (a.hi != NAT64_HI || (a.lo >> 32) != 0)
		return FALSE;
	if (v4 != NULL)
		*v4 = (guint32) a.lo;
	return TRUE;
}

/* ============================================================== audit */

/* Escape `\', `|', line breaks and control bytes, so a detail is one
 * line and never forges a field or an entry [S17.1]. */
static gchar *
audit_escape (const gchar *text)
{
	GString *out = g_string_new (NULL);

	for (const guchar *p = (const guchar *) (text ? text : ""); *p; p++) {
		switch (*p) {
		case '\\':
			g_string_append (out, "\\\\");
			break;
		case '|':
			g_string_append (out, "\\|");
			break;
		case '\n':
			g_string_append (out, "\\n");
			break;
		case '\r':
			g_string_append (out, "\\r");
			break;
		default:
			if (*p < 0x20 || *p == 0x7f)
				g_string_append_printf (out, "\\x%02x", *p);
			else
				g_string_append_c (out, (gchar) *p);
		}
	}
	return g_string_free (out, FALSE);
}

static void
audit (const gchar *action, const gchar *detail)
{
	gchar *clean = audit_escape (detail);

	fs_audit_log (action, clean);
	g_free (clean);
}

/* An error's message for a note, a state file or the audit. */
static gchar *
error_text (const GError *error)
{
	return first_line (error != NULL ? error->message : _("unknown error"),
	                   AUDIT_TEXT_MAX);
}

/* ============================================================== store */

#ifdef __linux__

static gboolean
dir_mode_is_safe (const struct stat *st, uid_t me)
{
	return S_ISDIR (st->st_mode) &&
	       (st->st_uid == me || st->st_uid == 0) &&
	       (st->st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static void
unsafe (GError **error, const gchar *path, const gchar *why)
{
	g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNSAFE_DIR,
	             _("The threat-intel directory %s is not safe to use: %s."),
	             path, why);
}

/* Every component of an absolute, canonical path, from "/" down, must
 * be a directory owned by `me' or root that neither group nor others
 * can write (OpenSSH's StrictModes) [S2.1-2]. */
static gboolean
chain_is_safe (const gchar *canon, uid_t me, GError **error)
{
	gchar *path = g_strdup (canon);
	gsize n = strlen (path);
	gboolean ok = TRUE;

	for (gsize i = 1; i <= n && ok; i++) {
		struct stat st;
		gchar keep;

		if (i < n && path[i] != '/')
			continue;
		keep = path[i];
		path[i] = '\0';
		if (lstat (path, &st) != 0) {
			unsafe (error, canon, g_strerror (errno));
			ok = FALSE;
		} else if (S_ISLNK (st.st_mode)) {
			gchar *why = g_strdup_printf (_("%s is a symbolic link"),
			                              path);
			unsafe (error, canon, why);
			g_free (why);
			ok = FALSE;
		} else if (!dir_mode_is_safe (&st, me)) {
			gchar *why = g_strdup_printf (
				_("%s is owned by another user or writable by "
				  "others"), *path ? path : "/");
			unsafe (error, canon, why);
			g_free (why);
			ok = FALSE;
		}
		path[i] = keep;
	}
	/* The root directory itself. */
	if (ok) {
		struct stat st;

		if (lstat ("/", &st) != 0 || !dir_mode_is_safe (&st, me)) {
			unsafe (error, canon, _("/ is not safe"));
			ok = FALSE;
		}
	}
	g_free (path);
	return ok;
}

/* The store is 0700 (design 6.1): its files are 0600, but a directory
 * others can read still lists them, and so the feeds and local lists in
 * use.  An existing store that group or others can read or enter is
 * set to 0700 through a descriptor opened without following a link
 * (the chain above it is already known safe).  FALSE when that is not
 * possible: a store owned by root while we are not root. */
static gboolean
tighten_dir (const gchar *full)
{
	struct stat st;
	gboolean ok;
	int fd = open (full, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

	if (fd < 0)
		return FALSE;
	ok = fstat (fd, &st) == 0 && S_ISDIR (st.st_mode) &&
	     ((st.st_mode & (S_IRWXG | S_IRWXO)) == 0 ||
	      fchmod (fd, 0700) == 0);
	close (fd);
	return ok;
}

/* `path' (absolute) as a safe directory: its parent is resolved to a
 * canonical path whose every component is checked, and the directory
 * itself must not be a symbolic link.  Created (0700) when missing, set
 * to 0700 when group or others may read it.  Returns the canonical
 * path. */
static gchar *
checked_dir (const gchar *path, uid_t me, GError **error)
{
	gchar *trimmed = g_strdup (path);
	gchar *base, *parent, *canon_parent, *full = NULL;
	char resolved[PATH_MAX];
	struct stat st;
	gsize n = strlen (trimmed);

	while (n > 1 && trimmed[n - 1] == '/')
		trimmed[--n] = '\0';

	base = g_path_get_basename (trimmed);
	parent = g_path_get_dirname (trimmed);
	if (strcmp (base, ".") == 0 || strcmp (base, "..") == 0 ||
	    strcmp (base, "/") == 0) {
		unsafe (error, path, _("it must name a directory"));
		goto out;
	}
	if (realpath (parent, resolved) == NULL) {
		unsafe (error, path, g_strerror (errno));
		goto out;
	}
	canon_parent = resolved;
	if (!chain_is_safe (canon_parent, me, error))
		goto out;

	full = g_build_filename (canon_parent, base, NULL);
	if (lstat (full, &st) != 0) {
		if (errno != ENOENT || mkdir (full, 0700) != 0 ||
		    lstat (full, &st) != 0) {
			unsafe (error, path, g_strerror (errno));
			g_clear_pointer (&full, g_free);
			goto out;
		}
	}
	if (S_ISLNK (st.st_mode)) {
		unsafe (error, path, _("it is a symbolic link"));
		g_clear_pointer (&full, g_free);
	} else if (!dir_mode_is_safe (&st, me)) {
		unsafe (error, path,
		        _("it is not a directory, is owned by another user, "
		          "or is writable by others"));
		g_clear_pointer (&full, g_free);
	} else if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0 &&
	           !tighten_dir (full)) {
		unsafe (error, path,
		        _("other users can read it, and its mode could not be "
		          "changed to 0700"));
		g_clear_pointer (&full, g_free);
	}
out:
	g_free (base);
	g_free (parent);
	g_free (trimmed);
	return full;
}

#endif /* __linux__ */

gchar *
fs_intel_dir (GError **error)
{
#ifdef __linux__
	const gchar *override = g_getenv ("STOCKFW_INTEL_DIR");
	uid_t me = geteuid ();

	if (override != NULL && *override != '\0') {
		if (!g_path_is_absolute (override)) {
			unsafe (error, override, _("it must be an absolute path"));
			return NULL;
		}
		return checked_dir (override, me, error);
	}
	if (me != 0) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_NEEDS_ROOT,
		             _("Threat intel needs administrator rights "
		               "(root) on Linux."));
		return NULL;
	}
	if (mkdir (STORE_PARENT, 0755) != 0 && errno != EEXIST) {
		unsafe (error, STORE_PARENT, g_strerror (errno));
		return NULL;
	}
	return checked_dir (STORE_DEFAULT, me, error);
#elif defined G_OS_WIN32
	return fs_winstore_dir (error);
#else
	g_set_error_literal (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNSUPPORTED,
	                     unsupported_text ());
	return NULL;
#endif
}

/* An open store: a directory descriptor every file operation goes
 * through (openat, renameat, unlinkat) [S2.3].  On Windows, the
 * directory pinned (fs_winstore_pin) and its path, which then keeps
 * naming it. */
typedef struct
{
	int fd;
#ifdef G_OS_WIN32
	gpointer pin;
	gchar   *path;
#endif
} Store;

#ifdef G_OS_WIN32
#define STORE_INIT { -1, NULL, NULL }
#else
#define STORE_INIT { -1 }
#endif

static gboolean
store_open (Store *store, GError **error)
{
#ifdef __linux__
	gchar *path = fs_intel_dir (error);
	struct stat st;

	store->fd = -1;
	if (path == NULL)
		return FALSE;
	store->fd = open (path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
	                        O_CLOEXEC);
	if (store->fd < 0 || fstat (store->fd, &st) != 0 ||
	    !dir_mode_is_safe (&st, geteuid ())) {
		if (store->fd >= 0)
			close (store->fd);
		store->fd = -1;
		unsafe (error, path, _("it changed while it was opened"));
		g_free (path);
		return FALSE;
	}
	g_free (path);
	return TRUE;
#elif defined G_OS_WIN32
	store->fd = -1;
	store->pin = NULL;
	store->path = fs_intel_dir (error);
	if (store->path == NULL)
		return FALSE;
	store->pin = fs_winstore_pin (store->path, error);
	if (store->pin == NULL) {
		g_clear_pointer (&store->path, g_free);
		return FALSE;
	}
	return TRUE;
#else
	store->fd = -1;
	return fs_intel_dir (error) != NULL;  /* always FALSE here */
#endif
}

/* Whether a store directory is there at all, found without creating
 * it: a computer where no list was ever turned on has none, and a Stop
 * or a Start there must not make one.  An error other than "no such
 * file" counts as there (store_open then says what is wrong). */
static gboolean
store_exists (void)
{
#ifdef __linux__
	const gchar *override = g_getenv ("STOCKFW_INTEL_DIR");
	struct stat st;

	if (lstat (override != NULL && *override != '\0' ? override
	                                                : STORE_DEFAULT,
	           &st) == 0)
		return TRUE;
	return errno != ENOENT;
#elif defined G_OS_WIN32
	return fs_winstore_exists ();
#else
	return FALSE;
#endif
}

gboolean
fs_intel_store_exists (void)
{
	return store_exists ();
}

static void
store_close (Store *store)
{
#ifdef __linux__
	if (store->fd >= 0)
		close (store->fd);
#elif defined G_OS_WIN32
	fs_winstore_unpin (store->pin);
	store->pin = NULL;
	g_clear_pointer (&store->path, g_free);
#endif
	store->fd = -1;
}

/* ---- the engine lock ------------------------------------------------
 * Every operation that changes the live rules or applied.state (an
 * apply, a Stop, a clear, a Start) holds an exclusive lock on
 * <store>/engine.lock, so the CLI, cron, the app and the app's own
 * threads never interleave them: a Stop that arrives during an apply
 * waits for it and then takes the rules down, instead of being undone
 * by the apply's record.
 *
 * Linux: flock on a descriptor opened through the store's directory
 * descriptor.  flock locks belong to the open file, so two threads of
 * one process that each open the file exclude each other too.
 *
 * Windows: LockFileEx on a handle to the same file in the pinned store
 * (fs_winstore_lock).  Byte-range locks belong to the handle, so two
 * threads that each open the file exclude each other, as on Linux; the
 * file is opened without following a link and refused when it is one.
 *
 * Unlocked (no handle) when the lock file cannot be opened: the
 * operation then goes ahead unlocked, as before (a store that cannot
 * hold a lock file cannot hold a record either, and says so on the
 * write). */
typedef struct
{
	int  fd;
	gboolean waited;   /* another operation held it first */
#ifdef G_OS_WIN32
	gpointer handle;
#endif
} EngineLock;

#ifdef G_OS_WIN32
#define ENGINE_LOCK_INIT { -1, FALSE, NULL }
#else
#define ENGINE_LOCK_INIT { -1, FALSE }
#endif

static void
engine_lock (const Store *store, EngineLock *lock)
{
	lock->fd = -1;
	lock->waited = FALSE;
#ifdef __linux__
	if (store->fd < 0)
		return;
	lock->fd = openat (store->fd, LOCK_NAME,
	                   O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (lock->fd < 0)
		return;
	if (flock (lock->fd, LOCK_EX | LOCK_NB) == 0)
		return;
	lock->waited = TRUE;
	while (flock (lock->fd, LOCK_EX) != 0) {
		if (errno != EINTR) {
			close (lock->fd);
			lock->fd = -1;
			return;
		}
	}
#elif defined G_OS_WIN32
	lock->handle = NULL;
	if (store->pin == NULL || store->path == NULL)
		return;
	lock->handle = fs_winstore_lock (store->path, LOCK_NAME,
	                                 &lock->waited);
#else
	(void) store;
#endif
}

/* Whether `lock' holds the engine lock (on any platform: Windows has
 * no descriptor, only a handle). */
static gboolean
engine_held (const EngineLock *lock)
{
#ifdef G_OS_WIN32
	return lock->handle != NULL;
#else
	return lock->fd >= 0;
#endif
}

static void
engine_unlock (EngineLock *lock)
{
#ifdef __linux__
	if (lock->fd >= 0)
		close (lock->fd);   /* releases the flock */
#elif defined G_OS_WIN32
	fs_winstore_unlock (lock->handle);   /* UnlockFileEx, CloseHandle */
	lock->handle = NULL;
#endif
	lock->fd = -1;
}

#ifndef G_OS_WIN32
static void
store_error (GError **error, const gchar *name, const gchar *why)
{
	g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_STORE,
	             _("Threat-intel file %s: %s."), name, why);
}
#endif

#ifdef __linux__
/* A file name inside the store: never a path.  Names are built from
 * valid ids, so this only stops a hand-filled config struct. */
static gboolean
store_name_ok (const gchar *name, GError **error)
{
	if (name != NULL && *name != '\0' && strchr (name, '/') == NULL &&
	    strcmp (name, ".") != 0 && strcmp (name, "..") != 0)
		return TRUE;
	store_error (error, name ? name : "", _("not a file name"));
	return FALSE;
}
#endif

/* Read one file: no symlink, a regular file, at most `cap' bytes.
 * *missing is set when the file does not exist (error set too).  The
 * result is NUL-terminated. */
static gchar *
store_read (const Store *store, const gchar *name, gsize cap, gsize *len,
            gboolean *missing, GError **error)
{
#ifdef __linux__
	int fd;
	struct stat st;
	GByteArray *buf;

	if (missing != NULL)
		*missing = FALSE;
	if (!store_name_ok (name, error))
		return NULL;
	fd = openat (store->fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
	                              O_NONBLOCK | O_NOCTTY);
	if (fd < 0) {
		if (errno == ENOENT && missing != NULL)
			*missing = TRUE;
		store_error (error, name, errno == ELOOP
		             ? _("it is a symbolic link") : g_strerror (errno));
		return NULL;
	}
	if (fstat (fd, &st) != 0 || !S_ISREG (st.st_mode)) {
		close (fd);
		store_error (error, name, _("it is not a regular file"));
		return NULL;
	}
	if ((guint64) st.st_size > cap) {
		close (fd);
		store_error (error, name, _("it is larger than expected"));
		return NULL;
	}
	buf = g_byte_array_sized_new ((guint) st.st_size + 1);
	for (;;) {
		guint8 chunk[64 * 1024];
		ssize_t got = read (fd, chunk, sizeof chunk);

		if (got < 0 && errno == EINTR)
			continue;
		if (got < 0) {
			store_error (error, name, g_strerror (errno));
			close (fd);
			g_byte_array_free (buf, TRUE);
			return NULL;
		}
		if (got == 0)
			break;
		if (buf->len + (gsize) got > cap) {
			close (fd);
			g_byte_array_free (buf, TRUE);
			store_error (error, name, _("it is larger than expected"));
			return NULL;
		}
		g_byte_array_append (buf, chunk, (guint) got);
	}
	close (fd);
	if (len != NULL)
		*len = buf->len;
	g_byte_array_append (buf, (const guint8 *) "", 1);
	return (gchar *) g_byte_array_free (buf, FALSE);
#elif defined G_OS_WIN32
	return fs_winstore_read (store->path, name, cap, len, missing, error);
#else
	if (missing != NULL)
		*missing = FALSE;
	store_error (error, name, _("not supported on this platform"));
	return NULL;
#endif
}

/* Write a whole file: a fresh temporary name (O_EXCL, 0600), fsync,
 * rename over the old one, fsync the directory.  A crash leaves either
 * the old file or the new one, and at worst a stray temporary that is
 * never read. */
static gboolean
store_write (const Store *store, const gchar *name, const gchar *data,
             gsize len, GError **error)
{
#ifdef __linux__
	gchar *tmp = NULL;
	int fd = -1;
	gsize done = 0;

	if (!store_name_ok (name, error))
		return FALSE;
	for (guint tries = 0; tries < 16 && fd < 0; tries++) {
		g_free (tmp);
		tmp = g_strdup_printf (".%s.%08x.tmp", name, g_random_int ());
		fd = openat (store->fd, tmp, O_WRONLY | O_CREAT | O_EXCL |
		                             O_NOFOLLOW | O_CLOEXEC, 0600);
		if (fd < 0 && errno != EEXIST)
			break;
	}
	if (fd < 0) {
		store_error (error, name, g_strerror (errno));
		g_free (tmp);
		return FALSE;
	}
	while (done < len) {
		ssize_t put = write (fd, data + done, len - done);

		if (put < 0 && errno == EINTR)
			continue;
		if (put <= 0)
			goto fail;
		done += (gsize) put;
	}
	if (fchmod (fd, 0600) != 0 || fsync (fd) != 0)
		goto fail;
	if (close (fd) != 0) {
		fd = -1;
		goto fail;
	}
	fd = -1;
	if (renameat (store->fd, tmp, store->fd, name) != 0)
		goto fail;
	fsync (store->fd);
	g_free (tmp);
	return TRUE;

fail:
	store_error (error, name, g_strerror (errno ? errno : EIO));
	if (fd >= 0)
		close (fd);
	unlinkat (store->fd, tmp, 0);
	g_free (tmp);
	return FALSE;
#elif defined G_OS_WIN32
	return fs_winstore_write (store->path, name, data, len, error);
#else
	store_error (error, name, _("not supported on this platform"));
	return FALSE;
#endif
}

/* Remove a file; a missing one is not an error. */
static gboolean
store_unlink (const Store *store, const gchar *name, GError **error)
{
#ifdef __linux__
	if (!store_name_ok (name, error))
		return FALSE;
	if (unlinkat (store->fd, name, 0) != 0 && errno != ENOENT) {
		store_error (error, name, g_strerror (errno));
		return FALSE;
	}
	return TRUE;
#elif defined G_OS_WIN32
	return fs_winstore_unlink (store->path, name, error);
#else
	store_error (error, name, _("not supported on this platform"));
	return FALSE;
#endif
}

static gboolean
running_as_root (void)
{
#ifdef __linux__
	return geteuid () == 0;
#elif defined G_OS_WIN32
	return fs_winstore_is_admin ();
#else
	return FALSE;
#endif
}

/* ============================================================= config */

static void
feed_conf_free (gpointer p)
{
	FsIntelFeedConf *f = p;

	if (f == NULL)
		return;
	g_free (f->id);
	g_free (f->name);
	g_free (f->url);
	g_free (f);
}

static void
list_conf_free (gpointer p)
{
	FsIntelListConf *l = p;

	if (l == NULL)
		return;
	g_free (l->id);
	g_free (l->name);
	g_free (l);
}

static void
location_conf_free (gpointer p)
{
	FsIntelLocationConf *l = p;

	if (l == NULL)
		return;
	g_free (l->id);
	g_free (l->name);
	g_strfreev (l->countries);
	if (l->asns != NULL)
		g_array_unref (l->asns);
	g_free (l);
}

FsIntelConfig *
fs_intel_config_new (void)
{
	FsIntelConfig *config = g_new0 (FsIntelConfig, 1);
	const FsFeedInfo *cat;
	guint n = 0;

	config->enabled = TRUE;
	config->feeds = g_ptr_array_new_with_free_func (feed_conf_free);
	config->lists = g_ptr_array_new_with_free_func (list_conf_free);
	config->exceptions = fs_range_set_new ();
	config->locations = g_ptr_array_new_with_free_func (location_conf_free);

	cat = fs_feed_catalog (&n);
	for (guint i = 0; i < n; i++) {
		FsIntelFeedConf *f = g_new0 (FsIntelFeedConf, 1);

		f->id = g_strdup (cat[i].id);
		f->dir = cat[i].default_dir;
		f->format = cat[i].format;
		g_ptr_array_add (config->feeds, f);
	}
	return config;
}

void
fs_intel_config_free (FsIntelConfig *config)
{
	if (config == NULL)
		return;
	g_free (config->proxy);
	g_ptr_array_unref (config->feeds);
	g_ptr_array_unref (config->lists);
	if (config->locations != NULL)
		g_ptr_array_unref (config->locations);
	fs_range_set_free (config->exceptions);
	g_free (config);
}

FsIntelFeedConf *
fs_intel_config_feed (const FsIntelConfig *config, const gchar *id)
{
	if (config == NULL || id == NULL)
		return NULL;
	for (guint i = 0; i < config->feeds->len; i++) {
		FsIntelFeedConf *f = g_ptr_array_index (config->feeds, i);

		if (strcmp (f->id, id) == 0)
			return f;
	}
	return NULL;
}

FsIntelListConf *
fs_intel_config_list (const FsIntelConfig *config, const gchar *id)
{
	if (config == NULL || id == NULL)
		return NULL;
	for (guint i = 0; i < config->lists->len; i++) {
		FsIntelListConf *l = g_ptr_array_index (config->lists, i);

		if (strcmp (l->id, id) == 0)
			return l;
	}
	return NULL;
}

FsIntelLocationConf *
fs_intel_config_location (const FsIntelConfig *config, const gchar *id)
{
	if (config == NULL || id == NULL || config->locations == NULL)
		return NULL;
	for (guint i = 0; i < config->locations->len; i++) {
		FsIntelLocationConf *l = g_ptr_array_index (config->locations, i);

		if (strcmp (l->id, id) == 0)
			return l;
	}
	return NULL;
}

const gchar *
fs_intel_config_label (const FsIntelConfig *config, const gchar *id)
{
	FsIntelFeedConf *f = fs_intel_config_feed (config, id);
	FsIntelListConf *l;
	FsIntelLocationConf *g;

	if (f != NULL) {
		const FsFeedInfo *fi;

		if (f->custom)
			return f->name;
		fi = fs_feed_catalog_find (id);
		return fi != NULL ? _(fi->name) : f->id;
	}
	l = fs_intel_config_list (config, id);
	if (l != NULL)
		return l->name;
	g = fs_intel_config_location (config, id);
	if (g != NULL)
		return g->name;
	if (g_strcmp0 (id, FS_INTEL_GEO_ID) == 0)
		return _("Location database");
	return NULL;
}

/* A name the user typed: valid UTF-8, 1-128 bytes, no control
 * characters (it reaches labels, notes and the audit). */
static gboolean
name_is_acceptable (const gchar *name)
{
	gsize n;

	if (name == NULL || !g_utf8_validate (name, -1, NULL))
		return FALSE;
	n = strlen (name);
	if (n == 0 || n > 128)
		return FALSE;
	for (const gchar *p = name; *p; p = g_utf8_next_char (p)) {
		gunichar c = g_utf8_get_char (p);

		if (g_unichar_iscntrl (c))
			return FALSE;
	}
	{
		gchar *t = g_strstrip (g_strdup (name));
		gboolean blank = (*t == '\0');

		g_free (t);
		return !blank;
	}
}

/* "custom-" / "local-" + a slug of `name': a-z and 0-9 kept (ASCII
 * letters lowered), every other run one '-', trimmed, cut to fit 40
 * bytes; a name with no such character gets a hash instead. */
static gchar *
slug_id (const gchar *prefix, const gchar *name)
{
	gsize room = 40 - strlen (prefix);
	GString *s = g_string_new (NULL);
	gchar *id;

	for (const gchar *p = name; *p; p++) {
		gchar c = g_ascii_tolower (*p);

		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
			g_string_append_c (s, c);
		else if (s->len > 0 && s->str[s->len - 1] != '-')
			g_string_append_c (s, '-');
	}
	if (s->len > room)
		g_string_truncate (s, room);
	while (s->len > 0 && s->str[s->len - 1] == '-')
		g_string_truncate (s, s->len - 1);
	if (s->len == 0) {
		gchar *hex = sha256_hex (name, strlen (name));

		g_string_append_len (s, hex, 12);
		g_free (hex);
	}
	id = g_strconcat (prefix, s->str, NULL);
	g_string_free (s, TRUE);
	return id;
}

/* The host an https:// URL contacts -- or, with http_too, an http://
 * one (a proxy) -- for consent text and for keeping a download's
 * server reachable.  The scheme is matched in any case, as the URL
 * rule and curl match it (a feed typed as "HTTPS://..." must keep its
 * server reachable too), and a "user@" part is skipped.  NULL when
 * there is none. */
static gchar *
host_of (const gchar *url, gboolean http_too)
{
	const gchar *p, *end, *at;

	if (url == NULL)
		return NULL;
	if (g_ascii_strncasecmp (url, "https://", 8) == 0)
		p = url + 8;
	else if (http_too && g_ascii_strncasecmp (url, "http://", 7) == 0)
		p = url + 7;
	else
		return NULL;
	end = p + strcspn (p, "/?#");
	for (at = end; at > p && at[-1] != '@'; at--)
		;
	p = at;
	if (end == p)
		return NULL;
	if (*p == '[') {
		const gchar *close = memchr (p, ']', (gsize) (end - p));

		return close != NULL ? g_strndup (p + 1, (gsize) (close - p - 1))
		                     : NULL;
	}
	{
		const gchar *colon = memchr (p, ':', (gsize) (end - p));

		if (colon != NULL)
			end = colon;
	}
	return end > p ? g_strndup (p, (gsize) (end - p)) : NULL;
}

/* A proxy for intel.conf: what fs-fetch accepts, and no "user:pass@":
 * curl's argv is readable by every local user (/proc/<pid>/cmdline),
 * so a credential there would be published. */
static gboolean
proxy_is_acceptable (const gchar *proxy)
{
	const gchar *auth, *end;

	if (!fs_fetch_proxy_is_acceptable (proxy))
		return FALSE;
	auth = strstr (proxy, "://");
	if (auth == NULL)
		return FALSE;
	auth += 3;
	end = auth + strcspn (auth, "/?#");
	return memchr (auth, '@', (gsize) (end - auth)) == NULL;
}

/* ---- location rule values (design 13.3) ----------------------------- */

static FsIntelLocationKind
location_kind_of_id (const gchar *id)
{
	if (id == NULL)
		return 0;
	if (g_str_has_prefix (id, "country-"))
		return FS_INTEL_LOCATION_COUNTRY;
	if (g_str_has_prefix (id, "asn-"))
		return FS_INTEL_LOCATION_ASN;
	return 0;
}

static gint
cmp_str (gconstpointer a, gconstpointer b)
{
	return strcmp (*(const gchar *const *) a, *(const gchar *const *) b);
}

static gint
cmp_u32 (gconstpointer a, gconstpointer b)
{
	guint32 x = *(const guint32 *) a, y = *(const guint32 *) b;

	return x < y ? -1 : x > y;
}

/* "DE", "de" -> "DE"; NULL for anything but two ASCII letters. */
static gchar *
country_code (const gchar *text)
{
	gchar *t = g_strstrip (g_strdup (text != NULL ? text : ""));
	gchar *out = NULL;

	if (strlen (t) == 2 && g_ascii_isalpha (t[0]) && g_ascii_isalpha (t[1]))
		out = g_ascii_strup (t, 2);
	g_free (t);
	return out;
}

/* "13335", "AS13335", "as13335" -> 13335; FALSE for anything else,
 * AS 0 included (it means "no AS"). */
static gboolean
as_number (const gchar *text, guint32 *asn)
{
	gchar *t = g_strstrip (g_strdup (text != NULL ? text : ""));
	const gchar *d = t;
	guint64 v = 0;
	gboolean ok;

	if (g_ascii_strncasecmp (d, "AS", 2) == 0)
		d += 2;
	ok = *d != '\0' && strspn (d, "0123456789") == strlen (d) &&
	     strlen (d) <= 10 &&
	     g_ascii_string_to_unsigned (d, 10, 1, G_MAXUINT32, &v, NULL);
	g_free (t);
	if (ok)
		*asn = (guint32) v;
	return ok;
}

/* The values of a rule of `kind', normalized: country codes upper case
 * and sorted, or AS numbers sorted; duplicates dropped; 1 to
 * FS_INTEL_LOCATION_MAX_VALUES.  On failure *why gets one sentence. */
static gboolean
location_values (FsIntelLocationKind kind, const gchar *const *values,
                 gchar ***codes, GArray **asns, gchar **why)
{
	GPtrArray *c = g_ptr_array_new_with_free_func (g_free);
	GArray *a = g_array_new (FALSE, FALSE, sizeof (guint32));
	gboolean ok = TRUE;

	*codes = NULL;
	*asns = NULL;
	*why = NULL;
	for (guint i = 0; ok && values != NULL && values[i] != NULL; i++) {
		gchar *t = g_strstrip (g_strdup (values[i]));

		if (*t == '\0') {
			g_free (t);
			continue;   /* "CN;;HK" and a trailing ';' */
		}
		if (kind == FS_INTEL_LOCATION_COUNTRY) {
			gchar *code = country_code (t);

			if (code == NULL) {
				*why = g_strdup_printf (_("\"%s\" is not a country "
				                          "code (two letters)"), t);
				ok = FALSE;
			} else
				g_ptr_array_add (c, code);
		} else if (kind == FS_INTEL_LOCATION_ASN) {
			guint32 n = 0;

			if (!as_number (t, &n)) {
				*why = g_strdup_printf (_("\"%s\" is not an AS number "
				                          "(1 to 4294967295)"), t);
				ok = FALSE;
			} else
				g_array_append_val (a, n);
		} else {
			*why = g_strdup (_("not a kind of location rule"));
			ok = FALSE;
		}
		g_free (t);
	}
	if (ok && kind == FS_INTEL_LOCATION_COUNTRY) {
		g_ptr_array_sort (c, cmp_str);
		for (guint i = 1; i < c->len; )
			if (strcmp (g_ptr_array_index (c, i),
			            g_ptr_array_index (c, i - 1)) == 0)
				g_ptr_array_remove_index (c, i);
			else
				i++;
	} else if (ok) {
		g_array_sort (a, cmp_u32);
		for (guint i = 1; i < a->len; )
			if (g_array_index (a, guint32, i) ==
			    g_array_index (a, guint32, i - 1))
				g_array_remove_index (a, i);
			else
				i++;
	}
	if (ok) {
		guint n = kind == FS_INTEL_LOCATION_COUNTRY ? c->len : a->len;

		if (n == 0 || n > FS_INTEL_LOCATION_MAX_VALUES) {
			*why = g_strdup_printf (_("a rule holds 1 to %u values"),
			                        FS_INTEL_LOCATION_MAX_VALUES);
			ok = FALSE;
		}
	}
	if (ok && kind == FS_INTEL_LOCATION_COUNTRY) {
		g_ptr_array_add (c, NULL);
		*codes = (gchar **) g_ptr_array_free (c, FALSE);
		g_array_unref (a);
	} else if (ok) {
		*asns = a;
		g_ptr_array_unref (c);
	} else {
		g_ptr_array_unref (c);
		g_array_unref (a);
	}
	return ok;
}

/* ---- intel.conf ---------------------------------------------------- */

static void
config_error (GError **error, const gchar *group, const gchar *key,
              const gchar *why)
{
	g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_CONFIG,
	             _("intel.conf: [%s] %s: %s"), group, key, why);
}

/* A key's raw value, or NULL when absent. */
static gchar *
kf_raw (GKeyFile *kf, const gchar *group, const gchar *key)
{
	return g_key_file_has_key (kf, group, key, NULL)
	       ? g_key_file_get_value (kf, group, key, NULL) : NULL;
}

static gboolean
kf_bool (GKeyFile *kf, const gchar *group, const gchar *key,
         gboolean *out, GError **error)
{
	gchar *raw = kf_raw (kf, group, key);
	gboolean ok = TRUE;

	if (raw == NULL)
		return TRUE;
	if (strcmp (raw, "true") == 0)
		*out = TRUE;
	else if (strcmp (raw, "false") == 0)
		*out = FALSE;
	else {
		config_error (error, group, key, _("not true or false"));
		ok = FALSE;
	}
	g_free (raw);
	return ok;
}

static gboolean
kf_time (GKeyFile *kf, const gchar *group, const gchar *key,
         gint64 *out, GError **error)
{
	gchar *raw = kf_raw (kf, group, key);
	gint64 v = 0;
	gboolean ok = TRUE;

	if (raw == NULL)
		return TRUE;
	if (!g_ascii_string_to_signed (raw, 10, 0, G_MAXINT64, &v, NULL)) {
		config_error (error, group, key, _("not a time"));
		ok = FALSE;
	} else
		*out = v;
	g_free (raw);
	return ok;
}

static gboolean
kf_dir (GKeyFile *kf, const gchar *group, FsIntelDir *out, GError **error)
{
	gchar *raw = kf_raw (kf, group, "direction");
	gboolean ok = TRUE;

	if (raw == NULL)
		return TRUE;
	if (!fs_intel_dir_from_string (raw, out)) {
		config_error (error, group, "direction",
		              _("not in, out or both"));
		ok = FALSE;
	}
	g_free (raw);
	return ok;
}

/* A key's string value; *out is NULL when the key is absent.  FALSE
 * when the key is there but GKeyFile cannot decode its value (a bad
 * escape such as "\q"): such a value is invalid, never "absent" -- a
 * proxy or an exception list read as absent would be dropped without
 * a word. */
static gboolean
kf_string (GKeyFile *kf, const gchar *group, const gchar *key, gchar **out)
{
	*out = NULL;
	if (!g_key_file_has_key (kf, group, key, NULL))
		return TRUE;
	*out = g_key_file_get_string (kf, group, key, NULL);
	return *out != NULL;
}

/* The same for a list (an empty value is an empty list, not NULL). */
static gboolean
kf_list (GKeyFile *kf, const gchar *group, const gchar *key, gchar ***out,
         gsize *n)
{
	*out = NULL;
	*n = 0;
	if (!g_key_file_has_key (kf, group, key, NULL))
		return TRUE;
	*out = g_key_file_get_string_list (kf, group, key, n, NULL);
	return *out != NULL;
}

/* kf_string for intel.conf: an undecodable value fails the load naming
 * the group and key. */
static gboolean
kf_text (GKeyFile *kf, const gchar *group, const gchar *key, gchar **out,
         GError **error)
{
	if (kf_string (kf, group, key, out))
		return TRUE;
	config_error (error, group, key,
	              _("the value cannot be read (an invalid escape "
	                "sequence)"));
	return FALSE;
}

static gboolean
config_feed_group (FsIntelConfig *config, GKeyFile *kf, const gchar *group,
                   const gchar *id, GError **error)
{
	FsIntelFeedConf *f = fs_intel_config_feed (config, id);
	gboolean custom = (f == NULL);

	if (!fs_intel_id_is_valid (id)) {
		config_error (error, group, "id", _("not a valid id"));
		return FALSE;
	}
	if (custom && !g_str_has_prefix (id, "custom-"))
		return TRUE;   /* a feed this version does not know: ignored */
	if (custom) {
		gchar *name = NULL, *url = NULL, *fmt = NULL;
		FsFeedFormat format = FS_FEED_FMT_PLAIN;
		gboolean ok = FALSE;

		gboolean read = kf_text (kf, group, "name", &name, error) &&
		                kf_text (kf, group, "url", &url, error) &&
		                kf_text (kf, group, "format", &fmt, error);

		if (!read)
			ok = FALSE;   /* error set, naming the key */
		else if (!name_is_acceptable (name))
			config_error (error, group, "name", _("missing or invalid"));
		else if (url == NULL || !fs_feed_url_is_acceptable (url, NULL))
			config_error (error, group, "url",
			              _("missing, or not an acceptable https:// "
			                "address"));
		else if (fmt == NULL || !fs_feed_format_from_string (fmt, &format))
			config_error (error, group, "format",
			              _("not plain, spamhaus-json or dshield"));
		else
			ok = TRUE;
		g_free (fmt);
		if (!ok) {
			g_free (name);
			g_free (url);
			return FALSE;
		}
		f = g_new0 (FsIntelFeedConf, 1);
		f->id = g_strdup (id);
		f->custom = TRUE;
		f->name = name;
		f->url = url;
		f->format = format;
		f->dir = FS_INTEL_DIR_IN;
		g_ptr_array_add (config->feeds, f);
	}
	return kf_bool (kf, group, "enabled", &f->enabled, error) &&
	       kf_dir (kf, group, &f->dir, error) &&
	       kf_time (kf, group, "accepted-at", &f->accepted_at, error);
}

static gboolean
config_list_group (FsIntelConfig *config, GKeyFile *kf, const gchar *group,
                   const gchar *id, GError **error)
{
	FsIntelListConf *l;
	gchar *name;

	if (!fs_intel_id_is_valid (id) || !g_str_has_prefix (id, "local-")) {
		config_error (error, group, "id", _("not a valid list id"));
		return FALSE;
	}
	if (fs_intel_config_list (config, id) != NULL)
		return TRUE;
	if (!kf_text (kf, group, "name", &name, error))
		return FALSE;
	if (!name_is_acceptable (name)) {
		g_free (name);
		config_error (error, group, "name", _("missing or invalid"));
		return FALSE;
	}
	l = g_new0 (FsIntelListConf, 1);
	l->id = g_strdup (id);
	l->name = name;
	l->dir = FS_INTEL_DIR_IN;
	g_ptr_array_add (config->lists, l);
	return kf_bool (kf, group, "enabled", &l->enabled, error) &&
	       kf_dir (kf, group, &l->dir, error) &&
	       kf_time (kf, group, "imported-at", &l->imported_at, error);
}

static gboolean
config_location_group (FsIntelConfig *config, GKeyFile *kf,
                       const gchar *group, const gchar *id, GError **error)
{
	FsIntelLocationKind kind = location_kind_of_id (id);
	const gchar *key = kind == FS_INTEL_LOCATION_COUNTRY ? "countries"
	                                                     : "asns";
	const gchar *other = kind == FS_INTEL_LOCATION_COUNTRY ? "asns"
	                                                       : "countries";
	FsIntelLocationConf *l;
	gchar *name = NULL, *why = NULL;
	gchar **values = NULL;
	gsize n = 0;

	if (!fs_intel_id_is_valid (id) || kind == 0) {
		config_error (error, group, "id",
		              _("not a valid location rule id (country-... or "
		                "asn-...)"));
		return FALSE;
	}
	if (fs_intel_config_location (config, id) != NULL)
		return TRUE;
	if (!kf_text (kf, group, "name", &name, error))
		return FALSE;
	if (!name_is_acceptable (name)) {
		g_free (name);
		config_error (error, group, "name", _("missing or invalid"));
		return FALSE;
	}
	if (g_key_file_has_key (kf, group, other, NULL)) {
		g_free (name);
		config_error (error, group, other,
		              kind == FS_INTEL_LOCATION_COUNTRY
		              ? _("a country rule holds no AS numbers")
		              : _("an AS rule holds no countries"));
		return FALSE;
	}
	if (!kf_list (kf, group, key, &values, &n) || values == NULL) {
		g_free (name);
		config_error (error, group, key, values == NULL &&
		              !g_key_file_has_key (kf, group, key, NULL)
		              ? _("missing") : _("the value cannot be read"));
		g_strfreev (values);
		return FALSE;
	}
	l = g_new0 (FsIntelLocationConf, 1);
	l->id = g_strdup (id);
	l->name = name;
	l->kind = kind;
	l->dir = FS_INTEL_DIR_IN;
	if (!location_values (kind, (const gchar *const *) values,
	                      &l->countries, &l->asns, &why)) {
		config_error (error, group, key, why);
		g_free (why);
		g_strfreev (values);
		location_conf_free (l);
		return FALSE;
	}
	g_strfreev (values);
	g_ptr_array_add (config->locations, l);
	return kf_bool (kf, group, "enabled", &l->enabled, error) &&
	       kf_dir (kf, group, &l->dir, error);
}

static FsIntelConfig *
config_parse (const gchar *text, gsize len, GError **error)
{
	GKeyFile *kf = g_key_file_new ();
	FsIntelConfig *config = fs_intel_config_new ();
	GError *local = NULL;
	gchar **groups = NULL;
	gboolean ok = TRUE;

	if (!g_utf8_validate (text, (gssize) len, NULL) ||
	    !g_key_file_load_from_data (kf, text, len, G_KEY_FILE_NONE, &local)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_CONFIG,
		             _("intel.conf is not a valid configuration file%s%s"),
		             local ? ": " : "", local ? local->message : "");
		g_clear_error (&local);
		ok = FALSE;
		goto out;
	}

	if (g_key_file_has_group (kf, "intel")) {
		gchar *proxy = NULL;

		ok = kf_bool (kf, "intel", "enabled", &config->enabled, error) &&
		     kf_text (kf, "intel", "proxy", &proxy, error);
		if (proxy != NULL && *proxy != '\0') {
			if (!proxy_is_acceptable (proxy)) {
				config_error (error, "intel", "proxy",
				              _("not an http:// or https:// proxy "
				                "address without a password"));
				ok = FALSE;
				g_free (proxy);
			} else
				config->proxy = proxy;
		} else
			g_free (proxy);
	}

	groups = g_key_file_get_groups (kf, NULL);
	for (guint i = 0; ok && groups[i] != NULL; i++) {
		const gchar *g = groups[i];

		if (g_str_has_prefix (g, "feed "))
			ok = config_feed_group (config, kf, g, g + 5, error);
		else if (g_str_has_prefix (g, "list "))
			ok = config_list_group (config, kf, g, g + 5, error);
		else if (g_str_has_prefix (g, "location "))
			ok = config_location_group (config, kf, g, g + 9, error);
	}
	if (ok && g_key_file_has_group (kf, "geo"))
		ok = kf_bool (kf, "geo", "enabled", &config->geo_enabled, error) &&
		     kf_time (kf, "geo", "accepted-at", &config->geo_accepted_at,
		              error);

	if (ok && g_key_file_has_key (kf, "exceptions", "ranges", NULL)) {
		gsize n = 0;
		gchar **ranges = NULL;

		/* One bad escape must not drop every exception: an address
		 * the user excepted would be blocked without a word. */
		if (!kf_list (kf, "exceptions", "ranges", &ranges, &n)) {
			config_error (error, "exceptions", "ranges",
			              _("the value cannot be read (an invalid "
			                "escape sequence)"));
			ok = FALSE;
		}
		for (gsize i = 0; ok && ranges != NULL && i < n; i++) {
			gchar *r = g_strstrip (g_strdup (ranges[i]));

			if (*r != '\0' &&
			    !fs_range_set_add_text (config->exceptions, r)) {
				gchar *why = g_strdup_printf (
					_("\"%s\" is not an address, CIDR or range"),
					r);
				config_error (error, "exceptions", "ranges", why);
				g_free (why);
				ok = FALSE;
			}
			g_free (r);
		}
		g_strfreev (ranges);
		fs_range_set_normalize (config->exceptions);
	}
out:
	g_strfreev (groups);
	g_key_file_free (kf);
	if (!ok) {
		fs_intel_config_free (config);
		return NULL;
	}
	return config;
}

static gchar *
config_serialize (const FsIntelConfig *config, gsize *len)
{
	GKeyFile *kf = g_key_file_new ();
	gchar *data;

	g_key_file_set_comment (kf, NULL, NULL,
	                        " StockFW threat intel (docs/1.0.7-threat-"
	                        "intel-design.md, 6.2)", NULL);
	g_key_file_set_boolean (kf, "intel", "enabled", config->enabled);
	if (config->proxy != NULL)
		g_key_file_set_string (kf, "intel", "proxy", config->proxy);

	for (guint i = 0; i < config->feeds->len; i++) {
		const FsIntelFeedConf *f = g_ptr_array_index (config->feeds, i);
		gchar *g = g_strconcat ("feed ", f->id, NULL);

		g_key_file_set_boolean (kf, g, "enabled", f->enabled);
		g_key_file_set_string (kf, g, "direction",
		                       fs_intel_dir_to_string (f->dir));
		g_key_file_set_int64 (kf, g, "accepted-at", f->accepted_at);
		if (f->custom) {
			g_key_file_set_string (kf, g, "name", f->name);
			g_key_file_set_string (kf, g, "url", f->url);
			g_key_file_set_string (kf, g, "format",
			                       fs_feed_format_to_string (f->format));
		}
		g_free (g);
	}
	for (guint i = 0; i < config->lists->len; i++) {
		const FsIntelListConf *l = g_ptr_array_index (config->lists, i);
		gchar *g = g_strconcat ("list ", l->id, NULL);

		g_key_file_set_string (kf, g, "name", l->name);
		g_key_file_set_boolean (kf, g, "enabled", l->enabled);
		g_key_file_set_string (kf, g, "direction",
		                       fs_intel_dir_to_string (l->dir));
		g_key_file_set_int64 (kf, g, "imported-at", l->imported_at);
		g_free (g);
	}
	g_key_file_set_boolean (kf, "geo", "enabled", config->geo_enabled);
	g_key_file_set_int64 (kf, "geo", "accepted-at", config->geo_accepted_at);
	for (guint i = 0; i < config->locations->len; i++) {
		const FsIntelLocationConf *l = g_ptr_array_index (config->locations,
		                                                  i);
		gchar *g = g_strconcat ("location ", l->id, NULL);

		g_key_file_set_string (kf, g, "name", l->name);
		if (l->kind == FS_INTEL_LOCATION_COUNTRY)
			g_key_file_set_string_list (kf, g, "countries",
			                            (const gchar *const *) l->countries,
			                            g_strv_length (l->countries));
		else {
			gchar **v = g_new0 (gchar *, l->asns->len + 1);

			for (guint j = 0; j < l->asns->len; j++)
				v[j] = g_strdup_printf ("%u", g_array_index (l->asns,
				                                             guint32, j));
			g_key_file_set_string_list (kf, g, "asns",
			                            (const gchar *const *) v,
			                            l->asns->len);
			g_strfreev (v);
		}
		g_key_file_set_string (kf, g, "direction",
		                       fs_intel_dir_to_string (l->dir));
		g_key_file_set_boolean (kf, g, "enabled", l->enabled);
		g_free (g);
	}
	if (!fs_range_set_is_empty (config->exceptions)) {
		gchar *text = fs_range_set_to_text (config->exceptions);
		gchar **lines = g_strsplit (g_strstrip (text), "\n", -1);

		g_key_file_set_string_list (kf, "exceptions", "ranges",
		                            (const gchar *const *) lines,
		                            g_strv_length (lines));
		g_strfreev (lines);
		g_free (text);
	}
	data = g_key_file_to_data (kf, len, NULL);
	g_key_file_free (kf);
	return data;
}

static FsIntelConfig *
config_load_in (const Store *store, GError **error)
{
	gboolean missing = FALSE;
	GError *local = NULL;
	gsize len = 0;
	gchar *text = store_read (store, CONF_NAME, CONF_MAX, &len, &missing,
	                          &local);
	FsIntelConfig *config;

	if (text == NULL) {
		if (missing) {
			g_clear_error (&local);
			return fs_intel_config_new ();
		}
		g_propagate_error (error, local);
		return NULL;
	}
	config = config_parse (text, len, error);
	g_free (text);
	return config;
}

FsIntelConfig *
fs_intel_config_load (GError **error)
{
	Store store;
	FsIntelConfig *config;

	if (!store_open (&store, error))
		return NULL;
	config = config_load_in (&store, error);
	store_close (&store);
	return config;
}

gboolean
fs_intel_config_save (const FsIntelConfig *config, GError **error)
{
	Store store;
	gsize len = 0;
	gchar *data;
	gboolean ok;

	g_return_val_if_fail (config != NULL, FALSE);
	if (!store_open (&store, error))
		return FALSE;
	data = config_serialize (config, &len);
	ok = store_write (&store, CONF_NAME, data, len, error);
	g_free (data);
	store_close (&store);
	return ok;
}

/* ---- config edits -------------------------------------------------- */

static gboolean
unknown_source (GError **error, const gchar *id)
{
	g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNKNOWN,
	             _("There is no feed or list called \"%s\"."),
	             id ? id : "");
	return FALSE;
}

static gboolean
dir_arg_ok (FsIntelDir dir, gboolean zero_ok, GError **error)
{
	if ((zero_ok && dir == 0) || dir == FS_INTEL_DIR_IN ||
	    dir == FS_INTEL_DIR_OUT || dir == FS_INTEL_DIR_BOTH)
		return TRUE;
	g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
	             _("The direction must be in, out or both."));
	return FALSE;
}

gboolean
fs_intel_config_set_proxy (FsIntelConfig *config, const gchar *proxy,
                           GError **error)
{
	g_return_val_if_fail (config != NULL, FALSE);
	if (proxy == NULL || *proxy == '\0') {
		g_clear_pointer (&config->proxy, g_free);
		return TRUE;
	}
	if (!proxy_is_acceptable (proxy)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("The proxy must be an http:// or https:// URL "
		               "without a user name or password (other users "
		               "could read them): \"%s\"."), proxy);
		return FALSE;
	}
	g_free (config->proxy);
	config->proxy = g_strdup (proxy);
	return TRUE;
}

gboolean
fs_intel_config_enable_feed (FsIntelConfig *config, const gchar *id,
                             FsIntelDir dir, gboolean accept_terms,
                             GError **error)
{
	FsIntelFeedConf *f;

	g_return_val_if_fail (config != NULL, FALSE);
	f = fs_intel_config_feed (config, id);
	if (f == NULL)
		return unknown_source (error, id);
	if (!dir_arg_ok (dir, TRUE, error))
		return FALSE;
	if (f->accepted_at == 0 && !accept_terms) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_CONSENT,
		             _("Turning on %s needs its terms accepted first."),
		             fs_intel_config_label (config, id));
		return FALSE;
	}
	if (f->accepted_at == 0)
		f->accepted_at = g_get_real_time () / G_USEC_PER_SEC;
	if (dir != 0)
		f->dir = dir;
	f->enabled = TRUE;
	return TRUE;
}

gboolean
fs_intel_config_disable_feed (FsIntelConfig *config, const gchar *id,
                              GError **error)
{
	FsIntelFeedConf *f;

	g_return_val_if_fail (config != NULL, FALSE);
	f = fs_intel_config_feed (config, id);
	if (f == NULL)
		return unknown_source (error, id);
	f->enabled = FALSE;
	return TRUE;
}

gboolean
fs_intel_config_add_custom (FsIntelConfig *config, const gchar *name,
                            const gchar *url, FsFeedFormat format,
                            FsIntelDir dir, gchar **id_out, GError **error)
{
	FsIntelFeedConf *f;
	GError *local = NULL;
	gchar *id;

	g_return_val_if_fail (config != NULL, FALSE);
	if (id_out != NULL)
		*id_out = NULL;
	if (!name_is_acceptable (name)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("A feed needs a name of 1 to 128 characters."));
		return FALSE;
	}
	if (!fs_feed_url_is_acceptable (url, &local)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID, "%s",
		             local ? local->message : _("The address is refused."));
		g_clear_error (&local);
		return FALSE;
	}
	if (fs_feed_format_to_string (format) == NULL) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("Unknown feed format."));
		return FALSE;
	}
	if (!dir_arg_ok (dir, FALSE, error))
		return FALSE;
	id = slug_id ("custom-", name);
	if (fs_intel_config_feed (config, id) != NULL) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("A feed called \"%s\" already exists."), name);
		g_free (id);
		return FALSE;
	}
	f = g_new0 (FsIntelFeedConf, 1);
	f->id = id;
	f->custom = TRUE;
	f->name = g_strdup (name);
	f->url = g_strdup (url);
	f->format = format;
	f->dir = dir;
	f->enabled = TRUE;
	/* Typing the address is the consent for that host. */
	f->accepted_at = g_get_real_time () / G_USEC_PER_SEC;
	g_ptr_array_add (config->feeds, f);
	if (id_out != NULL)
		*id_out = g_strdup (id);
	return TRUE;
}

static gboolean
store_remove_source (const gchar *id, GError **error)
{
	Store store;
	gchar *list = g_strconcat (id, ".list", NULL);
	gchar *state = g_strconcat (id, ".state", NULL);
	gboolean ok = FALSE;

	if (store_open (&store, error)) {
		ok = store_unlink (&store, list, error) &&
		     store_unlink (&store, state, error);
		store_close (&store);
	}
	g_free (list);
	g_free (state);
	return ok;
}

gboolean
fs_intel_config_remove (FsIntelConfig *config, const gchar *id,
                        GError **error)
{
	FsIntelFeedConf *f;
	FsIntelListConf *l;

	g_return_val_if_fail (config != NULL, FALSE);
	f = fs_intel_config_feed (config, id);
	l = fs_intel_config_list (config, id);
	if (f == NULL && l == NULL) {
		FsIntelLocationConf *g = fs_intel_config_location (config, id);

		if (g == NULL)
			return unknown_source (error, id);
		/* Its counters' state; it has no stored list. */
		if (!store_remove_source (id, error))
			return FALSE;
		g_ptr_array_remove (config->locations, g);
		return TRUE;
	}
	if (f != NULL && !f->custom) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("Built-in feeds cannot be removed; turn %s off "
		               "instead."), fs_intel_config_label (config, id));
		return FALSE;
	}
	/* The files first: a config that forgot a list whose file is
	 * still there is harmless, the reverse would leave a list in the
	 * config with nothing behind it. */
	if (!store_remove_source (id, error))
		return FALSE;
	if (f != NULL)
		g_ptr_array_remove (config->feeds, f);
	else
		g_ptr_array_remove (config->lists, l);
	return TRUE;
}

gboolean
fs_intel_config_set_dir (FsIntelConfig *config, const gchar *id,
                         FsIntelDir dir, GError **error)
{
	FsIntelFeedConf *f = fs_intel_config_feed (config, id);
	FsIntelListConf *l = fs_intel_config_list (config, id);
	FsIntelLocationConf *g = fs_intel_config_location (config, id);

	g_return_val_if_fail (config != NULL, FALSE);
	if (f == NULL && l == NULL && g == NULL)
		return unknown_source (error, id);
	if (!dir_arg_ok (dir, FALSE, error))
		return FALSE;
	if (f != NULL)
		f->dir = dir;
	else if (l != NULL)
		l->dir = dir;
	else
		g->dir = dir;
	return TRUE;
}

gboolean
fs_intel_config_set_enabled (FsIntelConfig *config, const gchar *id,
                             gboolean enabled, GError **error)
{
	FsIntelFeedConf *f = fs_intel_config_feed (config, id);
	FsIntelListConf *l = fs_intel_config_list (config, id);
	FsIntelLocationConf *g = fs_intel_config_location (config, id);

	g_return_val_if_fail (config != NULL, FALSE);
	if (f == NULL && l == NULL && g == NULL)
		return unknown_source (error, id);
	if (g != NULL) {
		/* Never a way around the database's consent [S14.1]. */
		if (enabled && config->geo_accepted_at <= 0) {
			g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_CONSENT,
			             _("Turning on %s needs the location database's "
			               "terms accepted first."), g->name);
			return FALSE;
		}
		g->enabled = enabled;
		return TRUE;
	}
	if (f != NULL) {
		/* Never a way around the consent [S14.1]. */
		if (enabled)
			return fs_intel_config_enable_feed (config, id, 0, FALSE,
			                                    error);
		f->enabled = FALSE;
	} else
		l->enabled = enabled;
	return TRUE;
}

/* ---- consent ------------------------------------------------------- */

gchar *
fs_intel_consent_text (const FsIntelConfig *config, const gchar *id)
{
	FsIntelFeedConf *f = fs_intel_config_feed (config, id);
	const FsFeedInfo *fi;
	GString *out;
	gchar *host, *often;
	guint hours;

	if (f == NULL)
		return NULL;
	fi = f->custom ? NULL : fs_feed_catalog_find (id);
	if (!f->custom && fi == NULL)
		return NULL;
	host = fi != NULL ? g_strdup (fi->host) : host_of (f->url, FALSE);
	hours = fi != NULL ? fi->interval_hours : CUSTOM_INTERVAL_H;
	if (hours == 24)
		often = g_strdup (_("once a day"));
	else
		often = g_strdup_printf (_("every %u hours"), hours);

	out = g_string_new (NULL);
	g_string_append_printf (out,
		_("Turning on %s makes StockFW download it from %s %s."),
		fs_intel_config_label (config, id), host ? host : "?", often);
	g_string_append (out, "\n\n");
	g_string_append_printf (out,
		_("Each download shows %s this computer's public IP address "
		  "and that it runs \"StockFW/%s\". Nothing else is sent."),
		host ? host : "?", FS_VERSION);
	g_string_append (out, "\n\n");
	if (fi != NULL) {
		if (fi->license != NULL)
			g_string_append_printf (out,
				_("Licence: %s. Terms of use: %s"),
				fi->license, fi->terms_url);
		else
			g_string_append_printf (out,
				_("See the provider's terms of use: %s"),
				fi->terms_url);
		g_string_append_printf (out, _("\nAbout this list: %s"),
		                        fi->info_url);
		if (fi->noncommercial) {
			g_string_append (out, "\n\n");
			g_string_append (out,
				_("Its terms do not allow commercial use: do not "
				  "use it on a business computer without the "
				  "provider's permission."));
		}
	} else {
		gchar *shown = fs_feed_url_redacted (f->url);

		g_string_append_printf (out,
			_("You entered this address yourself (%s); its terms "
			  "are the provider's."), shown);
		g_free (shown);
	}
	g_string_append (out, "\n\n");
	g_string_append (out,
		_("Blocklists contain mistakes. If a list blocks something you "
		  "need, add an exception for that address: put it on the allow "
		  "list on the Threat Intel page" FS_INTEL_EXCEPT_CLI "."));
	g_free (often);
	g_free (host);
	return g_string_free (out, FALSE);
}

/* ---- Round 2: the location database's switch and rules (13.2, 13.3) */

/* The host the database is downloaded from, for consent and for
 * keeping it reachable. */
#define GEO_HOST "location.ipfire.org"
#define GEO_TERMS_URL "https://location.ipfire.org/"
/* The database is due once a day. */
#define GEO_INTERVAL_S (24 * 3600)

gboolean
fs_intel_geo_supported (void)
{
#ifdef __linux__
	return TRUE;
#else
	return FALSE;
#endif
}

FsIntelSourceKind
fs_intel_source_kind (const gchar *id)
{
	if (!fs_intel_id_is_valid (id))
		return FS_INTEL_KIND_UNKNOWN;
	if (g_str_has_prefix (id, "custom-"))
		return FS_INTEL_KIND_CUSTOM;
	if (g_str_has_prefix (id, "local-"))
		return FS_INTEL_KIND_LIST;
	if (g_str_has_prefix (id, "country-"))
		return FS_INTEL_KIND_COUNTRY;
	if (g_str_has_prefix (id, "asn-"))
		return FS_INTEL_KIND_ASN;
	if (fs_feed_catalog_find (id) != NULL)
		return FS_INTEL_KIND_FEED;
	return FS_INTEL_KIND_UNKNOWN;
}

/* The location database is in use: on, its terms accepted, and the
 * master switch on. */
static gboolean
geo_usable (const FsIntelConfig *config)
{
	return config->enabled && config->geo_enabled &&
	       config->geo_accepted_at > 0 && fs_intel_geo_supported ();
}

gboolean
fs_intel_config_enable_geo (FsIntelConfig *config, gboolean accept_terms,
                            GError **error)
{
	g_return_val_if_fail (config != NULL, FALSE);
	if (!fs_intel_geo_supported ()) {
		g_set_error_literal (error, FS_INTEL_ERROR,
		                     FS_INTEL_ERR_UNSUPPORTED,
		                     fs_intel_geo_unsupported_text ());
		return FALSE;
	}
	if (config->geo_accepted_at <= 0 && !accept_terms) {
		g_set_error_literal (error, FS_INTEL_ERROR, FS_INTEL_ERR_CONSENT,
		                     _("Turning on the location database needs its "
		                       "terms accepted first."));
		return FALSE;
	}
	if (config->geo_accepted_at <= 0)
		config->geo_accepted_at = g_get_real_time () / G_USEC_PER_SEC;
	config->geo_enabled = TRUE;
	return TRUE;
}

void
fs_intel_config_disable_geo (FsIntelConfig *config)
{
	g_return_if_fail (config != NULL);
	config->geo_enabled = FALSE;
}

gboolean
fs_intel_config_add_location (FsIntelConfig *config, const gchar *name,
                              FsIntelLocationKind kind,
                              const gchar *const *values, FsIntelDir dir,
                              gchar **id_out, GError **error)
{
	FsIntelLocationConf *l;
	gchar **codes = NULL, *why = NULL, *id;
	GArray *asns = NULL;

	g_return_val_if_fail (config != NULL, FALSE);
	if (id_out != NULL)
		*id_out = NULL;
	if (!fs_intel_geo_supported ()) {
		g_set_error_literal (error, FS_INTEL_ERROR,
		                     FS_INTEL_ERR_UNSUPPORTED,
		                     fs_intel_geo_unsupported_text ());
		return FALSE;
	}
	if (config->geo_accepted_at <= 0) {
		g_set_error_literal (error, FS_INTEL_ERROR, FS_INTEL_ERR_CONSENT,
		                     _("A location rule needs the location "
		                       "database's terms accepted first."));
		return FALSE;
	}
	if (kind != FS_INTEL_LOCATION_COUNTRY && kind != FS_INTEL_LOCATION_ASN) {
		g_set_error_literal (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		                     _("A location rule holds countries or AS "
		                       "numbers."));
		return FALSE;
	}
	if (!name_is_acceptable (name)) {
		g_set_error_literal (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		                     _("A rule needs a name of 1 to 128 "
		                       "characters."));
		return FALSE;
	}
	if (!dir_arg_ok (dir, FALSE, error))
		return FALSE;
	if (!location_values (kind, values, &codes, &asns, &why)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("Not a location rule: %s."), why);
		g_free (why);
		return FALSE;
	}
	id = slug_id (kind == FS_INTEL_LOCATION_COUNTRY ? "country-" : "asn-",
	              name);
	if (fs_intel_config_location (config, id) != NULL) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("A rule called \"%s\" already exists."), name);
		g_free (id);
		g_strfreev (codes);
		if (asns != NULL)
			g_array_unref (asns);
		return FALSE;
	}
	l = g_new0 (FsIntelLocationConf, 1);
	l->id = id;
	l->name = g_strdup (name);
	l->kind = kind;
	l->countries = codes;
	l->asns = asns;
	l->dir = dir;
	l->enabled = TRUE;
	g_ptr_array_add (config->locations, l);
	if (id_out != NULL)
		*id_out = g_strdup (id);
	return TRUE;
}

gboolean
fs_intel_config_set_location_values (FsIntelConfig *config, const gchar *id,
                                     const gchar *const *values,
                                     GError **error)
{
	FsIntelLocationConf *l = fs_intel_config_location (config, id);
	gchar **codes = NULL, *why = NULL;
	GArray *asns = NULL;

	g_return_val_if_fail (config != NULL, FALSE);
	if (l == NULL)
		return unknown_source (error, id);
	if (!location_values (l->kind, values, &codes, &asns, &why)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("Not a location rule: %s."), why);
		g_free (why);
		return FALSE;
	}
	g_strfreev (l->countries);
	if (l->asns != NULL)
		g_array_unref (l->asns);
	l->countries = codes;
	l->asns = asns;
	return TRUE;
}

gchar *
fs_intel_geo_attribution (void)
{
	return g_strdup_printf (
		_("Location data: IPFire location database (%s), licensed "
		  "CC BY-SA 4.0, as IPFire has confirmed: credit IPFire and "
		  "share any changed copy under the same licence."),
		GEO_TERMS_URL);
}

gchar *
fs_intel_geo_consent_text (const FsIntelConfig *config)
{
	GString *out = g_string_new (NULL);
	gchar *attribution = fs_intel_geo_attribution ();

	(void) config;
	g_string_append_printf (out,
		_("Turning on the location database makes StockFW download it "
		  "from %s once a day (about 6 MB)."), GEO_HOST);
	g_string_append (out, "\n\n");
	g_string_append_printf (out,
		_("Each download shows %s this computer's public IP address and "
		  "that it runs \"StockFW/%s\". Nothing else is sent. The file "
		  "is signed by IPFire; StockFW refuses any copy whose signature "
		  "does not verify, and never goes back to an older copy."),
		GEO_HOST, FS_VERSION);
	g_string_append (out, "\n\n");
	g_string_append (out, attribution);
	g_string_append_printf (out, _(" Terms: %s"), GEO_TERMS_URL);
	g_string_append (out, "\n\n");
	g_string_append (out,
		_("A country here is where an address range is registered, not "
		  "where a computer is. Some networks are anycast: the same "
		  "addresses answer from many places, so a country or network "
		  "rule can also block services elsewhere. StockFW keeps them in "
		  "the rule and tells you how many there are."));
	g_string_append (out, "\n\n");
	g_string_append (out,
		_("If a rule blocks something you need, add an exception for that "
		  "address; exceptions always win."));
	g_free (attribution);
	return g_string_free (out, FALSE);
}

/* ============================================================== state */

void
fs_intel_source_state_free (FsIntelSourceState *s)
{
	if (s == NULL)
		return;
	g_free (s->id);
	g_free (s->sha256);
	g_free (s->last_error);
	g_free (s->refused);
	g_free (s);
}

static gboolean
num_u64 (GKeyFile *kf, const gchar *key, guint64 max, guint64 *out)
{
	gchar *raw = kf_raw (kf, "state", key);
	gboolean ok = TRUE;

	if (raw != NULL) {
		ok = g_ascii_string_to_unsigned (raw, 10, 0, max, out, NULL);
		g_free (raw);
	}
	return ok;
}

static gboolean
num_time (GKeyFile *kf, const gchar *key, gint64 *out)
{
	guint64 v = 0;

	if (!num_u64 (kf, key, G_MAXINT64, &v))
		return FALSE;
	*out = (gint64) v;
	return TRUE;
}

static gboolean
num_uint (GKeyFile *kf, const gchar *key, guint *out)
{
	guint64 v = *out;

	if (!num_u64 (kf, key, G_MAXUINT, &v))
		return FALSE;
	*out = (guint) v;
	return TRUE;
}

/* A one-line text value: no line breaks, at most 1 KiB. */
static gboolean
text_value (GKeyFile *kf, const gchar *key, gchar **out)
{
	gchar *v = NULL;

	if (!kf_string (kf, "state", key, &v))
		return FALSE;   /* there, but undecodable: damaged */
	if (v == NULL)
		return TRUE;
	if (!g_utf8_validate (v, -1, NULL) || strlen (v) > AUDIT_TEXT_MAX ||
	    strpbrk (v, "\r\n") != NULL) {
		g_free (v);
		return FALSE;
	}
	*out = v;
	return TRUE;
}

/* "refused-override": which accept flag lets the refused copy in.
 * Absent is 0 (a state written before the key existed, or a refusal
 * nothing overrides); any other word is damage. */
static gboolean
override_value (GKeyFile *kf, guint *out)
{
	gchar *v = NULL;
	gboolean ok = TRUE;

	*out = 0;
	if (!text_value (kf, "refused-override", &v))
		return FALSE;
	if (v == NULL)
		return TRUE;
	if (strcmp (v, "shrink") == 0)
		*out = FS_INTEL_UPDATE_ACCEPT_SHRINK;
	else if (strcmp (v, "coverage") == 0)
		*out = FS_INTEL_UPDATE_ACCEPT_COVERAGE;
	else
		ok = FALSE;
	g_free (v);
	return ok;
}

/* Parse <id>.state.  NULL when it is damaged in any way; *list_digest
 * receives the digest of the list text it describes (NULL if none). */
static FsIntelSourceState *
state_parse (const gchar *id, const gchar *text, gsize len,
             gchar **list_digest)
{
	GKeyFile *kf = g_key_file_new ();
	FsIntelSourceState *s = g_new0 (FsIntelSourceState, 1);
	gboolean ok;
	gchar *sha = NULL, *ld = NULL;

	s->id = g_strdup (id);
	*list_digest = NULL;
	ok = g_utf8_validate (text, (gssize) len, NULL) &&
	     g_key_file_load_from_data (kf, text, len, G_KEY_FILE_NONE, NULL) &&
	     g_key_file_has_group (kf, "state") &&
	     num_time (kf, "fetched-at", &s->fetched_at) &&
	     num_time (kf, "attempted-at", &s->attempted_at) &&
	     num_time (kf, "content-date", &s->content_date) &&
	     num_uint (kf, "entries", &s->entries) &&
	     num_uint (kf, "count4", &s->count4) &&
	     num_uint (kf, "count6", &s->count6) &&
	     num_u64 (kf, "cover4", G_MAXUINT64, &s->cover4) &&
	     num_u64 (kf, "carried-packets", G_MAXUINT64, &s->carried_packets) &&
	     num_u64 (kf, "carried-bytes", G_MAXUINT64, &s->carried_bytes) &&
	     num_time (kf, "counted-since", &s->counted_since) &&
	     text_value (kf, "last-error", &s->last_error) &&
	     text_value (kf, "refused", &s->refused) &&
	     text_value (kf, "sha256", &sha) &&
	     override_value (kf, &s->refused_override) &&
	     text_value (kf, "list-digest", &ld);

	if (ok && sha != NULL) {
		ok = strlen (sha) == 64 && strspn (sha, "0123456789abcdef") == 64;
		s->sha256 = sha;
		sha = NULL;
	}

	/* History: two lists of the same length, at most FS_FEED_HISTORY. */
	if (ok) {
		gsize ne = 0, nc = 0;
		gchar **he = NULL, **hc = NULL;

		if (!kf_list (kf, "state", "history-entries", &he, &ne) ||
		    !kf_list (kf, "state", "history-cover4", &hc, &nc) ||
		    ne != nc || ne > FS_FEED_HISTORY)
			ok = FALSE;
		for (gsize i = 0; ok && i < ne; i++) {
			guint64 e, c;

			ok = g_ascii_string_to_unsigned (he[i], 10, 0, G_MAXUINT,
			                                 &e, NULL) &&
			     g_ascii_string_to_unsigned (hc[i], 10, 0,
			                                 G_MAXUINT64, &c, NULL);
			s->history.entries[i] = (guint) e;
			s->history.cover4[i] = c;
		}
		s->history.n = (guint) ne;
		g_strfreev (he);
		g_strfreev (hc);
		if (ok) {
			gchar *raw = kf_raw (kf, "state", "history-content-date");
			guint64 v = 0;

			if (raw != NULL)
				ok = g_ascii_string_to_unsigned (raw, 10, 0,
				                                 G_MAXINT64, &v,
				                                 NULL);
			s->history.content_date = (gint64) v;
			g_free (raw);
		}
	}
	g_key_file_free (kf);
	g_free (sha);
	if (!ok) {
		g_free (ld);
		fs_intel_source_state_free (s);
		return NULL;
	}
	*list_digest = ld;
	return s;
}

static gchar *
state_serialize (const FsIntelSourceState *s, const gchar *list_digest,
                 gsize *len)
{
	GKeyFile *kf = g_key_file_new ();
	gchar *data;
	gchar *he[FS_FEED_HISTORY + 1] = { NULL };
	gchar *hc[FS_FEED_HISTORY + 1] = { NULL };
	guint n = MIN (s->history.n, FS_FEED_HISTORY);

#define SET_U64(key, v) do {                                           \
	gchar *t_ = g_strdup_printf ("%" G_GUINT64_FORMAT, (guint64) (v)); \
	g_key_file_set_value (kf, "state", key, t_);                      \
	g_free (t_);                                                       \
} while (0)
	SET_U64 ("fetched-at", MAX (s->fetched_at, 0));
	SET_U64 ("attempted-at", MAX (s->attempted_at, 0));
	SET_U64 ("content-date", MAX (s->content_date, 0));
	SET_U64 ("entries", s->entries);
	SET_U64 ("count4", s->count4);
	SET_U64 ("count6", s->count6);
	SET_U64 ("cover4", s->cover4);
	SET_U64 ("carried-packets", s->carried_packets);
	SET_U64 ("carried-bytes", s->carried_bytes);
	SET_U64 ("counted-since", MAX (s->counted_since, 0));
	SET_U64 ("history-content-date", MAX (s->history.content_date, 0));
#undef SET_U64
	if (s->sha256 != NULL)
		g_key_file_set_string (kf, "state", "sha256", s->sha256);
	if (list_digest != NULL)
		g_key_file_set_string (kf, "state", "list-digest", list_digest);
	if (s->last_error != NULL)
		g_key_file_set_string (kf, "state", "last-error", s->last_error);
	if (s->refused != NULL)
		g_key_file_set_string (kf, "state", "refused", s->refused);
	if (s->refused != NULL && s->refused_override != 0)
		g_key_file_set_string (kf, "state", "refused-override",
			s->refused_override == FS_INTEL_UPDATE_ACCEPT_COVERAGE
			? "coverage" : "shrink");
	for (guint i = 0; i < n; i++) {
		he[i] = g_strdup_printf ("%u", s->history.entries[i]);
		hc[i] = g_strdup_printf ("%" G_GUINT64_FORMAT,
		                         s->history.cover4[i]);
	}
	g_key_file_set_string_list (kf, "state", "history-entries",
	                            (const gchar *const *) he, n);
	g_key_file_set_string_list (kf, "state", "history-cover4",
	                            (const gchar *const *) hc, n);
	for (guint i = 0; i < n; i++) {
		g_free (he[i]);
		g_free (hc[i]);
	}
	data = g_key_file_to_data (kf, len, NULL);
	g_key_file_free (kf);
	return data;
}

/* The state of `id' in an open store.  *damaged is set (and NULL
 * returned) when the file exists but cannot be trusted; NULL with
 * *damaged FALSE means never stored (or unreadable: error set). */
static FsIntelSourceState *
state_read (const Store *store, const gchar *id, gchar **list_digest,
            gboolean *damaged)
{
	gchar *name = g_strconcat (id, ".state", NULL);
	gboolean missing = FALSE;
	gsize len = 0;
	gchar *text = store_read (store, name, STATE_MAX, &len, &missing, NULL);
	FsIntelSourceState *s = NULL;
	gchar *ld = NULL;

	*damaged = FALSE;
	if (text != NULL) {
		s = state_parse (id, text, len, &ld);
		*damaged = (s == NULL);
	} else if (!missing)
		*damaged = TRUE;
	g_free (text);
	g_free (name);
	if (list_digest != NULL)
		*list_digest = ld;
	else
		g_free (ld);
	return s;
}

static gboolean
state_write (const Store *store, const FsIntelSourceState *s,
             const gchar *list_digest, GError **error)
{
	gchar *name = g_strconcat (s->id, ".state", NULL);
	gsize len = 0;
	gchar *data = state_serialize (s, list_digest, &len);
	gboolean ok = store_write (store, name, data, len, error);

	g_free (data);
	g_free (name);
	return ok;
}

FsIntelSourceState *
fs_intel_source_state (const gchar *id)
{
	Store store;
	FsIntelSourceState *s;
	gboolean damaged = FALSE;

	if (!fs_intel_id_is_valid (id) || !store_open (&store, NULL))
		return NULL;
	s = state_read (&store, id, NULL, &damaged);
	store_close (&store);
	return s;
}

/* ---- stored lists ------------------------------------------------- */

static void
tampered (GError **error, const gchar *id, const gchar *why)
{
	g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_TAMPERED,
	             _("The stored copy of %s cannot be trusted (%s); update "
	               "or import it again."), id, why);
}

/* Check a list read back from the store [S2.7, S4.4]: strict syntax
 * (fs_range_set_from_text), the entry count and the coverage caps.
 * The caps are measured exactly as the parser measured them
 * (fs_feed_cover6_64, fs_range_set_addresses4), so a list the parser
 * accepted always loads again: a count of its own that came out one
 * higher for every unaligned IPv6 interval once made an accepted list
 * "tampered" and failed every build.  The span floor of the parser
 * cannot be applied again here: a stored list is normalized, so
 * neighbouring entries that each passed it are merged (two adjacent
 * /10s read back as one /9).  The coverage caps bound what a tampered
 * list can block to what an accepted feed may.  Protected space (which
 * a later version may widen) is taken out quietly rather than called
 * tampering. */
static FsRangeSet *
list_check (const gchar *id, FsRangeSet *set, GError **error)
{
	const gchar *why = NULL;

	fs_range_set_subtract (set, fs_range_protected ());
	if (fs_range_set_count4 (set) + fs_range_set_count6 (set) >
	    LIST_MAX_INTERVALS)
		why = _("too many entries");
	else if (fs_range_set_addresses4 (set) > FS_FEED_MAX_COVER4 ||
	         fs_feed_cover6_64 (set) > FS_FEED_MAX_COVER6_64)
		why = _("it covers too many addresses");
	if (why != NULL) {
		tampered (error, id, why);
		fs_range_set_free (set);
		return NULL;
	}
	return set;
}

/* Read <id>.list.  *digest (nullable) receives the SHA-256 of its text. */
static FsRangeSet *
list_read (const Store *store, const gchar *id, gchar **digest,
           gboolean *missing, GError **error)
{
	gchar *name = g_strconcat (id, ".list", NULL);
	gsize len = 0;
	GError *local = NULL;
	gchar *text = store_read (store, name, LIST_MAX, &len, missing, &local);
	FsRangeSet *set;

	g_free (name);
	if (digest != NULL)
		*digest = NULL;
	if (text == NULL) {
		g_propagate_error (error, local);
		return NULL;
	}
	if (memchr (text, '\0', len) != NULL) {
		g_free (text);
		tampered (error, id, _("it holds a NUL byte"));
		return NULL;
	}
	set = fs_range_set_from_text (text, &local);
	if (set == NULL) {
		gchar *why = error_text (local);

		tampered (error, id, why);
		g_free (why);
		g_clear_error (&local);
		g_free (text);
		return NULL;
	}
	if (digest != NULL)
		*digest = sha256_hex (text, len);
	g_free (text);
	set = list_check (id, set, error);
	if (set == NULL && digest != NULL)
		g_clear_pointer (digest, g_free);
	return set;
}

/* Write <id>.list; returns the digest of the text written. */
static gchar *
list_write (const Store *store, const gchar *id, const FsRangeSet *set,
            GError **error)
{
	gchar *name = g_strconcat (id, ".list", NULL);
	gchar *text = fs_range_set_to_text (set);
	gsize len = strlen (text);
	gchar *digest = NULL;

	if (store_write (store, name, text, len, error))
		digest = sha256_hex (text, len);
	g_free (text);
	g_free (name);
	return digest;
}

FsRangeSet *
fs_intel_source_load (const gchar *id, GError **error)
{
	Store store;
	FsRangeSet *set;

	if (!fs_intel_id_is_valid (id)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("Not a valid list id."));
		return NULL;
	}
	if (!store_open (&store, error))
		return NULL;
	set = list_read (&store, id, NULL, NULL, error);
	store_close (&store);
	return set;
}

/* ---- schedule ------------------------------------------------------ */

/* Update interval of a feed in seconds; 0 for a local list. */
static gint64
source_interval (const FsIntelConfig *config, const gchar *id)
{
	FsIntelFeedConf *f = fs_intel_config_feed (config, id);
	const FsFeedInfo *fi;

	if (f == NULL)
		return 0;
	fi = f->custom ? NULL : fs_feed_catalog_find (id);
	return (gint64) (fi != NULL ? fi->interval_hours : CUSTOM_INTERVAL_H) *
	       3600;
}

static gboolean
is_due (const FsIntelSourceState *s, gint64 interval, gint64 now)
{
	if (interval <= 0)
		return FALSE;
	if (s == NULL || s->fetched_at == 0 || s->attempted_at == 0)
		return TRUE;
	/* The clock went back: start again rather than wait for it. */
	if (s->attempted_at > now + CLOCK_SLACK_S)
		return TRUE;
	return now - s->attempted_at >= interval;
}

static gboolean
is_stale (const FsIntelSourceState *s, gint64 interval, gint64 now)
{
	gint64 base;

	if (interval <= 0 || s == NULL)
		return FALSE;
	base = s->content_date > 0 ? s->content_date : s->fetched_at;
	if (base <= 0)
		return FALSE;
	return now - base > STALE_INTERVALS * interval;
}

gboolean
fs_intel_source_is_due (const FsIntelConfig *config, const gchar *id,
                        gint64 now)
{
	FsIntelSourceState *s = fs_intel_source_state (id);
	gboolean due = is_due (s, source_interval (config, id), now);

	fs_intel_source_state_free (s);
	return due;
}

gint64
fs_intel_source_next_due (const FsIntelConfig *config, const gchar *id,
                          gint64 now)
{
	gint64 interval = source_interval (config, id);
	FsIntelSourceState *s;
	gint64 next;

	if (interval <= 0)
		return -1;
	s = fs_intel_source_state (id);
	/* The rule of is_due: never fetched, or the clock went back, is
	 * due now; otherwise one interval after the last attempt. */
	if (is_due (s, interval, now))
		next = 0;
	else
		next = s->attempted_at + interval;
	fs_intel_source_state_free (s);
	return next;
}

gboolean
fs_intel_source_is_stale (const FsIntelConfig *config, const gchar *id,
                          gint64 now)
{
	FsIntelSourceState *s = fs_intel_source_state (id);
	gboolean stale = is_stale (s, source_interval (config, id), now);

	fs_intel_source_state_free (s);
	return stale;
}

/* ============================================================= import */

/* A name as the user means it: compatibility-normalized, case-folded,
 * every run of white space one space, trimmed. */
static gchar *
name_key (const gchar *name)
{
	gchar *norm = g_utf8_normalize (name, -1, G_NORMALIZE_ALL);
	gchar *fold = g_utf8_casefold (norm != NULL ? norm : name, -1);
	GString *out = g_string_new (NULL);

	for (const gchar *p = fold; *p; p = g_utf8_next_char (p)) {
		gunichar c = g_utf8_get_char (p);

		if (g_unichar_isspace (c)) {
			if (out->len > 0 && out->str[out->len - 1] != ' ')
				g_string_append_c (out, ' ');
		} else
			g_string_append_unichar (out, c);
	}
	if (out->len > 0 && out->str[out->len - 1] == ' ')
		g_string_truncate (out, out->len - 1);
	g_free (norm);
	g_free (fold);
	return g_string_free (out, FALSE);
}

/* Whether two list names are the same name, in any case or spacing. */
static gboolean
same_name (const gchar *a, const gchar *b)
{
	gchar *ka = name_key (a), *kb = name_key (b);
	gboolean same = strcmp (ka, kb) == 0;

	g_free (ka);
	g_free (kb);
	return same;
}

static gchar *
read_user_file (const gchar *path, gsize *len, GError **error)
{
#ifdef __linux__
	int fd = open (path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
	struct stat st;
	GByteArray *buf;

	if (fd < 0) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("Cannot open %s: %s."), path, g_strerror (errno));
		return NULL;
	}
	if (fstat (fd, &st) != 0 || !S_ISREG (st.st_mode)) {
		close (fd);
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("%s is not a regular file."), path);
		return NULL;
	}
	buf = g_byte_array_new ();
	for (;;) {
		guint8 chunk[64 * 1024];
		ssize_t got = read (fd, chunk, sizeof chunk);

		if (got < 0 && errno == EINTR)
			continue;
		if (got <= 0) {
			if (got < 0) {
				g_set_error (error, FS_INTEL_ERROR,
				             FS_INTEL_ERR_INVALID,
				             _("Cannot read %s: %s."), path,
				             g_strerror (errno));
				close (fd);
				g_byte_array_free (buf, TRUE);
				return NULL;
			}
			break;
		}
		if (buf->len + (gsize) got > FS_FEED_MAX_BYTES) {
			close (fd);
			g_byte_array_free (buf, TRUE);
			g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
			             _("%s is larger than 32 MiB."), path);
			return NULL;
		}
		g_byte_array_append (buf, chunk, (guint) got);
	}
	close (fd);
	*len = buf->len;
	g_byte_array_append (buf, (const guint8 *) "", 1);
	return (gchar *) g_byte_array_free (buf, FALSE);
#elif defined G_OS_WIN32
	return fs_winstore_read_user_file (path, FS_FEED_MAX_BYTES, len, error);
#else
	g_set_error_literal (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNSUPPORTED,
	                     unsupported_text ());
	return NULL;
#endif
}

/* [ fs_intel_exceptions_from_text ]
 * Each line cut at its first '#' (the Threat Intel page's editor does
 * the same, ui/fs-intelview.c strip_comments), then the strict reader.
 * The lines stay where they were, so an error names the line the user
 * typed. */
FsRangeSet *
fs_intel_exceptions_from_text (const gchar *text, GError **error)
{
	gchar **lines = g_strsplit (text != NULL ? text : "", "\n", -1);
	gchar *bare;
	FsRangeSet *set;

	for (guint i = 0; lines[i] != NULL; i++) {
		gchar *hash = strchr (lines[i], '#');

		if (hash != NULL)
			*hash = '\0';
	}
	bare = g_strjoinv ("\n", lines);
	g_strfreev (lines);
	set = fs_range_set_from_text (bare, error);
	g_free (bare);
	return set;
}

/* [ import_common ]
 * The body of both imports: the file at `path' (read here), or, with
 * path NULL, the `text' of `text_len' bytes a caller read itself.
 * `what' names the input in the messages and the audit line. */
static gboolean
import_common (FsIntelConfig *config, const gchar *path,
               const gchar *text, gsize text_len, const gchar *what,
               const gchar *name, FsIntelDir dir,
               FsFeedParseStats *stats, gchar **id_out, GError **error)
{
	FsFeedParseStats st = { 0 };
	FsIntelSourceState *s = NULL, *old;
	FsIntelListConf *l;
	FsRangeSet *set = NULL;
	Store store = STORE_INIT;
	GError *local = NULL;
	gchar *data = NULL, *id = NULL, *digest = NULL;
	gboolean damaged = FALSE, ok = FALSE;
	gsize len = 0;
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;

	g_return_val_if_fail (config != NULL && what != NULL, FALSE);
	g_return_val_if_fail (path != NULL || text != NULL, FALSE);
	if (id_out != NULL)
		*id_out = NULL;
	if (!name_is_acceptable (name)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("A list needs a name of 1 to 128 characters."));
		return FALSE;
	}
	if (!dir_arg_ok (dir, TRUE, error))
		return FALSE;
	/* The id is a slug of the name, so different names can share it
	 * ("Office VPN" and "office-vpn", or two long names that differ
	 * after 34 characters).  Only the same name replaces a list;
	 * another one that would take its id is refused before anything
	 * is written, or it would silently overwrite that list. */
	id = slug_id ("local-", name);
	l = fs_intel_config_list (config, id);
	if (l != NULL && !same_name (l->name, name)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("The list \"%s\" already uses the id %s; choose "
		               "another name, or remove that list first."),
		             l->name, id);
		g_free (id);
		return FALSE;
	}
	/* dir 0: the list imported again (the same name, in any case or
	 * spacing) keeps its direction; a new list blocks both ways. */
	if (dir == 0)
		dir = l != NULL ? l->dir : FS_INTEL_DIR_BOTH;
	if (!store_open (&store, error)) {
		g_free (id);
		return FALSE;
	}
	if (path != NULL) {
		data = read_user_file (path, &len, error);
	} else if (text_len > FS_FEED_MAX_BYTES) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("%s is larger than 32 MiB."), what);
	} else {
		data = g_malloc (text_len + 1);
		memcpy (data, text, text_len);
		data[text_len] = '\0';
		len = text_len;
	}
	if (data == NULL)
		goto out;
	set = fs_feed_parse_csv (data, len, &st, &local);
	if (stats != NULL)
		*stats = st;
	if (set == NULL) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("%s was not imported: %s"), what,
		             local ? local->message : "");
		g_clear_error (&local);
		goto out;
	}
	if (fs_range_set_is_empty (set)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("%s holds no address that could be blocked."),
		             what);
		goto out;
	}
	digest = list_write (&store, id, set, error);
	if (digest == NULL)
		goto out;

	s = g_new0 (FsIntelSourceState, 1);
	s->id = g_strdup (id);
	old = state_read (&store, id, NULL, &damaged);
	if (old != NULL) {
		/* The counters belong to the list, whatever its contents. */
		s->carried_packets = old->carried_packets;
		s->carried_bytes = old->carried_bytes;
		s->counted_since = old->counted_since;
		s->history = old->history;
		fs_intel_source_state_free (old);
	}
	s->fetched_at = s->attempted_at = now;
	s->sha256 = sha256_hex (data, len);
	s->entries = st.entries;
	s->count4 = st.v4;
	s->count6 = st.v6;
	s->cover4 = st.cover4;
	fs_feed_history_push (&s->history, &st);
	if (!state_write (&store, s, digest, error))
		goto out;

	l = fs_intel_config_list (config, id);
	if (l == NULL) {
		l = g_new0 (FsIntelListConf, 1);
		l->id = g_strdup (id);
		g_ptr_array_add (config->lists, l);
	}
	g_free (l->name);
	l->name = g_strdup (name);
	l->enabled = TRUE;
	l->dir = dir;
	l->imported_at = now;
	if (id_out != NULL)
		*id_out = g_strdup (id);
	ok = TRUE;
	{
		gchar *detail = g_strdup_printf ("%s: %u entries from %s", id,
		                                 st.entries, what);
		audit ("intel-import", detail);
		g_free (detail);
	}
out:
	store_close (&store);
	fs_intel_source_state_free (s);
	fs_range_set_free (set);
	g_free (data);
	g_free (id);
	g_free (digest);
	return ok;
}

gboolean
fs_intel_import_list (FsIntelConfig *config, const gchar *path,
                      const gchar *name, FsIntelDir dir,
                      FsFeedParseStats *stats, gchar **id_out,
                      GError **error)
{
	g_return_val_if_fail (path != NULL, FALSE);
	return import_common (config, path, NULL, 0, path, name, dir, stats,
	                      id_out, error);
}

gboolean
fs_intel_import_text (FsIntelConfig *config, const gchar *text, gsize len,
                      const gchar *what, const gchar *name, FsIntelDir dir,
                      FsFeedParseStats *stats, gchar **id_out,
                      GError **error)
{
	g_return_val_if_fail (text != NULL, FALSE);
	return import_common (config, NULL, text, len,
	                      what != NULL ? what : "the text", name, dir,
	                      stats, id_out, error);
}

FsIntelListConf *
fs_intel_config_list_by_name (const FsIntelConfig *config,
                              const gchar *name)
{
	if (config == NULL || name == NULL)
		return NULL;
	for (guint i = 0; i < config->lists->len; i++) {
		FsIntelListConf *l = g_ptr_array_index (config->lists, i);

		if (l->name != NULL && same_name (l->name, name))
			return l;
	}
	return NULL;
}

/* ============================================================ updates */

static FsIntelFetcher fetcher_fn;
static gpointer fetcher_data;
G_LOCK_DEFINE_STATIC (fetcher);

void
fs_intel_set_fetcher (FsIntelFetcher fetcher, gpointer user_data)
{
	G_LOCK (fetcher);
	fetcher_fn = fetcher;
	fetcher_data = user_data;
	G_UNLOCK (fetcher);
}

static GBytes *
default_fetcher (const gchar *url, const gchar *proxy, gpointer user_data,
                 GError **error)
{
	FsFetchRequest req = { 0 };

	req.url = url;
	req.max_bytes = FS_FEED_MAX_BYTES;
	req.timeout_s = FETCH_TIMEOUT_S;
	req.proxy = proxy;
	return fs_fetch (&req, error);
}

static GBytes *
fetch (const gchar *url, const gchar *proxy, GError **error)
{
	FsIntelFetcher fn;
	gpointer data;

	G_LOCK (fetcher);
	fn = fetcher_fn != NULL ? fetcher_fn : default_fetcher;
	data = fetcher_data;
	G_UNLOCK (fetcher);
	return fn (url, proxy, data, error);
}

/* ---- the location database in the store (design 13.4, 13.8) ------- */

/* The copy in use, opened once (verified and checked) and shared until
 * location.db changes: verifying 55 MB for every lookup would make a
 * busy event list crawl.  An FsGeodb is read-only, so one copy serves
 * every thread. */
typedef struct
{
	gint     ref;
	FsGeodb *db;
	guint64  dev, ino;
	gint64   size, mtime_ns;
} GeoHandle;

#ifdef __linux__
G_LOCK_DEFINE_STATIC (geo_cache);
static GeoHandle *geo_cached;
#endif

static void
geo_handle_unref (GeoHandle *h)
{
	if (h != NULL && g_atomic_int_dec_and_test (&h->ref)) {
		fs_geodb_close (h->db);
		g_free (h);
	}
}

#ifdef __linux__
static void
geo_untrusted (GError **error, const gchar *why)
{
	g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_TAMPERED,
	             _("The location database in use cannot be trusted (%s); "
	               "update it again."), why);
}
#endif

/* The copy in use.  NULL with *missing set (and no error) when there is
 * none; NULL with an error when it is there but does not open: a copy
 * that no longer verifies or checks is FS_INTEL_ERR_TAMPERED. */
static GeoHandle *
geo_acquire (const Store *store, gboolean *missing, GError **error)
{
#ifdef __linux__
	struct stat st;
	GeoHandle *h = NULL, *old;
	GError *local = NULL;
	gchar *dir, *why;
	FsGeodb *db;
	gint64 mtime;

	*missing = FALSE;
	if (fstatat (store->fd, FS_GEODB_FILE, &st, AT_SYMLINK_NOFOLLOW) != 0) {
		if (errno == ENOENT) {
			*missing = TRUE;
			return NULL;
		}
		store_error (error, FS_GEODB_FILE, g_strerror (errno));
		return NULL;
	}
	mtime = (gint64) st.st_mtim.tv_sec * 1000000000 + st.st_mtim.tv_nsec;
	G_LOCK (geo_cache);
	if (geo_cached != NULL && S_ISREG (st.st_mode) &&
	    geo_cached->dev == (guint64) st.st_dev &&
	    geo_cached->ino == (guint64) st.st_ino &&
	    geo_cached->size == (gint64) st.st_size &&
	    geo_cached->mtime_ns == mtime) {
		h = geo_cached;
		g_atomic_int_inc (&h->ref);
	}
	G_UNLOCK (geo_cache);
	if (h != NULL)
		return h;

	dir = fs_intel_dir (error);
	if (dir == NULL)
		return NULL;
	db = fs_geodb_open_store (dir, &local);
	g_free (dir);
	if (db == NULL) {
		why = error_text (local);
		geo_untrusted (error, why);
		g_free (why);
		g_clear_error (&local);
		return NULL;
	}
	h = g_new0 (GeoHandle, 1);
	h->ref = 2;   /* the cache's and the caller's */
	h->db = db;
	h->dev = (guint64) st.st_dev;
	h->ino = (guint64) st.st_ino;
	h->size = (gint64) st.st_size;
	h->mtime_ns = mtime;
	G_LOCK (geo_cache);
	old = geo_cached;
	geo_cached = h;
	G_UNLOCK (geo_cache);
	geo_handle_unref (old);
	return h;
#else
	(void) store;
	*missing = FALSE;
	g_set_error_literal (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNSUPPORTED,
	                     fs_intel_geo_unsupported_text ());
	return NULL;
#endif
}

/* geodb.state: the update's own record (13.4). */
#define GEO_STATE_NAME "geodb.state"

typedef struct
{
	gint64 attempted_at, fetched_at, created_at;
	gchar *last_error, *refused;
} GeoState;

static void
geo_state_clear (GeoState *g)
{
	g_free (g->last_error);
	g_free (g->refused);
	memset (g, 0, sizeof *g);
}

/* A missing or damaged record reads as "never attempted". */
static void
geo_state_read (const Store *store, GeoState *g)
{
	gsize len = 0;
	gchar *text = store_read (store, GEO_STATE_NAME, STATE_MAX, &len, NULL,
	                          NULL);
	GKeyFile *kf = g_key_file_new ();

	memset (g, 0, sizeof *g);
	if (text != NULL && g_utf8_validate (text, (gssize) len, NULL) &&
	    g_key_file_load_from_data (kf, text, len, G_KEY_FILE_NONE, NULL) &&
	    g_key_file_has_group (kf, "geodb")) {
		static const gchar *const keys[3] = {
			"attempted-at", "fetched-at", "created-at"
		};
		gint64 *slots[3] = { &g->attempted_at, &g->fetched_at,
		                     &g->created_at };
		gboolean ok = TRUE;

		for (guint i = 0; i < 3 && ok; i++) {
			gchar *raw = kf_raw (kf, "geodb", keys[i]);
			guint64 v = 0;

			if (raw != NULL)
				ok = g_ascii_string_to_unsigned (raw, 10, 0, G_MAXINT64,
				                                 &v, NULL);
			*slots[i] = (gint64) v;
			g_free (raw);
		}
		if (ok) {
			kf_string (kf, "geodb", "last-error", &g->last_error);
			kf_string (kf, "geodb", "refused", &g->refused);
		} else
			geo_state_clear (g);
	}
	g_key_file_free (kf);
	g_free (text);
}

static gboolean
geo_state_write (const Store *store, const GeoState *g, GError **error)
{
	GKeyFile *kf = g_key_file_new ();
	gchar *data;
	gsize len = 0;
	gboolean ok;

	g_key_file_set_int64 (kf, "geodb", "attempted-at", MAX (g->attempted_at, 0));
	g_key_file_set_int64 (kf, "geodb", "fetched-at", MAX (g->fetched_at, 0));
	g_key_file_set_int64 (kf, "geodb", "created-at", MAX (g->created_at, 0));
	if (g->last_error != NULL)
		g_key_file_set_string (kf, "geodb", "last-error", g->last_error);
	if (g->refused != NULL)
		g_key_file_set_string (kf, "geodb", "refused", g->refused);
	data = g_key_file_to_data (kf, &len, NULL);
	g_key_file_free (kf);
	ok = store_write (store, GEO_STATE_NAME, data, len, error);
	g_free (data);
	return ok;
}

/* "2026-11-02" */
static gchar *
day_text (gint64 t)
{
	GDateTime *dt = g_date_time_new_from_unix_utc (t);
	gchar *out = dt != NULL ? g_date_time_format (dt, "%Y-%m-%d")
	                        : g_strdup ("?");

	if (dt != NULL)
		g_date_time_unref (dt);
	return out;
}

void
fs_intel_update_result_free (FsIntelUpdateResult *result)
{
	if (result == NULL)
		return;
	g_free (result->id);
	g_free (result->message);
	g_free (result);
}

static FsIntelUpdateResult *
result_new (const gchar *id, FsIntelUpdateOutcome outcome, guint entries,
            gchar *message)
{
	FsIntelUpdateResult *r = g_new0 (FsIntelUpdateResult, 1);

	r->id = g_strdup (id);
	r->outcome = outcome;
	r->entries = entries;
	r->message = message;
	return r;
}

static const gchar *
outcome_word (FsIntelUpdateOutcome o)
{
	switch (o) {
	case FS_INTEL_UPDATED:       return "updated";
	case FS_INTEL_UNCHANGED:     return "unchanged";
	case FS_INTEL_NOT_DUE:       return "not-due";
	case FS_INTEL_NEEDS_CONSENT: return "needs-consent";
	case FS_INTEL_REFUSED:       return "refused";
	case FS_INTEL_FAILED:        return "failed";
	default:                     return "?";
	}
}

/* One feed, already known enabled, consented and due.  The previous
 * copy is never removed: a failure or a refusal only updates the
 * state. */
static FsIntelUpdateResult *
update_one (const Store *store, const FsIntelConfig *config,
            const FsIntelFeedConf *f, guint flags, gint64 now)
{
	const FsFeedInfo *fi = f->custom ? NULL : fs_feed_catalog_find (f->id);
	const gchar *url = fi != NULL ? fi->url : f->url;
	FsFeedFormat fmt = fi != NULL ? fi->format : f->format;
	FsIntelSourceState *s;
	FsIntelUpdateOutcome outcome;
	FsFeedParseStats st = { 0 };
	FsRangeSet *set = NULL;
	GBytes *body = NULL;
	GError *local = NULL;
	gchar *list_digest = NULL, *message = NULL, *sha = NULL, *why = NULL;
	gboolean damaged = FALSE;
	guint entries, override = 0;
	EngineLock lock = ENGINE_LOCK_INIT;

	s = state_read (store, f->id, &list_digest, &damaged);
	if (s == NULL) {
		s = g_new0 (FsIntelSourceState, 1);
		s->id = g_strdup (f->id);
	}
	s->attempted_at = now;

	/* The design's URL rule, also for the catalog: fs-fetch's own
	 * check is looser. */
	if (!fs_feed_url_is_acceptable (url, &local)) {
		outcome = FS_INTEL_FAILED;
		why = error_text (local);
		message = g_strdup_printf (_("Not downloaded: %s"), why);
		goto record;
	}

	body = fetch (url, config->proxy, &local);
	if (body == NULL) {
		outcome = FS_INTEL_FAILED;
		why = error_text (local);
		message = g_strdup_printf (_("Download failed: %s"), why);
		goto record;
	}

	{
		gsize len = 0;
		const gchar *data = g_bytes_get_data (body, &len);
		gboolean stored_ok;

		sha = sha256_hex (data != NULL ? data : "", len);
		/* Unchanged only when the stored list is the one this state
		 * describes: after a crash between writing the list and the
		 * state, the copy is stored again. */
		if (s->sha256 != NULL && strcmp (s->sha256, sha) == 0 &&
		    list_digest != NULL) {
			gchar *have = NULL;
			FsRangeSet *cur = list_read (store, f->id, &have, NULL, NULL);

			stored_ok = cur != NULL && have != NULL &&
			            strcmp (have, list_digest) == 0;
			fs_range_set_free (cur);
			g_free (have);
			if (stored_ok) {
				outcome = FS_INTEL_UNCHANGED;
				s->fetched_at = now;
				g_clear_pointer (&s->last_error, g_free);
				g_clear_pointer (&s->refused, g_free);
				message = g_strdup (_("Unchanged since the last "
				                      "download."));
				goto record;
			}
		}

		set = fs_feed_parse (data != NULL ? data : "", len, fmt, &st,
		                     &local);
	}
	if (set == NULL) {
		outcome = FS_INTEL_REFUSED;
		why = error_text (local);
		message = g_strdup_printf (_("Refused: %s"), why);
		goto record;
	}
	/* fs_feed_judge has no clock: a copy dated ahead of it would make
	 * every honest copy after it a rollback. */
	if (st.content_date > now + FUTURE_SLACK_S) {
		outcome = FS_INTEL_REFUSED;
		why = g_strdup (_("the list is dated in the future; check this "
		                  "computer's clock"));
		message = g_strdup_printf (_("Refused: %s"), why);
		goto record;
	}
	{
		FsFeedHistory history = s->history;
		guint jflags = 0;
		gchar *jwhy = NULL;

		/* A stored date ahead of the clock is forgotten for the same
		 * reason (the clock was put back, or the state was edited). */
		if (history.content_date > now + FUTURE_SLACK_S)
			history.content_date = 0;
		if (damaged)
			history.n = 0;
		if (flags & FS_INTEL_UPDATE_ACCEPT_SHRINK)
			jflags |= FS_FEED_ACCEPT_SHRINK;
		if (flags & FS_INTEL_UPDATE_ACCEPT_COVERAGE)
			jflags |= FS_FEED_ACCEPT_COVERAGE;
		FsFeedVerdict verdict = fs_feed_judge (&st, &history, jflags,
		                                       &jwhy);

		if (verdict != FS_FEED_VERDICT_OK) {
			/* The page offers the one flag that lets this copy
			 * in ("Accept smaller list"). */
			override = verdict == FS_FEED_VERDICT_GREW
			           ? FS_INTEL_UPDATE_ACCEPT_COVERAGE
			           : FS_INTEL_UPDATE_ACCEPT_SHRINK;
			outcome = FS_INTEL_REFUSED;
			why = first_line (jwhy, AUDIT_TEXT_MAX);
			g_free (jwhy);
			message = g_strdup_printf (_("Refused: %s"), why);
			goto record;
		}
		g_free (jwhy);
		s->history = history;
	}

	/* Accepted: the list first, then the state that describes it. */
	g_free (list_digest);
	list_digest = list_write (store, f->id, set, &local);
	if (list_digest == NULL) {
		outcome = FS_INTEL_FAILED;
		why = error_text (local);
		message = g_strdup_printf (_("Could not store the list: %s"), why);
		g_clear_pointer (&s->sha256, g_free);
		goto record;
	}
	fs_feed_history_push (&s->history, &st);
	s->fetched_at = now;
	s->content_date = st.content_date;
	g_free (s->sha256);
	s->sha256 = g_strdup (sha);
	s->entries = st.entries;
	s->count4 = st.v4;
	s->count6 = st.v6;
	s->cover4 = st.cover4;
	g_clear_pointer (&s->last_error, g_free);
	g_clear_pointer (&s->refused, g_free);
	outcome = FS_INTEL_UPDATED;
	{
		gchar *n = grouped (st.entries);

		message = g_strdup_printf (_("Updated: %s entries."), n);
		g_free (n);
	}

record:
	if (outcome == FS_INTEL_FAILED) {
		g_free (s->last_error);
		s->last_error = g_strdup (why);
	} else if (outcome == FS_INTEL_REFUSED) {
		g_free (s->refused);
		s->refused = g_strdup (why);
		s->refused_override = override;
		g_clear_pointer (&s->last_error, g_free);
	}
	g_clear_error (&local);
	/* The download can take minutes, and an apply or a Stop in the
	 * meantime carries the counters into this same file: take its
	 * carried totals as they are now, under the engine lock, so this
	 * write never puts back the older ones. */
	engine_lock (store, &lock);
	{
		gboolean dmg = FALSE;
		FsIntelSourceState *now_s = state_read (store, f->id, NULL, &dmg);

		if (now_s != NULL) {
			s->carried_packets = now_s->carried_packets;
			s->carried_bytes = now_s->carried_bytes;
			s->counted_since = now_s->counted_since;
			fs_intel_source_state_free (now_s);
		}
	}
	if (!state_write (store, s, list_digest, &local) &&
	    outcome == FS_INTEL_UPDATED) {
		/* The list is stored but its state is not: the next update
		 * sees the mismatch and stores the copy again. */
		gchar *w = error_text (local);

		g_free (message);
		message = g_strdup_printf (_("Updated, but its state was not "
		                             "saved: %s"), w);
		g_free (w);
	}
	engine_unlock (&lock);
	g_clear_error (&local);
	entries = s->entries;
	{
		gchar *detail = g_strdup_printf ("%s: %s: %s", f->id,
		                                 outcome_word (outcome), message);
		audit ("intel-update", detail);
		g_free (detail);
	}
	fs_intel_source_state_free (s);
	fs_range_set_free (set);
	if (body != NULL)
		g_bytes_unref (body);
	g_free (list_digest);
	g_free (sha);
	g_free (why);
	return result_new (f->id, outcome, entries, message);
}

/* The location database (13.5): enabled, consented and due, or no
 * request at all [S14].  The copy in use is replaced only by a newer
 * copy that verifies and checks (fs_geodb_update).  "Newer" is judged
 * against geodb.state's created-at too, the newest copy ever accepted,
 * so a copy in use that is damaged or gone never lets an older one
 * back in (review GEO-ROLLBACK-1); that floor is never lowered. */
static FsIntelUpdateResult *
geo_update_one (const FsIntelConfig *config, guint flags, gint64 now)
{
	FsIntelUpdateOutcome outcome;
	FsGeodbOutcome got;
	GeoState g;
	Store store;
	GError *local = NULL;
	gchar *dir, *why = NULL, *message, *detail;
	gint64 created = 0;

	if (!config->enabled)
		return result_new (FS_INTEL_GEO_ID, FS_INTEL_NOT_DUE, 0,
		                   g_strdup (_("Threat intel is switched off.")));
	if (!fs_intel_geo_supported ())
		return result_new (FS_INTEL_GEO_ID, FS_INTEL_FAILED, 0,
		                   g_strdup (fs_intel_geo_unsupported_text ()));
	if (config->geo_accepted_at <= 0)
		return result_new (FS_INTEL_GEO_ID, FS_INTEL_NEEDS_CONSENT, 0,
		                   g_strdup (_("Its terms have not been "
		                               "accepted.")));
	if (!store_open (&store, &local)) {
		why = error_text (local);
		g_clear_error (&local);
		return result_new (FS_INTEL_GEO_ID, FS_INTEL_FAILED, 0, why);
	}
	geo_state_read (&store, &g);
	if (!(flags & FS_INTEL_UPDATE_NOW) && g.attempted_at > 0 &&
	    g.attempted_at <= now && now - g.attempted_at < GEO_INTERVAL_S) {
		geo_state_clear (&g);
		store_close (&store);
		return result_new (FS_INTEL_GEO_ID, FS_INTEL_NOT_DUE, 0,
		                   g_strdup (_("Not due yet.")));
	}

	g.attempted_at = now;
	dir = fs_intel_dir (&local);
	got = dir != NULL ? fs_geodb_update (dir, config->proxy, now,
	                                     g.created_at, &created, &local)
	                  : FS_GEODB_FAILED;
	g_free (dir);
	switch (got) {
	case FS_GEODB_UPDATED:
	case FS_GEODB_UNCHANGED: {
		gchar *day = day_text (created);

		outcome = got == FS_GEODB_UPDATED ? FS_INTEL_UPDATED
		                                  : FS_INTEL_UNCHANGED;
		message = got == FS_GEODB_UPDATED
		          ? g_strdup_printf (_("Updated: the copy of %s is in "
		                               "use."), day)
		          : g_strdup (_("Unchanged since the last download."));
		g_free (day);
		g.fetched_at = now;
		g.created_at = MAX (g.created_at, created);
		g_clear_pointer (&g.last_error, g_free);
		g_clear_pointer (&g.refused, g_free);
		break;
	}
	case FS_GEODB_REFUSED:
		outcome = FS_INTEL_REFUSED;
		why = first_line (local != NULL ? local->message : "?",
		                  AUDIT_TEXT_MAX);
		message = g_strdup_printf (_("Refused: %s"), why);
		g_free (g.refused);
		g.refused = g_strdup (why);
		g_clear_pointer (&g.last_error, g_free);
		g.created_at = MAX (g.created_at, created);
		break;
	case FS_GEODB_FAILED:
	default:
		outcome = FS_INTEL_FAILED;
		why = error_text (local);
		message = g_strdup_printf (_("Download failed: %s"), why);
		g_free (g.last_error);
		g.last_error = g_strdup (why);
		g.created_at = MAX (g.created_at, created);
		break;
	}
	g_clear_error (&local);
	geo_state_write (&store, &g, NULL);
	detail = g_strdup_printf ("%s: %s: %s", FS_INTEL_GEO_ID,
	                          outcome_word (outcome), message);
	audit ("intel-update", detail);
	g_free (detail);
	geo_state_clear (&g);
	g_free (why);
	store_close (&store);
	return result_new (FS_INTEL_GEO_ID, outcome, 0, message);
}

GPtrArray *
fs_intel_update (const FsIntelConfig *config, const gchar *only_id,
                 guint flags, gint64 now)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_intel_update_result_free);
	Store store = STORE_INIT;
	GError *local = NULL;
	gboolean opened = FALSE;

	g_return_val_if_fail (config != NULL, out);

	if (g_strcmp0 (only_id, FS_INTEL_GEO_ID) == 0) {
		g_ptr_array_add (out, config->geo_enabled
			? geo_update_one (config, flags, now)
			: result_new (only_id, FS_INTEL_FAILED, 0,
			              g_strdup (_("The location database is "
			                          "turned off."))));
		return out;
	}
	if (only_id != NULL) {
		FsIntelFeedConf *f = fs_intel_config_feed (config, only_id);

		if (f == NULL) {
			g_ptr_array_add (out, result_new (only_id, FS_INTEL_FAILED, 0,
				g_strdup (fs_intel_config_list (config, only_id)
				          ? _("Local lists are imported, not "
				              "downloaded.")
				          : _("There is no such feed."))));
			return out;
		}
		if (!f->enabled) {
			g_ptr_array_add (out, result_new (only_id, FS_INTEL_FAILED, 0,
				g_strdup (_("This feed is turned off."))));
			return out;
		}
	}

	for (guint i = 0; i < config->feeds->len; i++) {
		const FsIntelFeedConf *f = g_ptr_array_index (config->feeds, i);
		FsIntelSourceState *s;
		gboolean damaged = FALSE;

		if (!f->enabled)
			continue;
		if (only_id != NULL && strcmp (f->id, only_id) != 0)
			continue;
		if (!config->enabled) {
			g_ptr_array_add (out, result_new (f->id, FS_INTEL_NOT_DUE, 0,
				g_strdup (_("Threat intel is switched off."))));
			continue;
		}
		/* Enabled and accepted, or no request at all [S14.1]. */
		if (f->accepted_at <= 0) {
			g_ptr_array_add (out, result_new (f->id,
				FS_INTEL_NEEDS_CONSENT, 0,
				g_strdup (_("Its terms have not been accepted."))));
			continue;
		}
		if (!opened) {
			if (!store_open (&store, &local)) {
				gchar *why = error_text (local);

				g_ptr_array_add (out, result_new (f->id,
					FS_INTEL_FAILED, 0, why));
				g_clear_error (&local);
				continue;
			}
			opened = TRUE;
		}
		s = state_read (&store, f->id, NULL, &damaged);
		if (!(flags & FS_INTEL_UPDATE_NOW) &&
		    !is_due (s, source_interval (config, f->id), now)) {
			g_ptr_array_add (out, result_new (f->id, FS_INTEL_NOT_DUE,
				s ? s->entries : 0,
				g_strdup (_("Not due yet."))));
			fs_intel_source_state_free (s);
			continue;
		}
		fs_intel_source_state_free (s);
		g_ptr_array_add (out, update_one (&store, config, f, flags, now));
	}
	if (opened)
		store_close (&store);
	/* The location database, after the feeds, while it is on. */
	if (only_id == NULL && config->geo_enabled)
		g_ptr_array_add (out, geo_update_one (config, flags, now));
	return out;
}

/* ============================================================== build */

/* What `host' keeps reachable, kind by kind, for the notes. */
typedef struct
{
	const FsRangeSet *set;
	const gchar *what;
} KeepKind;

/* a ∩ b, both normalized. */
static FsRangeSet *
intersect (const FsRangeSet *a, const FsRangeSet *b)
{
	FsRangeSet *rest = fs_range_set_copy (a);
	FsRangeSet *in = fs_range_set_copy (a);

	fs_range_set_subtract (rest, b);
	fs_range_set_subtract (in, rest);
	fs_range_set_free (rest);
	return in;
}

static FsRangeSet *
normalized_copy (const FsRangeSet *set)
{
	FsRangeSet *c = fs_range_set_copy (set);

	fs_range_set_normalize (c);
	return c;
}

/* "198.51.100.7, 203.0.113.0/24 and 4 more" */
static gchar *
addrs_text (const FsRangeSet *set)
{
	GString *out = g_string_new (NULL);
	guint total = fs_range_set_count4 (set) + fs_range_set_count6 (set);
	guint shown = 0;

	for (guint i = 0; i < set->v4->len && shown < NOTE_ADDRS; i++, shown++) {
		gchar *t = fs_range4_to_string (&g_array_index (set->v4,
		                                                FsRange4, i));
		g_string_append_printf (out, "%s%s", shown ? ", " : "", t);
		g_free (t);
	}
	for (guint i = 0; i < set->v6->len && shown < NOTE_ADDRS; i++, shown++) {
		gchar *t = fs_range6_to_string (&g_array_index (set->v6,
		                                                FsRange6, i));
		g_string_append_printf (out, "%s%s", shown ? ", " : "", t);
		g_free (t);
	}
	if (total > shown)
		g_string_append_printf (out, _(" and %u more"), total - shown);
	return g_string_free (out, FALSE);
}

/* One note per kind of address kept: what, which, and which lists
 * named it. */
static void
note_kept (GPtrArray *notes, const gchar *what, const FsRangeSet *hits,
           GPtrArray *labels)
{
	gchar *addrs, *names;

	if (fs_range_set_is_empty (hits))
		return;
	addrs = addrs_text (hits);
	g_ptr_array_add (labels, NULL);
	names = g_strjoinv (", ", (gchar **) labels->pdata);
	g_ptr_array_remove_index (labels, labels->len - 1);
	g_ptr_array_add (notes, g_strdup_printf (
		_("Kept reachable: %s (%s), although %s list%s it."),
		addrs, what, names, labels->len == 1 ? "s" : ""));
	g_free (addrs);
	g_free (names);
}

static gboolean
want_any (const FsIntelConfig *config)
{
	if (!config->enabled)
		return FALSE;
	for (guint i = 0; i < config->feeds->len; i++)
		if (((FsIntelFeedConf *) g_ptr_array_index (config->feeds, i))->enabled)
			return TRUE;
	for (guint i = 0; i < config->lists->len; i++)
		if (((FsIntelListConf *) g_ptr_array_index (config->lists, i))->enabled)
			return TRUE;
	/* A location rule counts only while the database is in use. */
	for (guint i = 0; geo_usable (config) && i < config->locations->len; i++)
		if (((FsIntelLocationConf *)
		     g_ptr_array_index (config->locations, i))->enabled)
			return TRUE;
	return FALSE;
}

/* Some location rule is turned on (whether or not the database is). */
static gboolean
any_location_enabled (const FsIntelConfig *config)
{
	for (guint i = 0; i < config->locations->len; i++)
		if (((FsIntelLocationConf *)
		     g_ptr_array_index (config->locations, i))->enabled)
			return TRUE;
	return FALSE;
}

/* The enabled sources in rule-set order: feeds (catalog order, then
 * custom), then local lists.  Borrowed ids; dirs alongside. */
static void
enabled_sources (const FsIntelConfig *config, GPtrArray *ids, GArray *dirs)
{
	for (guint i = 0; i < config->feeds->len; i++) {
		FsIntelFeedConf *f = g_ptr_array_index (config->feeds, i);

		if (f->enabled) {
			g_ptr_array_add (ids, f->id);
			g_array_append_val (dirs, f->dir);
		}
	}
	for (guint i = 0; i < config->lists->len; i++) {
		FsIntelListConf *l = g_ptr_array_index (config->lists, i);

		if (l->enabled) {
			g_ptr_array_add (ids, l->id);
			g_array_append_val (dirs, l->dir);
		}
	}
}

/* The largest sets of one kind, for a limit's error: "A (12,345), B
 * (9,000)".  locations: location sets only, else every other set. */
static gchar *
largest_sets (const FsIntelRuleset *rs, gboolean by_cover, gboolean locations)
{
	GPtrArray *order = g_ptr_array_new ();
	GString *out = g_string_new (NULL);

	for (guint i = 0; i < rs->sets->len; i++) {
		FsIntelSet *s = g_ptr_array_index (rs->sets, i);
		FsIntelSourceKind k = fs_intel_source_kind (s->id);
		gboolean loc = (k == FS_INTEL_KIND_COUNTRY || k == FS_INTEL_KIND_ASN);

		if (loc == locations)
			g_ptr_array_add (order, s);
	}
	for (guint i = 0; i < order->len; i++)
		for (guint j = i + 1; j < order->len; j++) {
			FsIntelSet *a = g_ptr_array_index (order, i);
			FsIntelSet *b = g_ptr_array_index (order, j);
			guint64 va = by_cover ? fs_range_set_addresses4 (a->ranges)
			             : fs_range_set_count4 (a->ranges) +
			               fs_range_set_count6 (a->ranges);
			guint64 vb = by_cover ? fs_range_set_addresses4 (b->ranges)
			             : fs_range_set_count4 (b->ranges) +
			               fs_range_set_count6 (b->ranges);

			if (vb > va) {
				order->pdata[i] = b;
				order->pdata[j] = a;
			}
		}
	for (guint i = 0; i < order->len && i < 3; i++) {
		FsIntelSet *s = g_ptr_array_index (order, i);
		guint64 v = by_cover ? fs_range_set_addresses4 (s->ranges)
		            : fs_range_set_count4 (s->ranges) +
		              fs_range_set_count6 (s->ranges);
		gchar *n = grouped (v);

		g_string_append_printf (out, "%s%s (%s)", i ? ", " : "",
		                        s->label ? s->label : s->id, n);
		g_free (n);
	}
	g_ptr_array_free (order, TRUE);
	return g_string_free (out, FALSE);
}

/* Everything one build keeps reachable (design 6.4), kind by kind, and
 * which sets named each kind, for the notes. */
typedef struct
{
	KeepKind    kinds[7];
	guint       nkinds;
	FsRangeSet *all;
	FsRangeSet *hits[7];
	GPtrArray  *labels[7];
} Keep;

/* Take everything `keep' holds out of `set' (normalized; owned), map
 * an outbound set into 64:ff9b::/96, and add it to the rule set.
 * anycast (nullable): the anycast networks of the database; the part
 * of the set inside them, after the subtractions, is counted into
 * *stats.  *intervals grows by the set's size. */
static gboolean
add_set (FsIntelRuleset *rs, Keep *keep, const gchar *id,
         const gchar *label, FsIntelDir dir, FsRangeSet *set,
         FsRangeSet *union4, const FsRangeSet *anycast,
         FsIntelLocationStats *stats, guint64 *intervals, GError **error)
{
	/* What each kind keeps reachable from this set. */
	for (guint k = 0; k < keep->nkinds; k++) {
		FsRangeSet *h = intersect (set, keep->kinds[k].set);

		if (!fs_range_set_is_empty (h)) {
			fs_range_set_union (keep->hits[k], h);
			g_ptr_array_add (keep->labels[k], (gpointer) label);
		}
		fs_range_set_free (h);
	}
	fs_range_set_subtract (set, keep->all);

	if (anycast != NULL && stats != NULL) {
		FsRangeSet *a = intersect (set, anycast);
		GPtrArray *p = fs_geodb_set_prefixes (a);

		stats->anycast_prefixes = p->len;
		stats->anycast_addresses4 = fs_range_set_addresses4 (a);
		stats->anycast_addresses6 = fs_range_set_addresses6 (a);
		g_ptr_array_unref (p);
		fs_range_set_free (a);
	}

	/* NAT64: an outbound set also stops 64:ff9b::<its v4>, or a NAT64
	 * network would reach the address anyway. */
	if (dir & FS_INTEL_DIR_OUT) {
		FsRangeSet *mapped = fs_range_set_new ();

		for (guint j = 0; j < set->v4->len; j++) {
			const FsRange4 *r = &g_array_index (set->v4, FsRange4, j);
			FsU128 a = { NAT64_HI, r->start };
			FsU128 b = { NAT64_HI, r->end };

			fs_range_set_add6 (mapped, a, b);
		}
		fs_range_set_normalize (mapped);
		/* Exceptions and kept addresses written in their NAT64 form
		 * stay reachable too. */
		fs_range_set_subtract (mapped, keep->all);
		fs_range_set_union (set, mapped);
		fs_range_set_free (mapped);
	}
	if (union4 != NULL)
		fs_range_set_union (union4, set);
	*intervals += fs_range_set_count4 (set) + fs_range_set_count6 (set);
	if (!fs_intel_ruleset_add (rs, id, label, dir, set)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("%s cannot be enforced: its id is not valid."), id);
		return FALSE;
	}
	return TRUE;
}

/* The location rules' sets (design 13.6), after the lists'. */
/* What a location rule's set is built from, for applied.state's
 * "inputs" (the lists record their .list's digest there): the copy of
 * the database (its signed creation time and size) and the rule's
 * kind and values.  fs_intel_lookup_live() computes it again and
 * trusts a set's membership only while the two agree. */
static gchar *
location_input_digest (const GeoHandle *geo, const FsIntelLocationConf *l)
{
	const FsGeodbInfo *info = fs_geodb_info (geo->db);
	GString *in = g_string_new (NULL);
	gchar *hex;

	g_string_append_printf (in, "location.db:%" G_GINT64_FORMAT ":%"
	                        G_GUINT64_FORMAT ":%d:", info->created_at,
	                        info->size, (int) l->kind);
	if (l->kind == FS_INTEL_LOCATION_COUNTRY) {
		for (guint i = 0; l->countries != NULL && l->countries[i]; i++)
			g_string_append_printf (in, "%s,", l->countries[i]);
	} else {
		for (guint i = 0; l->asns != NULL && i < l->asns->len; i++)
			g_string_append_printf (in, "%u,",
			                        g_array_index (l->asns, guint32, i));
	}
	hex = sha256_hex (in->str, in->len);
	g_string_free (in, TRUE);
	return hex;
}

static gboolean
build_locations (const Store *store, const FsIntelConfig *config,
                 FsIntelRuleset *rs, Keep *keep, GPtrArray *notes,
                 GHashTable *digests, guint64 *intervals, GError **error)
{
	GeoHandle *geo;
	FsRangeSet *anycast = NULL;
	gboolean missing = FALSE, ok = TRUE;
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;

	if (!any_location_enabled (config))
		return TRUE;
	geo = geo_acquire (store, &missing, error);
	if (geo == NULL && !missing)
		return FALSE;   /* fail closed: the kernel keeps what it had */
	if (geo == NULL) {
		for (guint i = 0; i < config->locations->len; i++) {
			FsIntelLocationConf *l = g_ptr_array_index (config->locations,
			                                            i);

			if (l->enabled)
				g_ptr_array_add (notes, g_strdup_printf (
					_("%s is not enforced: the location database "
					  "has not been downloaded yet."), l->name));
		}
		return TRUE;
	}
	{
		const FsGeodbInfo *info = fs_geodb_info (geo->db);

		if (fs_geodb_is_stale (info->created_at, now)) {
			gchar *day = day_text (info->created_at);

			g_ptr_array_add (notes, g_strdup_printf (
				_("The location database in use was made on %s, "
				  "more than 30 days ago; the location rules use it "
				  "until a newer copy is downloaded."), day));
			g_free (day);
		}
	}
	{
		FsGeodbFilter af = { NULL, NULL, 0, FS_GEODB_FLAG_ANYCAST };

		anycast = fs_geodb_enumerate (geo->db, &af, NULL);
		if (anycast == NULL)
			anycast = fs_range_set_new ();
	}

	for (guint i = 0; ok && i < config->locations->len; i++) {
		FsIntelLocationConf *l = g_ptr_array_index (config->locations, i);
		FsGeodbFilter f = { NULL, NULL, 0, 0 };
		FsIntelLocationStats st = { 0 };
		GError *local = NULL;
		FsRangeSet *set;

		if (!l->enabled)
			continue;
		if (l->kind == FS_INTEL_LOCATION_COUNTRY) {
			f.countries = (const gchar *const *) l->countries;
			for (guint j = 0; l->countries[j] != NULL; j++) {
				FsGeodbCountry *c = fs_geodb_country (geo->db,
				                                      l->countries[j]);

				if (c == NULL)
					g_ptr_array_add (notes, g_strdup_printf (
						_("%s: the location database names no "
						  "country %s."), l->name,
						l->countries[j]));
				fs_geodb_country_free (c);
			}
		} else {
			f.asns = (const guint32 *) (gpointer) l->asns->data;
			f.n_asns = l->asns->len;
		}
		set = fs_geodb_enumerate (geo->db, &f, &local);
		if (set == NULL) {
			gchar *why = error_text (local);

			g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
			             _("%s cannot be enforced: %s"), l->name, why);
			g_free (why);
			g_clear_error (&local);
			ok = FALSE;
			break;
		}
		fs_range_set_subtract (set, fs_range_protected ());
		if (fs_range_set_is_empty (set))
			g_ptr_array_add (notes, g_strdup_printf (
				_("%s matches no address in the location "
				  "database."), l->name));
		ok = add_set (rs, keep, l->id, l->name, l->dir, set, NULL,
		              anycast, &st, intervals, error);
		if (ok && digests != NULL)
			g_hash_table_replace (digests, g_strdup (l->id),
			                      location_input_digest (geo, l));
		if (ok && st.anycast_prefixes > 0) {
			gchar *n4 = grouped (st.anycast_addresses4);

			g_ptr_array_add (notes, g_strdup_printf (
				_("%s includes %u anycast prefix%s (%s IPv4 "
				  "address%s): anycast addresses are answered from "
				  "many places, so this may also block services "
				  "outside what you chose."), l->name,
				st.anycast_prefixes,
				st.anycast_prefixes == 1 ? "" : "es", n4,
				st.anycast_addresses4 == 1 ? "" : "es"));
			g_free (n4);
		}
	}
	fs_range_set_free (anycast);
	geo_handle_unref (geo);
	return ok;
}

static FsIntelRuleset *
build_in (const Store *store, const FsIntelConfig *config,
          const FsHostNet *host, GPtrArray *notes, GHashTable *digests,
          GError **error)
{
	FsIntelRuleset *rs = fs_intel_ruleset_new ();
	GPtrArray *ids = g_ptr_array_new ();
	GArray *dirs = g_array_new (FALSE, FALSE, sizeof (FsIntelDir));
	Keep keep;
	FsRangeSet *union4 = fs_range_set_new ();
	guint64 intervals = 0, loc_intervals = 0;
	gboolean ok = TRUE;

	memset (&keep, 0, sizeof keep);
	keep.all = fs_range_set_new ();
	if (!want_any (config))
		goto out;

	keep.kinds[keep.nkinds++] = (KeepKind) { config->exceptions,
		_("an exception") };
	if (host != NULL) {
		keep.kinds[keep.nkinds++] = (KeepKind) { host->own,
			_("this computer's own address") };
		keep.kinds[keep.nkinds++] = (KeepKind) { host->onlink,
			_("a network this computer is connected to") };
		keep.kinds[keep.nkinds++] = (KeepKind) { host->gateways,
			_("a default gateway") };
		keep.kinds[keep.nkinds++] = (KeepKind) { host->resolvers,
			_("a DNS server in use") };
		keep.kinds[keep.nkinds++] = (KeepKind) { host->sessions,
			_("an SSH session to this computer") };
		keep.kinds[keep.nkinds++] = (KeepKind) { host->update_hosts,
			_("a feed's download server or proxy") };
	}
	for (guint k = 0; k < keep.nkinds; k++) {
		FsRangeSet *n = normalized_copy (keep.kinds[k].set);

		keep.kinds[k].set = n;
		fs_range_set_union (keep.all, n);
		keep.hits[k] = fs_range_set_new ();
		keep.labels[k] = g_ptr_array_new ();
	}

	enabled_sources (config, ids, dirs);
	for (guint i = 0; i < ids->len && ok; i++) {
		const gchar *id = g_ptr_array_index (ids, i);
		FsIntelDir dir = g_array_index (dirs, FsIntelDir, i);
		const gchar *label = fs_intel_config_label (config, id);
		GError *local = NULL;
		gboolean missing = FALSE;
		gchar *list_digest = NULL;
		FsRangeSet *set;

		set = list_read (store, id, digests != NULL ? &list_digest : NULL,
		                 &missing, &local);
		if (set != NULL && digests != NULL && list_digest != NULL)
			g_hash_table_replace (digests, g_strdup (id), list_digest);
		else
			g_free (list_digest);
		if (set == NULL && missing) {
			g_clear_error (&local);
			g_ptr_array_add (notes, g_strdup_printf (
				_("%s is not enforced: it has not been "
				  "downloaded yet."), label));
			continue;
		}
		if (set == NULL) {
			g_propagate_error (error, local);
			ok = FALSE;
			break;
		}
		ok = add_set (rs, &keep, id, label, dir, set, union4, NULL, NULL,
		              &intervals, error);
	}

	/* Location rules: their own limit, never the lists' (13.6). */
	if (ok && geo_usable (config))
		ok = build_locations (store, config, rs, &keep, notes,
		                      digests, &loc_intervals, error);

	if (ok && intervals > FS_INTEL_MAX_INTERVALS) {
		gchar *big = largest_sets (rs, FALSE, FALSE);
		gchar *n = grouped (intervals);

		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_TOO_BIG,
		             _("The lists together have %s entries, more than "
		               "the 300,000 StockFW enforces; the largest are "
		               "%s."), n, big);
		g_free (n);
		g_free (big);
		ok = FALSE;
	} else if (ok && fs_range_set_addresses4 (union4) > FS_INTEL_MAX_UNION4) {
		gchar *big = largest_sets (rs, TRUE, FALSE);

		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_TOO_BIG,
		             _("The lists together cover more than 2^26 IPv4 "
		               "addresses; the largest are %s."), big);
		g_free (big);
		ok = FALSE;
	} else if (ok && loc_intervals > FS_INTEL_MAX_LOCATION_INTERVALS) {
		gchar *big = largest_sets (rs, FALSE, TRUE);
		gchar *n = grouped (loc_intervals);

		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_TOO_BIG,
		             _("The location rules together have %s entries, "
		               "more than the 500,000 StockFW enforces; the "
		               "largest are %s."), n, big);
		g_free (n);
		g_free (big);
		ok = FALSE;
	}

	if (ok) {
		for (guint k = 0; k < keep.nkinds; k++) {
			if (k == 0) {
				/* Exceptions: their own sentence. */
				if (!fs_range_set_is_empty (keep.hits[0])) {
					gchar *a = addrs_text (keep.hits[0]);
					gchar *names;

					g_ptr_array_add (keep.labels[0], NULL);
					names = g_strjoinv (", ",
						(gchar **) keep.labels[0]->pdata);
					g_ptr_array_add (notes, g_strdup_printf (
						_("Not blocked, by exception: %s "
						  "(listed by %s)."), a, names));
					g_free (names);
					g_ptr_array_remove_index (keep.labels[0],
						keep.labels[0]->len - 1);
					g_free (a);
				}
				continue;
			}
			note_kept (notes, keep.kinds[k].what, keep.hits[k],
			           keep.labels[k]);
		}
		/* Lists that already contain another enabled one. */
		for (guint i = 0; i < config->feeds->len; i++) {
			FsIntelFeedConf *f = g_ptr_array_index (config->feeds, i);
			const FsFeedInfo *fi;
			gchar **inc;

			if (!f->enabled || f->custom)
				continue;
			fi = fs_feed_catalog_find (f->id);
			if (fi == NULL || fi->includes == NULL)
				continue;
			inc = g_strsplit (fi->includes, " ", -1);
			for (guint j = 0; inc[j] != NULL; j++) {
				FsIntelFeedConf *o = fs_intel_config_feed (config,
				                                           inc[j]);

				if (o != NULL && o->enabled)
					g_ptr_array_add (notes, g_strdup_printf (
						_("%s already contains %s; both are "
						  "on."),
						fs_intel_config_label (config, f->id),
						fs_intel_config_label (config, o->id)));
			}
			g_strfreev (inc);
		}
	}

out:
	for (guint k = 0; k < keep.nkinds; k++) {
		fs_range_set_free ((FsRangeSet *) keep.kinds[k].set);
		fs_range_set_free (keep.hits[k]);
		g_ptr_array_free (keep.labels[k], TRUE);
	}
	fs_range_set_free (keep.all);
	fs_range_set_free (union4);
	g_ptr_array_free (ids, TRUE);
	g_array_free (dirs, TRUE);
	if (!ok) {
		fs_intel_ruleset_free (rs);
		return NULL;
	}
	return rs;
}

FsIntelRuleset *
fs_intel_build (const FsIntelConfig *config, const FsHostNet *host,
                GPtrArray **notes, GError **error)
{
	GPtrArray *n = g_ptr_array_new_with_free_func (g_free);
	FsIntelRuleset *rs;
	Store store = STORE_INIT;

	g_return_val_if_fail (config != NULL, NULL);
	if (notes != NULL)
		*notes = NULL;
	if (!want_any (config))
		rs = fs_intel_ruleset_new ();
	else if (!store_open (&store, error))
		rs = NULL;
	else {
		rs = build_in (&store, config, host, n, NULL, error);
		store_close (&store);
	}
	if (rs != NULL && notes != NULL)
		*notes = n;
	else
		g_ptr_array_unref (n);
	return rs;
}

/* ======================================================= applied.state */

typedef struct
{
	gchar     *digest;     /* NULL: nothing recorded                 */
	gint64     applied_at;
	gboolean   suspended;
	GPtrArray *ids;        /* gchar*                                 */
	GPtrArray *ruled;      /* gchar*: the ids whose set has addresses,
	                        * and so rules in the kernel (a set whose
	                        * every address was kept reachable has
	                        * none); NULL when the record predates it */
	GPtrArray *inputs;     /* gchar* "<id>:<dir>:<sha256 of its .list>"
	                        * per applied set: what each set was built
	                        * from; NULL when the record predates it   */
	GPtrArray *exceptions; /* gchar*: the exceptions' stored text
	                        * form, one interval each, as applied;
	                        * NULL when not recorded                 */
	guint      count4, count6;
} Applied;

static void
applied_clear (Applied *a)
{
	g_free (a->digest);
	if (a->ids != NULL)
		g_ptr_array_unref (a->ids);
	if (a->ruled != NULL)
		g_ptr_array_unref (a->ruled);
	if (a->inputs != NULL)
		g_ptr_array_unref (a->inputs);
	if (a->exceptions != NULL)
		g_ptr_array_unref (a->exceptions);
	memset (a, 0, sizeof *a);
}

/* A record of nothing loaded (the empty rule set's digest, no sets). */
static void
applied_empty (Applied *a, gboolean suspended)
{
	FsIntelRuleset *empty = fs_intel_ruleset_new ();

	memset (a, 0, sizeof *a);
	a->digest = fs_intel_ruleset_digest (empty);
	a->applied_at = g_get_real_time () / G_USEC_PER_SEC;
	a->suspended = suspended;
	a->ids = g_ptr_array_new_with_free_func (g_free);
	a->ruled = g_ptr_array_new_with_free_func (g_free);
	fs_intel_ruleset_free (empty);
}

/* Whether the record says StockFW left a table with rules in the
 * kernel: not suspended, and some set had addresses. */
static gboolean
applied_loaded (const Applied *a)
{
	return a->digest != NULL && !a->suspended &&
	       (a->ruled != NULL ? a->ruled->len : a->ids->len) > 0;
}

/* FALSE when there is no record or it cannot be trusted; *a is then
 * empty (ids an empty array). */
static gboolean
applied_read (const Store *store, Applied *a)
{
	gsize len = 0;
	gchar *text = store_read (store, APPLIED_NAME, APPLIED_MAX, &len, NULL,
	                          NULL);
	GKeyFile *kf = g_key_file_new ();
	gboolean ok = FALSE;

	memset (a, 0, sizeof *a);
	a->ids = g_ptr_array_new_with_free_func (g_free);
	if (text != NULL && g_utf8_validate (text, (gssize) len, NULL) &&
	    g_key_file_load_from_data (kf, text, len, G_KEY_FILE_NONE, NULL)) {
		gchar *digest = g_key_file_get_string (kf, "applied", "digest",
		                                       NULL);
		gchar *susp = kf_raw (kf, "applied", "suspended");
		gchar *at = kf_raw (kf, "applied", "applied-at");
		gchar *c4 = kf_raw (kf, "applied", "count4");
		gchar *c6 = kf_raw (kf, "applied", "count6");
		gsize n = 0, nr = 0, ni = 0, ne = 0;
		gchar **ids = NULL, **ruled = NULL, **inputs = NULL;
		gchar **exc = NULL;
		gboolean lists = kf_list (kf, "applied", "sets", &ids, &n) &&
		                 kf_list (kf, "applied", "ruled", &ruled, &nr) &&
		                 kf_list (kf, "applied", "inputs", &inputs, &ni) &&
		                 kf_list (kf, "applied", "exceptions", &exc, &ne);
		guint64 v4 = 0, v6 = 0, t = 0;

		ok = lists && digest != NULL && strlen (digest) == 32 &&
		     strspn (digest, "0123456789abcdef") == 32 &&
		     susp != NULL && (strcmp (susp, "true") == 0 ||
		                      strcmp (susp, "false") == 0) &&
		     at != NULL && g_ascii_string_to_unsigned (at, 10, 0,
		                                              G_MAXINT64, &t, NULL) &&
		     c4 != NULL && g_ascii_string_to_unsigned (c4, 10, 0,
		                                              G_MAXUINT, &v4, NULL) &&
		     c6 != NULL && g_ascii_string_to_unsigned (c6, 10, 0,
		                                              G_MAXUINT, &v6, NULL);
		for (gsize i = 0; ok && i < n; i++)
			ok = fs_intel_id_is_valid (ids[i]);
		for (gsize i = 0; ok && i < nr; i++)
			ok = fs_intel_id_is_valid (ruled[i]);
		if (ok) {
			a->digest = digest;
			digest = NULL;
			a->suspended = strcmp (susp, "true") == 0;
			a->applied_at = (gint64) t;
			a->count4 = (guint) v4;
			a->count6 = (guint) v6;
			for (gsize i = 0; i < n; i++)
				g_ptr_array_add (a->ids, g_strdup (ids[i]));
			if (ruled != NULL) {
				a->ruled = g_ptr_array_new_with_free_func (g_free);
				for (gsize i = 0; i < nr; i++)
					g_ptr_array_add (a->ruled,
					                 g_strdup (ruled[i]));
			}
			/* What the sets were built from, for lookups only:
			 * NULL in a record that predates them. */
			if (inputs != NULL) {
				a->inputs = g_ptr_array_new_with_free_func (g_free);
				for (gsize i = 0; i < ni; i++)
					g_ptr_array_add (a->inputs,
					                 g_strdup (inputs[i]));
			}
			if (exc != NULL) {
				a->exceptions = g_ptr_array_new_with_free_func (g_free);
				for (gsize i = 0; i < ne; i++)
					g_ptr_array_add (a->exceptions,
					                 g_strdup (exc[i]));
			}
		}
		g_free (digest);
		g_free (susp);
		g_free (at);
		g_free (c4);
		g_free (c6);
		g_strfreev (ids);
		g_strfreev (ruled);
		g_strfreev (inputs);
		g_strfreev (exc);
	}
	g_key_file_free (kf);
	g_free (text);
	return ok;
}

static gboolean
applied_write (const Store *store, const Applied *a, GError **error)
{
	GKeyFile *kf = g_key_file_new ();
	gchar *data, *t;
	gsize len = 0;
	gboolean ok;

	g_key_file_set_string (kf, "applied", "digest", a->digest);
	t = g_strdup_printf ("%" G_GINT64_FORMAT, MAX (a->applied_at, 0));
	g_key_file_set_value (kf, "applied", "applied-at", t);
	g_free (t);
	g_key_file_set_value (kf, "applied", "suspended",
	                      a->suspended ? "true" : "false");
	t = g_strdup_printf ("%u", a->count4);
	g_key_file_set_value (kf, "applied", "count4", t);
	g_free (t);
	t = g_strdup_printf ("%u", a->count6);
	g_key_file_set_value (kf, "applied", "count6", t);
	g_free (t);
	g_ptr_array_add (a->ids, NULL);
	g_key_file_set_string_list (kf, "applied", "sets",
	                            (const gchar *const *) a->ids->pdata,
	                            a->ids->len - 1);
	g_ptr_array_remove_index (a->ids, a->ids->len - 1);
	if (a->ruled != NULL) {
		g_ptr_array_add (a->ruled, NULL);
		g_key_file_set_string_list (kf, "applied", "ruled",
		                            (const gchar *const *) a->ruled->pdata,
		                            a->ruled->len - 1);
		g_ptr_array_remove_index (a->ruled, a->ruled->len - 1);
	}
	if (a->inputs != NULL) {
		g_ptr_array_add (a->inputs, NULL);
		g_key_file_set_string_list (kf, "applied", "inputs",
		                            (const gchar *const *) a->inputs->pdata,
		                            a->inputs->len - 1);
		g_ptr_array_remove_index (a->inputs, a->inputs->len - 1);
	}
	if (a->exceptions != NULL) {
		g_ptr_array_add (a->exceptions, NULL);
		g_key_file_set_string_list (kf, "applied", "exceptions",
		                            (const gchar *const *) a->exceptions->pdata,
		                            a->exceptions->len - 1);
		g_ptr_array_remove_index (a->exceptions, a->exceptions->len - 1);
	}
	data = g_key_file_to_data (kf, &len, NULL);
	g_key_file_free (kf);
	ok = store_write (store, APPLIED_NAME, data, len, error);
	g_free (data);
	return ok;
}

/* ================================================================ gate */

void
fs_intel_outcome_free (FsIntelOutcome *outcome)
{
	if (outcome == NULL)
		return;
	g_free (outcome->hold_reason);
	g_free (outcome->digest);
	g_free (outcome->not_in_force);
	if (outcome->notes != NULL)
		g_ptr_array_unref (outcome->notes);
	g_free (outcome);
}

/* Add a snapshot of the live counters to each source's carried total
 * (only once the table they were read from is gone). */
static void
carry_counters (const Store *store, GHashTable *snapshot, gint64 now)
{
	GHashTableIter it;
	gpointer key, value;

	if (snapshot == NULL)
		return;
	g_hash_table_iter_init (&it, snapshot);
	while (g_hash_table_iter_next (&it, &key, &value)) {
		const FsIntelCounter *c = value;
		FsIntelSourceState *s;
		gchar *ld = NULL;
		gboolean damaged = FALSE;

		if (!fs_intel_id_is_valid (key) ||
		    (c->packets == 0 && c->bytes == 0))
			continue;
		s = state_read (store, key, &ld, &damaged);
		if (s == NULL)
			continue;   /* a source that is gone */
		s->carried_packets = (s->carried_packets > G_MAXUINT64 - c->packets)
		                     ? G_MAXUINT64 : s->carried_packets + c->packets;
		s->carried_bytes = (s->carried_bytes > G_MAXUINT64 - c->bytes)
		                   ? G_MAXUINT64 : s->carried_bytes + c->bytes;
		if (s->counted_since == 0)
			s->counted_since = now;
		state_write (store, s, ld, NULL);
		fs_intel_source_state_free (s);
		g_free (ld);
	}
}

/* Counting starts when a source is first enforced. */
static void
mark_counted_since (const Store *store, const FsIntelRuleset *rs, gint64 now)
{
	for (guint i = 0; i < rs->sets->len; i++) {
		const FsIntelSet *set = g_ptr_array_index (rs->sets, i);
		gchar *ld = NULL;
		gboolean damaged = FALSE;
		FsIntelSourceState *s = state_read (store, set->id, &ld, &damaged);
		FsIntelSourceKind kind = fs_intel_source_kind (set->id);

		/* A location rule has no download, so its state (the carried
		 * counters) is made here, the first time it is enforced. */
		if (s == NULL && (kind == FS_INTEL_KIND_COUNTRY ||
		                  kind == FS_INTEL_KIND_ASN)) {
			s = g_new0 (FsIntelSourceState, 1);
			s->id = g_strdup (set->id);
		}
		if (s != NULL && s->counted_since == 0) {
			s->counted_since = now;
			state_write (store, s, ld, NULL);
		}
		fs_intel_source_state_free (s);
		g_free (ld);
	}
}

/* Whether some of StockFW's rules are there: whole (PRESENT), not
 * whole (PARTIAL), or there but not enforced (INACTIVE; Round 3). */
static gboolean
live_holds (FsIntelLive live)
{
	return live == FS_INTEL_LIVE_PRESENT || live == FS_INTEL_LIVE_PARTIAL ||
	       live == FS_INTEL_LIVE_INACTIVE;
}

/* Whether the rules there are whole, with a digest to compare: PRESENT,
 * or INACTIVE when the backend could read them whole. */
static gboolean
live_whole (FsIntelLive live)
{
	return live == FS_INTEL_LIVE_PRESENT || live == FS_INTEL_LIVE_INACTIVE;
}

/* Why the platform's firewall does not enforce the rules (the backend's
 * sentence), or a general one.  Caller frees. */
static gchar *
not_in_force_text (const FsBackend *backend)
{
	gchar *why = backend->intel_not_in_force != NULL
	             ? backend->intel_not_in_force () : NULL;

	return why != NULL ? why
	                   : g_strdup (_("The firewall is not enforcing the "
	                                 "blocklist rules on the network in "
	                                 "use."));
}

/* Whether the kernel holds what `rs' should leave there: its table with
 * its digest, or (the empty rule set renders no table) none at all.
 * Rules that are whole but not enforced (INACTIVE: Windows Firewall off
 * for the profile in use) are what was asked for; the outcome notes
 * that they block nothing yet, and the state says so.  *live receives
 * what was read. */
static gboolean
kernel_matches (const FsBackend *backend, const FsIntelRuleset *rs,
                const gchar *digest, FsIntelLive *live)
{
	gchar *got = NULL;
	gboolean match;

	*live = backend->intel_live != NULL ? backend->intel_live (&got)
	                                    : FS_INTEL_LIVE_UNKNOWN;
	if (rs->sets->len == 0)
		match = (*live == FS_INTEL_LIVE_ABSENT);
	else
		match = (live_whole (*live) && got != NULL &&
		         strcmp (got, digest) == 0);
	g_free (got);
	return match;
}

/* Whether anything was counted in a snapshot of the counters. */
static gboolean
counted_anything (GHashTable *snapshot)
{
	GHashTableIter it;
	gpointer key, value;

	if (snapshot == NULL)
		return FALSE;
	g_hash_table_iter_init (&it, snapshot);
	while (g_hash_table_iter_next (&it, &key, &value)) {
		const FsIntelCounter *c = value;

		if (c->packets != 0 || c->bytes != 0)
			return TRUE;
	}
	return FALSE;
}

/* Whether some counter read before an apply (`before') is lower in the
 * table read after it (`after'): a counter only grows while its table
 * lives, so a lower one proves the table was replaced.  An id missing
 * from a readable `after' counts as zero.  FALSE when `after' could
 * not be read. */
static gboolean
counters_went_down (GHashTable *before, GHashTable *after)
{
	GHashTableIter it;
	gpointer key, value;

	if (before == NULL || after == NULL)
		return FALSE;
	g_hash_table_iter_init (&it, before);
	while (g_hash_table_iter_next (&it, &key, &value)) {
		const FsIntelCounter *b = value;
		const FsIntelCounter *a = g_hash_table_lookup (after, key);

		if ((a != NULL ? a->packets : 0) < b->packets ||
		    (a != NULL ? a->bytes : 0) < b->bytes)
			return TRUE;
	}
	return FALSE;
}

static void
add_host (GPtrArray *hosts, gchar *h)
{
	if (h == NULL)
		return;
	for (guint i = 0; i < hosts->len; i++)
		if (g_ascii_strcasecmp (g_ptr_array_index (hosts, i), h) == 0) {
			g_free (h);
			return;
		}
	g_ptr_array_add (hosts, h);
}

gchar **
fs_intel_update_hosts (const FsIntelConfig *config)
{
	GPtrArray *hosts = g_ptr_array_new ();
	gboolean any = FALSE;

	for (guint i = 0; config != NULL && i < config->feeds->len; i++) {
		FsIntelFeedConf *f = g_ptr_array_index (config->feeds, i);
		const FsFeedInfo *fi;

		if (!f->enabled)
			continue;
		any = TRUE;
		fi = f->custom ? NULL : fs_feed_catalog_find (f->id);
		add_host (hosts, fi != NULL ? g_strdup (fi->host)
		                            : host_of (f->url, FALSE));
	}
	/* The location database is downloaded while it is on (13.5): a
	 * country rule must not block its own updates. */
	if (config != NULL && config->geo_enabled &&
	    config->geo_accepted_at > 0) {
		any = TRUE;
		add_host (hosts, g_strdup (GEO_HOST));
	}
	/* Every download connects to the proxy, not to the feed's host: a
	 * list naming the proxy would stop every update, the one that
	 * would fix the list included [S7.2]. */
	if (any && config->proxy != NULL)
		add_host (hosts, host_of (config->proxy, TRUE));
	g_ptr_array_add (hosts, NULL);
	return (gchar **) g_ptr_array_free (hosts, FALSE);
}

/* Whether applied.state says the user stopped the firewall. */
static gboolean
applied_suspended (const Store *store)
{
	Applied a;
	gboolean suspended = applied_read (store, &a) && a.suspended;

	applied_clear (&a);
	return suspended;
}

/* The exceptions' text form, one interval per element. */
static GPtrArray *
exceptions_lines (const FsRangeSet *exceptions)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (g_free);
	gchar *text = fs_range_set_to_text (exceptions);
	gchar **lines = g_strsplit (text, "\n", -1);

	for (guint i = 0; lines[i] != NULL; i++)
		if (*lines[i] != '\0')
			g_ptr_array_add (out, g_strdup (lines[i]));
	g_strfreev (lines);
	g_free (text);
	return out;
}

/* fs_intel_apply_safe; `locked': the caller (fs_intel_resume) already
 * holds the engine lock. */
static FsIntelOutcome *
apply_in (const FsBackend *backend, const FsIntelConfig *config,
          const FsHostNet *host, const gchar *source, const gchar *hold,
          gboolean locked, GError **error)
{
	FsIntelOutcome *o;
	FsIntelRuleset *rs;
	FsHostNet *own_host = NULL;
	GPtrArray *notes = g_ptr_array_new_with_free_func (g_free);
	Store store = STORE_INIT;
	EngineLock lock = ENGINE_LOCK_INIT;
	GError *local = NULL;
	GHashTable *snapshot = NULL, *after = NULL, *digests;
	gchar *detail, *before_digest = NULL;
	const gchar *src = (source != NULL && *source) ? source : "-";
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;
	FsIntelLive live, before;
	gboolean ok, said_ok, matches, replaced = FALSE;

	g_return_val_if_fail (backend != NULL && config != NULL, NULL);

	if (!store_open (&store, &local)) {
		gchar *why = error_text (local);

		detail = g_strdup_printf ("source=%s result=failed error=%s",
		                          src, why);
		audit ("intel-apply", detail);
		g_free (detail);
		g_free (why);
		g_propagate_error (error, local);
		g_ptr_array_unref (notes);
		return NULL;
	}

	/* One engine operation at a time, across processes.  An apply
	 * that had to wait, and finds the firewall stopped by the
	 * operation it waited for, does not load the lists behind that
	 * Stop's back: it is held, and Start puts them in. */
	if (!locked) {
		gboolean was_suspended = applied_suspended (&store);

		engine_lock (&store, &lock);
		if (lock.waited && !was_suspended &&
		    applied_suspended (&store) &&
		    (hold == NULL || *hold == '\0'))
			hold = _("the firewall was stopped while this apply "
			         "waited; the lists go in when it is started");
	}

	if (host == NULL && want_any (config)) {
		gchar **hosts = fs_intel_update_hosts (config);

		own_host = fs_hostnet_read ((const gchar *const *) hosts);
		g_strfreev (hosts);
		host = own_host;
	}
	digests = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
	                                 g_free);
	rs = want_any (config) ? build_in (&store, config, host, notes,
	                                   digests, &local)
	                       : fs_intel_ruleset_new ();
	fs_hostnet_free (own_host);
	if (rs == NULL) {
		gchar *why = error_text (local);

		detail = g_strdup_printf ("source=%s result=failed build: %s",
		                          src, why);
		audit ("intel-apply", detail);
		g_free (detail);
		g_free (why);
		g_propagate_error (error, local);
		g_ptr_array_unref (notes);
		g_hash_table_unref (digests);
		engine_unlock (&lock);
		store_close (&store);
		return NULL;
	}

	o = g_new0 (FsIntelOutcome, 1);
	o->notes = notes;
	o->digest = fs_intel_ruleset_digest (rs);
	o->sets = rs->sets->len;
	o->count4 = fs_intel_ruleset_count4 (rs);
	o->count6 = fs_intel_ruleset_count6 (rs);

	if (hold != NULL && *hold != '\0') {
		o->result = FS_APPLY_DRY_RUN;
		o->held = TRUE;
		o->hold_reason = g_strdup (hold);
		detail = g_strdup_printf ("source=%s result=held hold=%s "
		                          "digest=%s sets=%u", src, hold,
		                          o->digest, o->sets);
		goto done;
	}
	if (backend->intel_apply == NULL) {
		o->result = FS_APPLY_FAILED;
		g_set_error_literal (error, FS_INTEL_ERROR,
		                     FS_INTEL_ERR_UNSUPPORTED, unsupported_text ());
		detail = g_strdup_printf ("source=%s result=failed "
		                          "error=unsupported", src);
		goto done;
	}

	/* What the kernel holds and has counted, read before the table is
	 * replaced.  The counters are carried only once the replacement is
	 * proven, so an apply that changed nothing (the old table still
	 * counting) never counts them twice [N8, P8]. */
	before = backend->intel_live != NULL
	         ? backend->intel_live (&before_digest) : FS_INTEL_LIVE_UNKNOWN;
	snapshot = backend->intel_counters != NULL ? backend->intel_counters ()
	                                           : NULL;
	said_ok = ok = backend->intel_apply (rs, &local);

	/* Never trust the verdict alone: nft can commit and still time
	 * out, or fail after a partial read.  What the kernel holds now
	 * decides [S10]. */
	matches = kernel_matches (backend, rs, o->digest, &live);
	if (matches)
		ok = TRUE;
	else if (ok && live != FS_INTEL_LIVE_UNKNOWN) {
		ok = FALSE;
		g_set_error (&local, FS_INTEL_ERROR, FS_INTEL_ERR_STORE,
		             _("The rules were applied, but " FS_INTEL_WHERE " holds "
		               "something else."));
	}
	/* live UNKNOWN after a reported success: cannot tell, the
	 * backend's verdict stands. */

	/* Was the old table replaced?  The new digest where another one,
	 * or none, was before proves it.  The same digest proves nothing:
	 * it is also exactly what a transaction the kernel refused leaves
	 * behind (a re-apply of an unchanged rule set, as the hourly check
	 * makes) -- then only counters that went down prove it, read again
	 * now.  For the empty rule set, no table now where one was. */
	if (ok) {
		if (matches && rs->sets->len > 0)
			replaced = before == FS_INTEL_LIVE_ABSENT ||
			           (live_holds (before) &&
			            g_strcmp0 (before_digest, o->digest) != 0);
		else if (matches)
			replaced = live_holds (before) || snapshot != NULL;
		if (!replaced && counted_anything (snapshot)) {
			after = backend->intel_counters != NULL
			        ? backend->intel_counters () : NULL;
			replaced = counters_went_down (snapshot, after);
		}
	}
	if (ok && !said_ok && !replaced && rs->sets->len > 0 &&
	    live_whole (before) &&
	    g_strcmp0 (before_digest, o->digest) == 0) {
		/* The tool failed, and the kernel holds the rules it held
		 * before -- the same ones.  Nothing shows the transaction
		 * went through, so it is not reported as applied, and the
		 * counters are not carried: the old table still counts. */
		ok = FALSE;
		g_ptr_array_add (o->notes, g_strdup (
			_("The same rules were already in force, and still "
			  "are.")));
	} else if (ok && !said_ok) {
		gchar *why = error_text (local);

		g_ptr_array_add (o->notes, g_strdup_printf (
			_(FS_INTEL_WHERE_CAP " reported an error (%s), but holds the "
			  "new rules."), why));
		g_free (why);
		g_clear_error (&local);
	}

	if (!ok) {
		gchar *why;

		if (local == NULL)
			g_set_error (&local, FS_INTEL_ERROR, FS_INTEL_ERR_STORE,
			             _("The rules could not be applied."));
		why = error_text (local);
		o->result = FS_APPLY_FAILED;
		detail = g_strdup_printf ("source=%s result=failed digest=%s "
		                          "sets=%u error=%s", src, o->digest,
		                          o->sets, why);
		g_free (why);
		g_propagate_error (error, local);
		local = NULL;
		goto done;
	}

	o->result = FS_APPLY_OK;
	if (live == FS_INTEL_LIVE_INACTIVE && rs->sets->len > 0) {
		/* Written as asked, and not blocking yet: never let "applied"
		 * read as "protected" [S10]. */
		gchar *why = not_in_force_text (backend);

		g_ptr_array_add (o->notes, g_strdup_printf (
			_("The rules are in place, but not in force: %s"), why));
		o->not_in_force = why;
	}
	if (replaced)
		carry_counters (&store, snapshot, now);
	mark_counted_since (&store, rs, now);
	{
		Applied a = { 0 };

		a.digest = o->digest;
		a.applied_at = now;
		a.suspended = FALSE;
		a.count4 = o->count4;
		a.count6 = o->count6;
		a.ids = g_ptr_array_new ();
		a.ruled = g_ptr_array_new ();
		a.inputs = g_ptr_array_new_with_free_func (g_free);
		a.exceptions = exceptions_lines (config->exceptions);
		for (guint i = 0; i < rs->sets->len; i++) {
			const FsIntelSet *set = g_ptr_array_index (rs->sets, i);
			const gchar *ld = g_hash_table_lookup (digests, set->id);

			g_ptr_array_add (a.ids, set->id);
			if (!fs_range_set_is_empty (set->ranges))
				g_ptr_array_add (a.ruled, set->id);
			g_ptr_array_add (a.inputs, g_strdup_printf ("%s:%d:%s",
				set->id, (int) set->dir, ld != NULL ? ld : "-"));
		}
		if (!applied_write (&store, &a, &local)) {
			gchar *why = error_text (local);

			g_ptr_array_add (o->notes, g_strdup_printf (
				_("The rules are in force, but StockFW could not "
				  "record them (%s); the state will read "
				  "\"differs\"."), why));
			g_free (why);
			g_clear_error (&local);
		}
		g_ptr_array_free (a.ids, TRUE);
		g_ptr_array_free (a.ruled, TRUE);
		g_ptr_array_unref (a.inputs);
		g_ptr_array_unref (a.exceptions);
	}
	detail = g_strdup_printf ("source=%s result=ok digest=%s sets=%u "
	                          "v4=%u v6=%u", src, o->digest, o->sets,
	                          o->count4, o->count6);
done:
	audit ("intel-apply", detail);
	g_free (detail);
	if (snapshot != NULL)
		g_hash_table_unref (snapshot);
	if (after != NULL)
		g_hash_table_unref (after);
	g_free (before_digest);
	g_hash_table_unref (digests);
	fs_intel_ruleset_free (rs);
	engine_unlock (&lock);
	store_close (&store);
	return o;
}

FsIntelOutcome *
fs_intel_apply_safe (const FsBackend *backend, const FsIntelConfig *config,
                     const FsHostNet *host, const gchar *source,
                     const gchar *hold, GError **error)
{
	return apply_in (backend, config, host, source, hold, FALSE, error);
}

/* Remove the table, carrying its counters first.  suspend: the user
 * stopped the firewall, and applied.state says so ("intel-suspend");
 * otherwise an explicit clear, after which applied.state records
 * nothing loaded ("intel-clear"). */
static gboolean
take_down (const FsBackend *backend, const gchar *source, gboolean suspend,
           GError **error)
{
	const gchar *action = suspend ? "intel-suspend" : "intel-clear";
	Store store = STORE_INIT;
	EngineLock lock = ENGINE_LOCK_INIT;
	GError *local = NULL, *store_err = NULL;
	GHashTable *snapshot = NULL;
	Applied a = { 0 };
	const gchar *src = (source != NULL && *source) ? source : "-";
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;
	gboolean ok = TRUE, have_store, have_record;
	FsIntelLive live;
	gchar *detail;

	g_return_val_if_fail (backend != NULL, FALSE);
	if (backend->intel_clear == NULL)
		return TRUE;

	/* No store: no list was ever turned on here, and nothing applied
	 * (an apply needs the store).  A table left behind anyway (the
	 * store removed by hand) is still removed, but no store is made
	 * just to record a Stop. */
	if (!store_exists ()) {
		live = backend->intel_live != NULL ? backend->intel_live (NULL)
		                                   : FS_INTEL_LIVE_UNKNOWN;
		if (!live_holds (live))
			return TRUE;
		ok = backend->intel_clear (&local);
		if (ok) {
			detail = g_strdup_printf ("source=%s result=ok no-store",
			                          src);
		} else {
			gchar *why = error_text (local);

			detail = g_strdup_printf ("source=%s result=failed "
			                          "no-store error=%s", src, why);
			g_free (why);
		}
		audit (action, detail);
		g_free (detail);
		if (!ok)
			g_propagate_error (error, local);
		return ok;
	}

	have_store = store_open (&store, &store_err);
	if (have_store)
		engine_lock (&store, &lock);
	have_record = have_store && applied_read (&store, &a);

	/* No table: nothing to remove and nothing counted -- a Stop on a
	 * computer that never used a list runs one listing, no load. */
	live = backend->intel_live != NULL ? backend->intel_live (NULL)
	                                   : FS_INTEL_LIVE_UNKNOWN;
	if (live != FS_INTEL_LIVE_ABSENT) {
		snapshot = backend->intel_counters != NULL
		           ? backend->intel_counters () : NULL;
		ok = backend->intel_clear (&local);
	}
	if (!ok) {
		live = backend->intel_live != NULL ? backend->intel_live (NULL)
		                                   : FS_INTEL_LIVE_UNKNOWN;

		/* The table may be gone although the tool complained. */
		if (live == FS_INTEL_LIVE_ABSENT) {
			ok = TRUE;
			g_clear_error (&local);
		} else if (g_error_matches (local, G_IO_ERROR,
		                            G_IO_ERROR_NOT_FOUND) &&
		           have_store &&
		           (!have_record || !applied_loaded (&a))) {
			/* The tool is not even installed (Linux without nft),
			 * and StockFW's record says it never left a table there
			 * (or there is no record at all): nothing to remove,
			 * and a Stop is not an error. */
			ok = TRUE;
			g_clear_error (&local);
		}
	}
	if (ok && have_store) {
		carry_counters (&store, snapshot, now);
		if (!have_record || !suspend) {
			applied_clear (&a);
			applied_empty (&a, suspend);
		}
		a.suspended = suspend;
		if (!applied_write (&store, &a, &local))
			ok = FALSE;
	}
	if (ok && !have_store) {
		/* The table is gone; only the record is missing. */
		g_propagate_error (&local, store_err);
		store_err = NULL;
		ok = FALSE;
	}
	{
		gchar *why = ok ? NULL : error_text (local);

		detail = ok ? g_strdup_printf ("source=%s result=ok", src)
		            : g_strdup_printf ("source=%s result=failed error=%s",
		                               src, why);
		g_free (why);
	}
	audit (action, detail);
	g_free (detail);
	if (!ok)
		g_propagate_error (error, local);
	else
		g_clear_error (&local);
	g_clear_error (&store_err);
	if (snapshot != NULL)
		g_hash_table_unref (snapshot);
	applied_clear (&a);
	engine_unlock (&lock);
	if (have_store)
		store_close (&store);
	return ok;
}

gboolean
fs_intel_suspend (const FsBackend *backend, const gchar *source,
                  GError **error)
{
	return take_down (backend, source, TRUE, error);
}

gboolean
fs_intel_clear (const FsBackend *backend, const gchar *source,
                GError **error)
{
	return take_down (backend, source, FALSE, error);
}

FsIntelOutcome *
fs_intel_resume (const FsBackend *backend, const gchar *source,
                 const gchar *hold, GError **error)
{
	FsIntelConfig *config;
	FsIntelOutcome *o = NULL;
	Store store = STORE_INIT;
	EngineLock lock = ENGINE_LOCK_INIT;
	gboolean opened;

	g_return_val_if_fail (backend != NULL, NULL);
	/* Nothing to resume where nothing could be suspended, or where no
	 * list was ever turned on (no store). */
	if (backend->intel_apply == NULL || !store_exists ())
		return NULL;
	config = fs_intel_config_load (error);
	if (config == NULL)
		return NULL;

	/* The user started the firewall: from here on the lists are not
	 * off on purpose, whatever the apply below does.  A Start whose
	 * apply is held, refused (a tampered list, a limit) or fails reads
	 * "not-loaded", which says to apply, never "suspended", which says
	 * the firewall is stopped; the record says nothing is loaded,
	 * which is the truth until an apply succeeds. */
	opened = store_open (&store, NULL);
	if (opened) {
		Applied a;

		engine_lock (&store, &lock);
		if (applied_read (&store, &a) && a.suspended) {
			applied_clear (&a);
			applied_empty (&a, FALSE);
			applied_write (&store, &a, NULL);
		}
		applied_clear (&a);
	}
	/* Under the same lock: a Stop pressed right after this Start
	 * waits for the apply, then takes the lists down again. */
	if (want_any (config))
		o = apply_in (backend, config, NULL, source, hold,
		              engine_held (&lock), error);
	engine_unlock (&lock);
	if (opened)
		store_close (&store);
	fs_intel_config_free (config);
	return o;
}

/* ======================================================= honest state */

const gchar *
fs_intel_state_to_string (FsIntelState state)
{
	switch (state) {
	case FS_INTEL_STATE_OFF:         return "off";
	case FS_INTEL_STATE_ENFORCED:    return "enforced";
	case FS_INTEL_STATE_NOT_LOADED:  return "not-loaded";
	case FS_INTEL_STATE_DIFFERS:     return "differs";
	case FS_INTEL_STATE_SUSPENDED:   return "suspended";
	case FS_INTEL_STATE_UNSUPPORTED: return "unsupported";
	case FS_INTEL_STATE_NEEDS_ROOT:  return "needs-root";
	case FS_INTEL_STATE_NOT_IN_FORCE: return "not-in-force";
	case FS_INTEL_STATE_UNKNOWN:
	default:                         return "unknown";
	}
}

/* Why nothing is enforced, when nothing is (the "off" sentence). */
static gchar *
off_text (const FsIntelConfig *config)
{
	if (!config->enabled)
		return g_strdup (_("Threat intel is switched off."));
	if (any_location_enabled (config) && !geo_usable (config))
		return g_strdup (_("No blocklist is turned on; the location rules "
		                   "are not enforced because the location database "
		                   "is off."));
	return g_strdup (_("No blocklist is turned on."));
}

/* "2 lists are enforced: A, B." -- naming location rules as rules
 * (13.9). */
static gchar *
enforced_text (const FsIntelConfig *config, GPtrArray *ids)
{
	GString *names = g_string_new (NULL);
	guint lists = 0, rules = 0;
	gchar *out;

	for (guint i = 0; i < ids->len; i++) {
		const gchar *id = g_ptr_array_index (ids, i);
		const gchar *label = fs_intel_config_label (config, id);
		FsIntelSourceKind k = fs_intel_source_kind (id);

		if (k == FS_INTEL_KIND_COUNTRY || k == FS_INTEL_KIND_ASN)
			rules++;
		else
			lists++;
		g_string_append_printf (names, "%s%s", i ? ", " : "",
		                        label ? label : id);
	}
	if (rules == 0)
		out = lists == 1
		      ? g_strdup_printf (_("1 list is enforced: %s."), names->str)
		      : g_strdup_printf (_("%u lists are enforced: %s."), lists,
		                         names->str);
	else if (lists == 0)
		out = rules == 1
		      ? g_strdup_printf (_("1 location rule is enforced: %s."),
		                         names->str)
		      : g_strdup_printf (_("%u location rules are enforced: %s."),
		                         rules, names->str);
	else {
		gchar *l = lists == 1 ? g_strdup (_("1 list"))
		           : g_strdup_printf (_("%u lists"), lists);
		gchar *r = rules == 1 ? g_strdup (_("1 location rule"))
		           : g_strdup_printf (_("%u location rules"), rules);

		out = g_strdup_printf (_("%s and %s are enforced: %s."), l, r,
		                       names->str);
		g_free (l);
		g_free (r);
	}
	g_string_free (names, TRUE);
	return out;
}

static void
set_detail (gchar **detail, gchar *text)
{
	if (detail != NULL)
		*detail = text;
	else
		g_free (text);
}

/* The table carries the right digest, but the comment is all the
 * digest checks: a table whose chains were flushed (`nft flush table')
 * still carries it and blocks nothing.  Every set that had addresses
 * has its counter rules in the chains, which intel_counters lists
 * cheaply (never the sets' elements [S8.3]); the names of the lists
 * whose rules are gone, or NULL when none is (or when the chains cannot
 * be read: the digest is then all there is).  What this cannot see:
 * elements removed from a set, or some of a list's rules removed while
 * others remain. */
static gchar *
rules_missing (const FsBackend *backend, const FsIntelConfig *config,
               const Applied *a)
{
	GHashTable *counters;
	GString *names = NULL;

	if (a->ruled == NULL || a->ruled->len == 0 ||
	    backend->intel_counters == NULL)
		return NULL;
	counters = backend->intel_counters ();
	if (counters == NULL)
		return NULL;
	for (guint i = 0; i < a->ruled->len; i++) {
		const gchar *id = g_ptr_array_index (a->ruled, i);
		const gchar *label;

		if (g_hash_table_contains (counters, id))
			continue;
		label = fs_intel_config_label (config, id);
		if (names == NULL)
			names = g_string_new (NULL);
		g_string_append_printf (names, "%s%s", names->len ? ", " : "",
		                        label != NULL ? label : id);
	}
	g_hash_table_unref (counters);
	return names != NULL ? g_string_free (names, FALSE) : NULL;
}

FsIntelState
fs_intel_state (const FsBackend *backend, const FsIntelConfig *config,
                gchar **detail)
{
	FsIntelConfig *own = NULL;
	FsIntelState state;
	FsIntelLive live;
	Applied a = { 0 };
	Store store = STORE_INIT;
	GError *local = NULL;
	gchar *digest = NULL;
	gboolean have_record = FALSE, want, have_copy = FALSE;

	if (detail != NULL)
		*detail = NULL;
	if (backend == NULL || backend->intel_live == NULL ||
	    backend->intel_apply == NULL) {
		set_detail (detail, g_strdup (unsupported_text ()));
		return FS_INTEL_STATE_UNSUPPORTED;
	}
	if (!store_exists () && (config == NULL || !want_any (config))) {
		/* No list was ever turned on here: nothing to read, and a
		 * question about the state never creates the store. */
		live = backend->intel_live (NULL);
		if (live_holds (live)) {
			set_detail (detail, g_strdup (
				_("Blocklists are turned off, but " FS_INTEL_WHERE " still "
				  "holds blocklist rules; apply to remove them.")));
			return FS_INTEL_STATE_DIFFERS;
		}
		set_detail (detail, g_strdup (_("No blocklist is turned on.")));
		return FS_INTEL_STATE_OFF;
	}
	if (!store_open (&store, &local)) {
		state = g_error_matches (local, FS_INTEL_ERROR,
		                         FS_INTEL_ERR_NEEDS_ROOT)
		        ? FS_INTEL_STATE_NEEDS_ROOT : FS_INTEL_STATE_UNKNOWN;
		set_detail (detail, error_text (local));
		g_clear_error (&local);
		return state;
	}
	if (config == NULL) {
		own = config_load_in (&store, &local);
		if (own == NULL) {
			set_detail (detail, error_text (local));
			g_clear_error (&local);
			store_close (&store);
			return FS_INTEL_STATE_UNKNOWN;
		}
		config = own;
	}
	have_record = applied_read (&store, &a);
	want = want_any (config);
	/* Whether a list that is on has a copy to load: "not loaded" then
	 * says to apply, not to download. */
	if (want && have_record && a.ids->len == 0) {
		GPtrArray *ids = g_ptr_array_new ();
		GArray *dirs = g_array_new (FALSE, FALSE, sizeof (FsIntelDir));

		enabled_sources (config, ids, dirs);
		for (guint i = 0; i < ids->len && !have_copy; i++) {
			gboolean dmg = FALSE;
			FsIntelSourceState *st = state_read (&store,
				g_ptr_array_index (ids, i), NULL, &dmg);

			have_copy = st != NULL && st->fetched_at > 0;
			fs_intel_source_state_free (st);
		}
		g_ptr_array_free (ids, TRUE);
		g_array_free (dirs, TRUE);
	}
	store_close (&store);

	live = backend->intel_live (&digest);
	if (live == FS_INTEL_LIVE_UNKNOWN && !want &&
	    !(have_record && applied_loaded (&a))) {
		/* Off is "nothing turned on" (design 6.6), and StockFW's
		 * record says it left nothing in the kernel: a kernel that
		 * cannot be read -- Linux without nft -- does not make that
		 * unknown. */
		state = FS_INTEL_STATE_OFF;
		set_detail (detail, off_text (config));
		goto out;
	}
	if (live == FS_INTEL_LIVE_UNKNOWN &&
	    backend->intel_not_in_force != NULL) {
		/* The rules cannot be read, but the platform can say that
		 * nothing is enforced (Windows: the firewall service is
		 * stopped): that is the answer, whatever rules are there. */
		gchar *why = backend->intel_not_in_force ();

		if (why != NULL) {
			state = FS_INTEL_STATE_NOT_IN_FORCE;
			set_detail (detail, why);
			goto out;
		}
	}
	if (live == FS_INTEL_LIVE_UNKNOWN) {
		gchar *why = backend->intel_live_error != NULL
		             ? backend->intel_live_error () : NULL;

		state = running_as_root () ? FS_INTEL_STATE_UNKNOWN
		                           : FS_INTEL_STATE_NEEDS_ROOT;
		/* Say why when the backend can (no nft installed, a
		 * timeout): "could not be read" alone gives nothing to do. */
		/* Without rights, still say what the backend saw: when nft
		 * is missing, administrator rights alone will not help. */
		if (state == FS_INTEL_STATE_NEEDS_ROOT && why != NULL &&
		    *why != '\0')
			set_detail (detail, g_strdup_printf (
				_("Reading " FS_INTEL_WHERE "'s rules needs administrator "
				  "rights. %s"), why));
		else if (state == FS_INTEL_STATE_NEEDS_ROOT)
			set_detail (detail, g_strdup (
				_("Reading " FS_INTEL_WHERE "'s rules needs administrator "
				  "rights.")));
		else if (why != NULL && *why != '\0')
			set_detail (detail, g_strdup_printf (
				_(FS_INTEL_WHERE_CAP "'s rules could not be read: %s"), why));
		else
			set_detail (detail, g_strdup (
				_(FS_INTEL_WHERE_CAP "'s rules could not be read.")));
		g_free (why);
		goto out;
	}

	if (!want) {
		if (live == FS_INTEL_LIVE_ABSENT) {
			state = FS_INTEL_STATE_OFF;
			set_detail (detail, off_text (config));
		} else {
			state = FS_INTEL_STATE_DIFFERS;
			set_detail (detail, g_strdup (
				_("Blocklists are turned off, but " FS_INTEL_WHERE " still "
				  "holds blocklist rules; apply to remove them.")));
		}
		goto out;
	}
	if (have_record && a.suspended) {
		if (live == FS_INTEL_LIVE_ABSENT) {
			state = FS_INTEL_STATE_SUSPENDED;
			set_detail (detail, g_strdup (
				_("The firewall was stopped, so the blocklists are "
				  "off until it is started.")));
		} else {
			state = FS_INTEL_STATE_DIFFERS;
			set_detail (detail, g_strdup (
				_("The blocklists were suspended, but " FS_INTEL_WHERE " "
				  "holds blocklist rules StockFW did not apply.")));
		}
		goto out;
	}
	if (live == FS_INTEL_LIVE_INACTIVE) {
		/* Rules on the firewall that it does not enforce (Windows:
		 * off for the profile in use): whatever they are, they block
		 * nothing, and that comes first [S10]. */
		gchar *why = not_in_force_text (backend);

		state = FS_INTEL_STATE_NOT_IN_FORCE;
		if (have_record && digest != NULL &&
		    strcmp (digest, a.digest) == 0) {
			set_detail (detail, why);
		} else {
			set_detail (detail, g_strdup_printf (
				_("%s The rules there are not the ones StockFW "
				  "last applied either; apply once the firewall "
				  "is on."), why));
			g_free (why);
		}
		goto out;
	}
	if (live == FS_INTEL_LIVE_PRESENT && have_record && digest != NULL &&
	    strcmp (digest, a.digest) == 0 && a.ids->len > 0) {
		gchar *missing = rules_missing (backend, config, &a);

		if (missing != NULL) {
			state = FS_INTEL_STATE_DIFFERS;
			set_detail (detail, g_strdup_printf (
				_("The blocklist table is loaded, but the rules of "
				  "%s are gone (removed by another program); apply "
				  "to restore them."), missing));
			g_free (missing);
		} else {
			state = FS_INTEL_STATE_ENFORCED;
			set_detail (detail, enforced_text (config, a.ids));
		}
	} else if (live == FS_INTEL_LIVE_PRESENT) {
		state = FS_INTEL_STATE_DIFFERS;
		set_detail (detail, g_strdup (
			_(FS_INTEL_WHERE_CAP " holds blocklist rules, but not the ones "
			  "StockFW last applied; apply to replace them.")));
	} else if (live == FS_INTEL_LIVE_PARTIAL) {
		state = FS_INTEL_STATE_DIFFERS;
		set_detail (detail, g_strdup (
			_("Some of the blocklist rules are missing or were "
			  "changed outside StockFW; apply to restore them.")));
	} else {
		state = FS_INTEL_STATE_NOT_LOADED;
		if (have_record && a.ids->len == 0 && have_copy)
			set_detail (detail, g_strdup (
				_("The lists that are turned on are not in "
				  FS_INTEL_WHERE ": the last Start or apply was held "
				  "or did not finish; apply to load them.")));
		else if (have_record && a.ids->len == 0)
			set_detail (detail, g_strdup (
				_("The lists that are turned on have not been "
				  "applied (or not downloaded yet); update, then "
				  "apply.")));
		else
			set_detail (detail, g_strdup (
				_("The blocklists are not in " FS_INTEL_WHERE " ("
				  FS_INTEL_GONE_WHY "); apply to load them.")));
	}
out:
	g_free (digest);
	applied_clear (&a);
	fs_intel_config_free (own);
	return state;
}

GHashTable *
fs_intel_counters (const FsBackend *backend)
{
	GHashTable *out = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                         g_free, g_free);
	GHashTable *live = NULL;
	Store store;

	/* The carried totals live in the store; a question about the
	 * counters never creates one. */
	if (store_exists () && store_open (&store, NULL)) {
		FsIntelConfig *config = config_load_in (&store, NULL);
		GPtrArray *ids = g_ptr_array_new ();

		if (config != NULL) {
			for (guint i = 0; i < config->feeds->len; i++)
				g_ptr_array_add (ids, ((FsIntelFeedConf *)
				                 g_ptr_array_index (config->feeds, i))->id);
			for (guint i = 0; i < config->lists->len; i++)
				g_ptr_array_add (ids, ((FsIntelListConf *)
				                 g_ptr_array_index (config->lists, i))->id);
			for (guint i = 0; i < config->locations->len; i++)
				g_ptr_array_add (ids, ((FsIntelLocationConf *)
				                 g_ptr_array_index (config->locations,
				                                    i))->id);
		}
		for (guint i = 0; i < ids->len; i++) {
			gboolean damaged = FALSE;
			FsIntelSourceState *s = state_read (&store,
				g_ptr_array_index (ids, i), NULL, &damaged);

			if (s != NULL && (s->carried_packets || s->carried_bytes)) {
				FsIntelCounter *c = g_new0 (FsIntelCounter, 1);

				c->packets = s->carried_packets;
				c->bytes = s->carried_bytes;
				g_hash_table_insert (out, g_strdup (s->id), c);
			}
			fs_intel_source_state_free (s);
		}
		g_ptr_array_free (ids, TRUE);
		fs_intel_config_free (config);
		store_close (&store);
	}
	if (backend != NULL && backend->intel_counters != NULL)
		live = backend->intel_counters ();
	if (live != NULL) {
		GHashTableIter it;
		gpointer key, value;

		g_hash_table_iter_init (&it, live);
		while (g_hash_table_iter_next (&it, &key, &value)) {
			const FsIntelCounter *l = value;
			FsIntelCounter *c = g_hash_table_lookup (out, key);

			if (!fs_intel_id_is_valid (key))
				continue;
			if (c == NULL) {
				c = g_new0 (FsIntelCounter, 1);
				g_hash_table_insert (out, g_strdup (key), c);
			}
			c->packets = (c->packets > G_MAXUINT64 - l->packets)
			             ? G_MAXUINT64 : c->packets + l->packets;
			c->bytes = (c->bytes > G_MAXUINT64 - l->bytes)
			           ? G_MAXUINT64 : c->bytes + l->bytes;
		}
		g_hash_table_unref (live);
	}
	return out;
}

const gchar *
fs_intel_counts_unavailable (const FsBackend *backend)
{
	if (backend == NULL || backend->intel_apply == NULL ||
	    backend->intel_counters != NULL)
		return NULL;
	return _("Windows Firewall does not count what each rule blocks, so "
	         "StockFW cannot show blocked counts here.");
}

/* ============================================================== lookup */

void
fs_intel_lookup_clear (FsIntelLookup *result)
{
	if (result == NULL)
		return;
	if (result->sources != NULL)
		g_ptr_array_unref (result->sources);
	if (result->locations != NULL)
		g_ptr_array_unref (result->locations);
	if (result->locations_unknown != NULL)
		g_ptr_array_unref (result->locations_unknown);
	g_free (result->country_name);
	g_free (result->as_name);
	g_free (result->network);
	if (result->kernel_sources != NULL)
		g_ptr_array_unref (result->kernel_sources);
	g_free (result->state_detail);
	memset (result, 0, sizeof *result);
}

/* Whether a location rule holds a database answer. */
static gboolean
location_holds (const FsIntelLocationConf *l, const FsGeodbMatch *m)
{
	if (!m->found)
		return FALSE;
	if (l->kind == FS_INTEL_LOCATION_COUNTRY) {
		for (guint i = 0; m->country[0] != '\0' && l->countries[i]; i++)
			if (strcmp (l->countries[i], m->country) == 0)
				return TRUE;
		return FALSE;
	}
	for (guint i = 0; m->asn != 0 && i < l->asns->len; i++)
		if (g_array_index (l->asns, guint32, i) == m->asn)
			return TRUE;
	return FALSE;
}

/* The answer the lookup shows for an address: its own network, or for
 * a NAT64 address the database does not name, the IPv4 address it
 * carries (design 13.8). */
static void
lookup_fill (const GeoHandle *geo, const FsGeodbMatch *m, gboolean via_nat64,
             FsIntelLookup *result)
{
	FsGeodbCountry *c = m->country[0] != '\0'
	                    ? fs_geodb_country (geo->db, m->country) : NULL;

	result->geo_found = TRUE;
	result->geo_via_nat64 = via_nat64;
	memcpy (result->country, m->country, sizeof result->country);
	result->country_name = c != NULL ? g_strdup (c->name) : NULL;
	fs_geodb_country_free (c);
	result->asn = m->asn;
	result->as_name = g_strdup (m->as_name);
	result->geo_flags = m->flags;
	result->network = g_strdup (m->network);
}

/* Review GEO-1: no usable copy, but the kernel may still hold location
 * sets (a build fails closed and keeps what was applied).  The enabled
 * rules that applied.state says are in force are named as "may hold
 * it": the lookup never says "not blocked" for what it cannot read. */
static void
lookup_locations_unknown (const Store *store, const FsIntelConfig *config,
                          gboolean missing, FsIntelLookup *result)
{
	Applied a;

	if (applied_read (store, &a) && !a.suspended) {
		GPtrArray *in = a.ruled != NULL ? a.ruled : a.ids;

		for (guint i = 0; i < config->locations->len; i++) {
			const FsIntelLocationConf *l =
				g_ptr_array_index (config->locations, i);

			for (guint j = 0; l->enabled && j < in->len; j++)
				if (strcmp (g_ptr_array_index (in, j), l->id) == 0) {
					g_ptr_array_add (result->locations_unknown,
					                 g_strdup (l->id));
					break;
				}
		}
	}
	applied_clear (&a);
	result->geo_unknown = !missing || result->locations_unknown->len > 0;
}

/* The location half of a lookup (13.8): the address's own answer, and
 * the enabled rules that hold it -- as the kernel sees it: a NAT64
 * address is in an outbound rule's set when the IPv4 address inside it
 * is, and in no inbound one (unless the address itself is). */
static void
lookup_locations (const Store *store, const FsIntelConfig *config,
                  const gchar *addr, FsAddrFamily fam, gboolean nat64,
                  guint32 inner, FsIntelLookup *result)
{
	FsGeodbMatch own = { 0 }, mapped = { 0 };
	gboolean missing = FALSE, have_mapped = FALSE;
	GeoHandle *geo = geo_acquire (store, &missing, NULL);

	(void) fam;
	if (geo == NULL) {
		lookup_locations_unknown (store, config, missing, result);
		return;
	}
	if (fs_geodb_lookup (geo->db, addr, &own, NULL) && own.found)
		lookup_fill (geo, &own, FALSE, result);
	if (nat64) {
		gchar *v4 = g_strdup_printf ("%u.%u.%u.%u", inner >> 24,
		                             (inner >> 16) & 255, (inner >> 8) & 255,
		                             inner & 255);

		have_mapped = fs_geodb_lookup (geo->db, v4, &mapped, NULL);
		g_free (v4);
		if (have_mapped && mapped.found && !own.found)
			lookup_fill (geo, &mapped, TRUE, result);
	}
	for (guint i = 0; i < config->locations->len; i++) {
		const FsIntelLocationConf *l = g_ptr_array_index (config->locations,
		                                                  i);

		if (!l->enabled)
			continue;
		if (location_holds (l, &own) ||
		    (have_mapped && (l->dir & FS_INTEL_DIR_OUT) &&
		     location_holds (l, &mapped))) {
			g_ptr_array_add (result->locations, g_strdup (l->id));
			result->dir |= l->dir;
		}
	}
	fs_geodb_match_clear (&own);
	fs_geodb_match_clear (&mapped);
	geo_handle_unref (geo);
}

/* Membership as the kernel sees it: the address itself, or -- for a
 * set that blocks outbound -- its IPv4 form inside 64:ff9b::/96, which
 * the build adds to the set. */
static gboolean
set_holds (const FsRangeSet *set, FsAddrFamily fam, guint32 v4, FsU128 v6,
           gboolean nat64, guint32 inner, gboolean outbound)
{
	if (fam == FS_AF_V4)
		return fs_range_set_contains4 (set, v4);
	if (fs_range_set_contains6 (set, v6))
		return TRUE;
	return nat64 && outbound && fs_range_set_contains4 (set, inner);
}

static gboolean
in_set (const FsRangeSet *set, FsAddrFamily fam, guint32 v4, FsU128 v6,
        gboolean nat64, guint32 inner)
{
	FsRangeSet *n;
	gboolean hit;

	if (set == NULL)
		return FALSE;
	n = normalized_copy (set);
	hit = (fam == FS_AF_V4) ? fs_range_set_contains4 (n, v4)
	      : (fs_range_set_contains6 (n, v6) ||
	         (nat64 && fs_range_set_contains4 (n, inner)));
	fs_range_set_free (n);
	return hit;
}

gboolean
fs_intel_lookup (const FsIntelConfig *config, const FsHostNet *host,
                 const gchar *addr, FsIntelLookup *result)
{
	guint32 v4 = 0, inner = 0;
	FsU128 v6 = { 0, 0 };
	FsAddrFamily fam;
	gboolean nat64 = FALSE;
	Store store;

	g_return_val_if_fail (result != NULL, FALSE);
	memset (result, 0, sizeof *result);
	result->sources = g_ptr_array_new_with_free_func (g_free);
	result->locations = g_ptr_array_new_with_free_func (g_free);
	result->locations_unknown = g_ptr_array_new_with_free_func (g_free);
	if (config == NULL || addr == NULL)
		return FALSE;
	fam = fs_addr_parse (addr, &v4, &v6);
	if (fam == FS_AF_NONE)
		return FALSE;
	if (fam == FS_AF_V6)
		nat64 = nat64_embedded (v6, &inner);

	/* Protected: the address itself; for a NAT64 address, the IPv4
	 * address it stands for (64:ff9b::/96 is protected as a whole,
	 * yet outbound lists block their own entries in it). */
	if (fam == FS_AF_V4)
		result->is_protected = fs_range_set_contains4 (fs_range_protected (),
		                                               v4);
	else if (nat64)
		result->is_protected = fs_range_set_contains4 (fs_range_protected (),
		                                               inner);
	else
		result->is_protected = fs_range_set_contains6 (fs_range_protected (),
		                                               v6);
	result->is_exception = in_set (config->exceptions, fam, v4, v6, nat64,
	                               inner);
	if (host != NULL) {
		FsRangeSet *all = fs_hostnet_all (host);

		result->is_host = in_set (all, fam, v4, v6, nat64, inner);
		fs_range_set_free (all);
	}

	if (want_any (config) && store_open (&store, NULL)) {
		GPtrArray *ids = g_ptr_array_new ();
		GArray *dirs = g_array_new (FALSE, FALSE, sizeof (FsIntelDir));

		enabled_sources (config, ids, dirs);
		for (guint i = 0; i < ids->len; i++) {
			const gchar *id = g_ptr_array_index (ids, i);
			FsIntelDir dir = g_array_index (dirs, FsIntelDir, i);
			FsRangeSet *set = list_read (&store, id, NULL, NULL, NULL);

			if (set == NULL)
				continue;
			if (set_holds (set, fam, v4, v6, nat64, inner,
			               (dir & FS_INTEL_DIR_OUT) != 0)) {
				g_ptr_array_add (result->sources, g_strdup (id));
				result->dir |= dir;
			}
			fs_range_set_free (set);
		}
		g_ptr_array_free (ids, TRUE);
		g_array_free (dirs, TRUE);
		store_close (&store);
	}
	/* The location database answers for any address while it is on,
	 * also when no rule is: that is the enrichment events use. */
	if (geo_usable (config) && store_open (&store, NULL)) {
		lookup_locations (&store, config, addr, fam, nat64, inner, result);
		store_close (&store);
	}
	result->blocked = (result->sources->len > 0 ||
	                   result->locations->len > 0) &&
	                  !result->is_protected && !result->is_exception &&
	                  !result->is_host;
	/* the build keeps these out of every set, whatever the database */
	if (result->is_protected || result->is_exception || result->is_host)
		g_ptr_array_set_size (result->locations_unknown, 0);
	return TRUE;
}

/* The applied record's input for `id': its direction and list digest
 * (borrowed into *digest); FALSE when not recorded. */
static gboolean
applied_input (const Applied *a, const gchar *id, FsIntelDir *dir,
               const gchar **digest)
{
	gsize n = strlen (id);

	if (a->inputs == NULL)
		return FALSE;
	for (guint i = 0; i < a->inputs->len; i++) {
		const gchar *in = g_ptr_array_index (a->inputs, i);

		if (strncmp (in, id, n) == 0 && in[n] == ':' &&
		    in[n + 1] >= '1' && in[n + 1] <= '3' && in[n + 2] == ':') {
			*dir = (FsIntelDir) (in[n + 1] - '0');
			*digest = in + n + 3;
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean
str_array_has (const GPtrArray *a, const gchar *s)
{
	for (guint i = 0; a != NULL && i < a->len; i++)
		if (g_strcmp0 (g_ptr_array_index (a, i), s) == 0)
			return TRUE;
	return FALSE;
}

/* The location database as fs_intel_lookup_live() asks it: opened at
 * most once per call, and the address looked up once. */
typedef struct
{
	gboolean     tried;
	GeoHandle   *geo;
	FsGeodbMatch own, mapped;
	gboolean     have_mapped;
} LiveGeo;

static GeoHandle *
live_geo (const Store *store, const gchar *addr, gboolean nat64,
          guint32 inner, LiveGeo *g)
{
	gboolean missing = FALSE;

	if (g->tried)
		return g->geo;
	g->tried = TRUE;
	g->geo = geo_acquire (store, &missing, NULL);
	if (g->geo == NULL)
		return NULL;
	fs_geodb_lookup (g->geo->db, addr, &g->own, NULL);
	if (nat64) {
		gchar *v4 = g_strdup_printf ("%u.%u.%u.%u", inner >> 24,
		                             (inner >> 16) & 255, (inner >> 8) & 255,
		                             inner & 255);

		g->have_mapped = fs_geodb_lookup (g->geo->db, v4, &g->mapped, NULL);
		g_free (v4);
	}
	return g->geo;
}

static void
live_geo_clear (LiveGeo *g)
{
	fs_geodb_match_clear (&g->own);
	fs_geodb_match_clear (&g->mapped);
	geo_handle_unref (g->geo);
	memset (g, 0, sizeof *g);
}

/* Whether the kernel's set for location rule `id' holds the address:
 * 1 yes, 0 no, -1 cannot be told -- the rule is gone from the
 * configuration, the record names no input for it, or the copy of the
 * database or the rule's values are no longer the ones the set was
 * built from (location_input_digest). */
static int
live_location_holds (const Store *store, const FsIntelConfig *config,
                     const gchar *id, const gchar *want, FsIntelDir dir,
                     const gchar *addr, gboolean nat64, guint32 inner,
                     LiveGeo *g)
{
	const FsIntelLocationConf *l = fs_intel_config_location (config, id);
	GeoHandle *geo;
	gchar *have;
	gboolean same;

	if (l == NULL || want == NULL || strcmp (want, "-") == 0)
		return -1;
	geo = live_geo (store, addr, nat64, inner, g);
	if (geo == NULL)
		return -1;
	have = location_input_digest (geo, l);
	same = strcmp (have, want) == 0;
	g_free (have);
	if (!same)
		return -1;
	return location_holds (l, &g->own) ||
	       (g->have_mapped && (dir & FS_INTEL_DIR_OUT) &&
	        location_holds (l, &g->mapped));
}

void
fs_intel_lookup_live (const FsBackend *backend, const FsIntelConfig *config,
                      const gchar *addr, FsIntelLookup *result)
{
	guint32 v4 = 0, inner = 0;
	FsU128 v6 = { 0, 0 };
	FsAddrFamily fam;
	gboolean nat64 = FALSE, was_exception;
	Store store = STORE_INIT;
	Applied a = { 0 };
	LiveGeo g = { 0 };
	GPtrArray *ids;
	GArray *dirs;

	g_return_if_fail (result != NULL);
	g_clear_pointer (&result->state_detail, g_free);
	if (result->kernel_sources == NULL)
		result->kernel_sources = g_ptr_array_new_with_free_func (g_free);
	g_ptr_array_set_size (result->kernel_sources, 0);
	result->in_force = FALSE;
	result->pending = FALSE;
	result->uncertain = FALSE;
	result->state = fs_intel_state (backend, config, &result->state_detail);
	if (result->state != FS_INTEL_STATE_ENFORCED || config == NULL ||
	    addr == NULL)
		return;
	fam = fs_addr_parse (addr, &v4, &v6);
	if (fam == FS_AF_NONE)
		return;
	if (fam == FS_AF_V6)
		nat64 = nat64_embedded (v6, &inner);
	if (!store_exists () || !store_open (&store, NULL))
		return;
	if (!applied_read (&store, &a)) {
		store_close (&store);
		return;
	}

	/* The exceptions the kernel's sets were built without. */
	was_exception = result->is_exception;
	if (a.exceptions != NULL) {
		FsRangeSet *exc = fs_range_set_new ();
		GPtrArray *now = exceptions_lines (config->exceptions);
		gboolean same = now->len == a.exceptions->len;

		for (guint i = 0; i < a.exceptions->len; i++) {
			const gchar *line = g_ptr_array_index (a.exceptions, i);

			fs_range_set_add_text (exc, line);
			if (same && strcmp (line, g_ptr_array_index (now, i)) != 0)
				same = FALSE;
		}
		was_exception = in_set (exc, fam, v4, v6, nat64, inner);
		if (!same)
			result->pending = TRUE;
		fs_range_set_free (exc);
		g_ptr_array_unref (now);
	}

	/* Each set the kernel was given, as long as its stored list is the
	 * one it was built from. */
	for (guint i = 0; i < a.ids->len; i++) {
		const gchar *id = g_ptr_array_index (a.ids, i);
		const gchar *want = NULL;
		FsIntelDir dir = FS_INTEL_DIR_BOTH;
		gchar *have = NULL;
		FsRangeSet *set;
		gboolean recorded = applied_input (&a, id, &dir, &want);
		FsIntelSourceKind kind = fs_intel_source_kind (id);

		if (kind == FS_INTEL_KIND_COUNTRY || kind == FS_INTEL_KIND_ASN) {
			/* A location rule's set (design 13.8): asked only
			 * while the copy of the database and the rule's
			 * values are the ones it was built from. */
			int held = live_location_holds (&store, config, id,
			                                recorded ? want : NULL,
			                                dir, addr, nat64, inner,
			                                &g);

			if (held < 0) {
				result->pending = TRUE;
				result->uncertain = TRUE;
			} else if (held > 0) {
				g_ptr_array_add (result->kernel_sources,
				                 g_strdup (id));
			}
			continue;
		}
		if (!recorded) {
			FsIntelFeedConf *fc = fs_intel_config_feed (config, id);
			FsIntelListConf *lc = fs_intel_config_list (config, id);

			dir = fc != NULL ? fc->dir : lc != NULL ? lc->dir
			                                        : FS_INTEL_DIR_BOTH;
		}
		set = list_read (&store, id, &have, NULL, NULL);
		if (set == NULL || (recorded && g_strcmp0 (have, want) != 0)) {
			/* A newer copy (or none): what the kernel holds for
			 * this list is no longer on disk to ask. */
			result->pending = TRUE;
			result->uncertain = TRUE;
			fs_range_set_free (set);
			g_free (have);
			continue;
		}
		if (set_holds (set, fam, v4, v6, nat64, inner,
		               (dir & FS_INTEL_DIR_OUT) != 0))
			g_ptr_array_add (result->kernel_sources, g_strdup (id));
		fs_range_set_free (set);
		g_free (have);
	}

	/* Changes since: a source turned on or off, or its direction. */
	ids = g_ptr_array_new ();
	dirs = g_array_new (FALSE, FALSE, sizeof (FsIntelDir));
	enabled_sources (config, ids, dirs);
	if (geo_usable (config))
		for (guint i = 0; i < config->locations->len; i++) {
			FsIntelLocationConf *l = g_ptr_array_index (config->locations,
			                                            i);

			if (l->enabled) {
				g_ptr_array_add (ids, l->id);
				g_array_append_val (dirs, l->dir);
			}
		}
	for (guint i = 0; i < ids->len && !result->pending; i++) {
		const gchar *id = g_ptr_array_index (ids, i);
		FsIntelDir dir = 0;
		const gchar *want = NULL;
		FsIntelSourceKind kind = fs_intel_source_kind (id);

		if (!str_array_has (a.ids, id) &&
		    (kind == FS_INTEL_KIND_COUNTRY || kind == FS_INTEL_KIND_ASN)) {
			/* Turned on, and there is a database to build it
			 * from. */
			if (live_geo (&store, addr, nat64, inner, &g) != NULL)
				result->pending = TRUE;
		} else if (!str_array_has (a.ids, id)) {
			gboolean dmg = FALSE;
			FsIntelSourceState *st = state_read (&store, id, NULL,
			                                     &dmg);

			/* Turned on, and there is a copy to put in. */
			if (st != NULL && st->fetched_at > 0)
				result->pending = TRUE;
			fs_intel_source_state_free (st);
		} else if (applied_input (&a, id, &dir, &want) &&
		           dir != g_array_index (dirs, FsIntelDir, i)) {
			result->pending = TRUE;
		}
	}
	for (guint i = 0; i < a.ids->len && !result->pending; i++)
		if (!str_array_has (ids, g_ptr_array_index (a.ids, i)))
			result->pending = TRUE;
	g_ptr_array_free (ids, TRUE);
	g_array_free (dirs, TRUE);

	result->in_force = result->kernel_sources->len > 0 &&
	                   !result->is_protected && !was_exception &&
	                   !result->is_host;
	live_geo_clear (&g);
	applied_clear (&a);
	store_close (&store);
}

gchar *
fs_intel_lookup_sentence (const FsIntelConfig *config,
                          const FsIntelLookup *result)
{
	GString *out;
	guint n = 0;

	if (result == NULL || result->sources == NULL)
		return NULL;
	out = g_string_new (NULL);
	if (result->blocked) {
		g_string_append (out, _("Blocked by threat intel: "));
		for (guint i = 0; i < result->sources->len; i++, n++) {
			const gchar *id = g_ptr_array_index (result->sources, i);
			const gchar *label = fs_intel_config_label (config, id);

			g_string_append_printf (out, "%s%s", n ? ", " : "",
			                        label ? label : id);
		}
		for (guint i = 0; result->locations != NULL &&
		                  i < result->locations->len; i++, n++) {
			const gchar *id = g_ptr_array_index (result->locations, i);
			const gchar *label = fs_intel_config_label (config, id);

			g_string_append_printf (out, "%s%s", n ? ", " : "",
			                        label ? label : id);
		}
		if (n == 0)
			g_string_truncate (out, 0);
	}
	/* Review GEO-1: never "not blocked" for what cannot be read. */
	if (result->locations_unknown != NULL &&
	    result->locations_unknown->len > 0) {
		if (out->len > 0)
			g_string_append (out, ". ");
		g_string_append (out, _("May be blocked by threat intel: "));
		for (guint i = 0; i < result->locations_unknown->len; i++) {
			const gchar *id = g_ptr_array_index (result->locations_unknown,
			                                     i);
			const gchar *label = fs_intel_config_label (config, id);

			g_string_append_printf (out, "%s%s", i ? ", " : "",
			                        label ? label : id);
		}
		g_string_append (out, _(" (the location database in use cannot "
		                        "be read)."));
	}
	if (out->len == 0) {
		g_string_free (out, TRUE);
		return NULL;
	}
	return g_string_free (out, FALSE);
}

/* ================================== the location database (13.8, 13.11) */

void
fs_intel_geo_status_clear (FsIntelGeoStatus *status)
{
	if (status == NULL)
		return;
	g_free (status->last_error);
	g_free (status->refused);
	g_free (status->damaged);
	g_free (status->license);
	memset (status, 0, sizeof *status);
}

gboolean
fs_intel_geo_status (FsIntelGeoStatus *status, gint64 now, GError **error)
{
	Store store;
	GeoState g;
	GeoHandle *geo;
	GError *local = NULL;
	gboolean missing = FALSE;

	g_return_val_if_fail (status != NULL, FALSE);
	memset (status, 0, sizeof *status);
	if (!store_open (&store, error))
		return FALSE;
	geo_state_read (&store, &g);
	status->attempted_at = g.attempted_at;
	status->fetched_at = g.fetched_at;
	status->last_error = g_strdup (g.last_error);
	status->refused = g_strdup (g.refused);
	geo_state_clear (&g);
	geo = geo_acquire (&store, &missing, &local);
	if (geo != NULL) {
		const FsGeodbInfo *info = fs_geodb_info (geo->db);

		status->present = TRUE;
		status->created_at = info->created_at;
		status->stale = fs_geodb_is_stale (info->created_at, now);
		status->license = g_strdup (info->license);
		status->networks = info->networks;
		status->countries = info->countries;
		status->ases = info->ases;
		geo_handle_unref (geo);
	} else if (!missing) {
		status->damaged = error_text (local);
	}
	g_clear_error (&local);
	store_close (&store);
	return TRUE;
}

/* The copy in use, or an error that says why there is none. */
static GeoHandle *
geo_open_for_use (GError **error)
{
	Store store;
	GeoHandle *geo;
	gboolean missing = FALSE;

	if (!store_open (&store, error))
		return NULL;
	geo = geo_acquire (&store, &missing, error);
	store_close (&store);
	if (geo == NULL && missing)
		g_set_error_literal (error, FS_INTEL_ERROR, FS_INTEL_ERR_STORE,
		                     _("The location database has not been "
		                       "downloaded yet."));
	return geo;
}

GPtrArray *
fs_intel_geo_countries (GError **error)
{
	GeoHandle *geo = geo_open_for_use (error);
	GPtrArray *out;

	if (geo == NULL)
		return NULL;
	out = fs_geodb_countries (geo->db);
	geo_handle_unref (geo);
	return out;
}

GPtrArray *
fs_intel_geo_search_as (const gchar *query, guint max, GError **error)
{
	GeoHandle *geo = geo_open_for_use (error);
	GPtrArray *out;

	if (geo == NULL)
		return NULL;
	out = fs_geodb_search_as (geo->db, query, max);
	geo_handle_unref (geo);
	return out;
}

gboolean
fs_intel_location_stats (const FsIntelConfig *config,
                         FsIntelLocationKind kind,
                         const gchar *const *values,
                         FsIntelLocationStats *stats, GError **error)
{
	FsGeodbFilter f = { NULL, NULL, 0, 0 };
	FsGeodbFilter af = { NULL, NULL, 0, FS_GEODB_FLAG_ANYCAST };
	FsRangeSet *set, *anycast, *a;
	GPtrArray *prefixes;
	GeoHandle *geo;
	gchar **codes = NULL, *why = NULL;
	GArray *asns = NULL;

	g_return_val_if_fail (stats != NULL, FALSE);
	memset (stats, 0, sizeof *stats);
	if (!location_values (kind, values, &codes, &asns, &why)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("Not a location rule: %s."), why);
		g_free (why);
		return FALSE;
	}
	geo = geo_open_for_use (error);
	if (geo == NULL) {
		g_strfreev (codes);
		if (asns != NULL)
			g_array_unref (asns);
		return FALSE;
	}
	f.countries = (const gchar *const *) codes;
	if (asns != NULL) {
		f.asns = (const guint32 *) (gpointer) asns->data;
		f.n_asns = asns->len;
	}
	set = fs_geodb_enumerate (geo->db, &f, NULL);
	anycast = fs_geodb_enumerate (geo->db, &af, NULL);
	if (set == NULL)
		set = fs_range_set_new ();
	if (anycast == NULL)
		anycast = fs_range_set_new ();
	fs_range_set_subtract (set, fs_range_protected ());
	if (config != NULL) {
		FsRangeSet *ex = normalized_copy (config->exceptions);

		fs_range_set_subtract (set, ex);
		fs_range_set_free (ex);
	}
	prefixes = fs_geodb_set_prefixes (set);
	for (guint i = 0; i < prefixes->len; i++) {
		if (strchr (g_ptr_array_index (prefixes, i), ':') != NULL)
			stats->prefixes6++;
		else
			stats->prefixes4++;
	}
	g_ptr_array_unref (prefixes);
	stats->addresses4 = fs_range_set_addresses4 (set);
	stats->addresses6 = fs_range_set_addresses6 (set);
	a = intersect (set, anycast);
	prefixes = fs_geodb_set_prefixes (a);
	stats->anycast_prefixes = prefixes->len;
	stats->anycast_addresses4 = fs_range_set_addresses4 (a);
	stats->anycast_addresses6 = fs_range_set_addresses6 (a);
	g_ptr_array_unref (prefixes);
	fs_range_set_free (a);
	fs_range_set_free (set);
	fs_range_set_free (anycast);
	g_strfreev (codes);
	if (asns != NULL)
		g_array_unref (asns);
	geo_handle_unref (geo);
	return TRUE;
}

gboolean
fs_intel_geo_lookup (const FsIntelConfig *config, const gchar *addr,
                     FsGeodbMatch *match, GError **error)
{
	GeoHandle *geo;
	gboolean ok;

	g_return_val_if_fail (match != NULL, FALSE);
	memset (match, 0, sizeof *match);
	if (config == NULL || !geo_usable (config)) {
		g_set_error_literal (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		                     _("The location database is turned off."));
		return FALSE;
	}
	geo = geo_open_for_use (error);
	if (geo == NULL)
		return FALSE;
	ok = fs_geodb_lookup (geo->db, addr, match, error);
	geo_handle_unref (geo);
	return ok;
}

/* ===================================================== applied journal */

#ifdef __linux__
G_LOCK_DEFINE_STATIC (applied_cache);
static gint64 cache_mtime_ns = -1;
static gint64 cache_size = -1;
static guint64 cache_ino;
static GHashTable *cache_ids;
#endif

gboolean
fs_intel_applied_has (const gchar *id)
{
#ifdef __linux__
	Store store;
	struct stat st;
	gboolean has = FALSE;

	/* No store: nothing was ever applied.  The Linux log reader asks
	 * this for every "STOCKFW-TI" line, which is only text in the
	 * kernel log; it must not create the store any more than the other
	 * read-only questions do. */
	if (!fs_intel_id_is_valid (id) || !store_exists () ||
	    !store_open (&store, NULL))
		return FALSE;
	G_LOCK (applied_cache);
	if (fstatat (store.fd, APPLIED_NAME, &st, AT_SYMLINK_NOFOLLOW) != 0) {
		g_clear_pointer (&cache_ids, g_hash_table_unref);
		cache_mtime_ns = -1;
	} else {
		gint64 mtime = (gint64) st.st_mtim.tv_sec * 1000000000 +
		               st.st_mtim.tv_nsec;

		if (cache_ids == NULL || mtime != cache_mtime_ns ||
		    (gint64) st.st_size != cache_size ||
		    (guint64) st.st_ino != cache_ino) {
			Applied a;

			g_clear_pointer (&cache_ids, g_hash_table_unref);
			cache_ids = g_hash_table_new_full (g_str_hash, g_str_equal,
			                                   g_free, NULL);
			if (applied_read (&store, &a) && !a.suspended)
				for (guint i = 0; i < a.ids->len; i++)
					g_hash_table_add (cache_ids, g_strdup (
						g_ptr_array_index (a.ids, i)));
			applied_clear (&a);
			cache_mtime_ns = mtime;
			cache_size = (gint64) st.st_size;
			cache_ino = (guint64) st.st_ino;
		}
		has = g_hash_table_contains (cache_ids, id);
	}
	G_UNLOCK (applied_cache);
	store_close (&store);
	return has;
#elif defined G_OS_WIN32
	/* Windows: no log reader asks this per line; the Threat Intel page
	 * asks once per list per refresh, so applied.state is read each
	 * time (no cache keyed on the file's identity). */
	Store store = STORE_INIT;
	Applied a;
	gboolean has = FALSE;

	if (!fs_intel_id_is_valid (id) || !store_exists () ||
	    !store_open (&store, NULL))
		return FALSE;
	if (applied_read (&store, &a) && !a.suspended)
		has = str_array_has (a.ids, id);
	applied_clear (&a);
	store_close (&store);
	return has;
#else
	return FALSE;
#endif
}

/* ======================================================== event rules */

G_LOCK_DEFINE_STATIC (rule_labels);
static GHashTable *rule_labels;

gchar *
fs_intel_rule_text (const gchar *id)
{
	const FsFeedInfo *fi;
	const gchar *label;
	gchar *name = NULL, *out;

	if (id == NULL)
		return NULL;
	G_LOCK (rule_labels);
	if (rule_labels == NULL)
		rule_labels = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                     g_free, g_free);
	label = g_hash_table_lookup (rule_labels, id);
	if (label != NULL) {
		out = g_strdup_printf (_("Threat intel: %s"), label);
		G_UNLOCK (rule_labels);
		return out;
	}
	G_UNLOCK (rule_labels);

	fi = fs_feed_catalog_find (id);
	if (fi != NULL) {
		name = g_strdup (fi->name);
	} else if (store_exists ()) {
		FsIntelConfig *config = fs_intel_config_load (NULL);

		if (config != NULL && fs_intel_config_label (config, id) != NULL)
			name = g_strdup (fs_intel_config_label (config, id));
		fs_intel_config_free (config);
	}
	if (name == NULL)
		return g_strdup_printf (_("Threat intel: %s"), id);
	out = g_strdup_printf (_("Threat intel: %s"), name);
	G_LOCK (rule_labels);
	g_hash_table_replace (rule_labels, g_strdup (id), name);
	G_UNLOCK (rule_labels);
	return out;
}
