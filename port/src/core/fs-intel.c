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
 * The store is Linux-only in Round 1; on any other platform every call
 * that needs it fails with FS_INTEL_ERR_UNSUPPORTED (Round 3 brings the
 * Windows store), while the in-memory parts (the config structure, the
 * build from a given host, lookups' sentence) still compile and work.
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
#else
	g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNSUPPORTED,
	             _("Blocklists are not available on this platform yet."));
	return NULL;
#endif
}

/* An open store: a directory descriptor every file operation goes
 * through (openat, renameat, unlinkat) [S2.3]. */
typedef struct
{
	int fd;
} Store;

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
#endif
	store->fd = -1;
}

/* ---- the engine lock ------------------------------------------------
 * Every operation that changes the kernel's table or applied.state
 * (an apply, a Stop, a clear, a Start) holds an exclusive flock on
 * <store>/engine.lock, so the CLI, cron, the app and the app's own
 * threads never interleave them: a Stop that arrives during an apply
 * waits for it and then takes the table down, instead of being undone
 * by the apply's record.  flock locks belong to the open file, so two
 * threads of one process that each open the file exclude each other
 * too.  -1 when the lock file cannot be opened: the operation then
 * goes ahead unlocked, as before (a store that cannot hold a lock file
 * cannot hold a record either, and says so on the write). */
typedef struct
{
	int  fd;
	gboolean waited;   /* another operation held it first */
} EngineLock;

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
#endif
}

static void
engine_unlock (EngineLock *lock)
{
#ifdef __linux__
	if (lock->fd >= 0)
		close (lock->fd);   /* releases the flock */
#endif
	lock->fd = -1;
}

static void
store_error (GError **error, const gchar *name, const gchar *why)
{
	g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_STORE,
	             _("Threat-intel file %s: %s."), name, why);
}

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

const gchar *
fs_intel_config_label (const FsIntelConfig *config, const gchar *id)
{
	FsIntelFeedConf *f = fs_intel_config_feed (config, id);
	FsIntelListConf *l;

	if (f != NULL) {
		const FsFeedInfo *fi;

		if (f->custom)
			return f->name;
		fi = fs_feed_catalog_find (id);
		return fi != NULL ? _(fi->name) : f->id;
	}
	l = fs_intel_config_list (config, id);
	return l != NULL ? l->name : NULL;
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
	}

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
	if (f == NULL && l == NULL)
		return unknown_source (error, id);
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

	g_return_val_if_fail (config != NULL, FALSE);
	if (f == NULL && l == NULL)
		return unknown_source (error, id);
	if (!dir_arg_ok (dir, FALSE, error))
		return FALSE;
	if (f != NULL)
		f->dir = dir;
	else
		l->dir = dir;
	return TRUE;
}

gboolean
fs_intel_config_set_enabled (FsIntelConfig *config, const gchar *id,
                             gboolean enabled, GError **error)
{
	FsIntelFeedConf *f = fs_intel_config_feed (config, id);
	FsIntelListConf *l = fs_intel_config_list (config, id);

	g_return_val_if_fail (config != NULL, FALSE);
	if (f == NULL && l == NULL)
		return unknown_source (error, id);
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
		  "list on the Threat Intel page, or run \"sudo stockfw intel "
		  "except <address>\"."));
	g_free (often);
	g_free (host);
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
#else
	g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNSUPPORTED,
	             _("Blocklists are not available on this platform yet."));
	return NULL;
#endif
}

gboolean
fs_intel_import_list (FsIntelConfig *config, const gchar *path,
                      const gchar *name, FsIntelDir dir,
                      FsFeedParseStats *stats, gchar **id_out,
                      GError **error)
{
	FsFeedParseStats st = { 0 };
	FsIntelSourceState *s = NULL, *old;
	FsIntelListConf *l;
	FsRangeSet *set = NULL;
	Store store = { -1 };
	GError *local = NULL;
	gchar *data = NULL, *id = NULL, *digest = NULL;
	gboolean damaged = FALSE, ok = FALSE;
	gsize len = 0;
	gint64 now = g_get_real_time () / G_USEC_PER_SEC;

	g_return_val_if_fail (config != NULL && path != NULL, FALSE);
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
	data = read_user_file (path, &len, error);
	if (data == NULL)
		goto out;
	set = fs_feed_parse_csv (data, len, &st, &local);
	if (stats != NULL)
		*stats = st;
	if (set == NULL) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("%s was not imported: %s"), path,
		             local ? local->message : "");
		g_clear_error (&local);
		goto out;
	}
	if (fs_range_set_is_empty (set)) {
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
		             _("%s holds no address that could be blocked."),
		             path);
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
		                                 st.entries, path);
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
	EngineLock lock = { -1, FALSE };

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

GPtrArray *
fs_intel_update (const FsIntelConfig *config, const gchar *only_id,
                 guint flags, gint64 now)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_intel_update_result_free);
	Store store = { -1 };
	GError *local = NULL;
	gboolean opened = FALSE;

	g_return_val_if_fail (config != NULL, out);

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

/* The largest sets, for a limit's error: "A (12,345), B (9,000)". */
static gchar *
largest_sets (const FsIntelRuleset *rs, gboolean by_cover)
{
	GPtrArray *order = g_ptr_array_new ();
	GString *out = g_string_new (NULL);

	for (guint i = 0; i < rs->sets->len; i++)
		g_ptr_array_add (order, g_ptr_array_index (rs->sets, i));
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

static FsIntelRuleset *
build_in (const Store *store, const FsIntelConfig *config,
          const FsHostNet *host, GPtrArray *notes, GHashTable *digests,
          GError **error)
{
	FsIntelRuleset *rs = fs_intel_ruleset_new ();
	GPtrArray *ids = g_ptr_array_new ();
	GArray *dirs = g_array_new (FALSE, FALSE, sizeof (FsIntelDir));
	KeepKind kinds[7];
	FsRangeSet *keep_all = fs_range_set_new ();
	FsRangeSet *hits[7] = { NULL };
	GPtrArray *hit_labels[7] = { NULL };
	FsRangeSet *union4 = fs_range_set_new ();
	guint nkinds = 0;
	guint64 intervals = 0;
	gboolean ok = TRUE;

	if (!want_any (config))
		goto out;

	kinds[nkinds++] = (KeepKind) { config->exceptions, _("an exception") };
	if (host != NULL) {
		kinds[nkinds++] = (KeepKind) { host->own,
			_("this computer's own address") };
		kinds[nkinds++] = (KeepKind) { host->onlink,
			_("a network this computer is connected to") };
		kinds[nkinds++] = (KeepKind) { host->gateways,
			_("a default gateway") };
		kinds[nkinds++] = (KeepKind) { host->resolvers,
			_("a DNS server in use") };
		kinds[nkinds++] = (KeepKind) { host->sessions,
			_("an SSH session to this computer") };
		kinds[nkinds++] = (KeepKind) { host->update_hosts,
			_("a feed's download server or proxy") };
	}
	for (guint k = 0; k < nkinds; k++) {
		FsRangeSet *n = normalized_copy (kinds[k].set);

		kinds[k].set = n;
		fs_range_set_union (keep_all, n);
		hits[k] = fs_range_set_new ();
		hit_labels[k] = g_ptr_array_new ();
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

		/* What each kind keeps reachable from this set. */
		for (guint k = 0; k < nkinds; k++) {
			FsRangeSet *h = intersect (set, kinds[k].set);

			if (!fs_range_set_is_empty (h)) {
				fs_range_set_union (hits[k], h);
				g_ptr_array_add (hit_labels[k], (gpointer) label);
			}
			fs_range_set_free (h);
		}
		fs_range_set_subtract (set, keep_all);

		/* NAT64: an outbound list also stops 64:ff9b::<listed v4>,
		 * or a NAT64 network would reach the address anyway. */
		if (dir & FS_INTEL_DIR_OUT) {
			FsRangeSet *mapped = fs_range_set_new ();

			for (guint j = 0; j < set->v4->len; j++) {
				const FsRange4 *r = &g_array_index (set->v4,
				                                    FsRange4, j);
				FsU128 a = { NAT64_HI, r->start };
				FsU128 b = { NAT64_HI, r->end };

				fs_range_set_add6 (mapped, a, b);
			}
			fs_range_set_normalize (mapped);
			/* Exceptions and kept addresses written in their
			 * NAT64 form stay reachable too. */
			fs_range_set_subtract (mapped, keep_all);
			fs_range_set_union (set, mapped);
			fs_range_set_free (mapped);
		}
		fs_range_set_union (union4, set);
		intervals += fs_range_set_count4 (set) + fs_range_set_count6 (set);
		if (!fs_intel_ruleset_add (rs, id, label, dir, set)) {
			g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_INVALID,
			             _("%s cannot be enforced: its id is not "
			               "valid."), id);
			ok = FALSE;
		}
	}

	if (ok && intervals > FS_INTEL_MAX_INTERVALS) {
		gchar *big = largest_sets (rs, FALSE);
		gchar *n = grouped (intervals);

		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_TOO_BIG,
		             _("The lists together have %s entries, more than "
		               "the 300,000 StockFW enforces; the largest are "
		               "%s."), n, big);
		g_free (n);
		g_free (big);
		ok = FALSE;
	} else if (ok && fs_range_set_addresses4 (union4) > FS_INTEL_MAX_UNION4) {
		gchar *big = largest_sets (rs, TRUE);

		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_TOO_BIG,
		             _("The lists together cover more than 2^26 IPv4 "
		               "addresses; the largest are %s."), big);
		g_free (big);
		ok = FALSE;
	}

	if (ok) {
		for (guint k = 0; k < nkinds; k++) {
			if (k == 0) {
				/* Exceptions: their own sentence. */
				if (!fs_range_set_is_empty (hits[0])) {
					gchar *a = addrs_text (hits[0]);

					g_ptr_array_add (hit_labels[0], NULL);
					{
						gchar *names = g_strjoinv (", ",
							(gchar **) hit_labels[0]->pdata);
						g_ptr_array_add (notes, g_strdup_printf (
							_("Not blocked, by exception: %s "
							  "(listed by %s)."), a, names));
						g_free (names);
					}
					g_ptr_array_remove_index (hit_labels[0],
						hit_labels[0]->len - 1);
					g_free (a);
				}
				continue;
			}
			note_kept (notes, kinds[k].what, hits[k], hit_labels[k]);
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
	for (guint k = 0; k < nkinds; k++) {
		fs_range_set_free ((FsRangeSet *) kinds[k].set);
		fs_range_set_free (hits[k]);
		g_ptr_array_free (hit_labels[k], TRUE);
	}
	fs_range_set_free (keep_all);
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
	Store store = { -1 };

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

		if (s != NULL && s->counted_since == 0) {
			s->counted_since = now;
			state_write (store, s, ld, NULL);
		}
		fs_intel_source_state_free (s);
		g_free (ld);
	}
}

/* Whether the kernel holds what `rs' should leave there: its table with
 * its digest, or (the empty rule set renders no table) none at all.
 * *live receives what was read. */
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
		match = (*live == FS_INTEL_LIVE_PRESENT && got != NULL &&
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
	Store store = { -1 };
	EngineLock lock = { -1, FALSE };
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
		g_set_error (error, FS_INTEL_ERROR, FS_INTEL_ERR_UNSUPPORTED,
		             _("Blocklists are not available on this platform "
		               "yet."));
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
		             _("The rules were applied, but the kernel holds "
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
			           (before == FS_INTEL_LIVE_PRESENT &&
			            g_strcmp0 (before_digest, o->digest) != 0);
		else if (matches)
			replaced = before == FS_INTEL_LIVE_PRESENT ||
			           snapshot != NULL;
		if (!replaced && counted_anything (snapshot)) {
			after = backend->intel_counters != NULL
			        ? backend->intel_counters () : NULL;
			replaced = counters_went_down (snapshot, after);
		}
	}
	if (ok && !said_ok && !replaced && rs->sets->len > 0 &&
	    before == FS_INTEL_LIVE_PRESENT &&
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
			_("The kernel reported an error (%s), but holds the "
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
	Store store = { -1 };
	EngineLock lock = { -1, FALSE };
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
		if (live != FS_INTEL_LIVE_PRESENT)
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
	Store store = { -1 };
	EngineLock lock = { -1, FALSE };

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
	if (store_open (&store, NULL)) {
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
		              lock.fd >= 0, error);
	engine_unlock (&lock);
	if (store.fd >= 0)
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
	case FS_INTEL_STATE_UNKNOWN:
	default:                         return "unknown";
	}
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
	Store store = { -1 };
	GError *local = NULL;
	gchar *digest = NULL;
	gboolean have_record = FALSE, want, have_copy = FALSE;

	if (detail != NULL)
		*detail = NULL;
	if (backend == NULL || backend->intel_live == NULL ||
	    backend->intel_apply == NULL) {
		set_detail (detail, g_strdup (_("Blocklists are not available "
		                                "on this platform yet.")));
		return FS_INTEL_STATE_UNSUPPORTED;
	}
	if (!store_exists () && (config == NULL || !want_any (config))) {
		/* No list was ever turned on here: nothing to read, and a
		 * question about the state never creates the store. */
		live = backend->intel_live (NULL);
		if (live == FS_INTEL_LIVE_PRESENT) {
			set_detail (detail, g_strdup (
				_("Blocklists are turned off, but the kernel still "
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
		set_detail (detail, g_strdup (config->enabled
			? _("No blocklist is turned on.")
			: _("Threat intel is switched off.")));
		goto out;
	}
	if (live == FS_INTEL_LIVE_UNKNOWN) {
		gchar *why = backend->intel_live_error != NULL
		             ? backend->intel_live_error () : NULL;

		state = running_as_root () ? FS_INTEL_STATE_UNKNOWN
		                           : FS_INTEL_STATE_NEEDS_ROOT;
		/* Say why when the backend can (no nft installed, a
		 * timeout): "could not be read" alone gives nothing to do. */
		if (state == FS_INTEL_STATE_NEEDS_ROOT)
			set_detail (detail, g_strdup (
				_("Reading the kernel's rules needs administrator "
				  "rights.")));
		else if (why != NULL && *why != '\0')
			set_detail (detail, g_strdup_printf (
				_("The kernel's rules could not be read: %s"), why));
		else
			set_detail (detail, g_strdup (
				_("The kernel's rules could not be read.")));
		g_free (why);
		goto out;
	}

	if (!want) {
		if (live == FS_INTEL_LIVE_ABSENT) {
			state = FS_INTEL_STATE_OFF;
			set_detail (detail, g_strdup (config->enabled
				? _("No blocklist is turned on.")
				: _("Threat intel is switched off.")));
		} else {
			state = FS_INTEL_STATE_DIFFERS;
			set_detail (detail, g_strdup (
				_("Blocklists are turned off, but the kernel still "
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
				_("The blocklists were suspended, but the kernel "
				  "holds blocklist rules StockFW did not apply.")));
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
			GString *names = g_string_new (NULL);

			state = FS_INTEL_STATE_ENFORCED;
			for (guint i = 0; i < a.ids->len; i++) {
				const gchar *id = g_ptr_array_index (a.ids, i);
				const gchar *label = fs_intel_config_label (config,
				                                            id);

				g_string_append_printf (names, "%s%s",
				                        i ? ", " : "",
				                        label ? label : id);
			}
			set_detail (detail, a.ids->len == 1
				? g_strdup_printf (_("1 list is enforced: %s."),
				                   names->str)
				: g_strdup_printf (_("%u lists are enforced: %s."),
				                   a.ids->len, names->str));
			g_string_free (names, TRUE);
		}
	} else if (live == FS_INTEL_LIVE_PRESENT) {
		state = FS_INTEL_STATE_DIFFERS;
		set_detail (detail, g_strdup (
			_("The kernel holds blocklist rules, but not the ones "
			  "StockFW last applied; apply to replace them.")));
	} else {
		state = FS_INTEL_STATE_NOT_LOADED;
		if (have_record && a.ids->len == 0 && have_copy)
			set_detail (detail, g_strdup (
				_("The lists that are turned on are not in the "
				  "kernel: the last Start or apply was held or did "
				  "not finish; apply to load them.")));
		else if (have_record && a.ids->len == 0)
			set_detail (detail, g_strdup (
				_("The lists that are turned on have not been "
				  "applied (or not downloaded yet); update, then "
				  "apply.")));
		else
			set_detail (detail, g_strdup (
				_("The blocklists are not in the kernel (after a "
				  "restart, or removed by another program); apply "
				  "to load them.")));
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

/* ============================================================== lookup */

void
fs_intel_lookup_clear (FsIntelLookup *result)
{
	if (result == NULL)
		return;
	if (result->sources != NULL)
		g_ptr_array_unref (result->sources);
	if (result->kernel_sources != NULL)
		g_ptr_array_unref (result->kernel_sources);
	g_free (result->state_detail);
	memset (result, 0, sizeof *result);
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
	result->blocked = result->sources->len > 0 && !result->is_protected &&
	                  !result->is_exception && !result->is_host;
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

void
fs_intel_lookup_live (const FsBackend *backend, const FsIntelConfig *config,
                      const gchar *addr, FsIntelLookup *result)
{
	guint32 v4 = 0, inner = 0;
	FsU128 v6 = { 0, 0 };
	FsAddrFamily fam;
	gboolean nat64 = FALSE, was_exception;
	Store store = { -1 };
	Applied a = { 0 };
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
	for (guint i = 0; i < ids->len && !result->pending; i++) {
		const gchar *id = g_ptr_array_index (ids, i);
		FsIntelDir dir = 0;
		const gchar *want = NULL;

		if (!str_array_has (a.ids, id)) {
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
	applied_clear (&a);
	store_close (&store);
}

gchar *
fs_intel_lookup_sentence (const FsIntelConfig *config,
                          const FsIntelLookup *result)
{
	GString *out;

	if (result == NULL || !result->blocked || result->sources == NULL ||
	    result->sources->len == 0)
		return NULL;
	out = g_string_new (_("Blocked by threat intel: "));
	for (guint i = 0; i < result->sources->len; i++) {
		const gchar *id = g_ptr_array_index (result->sources, i);
		const gchar *label = fs_intel_config_label (config, id);

		g_string_append_printf (out, "%s%s", i ? ", " : "",
		                        label ? label : id);
	}
	return g_string_free (out, FALSE);
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
