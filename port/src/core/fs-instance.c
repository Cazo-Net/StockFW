/*---[ fs-instance.c ]---------------------------------------------------
 * One StockFW per desktop session: see fs-instance.h for the design.
 *--------------------------------------------------------------------*/

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601      /* CreateMutexExW: Vista and later */
#endif
#include <windows.h>
#include <aclapi.h>              /* GetSecurityInfo */
#include <sddl.h>                /* ConvertStringSecurityDescriptor... */
#include <stdio.h>               /* _snwprintf */
#else
#define _GNU_SOURCE              /* accept4, struct ucred */
#endif

#include "core/fs-instance.h"

#include <string.h>

#ifndef G_OS_WIN32
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <glib-unix.h>
#endif

static gchar            *instance_name = NULL;
static FsInstanceHandler instance_handler = NULL;
static gpointer          instance_user = NULL;

#ifndef G_OS_WIN32
/* =====================================================================
 * Linux: an abstract Unix socket
 * ===================================================================== */

static gint   listen_fd = -1;
static guint  listen_source = 0;
static gboolean holder_weaker = FALSE;

/* The one-line requests on the socket. */
static const gchar *
command_word (FsInstanceCommand command)
{
	return command == FS_INSTANCE_QUIT ? "quit" : "show";
}

/* [ desktop_uid ] -- whose desktop this copy serves: the invoking
 * user's when root got here through sudo or pkexec, our own
 * otherwise.  Only consulted as root, where the variables were set by
 * the tool that elevated us. */
static uid_t
desktop_uid (void)
{
	if (geteuid () == 0) {
		const gchar *vars[] = { "SUDO_UID", "PKEXEC_UID" };

		for (guint i = 0; i < G_N_ELEMENTS (vars); i++) {
			const gchar *v = g_getenv (vars[i]);
			gchar *end = NULL;
			guint64 uid;

			if (v == NULL || *v == '\0')
				continue;
			uid = g_ascii_strtoull (v, &end, 10);
			if (end != NULL && *end == '\0' && uid < G_MAXUINT32)
				return (uid_t) uid;
		}
	}
	return getuid ();
}

const gchar *
fs_instance_name (void)
{
	if (instance_name == NULL) {
		const gchar *env = g_getenv ("STOCKFW_INSTANCE_NAME");

		instance_name = (env != NULL && *env != '\0')
		              ? g_strdup (env)
		              : g_strdup_printf ("stockfw-gui-%u",
		                                 (guint) desktop_uid ());
	}
	return instance_name;
}

/* [ abstract_addr ] -- the socket address; the leading NUL puts it in
 * the abstract namespace, which the kernel cleans up with the owner. */
static socklen_t
abstract_addr (struct sockaddr_un *addr)
{
	const gchar *name = fs_instance_name ();
	gsize len = MIN (strlen (name), sizeof addr->sun_path - 2);

	memset (addr, 0, sizeof *addr);
	addr->sun_family = AF_UNIX;
	memcpy (addr->sun_path + 1, name, len);

	return (socklen_t) (offsetof (struct sockaddr_un, sun_path) + 1 + len);
}

static gboolean
peer_uid (gint fd, uid_t *uid)
{
	struct ucred cred;
	socklen_t len = sizeof cred;

	if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0)
		return FALSE;
	*uid = cred.uid;
	return TRUE;
}

/* [ trusted_uid ] -- a uid this process may treat as "the StockFW of
 * this desktop": root, ourselves, or the desktop's user. */
static gboolean
trusted_uid (uid_t uid)
{
	return uid == 0 || uid == geteuid () || uid == desktop_uid ();
}

/* [ connect_instance ] -- -1 with errno set when nothing listens. */
static gint
connect_instance (void)
{
	struct sockaddr_un addr;
	socklen_t len = abstract_addr (&addr);
	gint fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;
	if (connect (fd, (struct sockaddr *) &addr, len) != 0) {
		gint saved = errno;

		close (fd);
		errno = saved;
		return -1;
	}
	return fd;
}

/* [ read_line ] -- the SENDING side's wait for the answer: at most
 * `size'-1 bytes up to a newline, no longer than timeout_ms overall.
 * FALSE on timeout or EOF first.  Never used by the running instance,
 * whose main loop must not wait on a client (on_client_io). */
static gboolean
read_line (gint fd, gchar *buf, gsize size, gint timeout_ms)
{
	gsize got = 0;
	gint64 end = g_get_monotonic_time () + (gint64) timeout_ms * 1000;

	while (got + 1 < size) {
		struct pollfd p = { fd, POLLIN, 0 };
		gint64 left = (end - g_get_monotonic_time ()) / 1000;
		ssize_t n;

		if (left <= 0 || poll (&p, 1, (gint) left) <= 0)
			return FALSE;
		n = read (fd, buf + got, 1);
		if (n <= 0)
			return FALSE;
		if (buf[got] == '\n')
			break;
		got++;
	}
	buf[got] = '\0';
	return TRUE;
}

/* [ send_text ] -- best effort, never blocking, never SIGPIPE: the
 * other side may have gone, and neither end must die of it. */
static void
send_text (gint fd, const gchar *text)
{
	gsize len = strlen (text);

	while (len > 0) {
		ssize_t n = send (fd, text, len, MSG_NOSIGNAL | MSG_DONTWAIT);

		if (n <= 0)
			return;
		text += n;
		len -= (gsize) n;
	}
}

/* ---------------------------------------------------------- the server
 *
 * Everything below runs on the GTK main loop, which also carries the
 * event monitor, Sentinel and the UI, so nothing here may wait on a
 * client.  Each connection is judged by its credentials the moment it
 * is accepted -- a uid that is not this desktop's StockFW gets
 * "denied" and is closed without a byte read -- and a trusted one gets
 * a watch of its own and CLIENT_DEADLINE_MS to say its line. */

#define CLIENT_DEADLINE_MS 1000
#define MAX_CLIENTS        8
#define ACCEPTS_PER_WAKEUP 64

typedef struct
{
	gint   fd;
	uid_t  uid;
	gchar  buf[32];
	gsize  len;
	guint  watch;
	guint  deadline;
} Client;

static GPtrArray *clients = NULL;

static void
client_free (Client *c)
{
	if (c->watch != 0)
		g_source_remove (c->watch);
	if (c->deadline != 0)
		g_source_remove (c->deadline);
	close (c->fd);
	g_free (c);
}

/* [ client_done ] -- from one of the client's own callbacks, which
 * removes its own source by returning G_SOURCE_REMOVE. */
static void
client_done (Client *c)
{
	g_ptr_array_remove_fast (clients, c);
	client_free (c);
}

/* [ client_answer ] -- the request is complete: answer, close, act. */
static void
client_answer (Client *c)
{
	FsInstanceCommand command = 0;
	gboolean allowed = FALSE;
	uid_t uid = c->uid;

	if (strcmp (c->buf, "show") == 0) {
		command = FS_INSTANCE_SHOW;
		allowed = TRUE;              /* trusted at accept */
	} else if (strcmp (c->buf, "quit") == 0) {
		/* Not the desktop user when we run as root: they could not
		 * kill this process either, so they cannot quit it. */
		command = FS_INSTANCE_QUIT;
		allowed = uid == 0 || uid == geteuid ();
	}

	send_text (c->fd, command == 0 ? "bad\n"
	                  : allowed ? "ok\n" : "denied\n");

	if (command != 0 && !allowed)
		g_message ("StockFW: refused \"%s\" from uid %u", c->buf,
		           (guint) uid);

	client_done (c);

	/* Last: the handler may quit, and nothing of the client is left
	 * to touch by then. */
	if (command != 0 && allowed && instance_handler != NULL)
		instance_handler (command, instance_user);
}

static gboolean
on_client_deadline (gpointer data)
{
	Client *c = data;

	c->deadline = 0;
	client_done (c);
	return G_SOURCE_REMOVE;
}

/* [ on_client_io ] -- read what has arrived, never more. */
static gboolean
on_client_io (gint fd, GIOCondition condition, gpointer data)
{
	Client *c = data;
	gchar *nl;
	ssize_t n;

	(void) condition;

	n = recv (fd, c->buf + c->len, sizeof c->buf - 1 - c->len,
	          MSG_DONTWAIT);
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
	              errno == EINTR))
		return G_SOURCE_CONTINUE;
	if (n <= 0) {
		c->watch = 0;
		client_done (c);
		return G_SOURCE_REMOVE;
	}
	c->len += (gsize) n;
	c->buf[c->len] = '\0';

	nl = strchr (c->buf, '\n');
	if (nl == NULL) {
		if (c->len + 1 < sizeof c->buf)
			return G_SOURCE_CONTINUE;
		/* A line this long is no request of ours. */
		c->watch = 0;
		client_done (c);
		return G_SOURCE_REMOVE;
	}
	*nl = '\0';
	c->watch = 0;
	client_answer (c);
	return G_SOURCE_REMOVE;
}

/* [ on_listen ] -- accept what is waiting, judge each by its uid. */
static gboolean
on_listen (gint fd, GIOCondition condition, gpointer data)
{
	(void) condition;
	(void) data;

	for (gint i = 0; i < ACCEPTS_PER_WAKEUP; i++) {
		gint client = accept4 (fd, NULL, NULL,
		                       SOCK_CLOEXEC | SOCK_NONBLOCK);
		uid_t uid = (uid_t) -1;
		Client *c;

		if (client < 0)
			break;

		if (!peer_uid (client, &uid) || !trusted_uid (uid)) {
			/* Not this desktop's StockFW: said so, not read, not
			 * waited for. */
			send_text (client, "denied\n");
			close (client);
			continue;
		}
		if (clients->len >= MAX_CLIENTS) {
			close (client);
			continue;
		}

		c = g_new0 (Client, 1);
		c->fd = client;
		c->uid = uid;
		c->watch = g_unix_fd_add (client, G_IO_IN | G_IO_HUP | G_IO_ERR,
		                          on_client_io, c);
		c->deadline = g_timeout_add (CLIENT_DEADLINE_MS,
		                             on_client_deadline, c);
		g_ptr_array_add (clients, c);
	}

	return G_SOURCE_CONTINUE;
}

FsInstanceRole
fs_instance_acquire (void)
{
	struct sockaddr_un addr;
	socklen_t len;

	holder_weaker = FALSE;
	if (listen_fd >= 0)
		return FS_INSTANCE_PRIMARY;

	len = abstract_addr (&addr);

	/* Two tries: the holder can exit between our bind and connect. */
	for (gint attempt = 0; attempt < 2; attempt++) {
		gint fd = socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		uid_t holder;

		if (fd < 0)
			return FS_INSTANCE_UNGUARDED;

		if (bind (fd, (struct sockaddr *) &addr, len) == 0 &&
		    listen (fd, 16) == 0) {
			g_unix_set_fd_nonblocking (fd, TRUE, NULL);
			listen_fd = fd;
			return FS_INSTANCE_PRIMARY;
		}
		close (fd);
		if (errno != EADDRINUSE)
			return FS_INSTANCE_UNGUARDED;

		fd = connect_instance ();
		if (fd < 0)
			continue;          /* it just went away: claim it */

		if (!peer_uid (fd, &holder) || !trusted_uid (holder)) {
			/* Another account holds our name: do not let it lock
			 * this user out of their own firewall. */
			close (fd);
			g_warning ("StockFW: the instance name %s is held by "
			           "another user; starting without the "
			           "single-instance guard",
			           fs_instance_name ());
			return FS_INSTANCE_UNGUARDED;
		}
		close (fd);
		/* Root finding the desktop user's own copy (the one started
		 * at sign-in, which can neither apply rules nor read the
		 * kernel log): that copy should make way. */
		holder_weaker = geteuid () == 0 && holder != 0;
		return FS_INSTANCE_SECONDARY;
	}

	return FS_INSTANCE_UNGUARDED;
}

gboolean
fs_instance_holder_weaker (void)
{
	return holder_weaker;
}

void
fs_instance_listen (FsInstanceHandler handler, gpointer user_data)
{
	instance_handler = handler;
	instance_user = user_data;

	if (clients == NULL)
		clients = g_ptr_array_new ();
	if (listen_fd >= 0 && listen_source == 0)
		listen_source = g_unix_fd_add (listen_fd, G_IO_IN, on_listen,
		                               NULL);
}

void
fs_instance_release (void)
{
	if (listen_source != 0) {
		g_source_remove (listen_source);
		listen_source = 0;
	}
	if (clients != NULL) {
		while (clients->len > 0) {
			Client *c = g_ptr_array_index (clients, 0);

			g_ptr_array_remove_index_fast (clients, 0);
			client_free (c);
		}
	}
	if (listen_fd >= 0) {
		close (listen_fd);
		listen_fd = -1;
	}
	instance_handler = NULL;
}

FsInstanceReply
fs_instance_send (FsInstanceCommand command, guint timeout_ms)
{
	gint fd = connect_instance ();
	uid_t holder;
	gchar *request, reply[16];
	FsInstanceReply result;

	if (fd < 0)
		return (errno == ECONNREFUSED || errno == ENOENT)
		       ? FS_INSTANCE_NONE_RUNNING : FS_INSTANCE_UNREACHABLE;

	/* Never hand a request to an impostor holding the name. */
	if (!peer_uid (fd, &holder) || !trusted_uid (holder)) {
		close (fd);
		return FS_INSTANCE_UNREACHABLE;
	}

	/* A holder that judged us untrusted has already answered and
	 * closed: the send may fail, the answer is still there to read. */
	request = g_strdup_printf ("%s\n", command_word (command));
	send_text (fd, request);
	g_free (request);

	if (!read_line (fd, reply, sizeof reply, (gint) timeout_ms))
		result = FS_INSTANCE_UNREACHABLE;
	else if (strcmp (reply, "ok") == 0)
		result = FS_INSTANCE_SENT;
	else if (strcmp (reply, "denied") == 0)
		result = FS_INSTANCE_REFUSED;
	else
		result = FS_INSTANCE_UNREACHABLE;

	close (fd);
	return result;
}

gboolean
fs_instance_wait_gone (guint timeout_ms)
{
	gint64 end = g_get_monotonic_time () + (gint64) timeout_ms * 1000;

	for (;;) {
		gint fd = connect_instance ();

		if (fd < 0 && (errno == ECONNREFUSED || errno == ENOENT))
			return TRUE;
		if (fd >= 0)
			close (fd);
		if (g_get_monotonic_time () >= end)
			return FALSE;
		g_usleep (100 * 1000);
	}
}

#else  /* G_OS_WIN32 */
/* =====================================================================
 * Windows: a named mutex and two events in the session namespace
 * ===================================================================== */

static HANDLE instance_mutex = NULL;
static HANDLE show_event = NULL;
static HANDLE quit_event = NULL;
static guint  poll_source = 0;

const gchar *
fs_instance_name (void)
{
	if (instance_name == NULL) {
		const gchar *env = g_getenv ("STOCKFW_INSTANCE_NAME");

		instance_name = g_strdup_printf (
			"Local\\%s", (env != NULL && *env != '\0')
			             ? env : "StockFW.GUI");
	}
	return instance_name;
}

/* [ object_name ] -- "Local\StockFW.GUI.<suffix>", UTF-16, g_free. */
static gunichar2 *
object_name (const gchar *suffix)
{
	gchar *utf8 = g_strdup_printf ("%s.%s", fs_instance_name (), suffix);
	gunichar2 *wide = g_utf8_to_utf16 (utf8, -1, NULL, NULL, NULL);

	g_free (utf8);
	return wide;
}

/* [ token_facts ] -- our own SID, as a string (LocalFree) and as a
 * copy in `self' (SECURITY_MAX_SID_SIZE bytes), and whether this
 * process runs elevated. */
static gboolean
token_facts (wchar_t **sid_string, BYTE *self, gboolean *elevated)
{
	HANDLE token = NULL;
	BYTE buffer[256];
	DWORD len = 0;
	TOKEN_ELEVATION elevation;
	gboolean ok = FALSE;

	*sid_string = NULL;
	*elevated = FALSE;
	memset (self, 0, SECURITY_MAX_SID_SIZE);

	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
		return FALSE;

	if (GetTokenInformation (token, TokenUser, buffer, sizeof buffer,
	                         &len) &&
	    CopySid (SECURITY_MAX_SID_SIZE, (PSID) self,
	             ((TOKEN_USER *) buffer)->User.Sid) &&
	    ConvertSidToStringSidW (((TOKEN_USER *) buffer)->User.Sid,
	                            sid_string))
		ok = TRUE;

	if (GetTokenInformation (token, TokenElevation, &elevation,
	                         sizeof elevation, &len))
		*elevated = elevation.TokenIsElevated != 0;

	CloseHandle (token);
	return ok;
}

/* [ make_sa ] -- a SECURITY_ATTRIBUTES from SDDL; the descriptor is
 * LocalFree'd by the caller (sa->lpSecurityDescriptor). */
static gboolean
make_sa (SECURITY_ATTRIBUTES *sa, const wchar_t *sddl)
{
	PSECURITY_DESCRIPTOR sd = NULL;

	memset (sa, 0, sizeof *sa);
	sa->nLength = sizeof *sa;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW (
		sddl, SDDL_REVISION_1, &sd, NULL))
		return FALSE;
	sa->lpSecurityDescriptor = sd;
	return TRUE;
}

/* DACLs.  SYSTEM and Administrators: full.  The rest, per object:
 *   mutex  -- SYNCHRONIZE for everyone signed in interactively (IU),
 *             so a second launch can see that it exists;
 *   show   -- EVENT_MODIFY_STATE | SYNCHRONIZE for IU;
 *   quit   -- for the instance's own user only when NOT elevated.
 * No owner in the SDDL: the creator's token supplies it, and that is
 * what tells a second launch who created the objects (owner_kind). */
#define SDDL_ADMIN  L"D:(A;;GA;;;SY)(A;;GA;;;BA)"

static HANDLE
create_object (gboolean mutex, const gchar *suffix, const wchar_t *extra,
               const wchar_t *user_ace_sid, const wchar_t *user_rights)
{
	SECURITY_ATTRIBUTES sa;
	gunichar2 *name = object_name (suffix);
	wchar_t sddl[512];
	HANDLE handle = NULL;

	if (user_ace_sid != NULL)
		_snwprintf (sddl, G_N_ELEMENTS (sddl), L"%ls%ls(A;;%ls;;;%ls)",
		            SDDL_ADMIN, extra, user_rights, user_ace_sid);
	else
		_snwprintf (sddl, G_N_ELEMENTS (sddl), L"%ls%ls", SDDL_ADMIN,
		            extra);
	sddl[G_N_ELEMENTS (sddl) - 1] = L'\0';

	if (make_sa (&sa, sddl)) {
		/* READ_CONTROL on the mutex: a second launch reads its
		 * owner.  An administrator always gets it (SDDL_ADMIN), the
		 * creating user as owner; anyone else is denied it, which
		 * says as much. */
		handle = mutex
		       ? CreateMutexExW (&sa, (wchar_t *) name, 0,
		                         SYNCHRONIZE | READ_CONTROL)
		       : CreateEventW (&sa, FALSE, FALSE, (wchar_t *) name);
		LocalFree (sa.lpSecurityDescriptor);
	}
	g_free (name);
	return handle;
}

/* [ create_own_event ] -- an event of ours, made by us.  We created
 * the mutex a moment ago, so no copy of ours can have made this event
 * already: if it exists, something else put it there first (any
 * process in the session may create objects in Local\), with its own
 * DACL, to signal us at will.  Then we run without that channel
 * rather than take orders from it. */
static HANDLE
create_own_event (const gchar *suffix, const wchar_t *extra,
                  const wchar_t *user_ace_sid, const wchar_t *user_rights)
{
	HANDLE event;
	DWORD err;

	SetLastError (0);
	event = create_object (FALSE, suffix, extra, user_ace_sid,
	                       user_rights);
	err = GetLastError ();
	if (event != NULL && err == ERROR_ALREADY_EXISTS) {
		CloseHandle (event);
		event = NULL;
	}
	if (event == NULL)
		g_warning ("StockFW: the %s.%s event already belongs to "
		           "another process; running without it",
		           fs_instance_name (), suffix);
	return event;
}

typedef enum
{
	OWNER_UNKNOWN,
	OWNER_ADMIN,     /* an elevated copy (or SYSTEM)            */
	OWNER_SELF,      /* this user's copy, NOT elevated          */
	OWNER_OTHER      /* nobody StockFW would be running as      */
} OwnerKind;

/* [ owner_kind ] -- who created the object behind `handle' (opened
 * with READ_CONTROL).  An elevated administrator's token makes the
 * Administrators group the owner of what it creates; a filtered
 * (unelevated) or standard token makes the user the owner. */
static OwnerKind
owner_kind (HANDLE handle, PSID self)
{
	PSID owner = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;
	OwnerKind kind;

	if (GetSecurityInfo (handle, SE_KERNEL_OBJECT,
	                     OWNER_SECURITY_INFORMATION, &owner, NULL, NULL,
	                     NULL, &sd) != ERROR_SUCCESS || owner == NULL)
		return OWNER_UNKNOWN;

	if (IsWellKnownSid (owner, WinBuiltinAdministratorsSid) ||
	    IsWellKnownSid (owner, WinLocalSystemSid))
		kind = OWNER_ADMIN;
	else if (IsValidSid (self) && EqualSid (owner, self))
		kind = OWNER_SELF;
	else
		kind = OWNER_OTHER;

	LocalFree (sd);
	return kind;
}

static gboolean holder_weaker = FALSE;

FsInstanceRole
fs_instance_acquire (void)
{
	wchar_t *sid = NULL;
	BYTE self[SECURITY_MAX_SID_SIZE];
	gboolean elevated = FALSE;
	DWORD err;

	holder_weaker = FALSE;
	if (instance_mutex != NULL)
		return FS_INSTANCE_PRIMARY;

	token_facts (&sid, self, &elevated);

	SetLastError (0);
	instance_mutex = create_object (TRUE, "Lock",
	                                 L"(A;;0x00100000;;;IU)", sid,
	                                 L"0x00100000");
	err = GetLastError ();

	if (instance_mutex == NULL) {
		if (sid != NULL)
			LocalFree (sid);
		if (err != ERROR_ACCESS_DENIED)
			return FS_INSTANCE_UNGUARDED;
		/* A copy of ours always lets administrators in: an
		 * elevated launch shut out of the name faces something
		 * else holding it, and is not locked out by it. */
		if (elevated) {
			g_warning ("StockFW: the instance name %s is held by "
			           "something else; starting without the "
			           "single-instance guard", fs_instance_name ());
			return FS_INSTANCE_UNGUARDED;
		}
		/* No READ_CONTROL for an unelevated launch: an elevated
		 * copy holds the name. */
		return FS_INSTANCE_SECONDARY;
	}

	if (err == ERROR_ALREADY_EXISTS) {
		OwnerKind owner = owner_kind (instance_mutex, (PSID) self);

		CloseHandle (instance_mutex);
		instance_mutex = NULL;
		if (sid != NULL)
			LocalFree (sid);

		switch (owner) {
		case OWNER_SELF:
			/* Our user's unelevated copy (the one started at
			 * sign-in): an elevated launch takes its place. */
			holder_weaker = elevated;
			return FS_INSTANCE_SECONDARY;
		case OWNER_OTHER:
			g_warning ("StockFW: the instance name %s is held by "
			           "another account; starting without the "
			           "single-instance guard", fs_instance_name ());
			return FS_INSTANCE_UNGUARDED;
		case OWNER_ADMIN:
		case OWNER_UNKNOWN:
		default:
			return FS_INSTANCE_SECONDARY;
		}
	}

	show_event = create_own_event ("Show", L"(A;;0x00100002;;;IU)",
	                               NULL, NULL);
	quit_event = create_own_event ("Quit", L"",
	                               elevated ? NULL : sid, L"0x00100002");

	if (sid != NULL)
		LocalFree (sid);
	return FS_INSTANCE_PRIMARY;
}

gboolean
fs_instance_holder_weaker (void)
{
	return holder_weaker;
}

/* [ poll_events ] -- four times a second: cheaper to reason about than
 * a handle source, and a show request needs no faster answer. */
static gboolean
poll_events (gpointer data)
{
	(void) data;

	if (show_event != NULL &&
	    WaitForSingleObject (show_event, 0) == WAIT_OBJECT_0 &&
	    instance_handler != NULL)
		instance_handler (FS_INSTANCE_SHOW, instance_user);

	if (quit_event != NULL &&
	    WaitForSingleObject (quit_event, 0) == WAIT_OBJECT_0 &&
	    instance_handler != NULL)
		instance_handler (FS_INSTANCE_QUIT, instance_user);

	return G_SOURCE_CONTINUE;
}

void
fs_instance_listen (FsInstanceHandler handler, gpointer user_data)
{
	instance_handler = handler;
	instance_user = user_data;

	if (instance_mutex != NULL && poll_source == 0)
		poll_source = g_timeout_add (250, poll_events, NULL);
}

void
fs_instance_release (void)
{
	if (poll_source != 0) {
		g_source_remove (poll_source);
		poll_source = 0;
	}
	if (show_event != NULL) {
		CloseHandle (show_event);
		show_event = NULL;
	}
	if (quit_event != NULL) {
		CloseHandle (quit_event);
		quit_event = NULL;
	}
	if (instance_mutex != NULL) {
		CloseHandle (instance_mutex);
		instance_mutex = NULL;
	}
	instance_handler = NULL;
}

/* [ mutex_exists ] */
static gboolean
mutex_exists (void)
{
	gunichar2 *name = object_name ("Lock");
	HANDLE h = OpenMutexW (SYNCHRONIZE, FALSE, (wchar_t *) name);
	DWORD err = GetLastError ();

	g_free (name);
	if (h != NULL) {
		CloseHandle (h);
		return TRUE;
	}
	return err != ERROR_FILE_NOT_FOUND;
}

FsInstanceReply
fs_instance_send (FsInstanceCommand command, guint timeout_ms)
{
	gunichar2 *name;
	HANDLE event;
	DWORD err;

	(void) timeout_ms;   /* an event has no answer to wait for */

	name = object_name (command == FS_INSTANCE_QUIT ? "Quit" : "Show");
	event = OpenEventW (EVENT_MODIFY_STATE, FALSE, (wchar_t *) name);
	err = GetLastError ();
	g_free (name);

	if (event == NULL) {
		if (err == ERROR_ACCESS_DENIED)
			return command == FS_INSTANCE_QUIT
			       ? FS_INSTANCE_REFUSED : FS_INSTANCE_UNREACHABLE;
		return mutex_exists () ? FS_INSTANCE_UNREACHABLE
		                       : FS_INSTANCE_NONE_RUNNING;
	}

	/* The user just launched us, so we may hand the foreground on:
	 * without this Windows only flashes the other window's button. */
	if (command == FS_INSTANCE_SHOW)
		AllowSetForegroundWindow (ASFW_ANY);

	SetEvent (event);
	CloseHandle (event);
	return FS_INSTANCE_SENT;
}

gboolean
fs_instance_wait_gone (guint timeout_ms)
{
	gint64 end = g_get_monotonic_time () + (gint64) timeout_ms * 1000;

	while (mutex_exists ()) {
		if (g_get_monotonic_time () >= end)
			return FALSE;
		g_usleep (100 * 1000);
	}
	return TRUE;
}

#endif /* G_OS_WIN32 */
