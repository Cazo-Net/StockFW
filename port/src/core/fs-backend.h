/*---[ fs-backend.h ]----------------------------------------------------
 * The firewall backend vtable.
 *
 * Everything the GUI needs from the operating system goes through this
 * interface.  On Linux it is implemented with iptables + syslog, on
 * Windows with the Windows Firewall API.  The core and the UI never
 * call the OS directly, so the same UI drives both.
 *--------------------------------------------------------------------*/
#ifndef FS_BACKEND_H
#define FS_BACKEND_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"
#include "core/fs-script.h"
#include "core/fs-trust.h"

G_BEGIN_DECLS

/* Result of applying firewall rules. */
typedef enum
{
	FS_APPLY_OK,
	FS_APPLY_NO_IPTABLES,
	FS_APPLY_EXT_IF_FAILED,
	FS_APPLY_INT_IF_FAILED,
	FS_APPLY_NO_PRIVILEGE,
	FS_APPLY_PARTIAL,
	FS_APPLY_FAILED
} FsApplyResult;

/* Callback invoked for each event reported by the platform's firewall. */
typedef void (*FsLogFunc) (const FsHit *hit, gpointer user_data);

typedef struct
{
	const gchar *name;          /* "linux" / "windows" */
	const gchar *display_name;  /* human readable, for the About box */

	/* TRUE when the backend's rules are built from the FsSettings the
	 * Preferences dialog edits.  FALSE when the backend works straight
	 * from the policy and ignores those settings entirely -- the
	 * Windows backend does, so the dialog greys the Firewall pages out
	 * rather than offering switches that would change nothing. */
	gboolean uses_settings;

	/* TRUE when the backend can actually manage a firewall here. */
	gboolean (*available) (void);

	/* Current firewall state.  Returns FS_FW_NONE if unknown. */
	FsFirewallState (*get_state) (void);

	/* Start / stop / reload the firewall. */
	gboolean (*start) (GError **error);
	gboolean (*stop)  (GError **error);
	gboolean (*reload) (GError **error);

	/* Apply the policy to the live firewall.
	 *
	 * The backend decides what that means: on Linux it generates and
	 * runs iptables commands, on Windows it creates INetFwRule objects.
	 * Either way it works from the same FsPolicy, which is why the
	 * signature takes the policy rather than pre-rendered text. */
	FsApplyResult (*apply_rules) (const FsPolicy *policy, GError **error);

	/* Remove every rule this application previously created, leaving
	 * rules owned by the user or by Windows alone. */
	FsApplyResult (*clear_rules) (GError **error);

	/* Enumerate usable network interfaces.  Returns a list of
	 * FsInterface*, caller frees with g_list_free_full +
	 * fs_interface_free. */
	GList *(*list_interfaces) (void);

	/* Live traffic counters for the Status page's Network panel.
	 * Returns a GList of FsIfaceStat* (caller frees with
	 * g_list_free_full (..., fs_iface_stat_free)).  Backends with no
	 * counters return NULL and the panel is left out. */
	GList *(*list_interface_stats) (void);

	/* Currently open sockets for the Status page's Active connections
	 * panel.  Returns a GList of FsConnection* (caller frees with
	 * g_list_free_full (..., fs_connection_free)).  May return NULL
	 * when the platform or the account cannot enumerate them. */
	GList *(*list_connections) (void);

	/* Live event monitor. */
	gboolean (*log_start) (FsLogFunc callback, gpointer user_data, GError **error);
	void     (*log_stop)  (void);
	gboolean (*log_active) (void);

	/* DHCP server control (meaningful for a router build). */
	gboolean (*dhcp_set_enabled) (gboolean enabled, GError **error);

	/* Per-profile state.  Windows exposes three independently
	 * switchable profiles (domain / private / public); Linux has one
	 * global state.  Backends with a single state return FALSE here
	 * and the UI hides the per-profile controls. */
	gboolean (*get_profile_enabled) (gint profile, gboolean *enabled);
	gboolean (*set_profile_enabled) (gint profile, gboolean enabled,
	                                GError **error);

	/* Authenticode status for one executable -- the platform half of
	 * the trust engine.  Returns TRUE with the verdict (and a
	 * signer's name when there is one), FALSE when the platform
	 * cannot say.  Backends with no trust engine leave the slot
	 * NULL and their executables read "Signature not checked". */
	gboolean (*trust_signature) (const gchar *path,
	                             FsTrustSignature *sig,
	                             gchar **publisher);
} FsBackend;

/* Profile identifiers, matching Windows' own numbering. */
#define FS_PROFILE_DOMAIN  0
#define FS_PROFILE_PRIVATE 1
#define FS_PROFILE_PUBLIC  2
#define FS_PROFILE_COUNT   3

/* The backend compiled in for this platform.  Never NULL: platforms
 * without a working implementation get the null backend so the GUI
 * still starts. */
const FsBackend *fs_backend (void);

const gchar *fs_error_domain (void);

/* Hands the backend the policy and settings the rule generator needs.
 * The Windows backend ignores this; the Linux one needs it to build
 * the iptables rules.  Optional: a backend may ignore the arguments. */
void fs_backend_set_context (FsPolicy *policy, FsSettings *settings);

G_END_DECLS

#endif /* FS_BACKEND_H */