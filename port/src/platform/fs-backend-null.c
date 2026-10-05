/*---[ fs-backend-null.c ]---------------------------------------------
 * The backend linked into the GUI on every platform for now.
 *
 * It answers truthfully ("this build cannot touch the firewall yet")
 * so the application starts, shows its Status/Events/Policy pages and
 * disables the firewall controls instead of pretending to work.
 * Milestone M1-M3 swap this for src/platform/{linux,windows}.
 *--------------------------------------------------------------------*/

#include "core/fs-backend.h"

static gboolean
null_available (void)
{
	return FALSE;
}

static FsFirewallState
null_get_state (void)
{
	return FS_FW_NONE;
}

static gboolean
null_unsupported (GError **error)
{
	g_set_error_literal (error, g_quark_from_static_string ("fs-backend"),
	                     1,
	                     "This build has no firewall backend");

	return FALSE;
}

static gboolean
null_start (GError **error)
{
	return null_unsupported (error);
}

static gboolean
null_stop (GError **error)
{
	return null_unsupported (error);
}

static gboolean
null_reload (GError **error)
{
	return null_unsupported (error);
}

static FsApplyResult
null_apply_rules (const FsPolicy *policy, GError **error)
{
	return FS_APPLY_FAILED;
}

static FsApplyResult
null_clear_rules (GError **error)
{
	return FS_APPLY_FAILED;
}

static gboolean
null_get_profile_enabled (gint profile, gboolean *enabled)
{
	if (enabled != NULL)
		*enabled = FALSE;

	return FALSE;
}

static gboolean
null_set_profile_enabled (gint profile, gboolean enabled, GError **error)
{
	g_set_error_literal (error, g_quark_from_static_string ("fs-backend"),
	                     1, "This build has no firewall backend");

	return FALSE;
}

static GList *
null_list_interfaces (void)
{
	return NULL;
}

static gboolean
null_log_start (FsLogFunc callback, gpointer user_data, GError **error)
{
	return null_unsupported (error);
}

static void
null_log_stop (void)
{
}

static gboolean
null_log_active (void)
{
	return FALSE;
}

static gboolean
null_dhcp_set_enabled (gboolean enabled, GError **error)
{
	return null_unsupported (error);
}

static gboolean
null_get_profile_enabled (gint profile, gboolean *enabled)
{
	if (enabled != NULL)
		*enabled = FALSE;

	return FALSE;
}

static gboolean
null_set_profile_enabled (gint profile, gboolean enabled, GError **error)
{
	return null_unsupported (error);
}

static const FsBackend null_backend = {
	"none",
	"No firewall backend",
	null_available,
	null_get_state,
	null_start,
	null_stop,
	null_reload,
	null_apply_rules,
	null_clear_rules,
	null_list_interfaces,
	null_log_start,
	null_log_stop,
	null_log_active,
	null_dhcp_set_enabled,
	null_get_profile_enabled,
	null_set_profile_enabled
};

const FsBackend *
fs_backend (void)
{
	return &null_backend;
}

const gchar *
fs_error_domain (void)
{
	return "fs-backend";
}