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
	return null_unsupported (error);
}

static GList *
null_list_interfaces (void)
{
	return NULL;
}

static GList *
null_list_interface_stats (void)
{
	return NULL;
}

static GList *
null_list_connections (void)
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

/* Every backend exports this -- fs-app.c calls it before the first
 * apply so the rule generator has a policy and settings to work from.
 * The null backend keeps nothing to generate against, so it accepts
 * and ignores the pointers.  Without this symbol the GUI could not
 * LINK against the null backend at all, which is precisely the
 * configuration this file exists for. */
void
fs_backend_set_context (FsPolicy *policy, FsSettings *settings)
{
	(void) policy;
	(void) settings;
}

static const FsBackend null_backend = {
	.name                  = "none",
	.display_name          = "No firewall backend",
	/* No sections, no honors: the dialog offers the four base pages
	 * only, which is what a backend that cannot apply anything should
	 * get. */
	.fw_sections           = 0,
	.fw_honors             = 0,
	.available             = null_available,
	.get_state             = null_get_state,
	.start                 = null_start,
	.stop                  = null_stop,
	.reload                = null_reload,
	.apply_rules           = null_apply_rules,
	.clear_rules           = null_clear_rules,
	.list_interfaces       = null_list_interfaces,
	.list_interface_stats  = null_list_interface_stats,
	.list_connections      = null_list_connections,
	.log_start             = null_log_start,
	.log_stop              = null_log_stop,
	.log_active            = null_log_active,
	.dhcp_set_enabled      = null_dhcp_set_enabled,
	.get_profile_enabled   = null_get_profile_enabled,
	.set_profile_enabled   = null_set_profile_enabled
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