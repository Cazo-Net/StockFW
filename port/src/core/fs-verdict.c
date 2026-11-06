/*---[ fs-verdict.c ]----------------------------------------------------
 * The Overview's verdict, without the window.  See fs-verdict.h.  The
 * checks and sentences follow ui/fs-statusview.c update_overview and
 * ui/fs-intelview.c fs_intelview_summary in the same order; change one
 * and the golden table in test-core.sh says so.
 *--------------------------------------------------------------------*/
#include "core/fs-verdict.h"
#include "core/fs-i18n.h"

#include <string.h>

static gboolean
state_is_running (FsFirewallState state)
{
	return state == FS_FW_RUNNING || state == FS_FW_LOCKED ||
	       state == FS_FW_HIT;
}

const gchar *
fs_verdict_level_name (FsVerdictLevel level)
{
	switch (level) {
	case FS_VERDICT_LEVEL_OK:   return "ok";
	case FS_VERDICT_LEVEL_WARN: return "warn";
	case FS_VERDICT_LEVEL_BAD:  return "bad";
	default:                    return "unknown";
	}
}

void
fs_verdict_result_free (FsVerdictResult *v)
{
	if (v == NULL)
		return;
	g_free (v->word);
	g_free (v->title);
	g_free (v->body);
	g_free (v);
}

/* [ fs_verdict_compute ] */
FsVerdictResult *
fs_verdict_compute (const FsVerdictInput *in)
{
	FsVerdictResult *v = g_new0 (FsVerdictResult, 1);
	GString *body = g_string_new (NULL);
	gboolean running = state_is_running (in->state);
	guint unguarded = in->place != NULL
		? fs_network_place_unguarded (in->place, in->profiles_known,
		                              in->profiles_on)
		: 0;
	const FsNetwork *primary = in->place != NULL
		? fs_network_place_primary (in->place) : NULL;
	gboolean primary_open = unguarded != 0 &&
		(primary == NULL || primary->profile < 0 ||
		 (unguarded & FS_PROFILE_BIT (primary->profile)) != 0);
	const gchar *title, *word;

	if (!running) {
		unguarded = 0;
		primary_open = FALSE;
	}

	if (running) {
		if (unguarded != 0) {
			gchar *why = fs_network_place_unguarded_sentence (
				in->place, unguarded, in->display_name);

			if (primary_open) {
				v->level = FS_VERDICT_LEVEL_BAD;
				v->key = "network-unprotected";
				title = _("This network is not protected");
				word = _("Not protected");
			} else {
				v->level = FS_VERDICT_LEVEL_WARN;
				v->key = "partly-protected";
				title = _("Some networks are not protected");
				word = _("Partly protected");
			}
			g_string_append (body, why);
			g_free (why);
		} else if (in->ipv6_known && in->ipv6 == FS_IPV6_UNFILTERED) {
			v->level = FS_VERDICT_LEVEL_WARN;
			v->key = "ipv6-unprotected";
			title = _("IPv6 is not protected");
			word = _("IPv6 not protected");
			g_string_append (body, _("IPv4 is filtered, but IPv6 "
			                         "traffic passes unfiltered."));
			if (in->ipv6_detail != NULL && *in->ipv6_detail != '\0') {
				g_string_append_c (body, ' ');
				g_string_append (body, _(in->ipv6_detail));
			}
		} else if (in->ipv6_known && in->ipv6 == FS_IPV6_UNKNOWN) {
			v->level = FS_VERDICT_LEVEL_OK;
			v->key = "running";
			title = _("The firewall is running");
			word = _("Running");
			g_string_append (body, in->ipv6_detail != NULL &&
			                       *in->ipv6_detail
			                       ? _(in->ipv6_detail)
			                       : _("StockFW could not check "
			                           "whether IPv6 is filtered."));
		} else if (in->ipv6_known && in->ipv6 == FS_IPV6_ABSENT) {
			v->level = FS_VERDICT_LEVEL_OK;
			v->key = "protected";
			title = _("This computer is protected");
			word = _("Protected");
			g_string_append (body, _("Your policy is in force. This "
			                         "system has no IPv6, so IPv4 is "
			                         "all there is to filter."));
		} else {
			v->level = FS_VERDICT_LEVEL_OK;
			v->key = "protected";
			title = _("This computer is protected");
			word = _("Protected");
			g_string_append (body, _("Your policy is in force for "
			                         "IPv4 and IPv6."));
		}

		if (unguarded == 0 && in->place != NULL) {
			gchar *using = fs_network_place_in_use_sentence (
				in->place, in->display_name);

			if (using != NULL) {
				g_string_append_c (body, ' ');
				g_string_append (body, using);
				g_free (using);
			}
		}

		if (in->state == FS_FW_LOCKED || in->locked)
			g_string_append (body, _(" Policy changes are locked."));
		/* The terminal's hold: audit-only (B2, the Lock folds into
		 * it on Linux). */
		if (in->hold_reason != NULL && *in->hold_reason != '\0')
			g_string_append_printf (body,
				_(" Policy changes are held: %s."),
				in->hold_reason);

		if (in->intel_summary != NULL) {
			g_string_append_c (body, ' ');
			g_string_append (body, in->intel_summary);
		}
	} else if (in->state == FS_FW_STOPPED) {
		v->level = FS_VERDICT_LEVEL_BAD;
		v->key = "stopped";
		title = _("This computer is not protected");
		word = _("Not protected");
		g_string_append (body, _("The firewall is stopped, so no "
		                         "traffic is filtered. Start it to put "
		                         "your policy in force."));
	} else {
		v->level = FS_VERDICT_LEVEL_UNKNOWN;
		v->key = "unknown";
		title = _("The firewall's state is unknown");
		word = _("State unknown");
		g_string_append (body, _("StockFW could not read the "
		                         "firewall's state."));
		if (!in->backend_usable)
			g_string_append (body, _(" The firewall tools are not "
			                         "available to this account."));
	}

	v->title = g_strdup (title);
	v->word = g_strdup (word);
	v->body = g_string_free (body, FALSE);
	return v;
}

/* [ fs_intel_summary_text ] -- fs_intelview_summary's sentences. */
gchar *
fs_intel_summary_text (FsIntelState state, const gchar *detail,
                       guint not_applied, gboolean wants)
{
	switch (state) {
	case FS_INTEL_STATE_ENFORCED:
		if (not_applied > 0)
			return g_strdup_printf (g_dngettext (NULL,
				"Threat-intel blocklists are in force, except %u "
				"list that is turned on but not applied yet: see "
				"the Threat Intel page.",
				"Threat-intel blocklists are in force, except %u "
				"lists that are turned on but not applied yet: see "
				"the Threat Intel page.", not_applied),
				not_applied);
		return g_strdup (_("Threat-intel blocklists are in force."));
	case FS_INTEL_STATE_NOT_IN_FORCE:
		return detail != NULL
		       ? g_strdup_printf (_("Threat-intel blocklists are not in "
		                            "force: %s"), detail)
		       : g_strdup (_("Threat-intel blocklists are not in "
		                     "force."));
	case FS_INTEL_STATE_DIFFERS:
		if (detail != NULL)
			return g_strdup_printf (_("Threat intel: %s"), detail);
		return g_strdup (wants
		                 ? _("Threat-intel blocklists were changed "
		                     "outside StockFW: see the Threat Intel "
		                     "page.")
		                 : _("Threat-intel blocklists are turned off, "
		                     "but rules are still in place: see the "
		                     "Threat Intel page."));
	case FS_INTEL_STATE_NOT_LOADED:
		return g_strdup (_("Threat-intel blocklists are turned on but "
		                   "not loaded: see the Threat Intel page."));
	default:
		return NULL;
	}
}

/* The configuration asks for a list (the page's config_wants). */
static gboolean
geo_on (const FsIntelConfig *config)
{
	return config != NULL && config->enabled && config->geo_enabled &&
	       config->geo_accepted_at > 0 && fs_intel_geo_supported ();
}

static gboolean
config_wants (const FsIntelConfig *config)
{
	if (config == NULL || !config->enabled)
		return FALSE;
	if (geo_on (config))
		for (guint i = 0; i < config->locations->len; i++)
			if (((FsIntelLocationConf *) g_ptr_array_index (
			        config->locations, i))->enabled)
				return TRUE;
	for (guint i = 0; i < config->feeds->len; i++)
		if (((FsIntelFeedConf *) g_ptr_array_index (config->feeds,
		                                            i))->enabled)
			return TRUE;
	for (guint i = 0; i < config->lists->len; i++)
		if (((FsIntelListConf *) g_ptr_array_index (config->lists,
		                                            i))->enabled)
			return TRUE;
	return FALSE;
}

/* [ fs_intel_summary ] -- the page's snapshot, the parts it needs. */
gchar *
fs_intel_summary (const FsBackend *backend)
{
	FsIntelConfig *config;
	FsIntelState state;
	gchar *detail = NULL, *text;
	guint not_applied = 0;
	gboolean geo_present = FALSE;

	/* No store: no list was ever turned on, and none is made here.
	 * Off or needs rights: nothing for the card. */
	if (!fs_intel_store_exists ())
		return NULL;
	config = fs_intel_config_load (NULL);
	if (config == NULL)
		return NULL;

	state = fs_intel_state (backend, config, &detail);

	for (guint i = 0; i < config->feeds->len; i++) {
		FsIntelFeedConf *f = g_ptr_array_index (config->feeds, i);
		FsIntelSourceState *st;

		if (fs_intel_applied_has (f->id))
			continue;
		st = fs_intel_source_state (f->id);
		if (f->enabled && (f->custom || f->accepted_at > 0) &&
		    st != NULL && st->fetched_at > 0)
			not_applied++;
		fs_intel_source_state_free (st);
	}
	for (guint i = 0; i < config->lists->len; i++) {
		FsIntelListConf *l = g_ptr_array_index (config->lists, i);
		FsIntelSourceState *st;

		if (fs_intel_applied_has (l->id))
			continue;
		st = fs_intel_source_state (l->id);
		if (l->enabled && st != NULL)
			not_applied++;
		fs_intel_source_state_free (st);
	}
	if (geo_on (config)) {
		FsIntelGeoStatus geo;

		memset (&geo, 0, sizeof geo);
		if (fs_intel_geo_status (&geo, g_get_real_time () / G_USEC_PER_SEC,
		                         NULL))
			geo_present = geo.present;
		fs_intel_geo_status_clear (&geo);
	}
	for (guint i = 0; i < config->locations->len; i++) {
		FsIntelLocationConf *l = g_ptr_array_index (config->locations, i);

		if (!fs_intel_applied_has (l->id) && l->enabled &&
		    geo_on (config) && geo_present)
			not_applied++;
	}

	text = fs_intel_summary_text (state, detail, not_applied,
	                              config_wants (config));
	g_free (detail);
	fs_intel_config_free (config);
	return text;
}
