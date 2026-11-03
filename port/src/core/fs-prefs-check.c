/*---[ fs-prefs-check.c ]------------------------------------------------
 * The Preferences window's rules without the window (PR 3, J0, J37):
 * which keys a backend acts on, what values they take, and what depends
 * on what.  The reasons are the window's own text (ui/fs-prefsdialog.c),
 * and the fake-backend Preferences smoke checks the two decide alike.
 * Portable: no OS calls.
 *--------------------------------------------------------------------*/
#include "core/fs-prefs.h"
#include "core/fs-backend.h"
#include "core/fs-eventlog.h"
#include "core/fs-eventstore.h"
#include "core/fs-i18n.h"
#include "core/fs-util.h"

#include <string.h>

/* The window's reasons, word for word (fs-prefsdialog.c). */
#define REASON_NAT \
	N_("Needs both devices: choose an Internet device and a local " \
	   "network device above.")
#define REASON_EXT_BCAST \
	N_("Has no effect until you choose an Internet device on the " \
	   "Network page.")
#define REASON_INT_BCAST \
	N_("Has no effect unless connection sharing is on and both " \
	   "devices are chosen on the Network page.")
#define REASON_RESERVED \
	N_("Has no effect until you choose an Internet device on the " \
	   "Network page.")
#define WARN_OUTBOUND \
	N_("Only connections that an outbound allow rule on the Policy " \
	   "page names can leave this computer. Everything else is " \
	   "blocked, including software updates, until you allow it.")
#define WARN_ABSENT \
	N_("A device marked \"not present\" is not connected right now. " \
	   "It stays chosen, and its rules apply again when it is back.")

static gboolean
is_icmp_type (const gchar *key)
{
	return g_str_has_prefix (key, "/apps/stockfw/firewall/icmp/") &&
	       strcmp (key, FS_PREFS_FW_FILTER_ICMP) != 0;
}

static gboolean
is_device (const gchar *key)
{
	return strcmp (key, FS_PREFS_FW_EXT_IF) == 0 ||
	       strcmp (key, FS_PREFS_FW_INT_IF) == 0;
}

/* [ fs_prefs_key_topic ] */
const gchar *
fs_prefs_key_topic (const gchar *key)
{
	if (key == NULL)
		return "preferences";
	if (strcmp (key, FS_PREFS_SKIP_REDUNDANT) == 0 ||
	    strcmp (key, FS_PREFS_SKIP_NOT_FOR_FIREWALL) == 0 ||
	    g_str_has_prefix (key, "/apps/stockfw/client/events/"))
		return "prefs-events";
	if (strcmp (key, FS_PREFS_APPLY_POLICY_INSTANTLY) == 0 ||
	    strcmp (key, FS_PREFS_AUDIT_ONLY) == 0)
		return "prefs-policy";
	if (is_device (key) || strcmp (key, FS_PREFS_FW_NAT) == 0)
		return "prefs-network";
	if (g_str_has_prefix (key, "/apps/stockfw/firewall/icmp/"))
		return "prefs-icmp";
	if (strcmp (key, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST) == 0 ||
	    strcmp (key, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST) == 0 ||
	    strcmp (key, FS_PREFS_FW_BLOCK_NON_ROUTABLES) == 0)
		return "prefs-protection";
	if (strcmp (key, FS_PREFS_FW_DENY_PACKETS) == 0 ||
	    strcmp (key, FS_PREFS_FW_RESTRICTIVE_OUTBOUND) == 0 ||
	    strcmp (key, FS_PREFS_FW_LOG_ALLOWED) == 0)
		return "prefs-firewall";
	if (fs_prefs_spec (key) != NULL)
		return "prefs-general";
	return "preferences";
}

/* [ fs_prefs_key_honoured ]
 * Where the window shows the row: build_network (FS_FWSEC_NETWORK),
 * build_icmp (FS_FWSEC_ICMP), build_protection (FS_FWSEC_ADVANCED, the
 * broadcasts only with devices) and build_firewall (one FS_FWHON_* bit
 * per row). */
gboolean
fs_prefs_key_honoured (const gchar *key, guint32 fw_sections,
                       guint32 fw_honors)
{
	const FsPrefSpec *spec = fs_prefs_spec (key);

	if (spec == NULL)
		return FALSE;
	if (!spec->firewall)
		return TRUE;
	if (is_device (key) || strcmp (key, FS_PREFS_FW_NAT) == 0)
		return (fw_sections & FS_FWSEC_NETWORK) != 0;
	if (g_str_has_prefix (key, "/apps/stockfw/firewall/icmp/"))
		return (fw_sections & FS_FWSEC_ICMP) != 0;
	if (strcmp (key, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST) == 0 ||
	    strcmp (key, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST) == 0)
		return (fw_sections & FS_FWSEC_ADVANCED) != 0 &&
		       (fw_sections & FS_FWSEC_NETWORK) != 0;
	if (strcmp (key, FS_PREFS_FW_BLOCK_NON_ROUTABLES) == 0)
		return (fw_sections & FS_FWSEC_ADVANCED) != 0;
	if (strcmp (key, FS_PREFS_FW_DENY_PACKETS) == 0)
		return (fw_honors & FS_FWHON_REJECT_METHOD) != 0;
	if (strcmp (key, FS_PREFS_FW_RESTRICTIVE_OUTBOUND) == 0)
		return (fw_honors & FS_FWHON_OUTBOUND_MODE) != 0;
	if (strcmp (key, FS_PREFS_FW_LOG_ALLOWED) == 0)
		return (fw_honors & FS_FWHON_LOG_ALLOWED) != 0;
	return FALSE;
}

static void
issue_add (GPtrArray *list, const gchar *key, const gchar *topic,
           gchar *reason)
{
	FsPrefsIssue *i = g_new0 (FsPrefsIssue, 1);

	i->key = key;
	i->reason = reason;
	i->topic = topic != NULL ? topic : fs_prefs_key_topic (key);
	g_ptr_array_add (list, i);
}

static void
issue_free (FsPrefsIssue *i)
{
	if (i == NULL)
		return;
	g_free (i->reason);
	g_free (i);
}

void
fs_prefs_check_free (FsPrefsCheck *check)
{
	if (check == NULL)
		return;
	g_ptr_array_unref (check->refusals);
	g_ptr_array_unref (check->warnings);
	g_hash_table_unref (check->values);
	g_free (check);
}

/* [ parse_bool ] -- the words a switch takes; FALSE when none. */
static gboolean
parse_bool (const gchar *key, const gchar *text, gboolean *out)
{
	static const gchar *yes[] = { "true", "on", "yes", "1" };
	static const gchar *no[]  = { "false", "off", "no", "0" };

	for (guint i = 0; i < G_N_ELEMENTS (yes); i++) {
		if (g_ascii_strcasecmp (text, yes[i]) == 0) {
			*out = TRUE;
			return TRUE;
		}
		if (g_ascii_strcasecmp (text, no[i]) == 0) {
			*out = FALSE;
			return TRUE;
		}
	}
	/* The window's two choices, by the words it shows them with. */
	if (strcmp (key, FS_PREFS_FW_DENY_PACKETS) == 0) {
		if (g_ascii_strcasecmp (text, "drop") == 0) {
			*out = TRUE;
			return TRUE;
		}
		if (g_ascii_strcasecmp (text, "reject") == 0) {
			*out = FALSE;
			return TRUE;
		}
	}
	if (strcmp (key, FS_PREFS_FW_RESTRICTIVE_OUTBOUND) == 0) {
		if (g_ascii_strcasecmp (text, "block") == 0) {
			*out = TRUE;
			return TRUE;
		}
		if (g_ascii_strcasecmp (text, "allow") == 0) {
			*out = FALSE;
			return TRUE;
		}
	}
	return FALSE;
}

/* [ number_range ] -- the window's limits for a number setting. */
static gboolean
number_range (const gchar *key, guint *min, guint *max)
{
	if (strcmp (key, FS_PREFS_EVENTS_MAX) == 0) {
		*min = FS_EVENTSTORE_MIN_CAPACITY;
		*max = FS_EVENTSTORE_MAX_CAPACITY;
		return TRUE;
	}
	if (strcmp (key, FS_PREFS_EVENTS_HISTORY_DAYS) == 0) {
		*min = FS_EVENTLOG_MIN_DAYS;
		*max = FS_EVENTLOG_MAX_DAYS;
		return TRUE;
	}
	if (strcmp (key, FS_PREFS_EVENTS_HISTORY_MB) == 0) {
		*min = FS_EVENTLOG_MIN_MB;
		*max = FS_EVENTLOG_MAX_MB;
		return TRUE;
	}
	return FALSE;
}

/* The value a key has once the set is applied: the set's, else the
 * store's (or the table's default). */
static gboolean
after_bool (FsPrefsCheck *c, const gchar *key)
{
	const gchar *v = g_hash_table_lookup (c->values, key);

	return v != NULL ? strcmp (v, "true") == 0 : fs_prefs_bool (key);
}

static gboolean
after_has_string (FsPrefsCheck *c, const gchar *key)
{
	const gchar *v = g_hash_table_lookup (c->values, key);
	gchar *now;
	gboolean has;

	if (v != NULL)
		return *v != '\0';
	now = fs_prefs_string (key);
	has = now != NULL && *now != '\0';
	g_free (now);
	return has;
}

/* Does the set change `key' from what is stored? */
static gboolean
changes (FsPrefsCheck *c, const gchar *key)
{
	const FsPrefSpec *spec = fs_prefs_spec (key);
	const gchar *v = g_hash_table_lookup (c->values, key);
	gchar *now;
	gboolean differs;

	if (v == NULL || spec == NULL)
		return FALSE;
	if (spec->type == FS_PREF_BOOL)
		return (strcmp (v, "true") == 0) != fs_prefs_bool (key);
	now = fs_prefs_string (key);
	differs = g_strcmp0 (now != NULL ? now : "", v) != 0;
	g_free (now);
	return differs;
}

/* [ fs_prefs_validate ] */
FsPrefsCheck *
fs_prefs_validate (const gchar * const *keys, const gchar * const *values,
                   guint n, guint32 fw_sections, guint32 fw_honors,
                   const gchar * const *devices)
{
	FsPrefsCheck *c = g_new0 (FsPrefsCheck, 1);
	GHashTable *seen = g_hash_table_new (g_str_hash, g_str_equal);

	c->refusals = g_ptr_array_new_with_free_func ((GDestroyNotify) issue_free);
	c->warnings = g_ptr_array_new_with_free_func ((GDestroyNotify) issue_free);
	c->values = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);

	/* 1. Each key and value on its own. */
	for (guint i = 0; i < n; i++) {
		const FsPrefSpec *spec = fs_prefs_spec (keys[i]);
		const gchar *text = values[i] != NULL ? values[i] : "";

		if (spec == NULL) {
			issue_add (c->refusals, NULL, "preferences",
			           g_strdup_printf (_("\"%s\" is not a setting."),
			                            keys[i]));
			continue;
		}
		if (g_hash_table_contains (seen, spec->key)) {
			issue_add (c->refusals, spec->key, NULL,
			           g_strdup (_("The same setting is given twice.")));
			continue;
		}
		g_hash_table_add (seen, (gpointer) spec->key);

		if (!fs_prefs_key_honoured (spec->key, fw_sections, fw_honors)) {
			issue_add (c->refusals, spec->key, NULL,
			           g_strdup (_("This firewall does not use this "
			                       "setting.")));
			continue;
		}
		/* J12: applying on every edit would skip the preview; the
		 * key is left as it is in the file. */
		if (strcmp (spec->key, FS_PREFS_APPLY_POLICY_INSTANTLY) == 0) {
			issue_add (c->refusals, spec->key, NULL,
			           g_strdup (_("Applying on every edit would skip "
			                       "the preview of what changes. Apply "
			                       "the policy when you are ready "
			                       "instead.")));
			continue;
		}

		if (spec->type == FS_PREF_BOOL) {
			gboolean b;

			if (!parse_bool (spec->key, text, &b)) {
				issue_add (c->refusals, spec->key, NULL,
				           g_strdup_printf (_("\"%s\" is not on or "
				                              "off."), text));
				continue;
			}
			g_hash_table_replace (c->values, (gpointer) spec->key,
			                      g_strdup (b ? "true" : "false"));
		} else if (is_device (spec->key)) {
			if (*text != '\0' && !fs_util_is_valid_ifname (text)) {
				issue_add (c->refusals, spec->key, NULL,
				           g_strdup_printf (_("\"%s\" is not a device "
				                              "name."), text));
				continue;
			}
			g_hash_table_replace (c->values, (gpointer) spec->key,
			                      g_strdup (text));
		} else {
			guint min = 0, max = 0;
			guint64 v = 0;

			if (number_range (spec->key, &min, &max) &&
			    (!g_ascii_string_to_unsigned (text, 10, min, max, &v,
			                                  NULL))) {
				issue_add (c->refusals, spec->key, NULL,
				           g_strdup_printf (_("Takes a number from %u "
				                              "to %u."), min, max));
				continue;
			}
			g_hash_table_replace (c->values, (gpointer) spec->key,
			                      number_range (spec->key, &min, &max)
			                      ? g_strdup_printf ("%" G_GUINT64_FORMAT,
			                                         v)
			                      : g_strdup (text));
		}
	}
	g_hash_table_unref (seen);

	/* 2. The set as a whole, on the values it leaves: the window's
	 * refresh(), where a row that cannot act is not changeable. */
	if (fw_sections & FS_FWSEC_NETWORK) {
		gboolean ext = after_has_string (c, FS_PREFS_FW_EXT_IF);
		gboolean intf = after_has_string (c, FS_PREFS_FW_INT_IF);
		gboolean nat = after_bool (c, FS_PREFS_FW_NAT);

		/* Sharing needs both devices; a switch stored on stays
		 * movable (it can always be turned off), and says why it
		 * does nothing. */
		if (changes (c, FS_PREFS_FW_NAT) && nat && !(ext && intf))
			issue_add (c->refusals, FS_PREFS_FW_NAT, NULL,
			           g_strdup (_(REASON_NAT)));
		else if (nat && !(ext && intf))
			issue_add (c->warnings, FS_PREFS_FW_NAT, NULL,
			           g_strdup (_(REASON_NAT)));

		if (changes (c, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST) && !ext)
			issue_add (c->refusals, FS_PREFS_FW_BLOCK_EXTERNAL_BROADCAST,
			           NULL, g_strdup (_(REASON_EXT_BCAST)));
		if (changes (c, FS_PREFS_FW_BLOCK_NON_ROUTABLES) && !ext)
			issue_add (c->refusals, FS_PREFS_FW_BLOCK_NON_ROUTABLES,
			           NULL, g_strdup (_(REASON_RESERVED)));
		if (changes (c, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST) &&
		    !(nat && ext && intf))
			issue_add (c->refusals, FS_PREFS_FW_BLOCK_INTERNAL_BROADCAST,
			           NULL, g_strdup (_(REASON_INT_BCAST)));

		/* A device that is not there now: kept, with the note. */
		for (guint d = 0; devices != NULL && d < 2; d++) {
			const gchar *key = d == 0 ? FS_PREFS_FW_EXT_IF
			                          : FS_PREFS_FW_INT_IF;
			const gchar *v = g_hash_table_lookup (c->values, key);

			if (v != NULL && *v != '\0' &&
			    !g_strv_contains (devices, v))
				issue_add (c->warnings, key, NULL,
				           g_strdup (_(WARN_ABSENT)));
		}
	}

	/* Rows under a master switch move only while it is on: the ICMP
	 * types under "Filter ICMP messages", the history limits under
	 * "Keep event history". */
	for (guint i = 0; i < n; i++) {
		const FsPrefSpec *spec = fs_prefs_spec (keys[i]);

		if (spec == NULL || !changes (c, spec->key))
			continue;
		if (is_icmp_type (spec->key) &&
		    !after_bool (c, FS_PREFS_FW_FILTER_ICMP))
			issue_add (c->refusals, spec->key, NULL,
			           g_strdup (_("Has no effect while \"Filter ICMP "
			                       "messages\" is off.")));
		if ((strcmp (spec->key, FS_PREFS_EVENTS_HISTORY_DAYS) == 0 ||
		     strcmp (spec->key, FS_PREFS_EVENTS_HISTORY_MB) == 0) &&
		    !after_bool (c, FS_PREFS_EVENTS_HISTORY))
			issue_add (c->refusals, spec->key, NULL,
			           g_strdup (_("Has no effect while \"Keep event "
			                       "history\" is off.")));
	}

	if (changes (c, FS_PREFS_FW_RESTRICTIVE_OUTBOUND) &&
	    after_bool (c, FS_PREFS_FW_RESTRICTIVE_OUTBOUND))
		issue_add (c->warnings, FS_PREFS_FW_RESTRICTIVE_OUTBOUND, NULL,
		           g_strdup (_(WARN_OUTBOUND)));

	return c;
}
