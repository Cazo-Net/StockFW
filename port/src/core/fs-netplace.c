/*---[ fs-netplace.c ]---------------------------------------------------
 * The network place and the Overview's words for it.  See the header.
 *--------------------------------------------------------------------*/

#include "core/fs-netplace.h"
#include "core/fs-i18n.h"

#include <string.h>

static void
network_free (gpointer data)
{
	FsNetwork *n = data;

	g_free (n->name);
	g_free (n->medium);
	g_free (n);
}

FsNetworkPlace *
fs_network_place_new (void)
{
	FsNetworkPlace *place = g_new0 (FsNetworkPlace, 1);

	place->networks = g_ptr_array_new_with_free_func (network_free);
	return place;
}

void
fs_network_place_free (FsNetworkPlace *place)
{
	if (place == NULL)
		return;
	g_ptr_array_unref (place->networks);
	g_free (place);
}

void
fs_network_place_add (FsNetworkPlace *place, const gchar *name,
                      gint profile, const gchar *medium, gboolean internet)
{
	FsNetwork *n;
	guint at;

	g_return_if_fail (place != NULL);

	n = g_new0 (FsNetwork, 1);
	n->name = g_strdup (name);
	n->profile = (profile >= 0 && profile < FS_PROFILE_COUNT) ? profile
	                                                          : -1;
	n->medium = g_strdup (medium);
	n->internet = internet;

	/* Internet-facing networks first, each group in arrival order:
	 * insert after the last network of the same or better rank. */
	at = place->networks->len;
	if (internet) {
		at = 0;
		while (at < place->networks->len &&
		       ((FsNetwork *) g_ptr_array_index (place->networks,
		                                         at))->internet)
			at++;
	}
	g_ptr_array_insert (place->networks, (gint) at, n);
}

const FsNetwork *
fs_network_place_primary (const FsNetworkPlace *place)
{
	if (place == NULL || place->networks->len == 0)
		return NULL;
	return g_ptr_array_index (place->networks, 0);
}

gboolean
fs_network_place_equal (const FsNetworkPlace *a, const FsNetworkPlace *b)
{
	if (a == NULL || b == NULL)
		return a == b;
	if (a->in_use != b->in_use || a->networks->len != b->networks->len)
		return FALSE;

	for (guint i = 0; i < a->networks->len; i++) {
		const FsNetwork *x = g_ptr_array_index (a->networks, i);
		const FsNetwork *y = g_ptr_array_index (b->networks, i);

		if (g_strcmp0 (x->name, y->name) != 0 ||
		    x->profile != y->profile ||
		    g_strcmp0 (x->medium, y->medium) != 0 ||
		    x->internet != y->internet)
			return FALSE;
	}
	return TRUE;
}

const gchar *
fs_profile_name (gint profile)
{
	switch (profile) {
	case FS_PROFILE_DOMAIN:  return _("Domain");
	case FS_PROFILE_PRIVATE: return _("Private");
	case FS_PROFILE_PUBLIC:  return _("Public");
	default:                 return NULL;
	}
}

/* "Private network" and friends, for the subtitle. */
static const gchar *
network_kind (gint profile)
{
	switch (profile) {
	case FS_PROFILE_DOMAIN:  return _("Domain network");
	case FS_PROFILE_PRIVATE: return _("Private network");
	case FS_PROFILE_PUBLIC:  return _("Public network");
	default:                 return NULL;
	}
}

/* "HomeNet (Wi-Fi)", "HomeNet", or "Unnamed network". */
static void
append_network_label (GString *out, const FsNetwork *n)
{
	g_string_append (out, n->name != NULL && *n->name != '\0'
	                      ? n->name : _("Unnamed network"));
	if (n->medium != NULL && *n->medium != '\0')
		g_string_append_printf (out, " (%s)", n->medium);
}

/* "a", "a and b", "a, b and c". */
static void
append_joined (GString *out, GPtrArray *words)
{
	for (guint i = 0; i < words->len; i++) {
		if (i > 0)
			g_string_append (out, i + 1 == words->len ? _(" and ")
			                                          : ", ");
		g_string_append (out, g_ptr_array_index (words, i));
	}
}

/* The names of the profiles in `mask', joined: "Private and Public". */
static guint
append_profiles (GString *out, guint mask)
{
	GPtrArray *words = g_ptr_array_new ();
	guint n;

	for (gint p = 0; p < FS_PROFILE_COUNT; p++)
		if (mask & FS_PROFILE_BIT (p))
			g_ptr_array_add (words, (gpointer) fs_profile_name (p));
	append_joined (out, words);
	n = words->len;
	g_ptr_array_unref (words);
	return n;
}

gchar *
fs_network_place_subtitle (const FsNetworkPlace *place)
{
	const FsNetwork *n = fs_network_place_primary (place);
	const gchar *kind;
	GString *out;

	if (n == NULL)
		return NULL;

	out = g_string_new (NULL);
	append_network_label (out, n);
	kind = network_kind (n->profile);
	if (kind != NULL)
		g_string_append_printf (out, " \xc2\xb7 %s", kind);
	return g_string_free (out, FALSE);
}

gchar *
fs_network_place_in_use_sentence (const FsNetworkPlace *place,
                                  const gchar *engine)
{
	GString *out;
	guint n;

	if (place == NULL || (place->in_use & FS_PROFILE_ALL_BITS) == 0)
		return NULL;

	out = g_string_new (NULL);
	g_string_append_printf (out, _("%s is applying the "),
	                        engine != NULL ? engine : _("The firewall"));
	n = append_profiles (out, place->in_use);
	g_string_append (out, n == 1 ? _(" profile.") : _(" profiles."));
	return g_string_free (out, FALSE);
}

guint
fs_network_place_unguarded (const FsNetworkPlace *place, guint known,
                            guint on)
{
	if (place == NULL)
		return 0;
	return place->in_use & known & ~on & FS_PROFILE_ALL_BITS;
}

gchar *
fs_network_place_unguarded_sentence (const FsNetworkPlace *place,
                                     guint unguarded, const gchar *engine)
{
	GString *out = g_string_new (NULL);
	GPtrArray *labels = g_ptr_array_new_with_free_func (g_free);
	guint n_profiles, shown = 0, more = 0;

	unguarded &= FS_PROFILE_ALL_BITS;

	g_string_append (out, _("The "));
	n_profiles = append_profiles (out, unguarded);
	g_string_append_printf (out, n_profiles == 1
	                             ? _(" profile of %s is off, so traffic on ")
	                             : _(" profiles of %s are off, so traffic on "),
	                        engine != NULL ? engine : _("the firewall"));

	/* The networks those profiles cover.  Three names at most; a
	 * fourth and beyond are counted, so the card cannot grow without
	 * bound on a machine with many virtual switches. */
	if (place != NULL) {
		for (guint i = 0; i < place->networks->len; i++) {
			const FsNetwork *n = g_ptr_array_index (place->networks, i);
			GString *label;

			if (n->profile < 0 ||
			    !(unguarded & FS_PROFILE_BIT (n->profile)))
				continue;
			if (shown == 3) {
				more++;
				continue;
			}
			label = g_string_new (NULL);
			append_network_label (label, n);
			g_ptr_array_add (labels, g_string_free (label, FALSE));
			shown++;
		}
	}
	if (more > 0)
		g_ptr_array_add (labels, g_strdup_printf (
			g_dngettext (NULL, "%u other network",
			             "%u other networks", more), more));

	if (labels->len == 0)
		g_string_append (out, _("this network"));
	else
		append_joined (out, labels);

	g_string_append (out, _(" is not filtered. "));
	g_string_append (out, n_profiles == 1
	                      ? _("Turn it on under Firewall profiles.")
	                      : _("Turn them on under Firewall profiles."));

	g_ptr_array_unref (labels);
	return g_string_free (out, FALSE);
}
