/*---[ fs-eventfilter.c ]------------------------------------------------
 * The two Events filters.  See fs-eventfilter.h.  The code is the
 * desktop app's (ui/fs-hitview.c, ported there from the original
 * hitview.c), moved unchanged in what it decides.
 *--------------------------------------------------------------------*/
#include "core/fs-eventfilter.h"

#include <string.h>

struct _FsHitFilter
{
	/* The row the list accepted most recently, kept as copies rather
	 * than as a pointer into a model: rows are trimmed once the cap is
	 * passed. */
	gchar *last_port;
	gchar *last_proto;
	gchar *last_src;
	gchar *last_dst;

	FsHitFilterAddrs   addrs;
	GList             *local;       /* FsInterface*                    */
	gint64             checked;     /* monotonic µs of the last read   */
	gboolean           read_once;
};

FsHitFilter *
fs_hit_filter_new (FsHitFilterAddrs addrs)
{
	FsHitFilter *f = g_new0 (FsHitFilter, 1);

	f->addrs = addrs;
	return f;
}

void
fs_hit_filter_free (FsHitFilter *f)
{
	if (f == NULL)
		return;
	g_free (f->last_port);
	g_free (f->last_proto);
	g_free (f->last_src);
	g_free (f->last_dst);
	g_list_free_full (f->local, (GDestroyNotify) fs_interface_free);
	g_free (f);
}

/* [ fs_hit_filter_is_redundant ] */
gboolean
fs_hit_filter_is_redundant (FsHitFilter *f, const FsHit *hit)
{
	if (f == NULL || hit == NULL || f->last_dst == NULL ||
	    hit->port == NULL || hit->protocol == NULL ||
	    hit->source == NULL || hit->destination == NULL)
		return FALSE;

	if (g_strcmp0 (hit->port, f->last_port) != 0)
		return FALSE;

	if (g_strcmp0 (hit->protocol, f->last_proto) != 0)
		return FALSE;

	if (g_strcmp0 (hit->source, f->last_src) != 0)
		return FALSE;

	return g_strcmp0 (hit->destination, f->last_dst) == 0;
}

void
fs_hit_filter_remember (FsHitFilter *f, const FsHit *hit)
{
	if (f == NULL || hit == NULL)
		return;

	g_free (f->last_port);
	g_free (f->last_proto);
	g_free (f->last_src);
	g_free (f->last_dst);

	f->last_port  = g_strdup (hit->port);
	f->last_proto = g_strdup (hit->protocol);
	f->last_src   = g_strdup (hit->source);
	f->last_dst   = g_strdup (hit->destination);
}

void
fs_hit_filter_refresh (FsHitFilter *f)
{
	if (f != NULL)
		f->read_once = FALSE;
}

/* [ local_addresses ] -- refreshed at most every 10 s. */
static GList *
local_addresses (FsHitFilter *f)
{
	const gint64 now = g_get_monotonic_time ();

	if (f->addrs == NULL)
		return NULL;
	if (!f->read_once || now - f->checked > 10 * G_USEC_PER_SEC) {
		g_list_free_full (f->local, (GDestroyNotify) fs_interface_free);
		f->local = f->addrs ();
		f->checked = now;
		f->read_once = TRUE;
	}
	return f->local;
}

/* [ fs_hit_filter_is_for_me ]
 * The original compared against the single external interface's IP.
 * Asking every interface is both more accurate and something that can
 * work on Windows, which has no one "external device" to query.  The
 * useful effect is the same: broadcast and multicast destinations are
 * not us, so discovery noise stops flooding the list. */
gboolean
fs_hit_filter_is_for_me (FsHitFilter *f, const FsHit *hit)
{
	if (f == NULL || hit == NULL || hit->destination == NULL)
		return FALSE;

	for (GList *l = local_addresses (f); l != NULL; l = l->next) {
		FsInterface *iface = l->data;

		if (iface->ip != NULL &&
		    g_ascii_strcasecmp (iface->ip, hit->destination) == 0)
			return TRUE;
	}

	return FALSE;
}

gboolean
fs_hit_is_outbound (const FsHit *hit)
{
	if (hit == NULL || hit->direction == NULL)
		return FALSE;

	return g_ascii_strcasecmp (hit->direction, "Out") == 0 ||
	       g_ascii_strcasecmp (hit->direction, "Outbound") == 0;
}

/* [ fs_hit_filter_keep ] */
gboolean
fs_hit_filter_keep (FsHitFilter *f, const FsHit *hit,
                    gboolean skip_repeats, gboolean skip_not_for_me)
{
	if (skip_repeats && fs_hit_filter_is_redundant (f, hit))
		return FALSE;

	if (skip_not_for_me && !fs_hit_filter_is_for_me (f, hit) &&
	    !fs_hit_is_outbound (hit))
		return FALSE;

	return TRUE;
}
