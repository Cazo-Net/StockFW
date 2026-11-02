/*---[ fs-blocktally.c ]-------------------------------------------------
 * Blocked today, and the last few blocks: see fs-blocktally.h.
 *--------------------------------------------------------------------*/

#include "core/fs-blocktally.h"
#include "core/fs-i18n.h"

#include <string.h>

static gint   tally_day = -1;      /* g_date_time_get_day_of_year + year */
static gint   tally_year = -1;
static guint  tally_count = 0;
static GQueue tally_recent = G_QUEUE_INIT;   /* gchar*, newest first */

static gboolean
same_day (GDateTime *now)
{
	return g_date_time_get_year (now) == tally_year &&
	       g_date_time_get_day_of_year (now) == tally_day;
}

static gboolean
hit_inbound (const FsHit *hit)
{
	return hit->direction != NULL &&
	       (g_ascii_strcasecmp (hit->direction, "In") == 0 ||
	        g_ascii_strcasecmp (hit->direction, "Inbound") == 0);
}

static gboolean
has_text (const gchar *s)
{
	return s != NULL && *s != '\0';
}

gchar *
fs_block_tally_describe (const FsHit *hit, const gchar *hhmm)
{
	GString *out = g_string_new (NULL);
	gboolean inbound = hit_inbound (hit);
	const gchar *host = inbound ? hit->source : hit->destination;

	if (has_text (hit->protocol)) {
		gchar *proto = g_ascii_strup (hit->protocol, -1);

		g_string_append (out, proto);
		g_free (proto);
	}
	if (has_text (hit->port)) {
		if (out->len > 0)
			g_string_append_c (out, ' ');
		g_string_append (out, hit->port);
	}
	if (out->len == 0)
		g_string_append (out, _("Traffic"));

	g_string_append_printf (out, inbound ? _(" from %s") : _(" to %s"),
	                        has_text (host) ? host : _("unknown"));
	if (has_text (hhmm))
		g_string_append_printf (out, " (%s)", hhmm);
	return g_string_free (out, FALSE);
}

void
fs_block_tally_note (const FsHit *hit, GDateTime *now)
{
	gchar *hhmm;

	if (hit == NULL || now == NULL)
		return;

	if (!same_day (now)) {
		tally_year = g_date_time_get_year (now);
		tally_day = g_date_time_get_day_of_year (now);
		tally_count = 0;
	}
	tally_count++;

	hhmm = g_date_time_format (now, "%H:%M");
	g_queue_push_head (&tally_recent, fs_block_tally_describe (hit, hhmm));
	g_free (hhmm);
	while (tally_recent.length > FS_BLOCK_TALLY_RECENT)
		g_free (g_queue_pop_tail (&tally_recent));
}

guint
fs_block_tally_today (GDateTime *now)
{
	return now != NULL && same_day (now) ? tally_count : 0;
}

gchar **
fs_block_tally_recent (void)
{
	gchar **out = g_new0 (gchar *, tally_recent.length + 1);
	guint i = 0;

	for (GList *l = tally_recent.head; l != NULL; l = l->next)
		out[i++] = g_strdup (l->data);
	return out;
}

void
fs_block_tally_reset (void)
{
	g_queue_clear_full (&tally_recent, g_free);
	tally_count = 0;
	tally_day = tally_year = -1;
}
