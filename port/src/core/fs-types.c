/*---[ fs-types.c ]------------------------------------------------------
 * Constructors / destructors for the portable data types.
 *--------------------------------------------------------------------*/

#include "core/fs-types.h"

#include <string.h>

void
fs_interface_clear (FsInterface *iface)
{
	if (iface == NULL)
		return;

	g_clear_pointer (&iface->name, g_free);
	g_clear_pointer (&iface->ip, g_free);
	g_clear_pointer (&iface->netmask, g_free);
	iface->nat_capable = FALSE;
}

void
fs_interface_free (FsInterface *iface)
{
	if (iface == NULL)
		return;

	fs_interface_clear (iface);
	g_free (iface);
}

void
fs_iface_stat_free (FsIfaceStat *s)
{
	if (s == NULL)
		return;

	g_free (s->device);
	g_free (s->kind);
	g_free (s->ip);
	g_free (s);
}

void
fs_connection_free (FsConnection *c)
{
	if (c == NULL)
		return;

	g_free (c->source);
	g_free (c->destination);
	g_free (c->port);
	g_free (c->protocol);
	g_free (c->service);
	g_free (c->program);
	g_free (c->direction);
	g_free (c);
}

FsHit *
fs_hit_new (void)
{
	return g_new0 (FsHit, 1);
}

FsHit *
fs_hit_copy (const FsHit *h)
{
	FsHit *copy;

	if (h == NULL)
		return NULL;

	copy = fs_hit_new ();
	copy->time        = g_strdup (h->time);
	copy->direction   = g_strdup (h->direction);
	copy->in          = g_strdup (h->in);
	copy->out         = g_strdup (h->out);
	copy->port        = g_strdup (h->port);
	copy->source      = g_strdup (h->source);
	copy->destination = g_strdup (h->destination);
	copy->length      = g_strdup (h->length);
	copy->tos         = g_strdup (h->tos);
	copy->protocol    = g_strdup (h->protocol);
	copy->service     = g_strdup (h->service);

	return copy;
}

void
fs_hit_free (FsHit *h)
{
	if (h == NULL)
		return;

	g_free (h->time);
	g_free (h->direction);
	g_free (h->in);
	g_free (h->out);
	g_free (h->port);
	g_free (h->source);
	g_free (h->destination);
	g_free (h->length);
	g_free (h->tos);
	g_free (h->protocol);
	g_free (h->service);

	g_free (h);
}