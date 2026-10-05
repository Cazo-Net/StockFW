/*---[ fs-service.h ]---------------------------------------------------
 * Port and service name lookup.
 *
 * Ported from service.c.  The original built a GtkListStore of the
 * known services; here the table is plain data and the UI builds its own
 * model from it, so core stays free of GTK.
 *--------------------------------------------------------------------*/
#ifndef FS_SERVICE_H
#define FS_SERVICE_H

#include <glib.h>

G_BEGIN_DECLS

typedef struct
{
	const gchar *name;
	const gchar *ports;   /* "80", "137-139 445", "1234,1243" */
} FsService;

/* Services a normal user wants to open. */
const FsService *fs_service_user_list  (guint *count);

/* Known back doors and other things worth blocking. */
const FsService *fs_service_misc_list  (guint *count);

/* Name for a port, e.g. 22 -> "SSH".  Returns a new string, or NULL
 * when nothing matches.  Caller frees. */
gchar *fs_service_lookup_port (gint port);

/* Name for an ICMP type, or NULL.  Caller frees. */
gchar *fs_service_icmp_name (gint type);

/* Expands "137-139 445,1234" into individual ports, appending each to
 * out.  Ports in already_listed are skipped. */
void fs_service_expand_ports (const gchar *ports,
                              GHashTable *already_listed,
                              GPtrArray *out);

G_END_DECLS

#endif /* FS_SERVICE_H */