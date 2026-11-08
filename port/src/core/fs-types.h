/*---[ fs-types.h ]------------------------------------------------------
 * Portable data types shared by the core, the UI and every platform
 * backend.  This header must never pull in a platform or GTK header.
 *--------------------------------------------------------------------*/
#ifndef FS_TYPES_H
#define FS_TYPES_H

#include <glib.h>
#include <glib-object.h>   /* GType */

G_BEGIN_DECLS

/* Firewall state as shown on the Status page.  Mirrors the original
 * FirewallStatus enum in statusview.h. */
typedef enum
{
	FS_FW_NONE,
	FS_FW_STOPPED,
	FS_FW_RUNNING,
	FS_FW_LOCKED,
	FS_FW_HIT
} FsFirewallState;

/* One network interface.  Replaces the GtkListStore that util.c used to
 * build for the device choosers. */
typedef struct
{
	gchar  *name;
	gchar  *ip;
	gchar  *netmask;
	gboolean nat_capable;
} FsInterface;

void fs_interface_clear (FsInterface *iface);
void fs_interface_free  (FsInterface *iface);

/* Per-interface traffic counters for the Status page's Network panel.
 * Kept apart from FsInterface so the settings choosers (which only need
 * name and address) are unaffected.  Bytes are cumulative since boot;
 * the view turns consecutive samples into an activity rate. */
typedef struct
{
	gchar    *device;      /* friendly name, e.g. "Ethernet"        */
	gchar    *kind;        /* "Ethernet", "Wireless", "Virtual" ... */
	gchar    *ip;
	guint64   received;    /* cumulative rx bytes                    */
	guint64   sent;        /* cumulative tx bytes                    */
	gboolean  up;
} FsIfaceStat;

void fs_iface_stat_free (FsIfaceStat *s);

/* Adapters that are not hardware: Docker and libvirt bridges, veth
 * pairs, Hyper-V switches, VPN tunnels, loopback (kind "Virtual",
 * "Tunnel" or "Loopback").  Real, but noise on a page that answers "is
 * this computer protected" (B12; `stockfw interfaces --no-virtual'). */
gboolean fs_netif_is_virtual (const FsIfaceStat *stat);

/* One row of the Status page's "Active connections" panel. */
typedef struct
{
	gchar *source;
	gchar *destination;
	gchar *port;        /* remote port                              */
	gchar *protocol;
	gchar *service;     /* well-known name for the remote port      */
	gchar *program;     /* owning process, when it could be read    */
	gchar *direction;   /* "Inbound" / "Outbound"                   */
	/* Added in 1.0.8 (cli-plan.md D4).  A backend that cannot tell
	 * leaves them 0 and NULL (the Windows backend does). */
	guint  local_port;
	guint  remote_port;
	gchar *state;       /* "ESTABLISHED", "SYN_SENT"...; NULL for UDP */
} FsConnection;

void fs_connection_free (FsConnection *c);

/* A single logged event ("hit").  Same shape as the original Hit struct. */
typedef struct
{
	gchar *time;
	gchar *direction;
	gchar *in;
	gchar *out;
	gchar *port;
	gchar *source;
	gchar *destination;
	gchar *length;
	gchar *tos;
	gchar *protocol;
	gchar *service;
	/* The full executable path the event was attributed to
	 * (Windows Security log Application field), e.g.
	 * C:\Program Files\App\app.exe.  Only set when the event source
	 * names a program; NULL otherwise.  Caller frees with fs_hit_free. */
	gchar *program;
	/* 1.0.7: what blocked it, when the log line says so
	 * ("Threat intel: Spamhaus DROP", or a country or network
	 * rule's "Threat intel: <its name>").  NULL
	 * for policy events and on platforms whose log cannot tell. */
	gchar *rule;
} FsHit;

FsHit *fs_hit_new  (void);
FsHit *fs_hit_copy (const FsHit *h);
void   fs_hit_free (FsHit *h);

/* Column indices for the Events view.  Same order as the original
 * HITCOL_* enum. */
typedef enum
{
	FS_HITCOL_TIME,
	FS_HITCOL_DIRECTION,
	FS_HITCOL_IN,
	FS_HITCOL_OUT,
	FS_HITCOL_PORT,
	FS_HITCOL_SOURCE,
	FS_HITCOL_DESTINATION,
	FS_HITCOL_LENGTH,
	FS_HITCOL_TOS,
	FS_HITCOL_PROTOCOL,
	FS_HITCOL_SERVICE,
	FS_HITCOL_COLOR,
	FS_NUM_HITCOLUMNS
} FsHitColumn;

/* Generic list/tree column description, replaces View_def in gui.h. */
typedef struct
{
	const gchar *label;
	GType        type;
	gboolean     visible;
	const gchar *pref_key;   /* remembers per-column visibility */
} FsColumnDef;

typedef struct
{
	const gchar         *title;
	gint                 num_columns;
	const FsColumnDef   *columns;
} FsViewDef;

/* Rule kinds understood by the policy editor. */
typedef enum
{
	FS_RULETYPE_INBOUND_ALLOW_FROM,
	FS_RULETYPE_INBOUND_ALLOW_SERVICE,
	FS_RULETYPE_INBOUND_ALLOW_SERVICE_FROM,
	FS_RULETYPE_OUTBOUND_ALLOW_TO,
	FS_RULETYPE_OUTBOUND_ALLOW_SERVICE,
	FS_RULETYPE_OUTBOUND_ALLOW_SERVICE_FROM
} FsRuleType;

G_END_DECLS

#endif /* FS_TYPES_H */