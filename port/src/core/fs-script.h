/*---[ fs-script.h ]----------------------------------------------------
 * Firewall rule script generation.
 *
 * Ported from netfilter-script.c and scriptwriter.c.  This module
 * turns an FsPolicy into text.  On Linux the text is a shell script
 * driving iptables; on Windows the generator is unused and the backend
 * builds INetFwRule objects directly, because there is no shell there.
 *
 * The output is deliberately kept as text rather than executed here, so
 * it can be inspected and diffed without touching the live firewall.
 *--------------------------------------------------------------------*/
#ifndef FS_SCRIPT_H
#define FS_SCRIPT_H

#include <glib.h>
#include "core/fs-types.h"
#include "core/fs-rules.h"

G_BEGIN_DECLS

/* Interface selection, as the wizard collects it. */
typedef struct
{
	gchar    *ext_device;
	gchar    *int_device;
	gboolean  nat;
	gboolean  filter_icmp;
	gboolean  filter_tos;
	gboolean  block_external_broadcast;
	gboolean  block_internal_broadcast;
	gboolean  block_non_routables;
	gboolean  deny_packets;
	gboolean  restrictive_outbound;
} FsSettings;

FsSettings *fs_settings_new  (void);
void        fs_settings_free (FsSettings *settings);

/* The control script: detects iptables, loads the policy modules and
 * dispatches to the per-direction setup scripts. */
gchar *fs_script_generate_control (const FsSettings *settings);

/* Per-direction setup.  "inbound" / "outbound". */
gchar *fs_script_generate_inbound  (const FsPolicy *policy,
                                    const FsSettings *settings);
gchar *fs_script_generate_outbound (const FsPolicy *policy,
                                    const FsSettings *settings);

/* Everything a start needs, as one script. */
gchar *fs_script_generate_full (const FsPolicy *policy,
                                const FsSettings *settings);

G_END_DECLS

#endif /* FS_SCRIPT_H */