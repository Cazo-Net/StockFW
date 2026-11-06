/*---[ fs-verdict.h ]----------------------------------------------------
 * "Is this computer protected?" in one judgement, without a window
 * (PR 3, B3).
 *
 * The Overview's verdict card (ui/fs-statusview.c update_overview) is
 * the desktop app's answer; this is the same answer for the terminal
 * and the dashboard: the same inputs, the same order of checks, the
 * same words.  The desktop app is not changed: a golden table in
 * test-core.sh holds this one to the card's text.
 *--------------------------------------------------------------------*/
#ifndef FS_VERDICT_H
#define FS_VERDICT_H

#include <glib.h>
#include "core/fs-backend.h"
#include "core/fs-netplace.h"
#include "core/fs-intel.h"

G_BEGIN_DECLS

/* The card's four looks.  Same order as the desktop app's FsVerdict. */
typedef enum
{
	FS_VERDICT_LEVEL_UNKNOWN = 0,   /* the state could not be read      */
	FS_VERDICT_LEVEL_OK,            /* running, every family filtered   */
	FS_VERDICT_LEVEL_WARN,          /* running, but something is open   */
	FS_VERDICT_LEVEL_BAD            /* nothing is filtered              */
} FsVerdictLevel;

typedef struct
{
	FsFirewallState      state;          /* the backend's get_state     */
	gboolean             backend_usable; /* backend->available ()       */
	gboolean             ipv6_known;     /* the IPv6 probe answered     */
	FsIpv6State          ipv6;
	const gchar         *ipv6_detail;    /* nullable; translated by us  */
	/* Windows network place (NULL on Linux): profiles in force that
	 * filter nothing make it "not protected" or "partly". */
	const FsNetworkPlace *place;
	gboolean             profiles_known;
	guint                profiles_on;
	const gchar         *display_name;   /* the backend's name          */
	gboolean             locked;         /* the GUI's Policy Lock       */
	/* Linux, the terminal: changes are held (audit-only), with why. */
	const gchar         *hold_reason;    /* nullable                    */
	/* fs_intel_summary (), nullable. */
	const gchar         *intel_summary;
} FsVerdictInput;

typedef struct
{
	FsVerdictLevel level;
	const gchar   *key;    /* stable word: "protected", "running",
	                        * "ipv6-unprotected", "partly-protected",
	                        * "network-unprotected", "stopped",
	                        * "unknown"                                */
	gchar         *word;   /* the sidebar's word: "Protected"          */
	gchar         *title;  /* the card's title                         */
	gchar         *body;   /* the card's sentences                     */
} FsVerdictResult;

/* Never NULL; fs_verdict_result_free. */
FsVerdictResult *fs_verdict_compute     (const FsVerdictInput *in);
void             fs_verdict_result_free (FsVerdictResult *v);
/* "unknown" "ok" "warn" "bad". */
const gchar     *fs_verdict_level_name  (FsVerdictLevel level);

/* [ fs_intel_summary_text ]
 * The blocklists in one sentence for the verdict card, as the Threat
 * Intel page's summary gives it (ui/fs-intelview.c fs_intelview_summary):
 * `not_applied' lists turned on but not applied yet, `wants' whether
 * the configuration asks for any list.  NULL when there is nothing the
 * card should claim (off, paused, unsupported, needs rights). */
gchar *fs_intel_summary_text (FsIntelState state, const gchar *detail,
                              guint not_applied, gboolean wants);

/* [ fs_intel_summary ]
 * The same, read now: fs_intel_state and the store, as the page's
 * snapshot reads them (creates nothing; no store: NULL).  The page's
 * replacement on Linux, where there is no page. */
gchar *fs_intel_summary (const FsBackend *backend);

G_END_DECLS

#endif /* FS_VERDICT_H */
