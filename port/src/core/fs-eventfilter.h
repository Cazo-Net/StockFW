/*---[ fs-eventfilter.h ]------------------------------------------------
 * The two Events filters of the Preferences window (C18, J5, J6):
 * "skip repeated events" and "skip events not addressed to this
 * computer".  Moved here from ui/fs-hitview.c so the desktop app, the
 * terminal (`events --collapse-repeats --for-me') and the daemon
 * filter alike.  Portable: no OS calls; the local addresses come from
 * a function the caller names (the backend's list_interfaces).
 *--------------------------------------------------------------------*/
#ifndef FS_EVENTFILTER_H
#define FS_EVENTFILTER_H

#include <glib.h>
#include "core/fs-types.h"

G_BEGIN_DECLS

/* The machine's addresses: a GList of FsInterface* the filter frees
 * (fs_interface_free), as FsBackend.list_interfaces gives them. */
typedef GList *(*FsHitFilterAddrs) (void);

typedef struct _FsHitFilter FsHitFilter;

/* addrs may be NULL: then no address is this computer's own. */
FsHitFilter *fs_hit_filter_new  (FsHitFilterAddrs addrs);
void         fs_hit_filter_free (FsHitFilter *filter);

/* [ fs_hit_filter_is_redundant ]
 * The original's test: port, protocol, source and destination the same
 * as the last event remembered (fs_hit_filter_remember), checked most
 * likely to differ first.  An event missing any of the four is never a
 * repeat. */
gboolean fs_hit_filter_is_redundant (FsHitFilter *filter,
                                    const FsHit *hit);
/* The event shown, for the next repeat check (copies). */
void     fs_hit_filter_remember     (FsHitFilter *filter,
                                    const FsHit *hit);

/* [ fs_hit_filter_is_for_me ]
 * TRUE when the destination is one of this machine's own addresses.
 * The addresses are read again at most every 10 s: on Windows the
 * list is far too heavy to ask for every packet of a flood. */
gboolean fs_hit_filter_is_for_me    (FsHitFilter *filter,
                                    const FsHit *hit);

/* "Out" or "Outbound". */
gboolean fs_hit_is_outbound         (const FsHit *hit);

/* [ fs_hit_filter_keep ]
 * Both filters as the Events list runs them, before anything is
 * counted: FALSE (leave the event out) when skip_repeats and it is a
 * repeat, or when skip_not_for_me and it is neither for this computer
 * nor one this computer sent.  Remembers nothing: call
 * fs_hit_filter_remember for the events that are shown. */
gboolean fs_hit_filter_keep         (FsHitFilter *filter,
                                    const FsHit *hit,
                                    gboolean skip_repeats,
                                    gboolean skip_not_for_me);

/* Test hook: the next address read happens now, not 10 s on. */
void     fs_hit_filter_refresh      (FsHitFilter *filter);

G_END_DECLS

#endif /* FS_EVENTFILTER_H */
