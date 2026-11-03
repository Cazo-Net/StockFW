/*---[ fs-netplace.h ]---------------------------------------------------
 * Where this computer is connected, as the firewall sees it (1.0.7).
 *
 * Windows applies one of three firewall profiles to each network
 * according to the network's category: Domain (a domain controller
 * answered), Private (the user said "trusted") or Public (everything
 * else, and the default).  The profile in force is the one that matters
 * right now: a laptop on cafe Wi-Fi is protected by the Public profile,
 * whatever the Private one says.
 *
 * The backend fills an FsNetworkPlace (on Windows from INetFwPolicy2 and
 * INetworkListManager, in-process; see fs-backend-windows.c).  The
 * functions here turn it into the Overview's words, and are pure so the
 * wording and the "is the profile in use switched off?" judgement are
 * tested on any platform (tests/test-netplace.c).
 *--------------------------------------------------------------------*/
#ifndef FS_NETPLACE_H
#define FS_NETPLACE_H

#include <glib.h>
#include "core/fs-backend.h"   /* FS_PROFILE_*, the FsNetworkPlace typedef */

G_BEGIN_DECLS

/* One bit per FS_PROFILE_* id. */
#define FS_PROFILE_BIT(p) (1u << (p))
#define FS_PROFILE_ALL_BITS \
	(FS_PROFILE_BIT (FS_PROFILE_DOMAIN) | \
	 FS_PROFILE_BIT (FS_PROFILE_PRIVATE) | \
	 FS_PROFILE_BIT (FS_PROFILE_PUBLIC))

typedef struct
{
	gchar   *name;      /* "HomeNet".  Windows names a Wi-Fi network
	                     * after its SSID unless the user renamed it */
	gint     profile;   /* FS_PROFILE_* the network is in; -1 unknown */
	gchar   *medium;    /* "Wi-Fi", "Ethernet", "Virtual"; NULL unknown */
	gboolean internet;  /* reaches the internet over IPv4 or IPv6     */
} FsNetwork;

struct _FsNetworkPlace
{
	/* FS_PROFILE_BIT() of each profile in force now.  More than one
	 * when adapters sit on networks of different kinds (a Hyper-V
	 * switch is an "Unidentified network", so Public, next to the
	 * home Wi-Fi's Private). */
	guint      in_use;
	/* FsNetwork*, the connected networks.  The first is the one the
	 * Overview names: the first that reaches the internet, else the
	 * first connected. */
	GPtrArray *networks;
};

FsNetworkPlace *fs_network_place_new  (void);
void            fs_network_place_free (FsNetworkPlace *place);

/* Copies name and medium.  Keeps networks that reach the internet
 * ahead of those that do not, otherwise in the order added. */
void fs_network_place_add (FsNetworkPlace *place, const gchar *name,
                           gint profile, const gchar *medium,
                           gboolean internet);

/* The network the Overview names, or NULL when there is none. */
const FsNetwork *fs_network_place_primary (const FsNetworkPlace *place);

/* Same profiles and same networks in the same order.  NULLs compare
 * equal only to each other. */
gboolean fs_network_place_equal (const FsNetworkPlace *a,
                                 const FsNetworkPlace *b);

/* "Domain", "Private", "Public"; NULL for anything else. */
const gchar *fs_profile_name (gint profile);

/* The Overview subtitle after "This computer": "HomeNet (Wi-Fi) .
 * Private network".  NULL when no network is connected.  Caller frees. */
gchar *fs_network_place_subtitle (const FsNetworkPlace *place);

/* "Private network", "Public network", "Domain network" for the primary
 * network (the tray menu's header); NULL when unknown or none. */
const gchar *fs_network_place_kind (const FsNetworkPlace *place);

/* "Windows Defender Firewall is applying the Private profile." or
 * "... the Private and Public profiles."  `engine' is the backend's
 * display name.  NULL when no profile is in use.  Caller frees. */
gchar *fs_network_place_in_use_sentence (const FsNetworkPlace *place,
                                         const gchar *engine);

/* The profiles in use that are switched off: in_use & known & ~on.  A
 * profile whose state could not be read (not in `known') is never
 * reported -- the Overview says what it knows, not what it fears. */
guint fs_network_place_unguarded (const FsNetworkPlace *place,
                                  guint known, guint on);

/* For the verdict card when fs_network_place_unguarded() is not 0:
 * "The Public profile of Windows Defender Firewall is off, so traffic
 * on CafeNet (Wi-Fi) is not filtered. Turn it on under Firewall
 * profiles."  Names the networks in the switched-off profile(s), not
 * merely the primary one.  Caller frees. */
gchar *fs_network_place_unguarded_sentence (const FsNetworkPlace *place,
                                            guint unguarded,
                                            const gchar *engine);

G_END_DECLS

#endif /* FS_NETPLACE_H */
