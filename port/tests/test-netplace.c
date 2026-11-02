/*---[ test-netplace.c ]-------------------------------------------------
 * The network place (1.0.7): which network the Overview names, the
 * words it uses, and the judgement that matters -- a firewall profile
 * that is in use but switched off.  GLib only; runs anywhere.  The
 * Windows half that fills the place (INetFwPolicy2, INetworkListManager)
 * needs a Windows machine; ui-overview-place-smoke.c drives the Overview
 * with a fake backend that answers the way it does.
 *--------------------------------------------------------------------*/
#include <glib.h>
#include <string.h>

#include "core/fs-netplace.h"

static guint failures = 0;

#define CHECK(cond, ...) do {                                   \
	if (cond) {                                             \
		g_print ("ok:   " __VA_ARGS__);                 \
	} else {                                                \
		g_print ("FAIL: " __VA_ARGS__);                 \
		failures++;                                     \
	}                                                       \
	g_print ("\n");                                         \
} while (0)

#define PRIV  FS_PROFILE_BIT (FS_PROFILE_PRIVATE)
#define PUB   FS_PROFILE_BIT (FS_PROFILE_PUBLIC)
#define DOM   FS_PROFILE_BIT (FS_PROFILE_DOMAIN)
#define ENGINE "Windows Defender Firewall"

/* A laptop at home with Hyper-V: the Wi-Fi is Private and reaches the
 * internet; the virtual switch is an Unidentified network, so Public. */
static FsNetworkPlace *
home_with_hyperv (void)
{
	FsNetworkPlace *p = fs_network_place_new ();

	/* Added in the order Windows might list them: the switch first. */
	fs_network_place_add (p, "Unidentified network", FS_PROFILE_PUBLIC,
	                      "Virtual", FALSE);
	fs_network_place_add (p, "HomeNet", FS_PROFILE_PRIVATE, "Wi-Fi",
	                      TRUE);
	p->in_use = PRIV | PUB;
	return p;
}

static void
test_primary_and_subtitle (void)
{
	FsNetworkPlace *p = home_with_hyperv ();
	FsNetworkPlace *q;
	gchar *s;

	CHECK (g_strcmp0 (fs_network_place_primary (p)->name, "HomeNet") == 0,
	       "the network that reaches the internet is named, not the "
	       "virtual switch listed before it");

	s = fs_network_place_subtitle (p);
	CHECK (g_strcmp0 (s, "HomeNet (Wi-Fi) \xc2\xb7 Private network") == 0,
	       "subtitle: name, medium, kind (got %s)", s);
	g_free (s);
	fs_network_place_free (p);

	q = fs_network_place_new ();
	fs_network_place_add (q, "corp.example", FS_PROFILE_DOMAIN, NULL, TRUE);
	fs_network_place_add (q, "Lab", FS_PROFILE_PRIVATE, "Ethernet", TRUE);
	s = fs_network_place_subtitle (q);
	CHECK (g_strcmp0 (s, "corp.example \xc2\xb7 Domain network") == 0,
	       "two internet networks: the first added stays first; no "
	       "medium, no brackets (got %s)", s);
	g_free (s);
	fs_network_place_free (q);

	q = fs_network_place_new ();
	fs_network_place_add (q, "", 7, "Ethernet", FALSE);
	s = fs_network_place_subtitle (q);
	CHECK (g_strcmp0 (s, "Unnamed network (Ethernet)") == 0,
	       "no name and an out-of-range category: no invented words "
	       "(got %s)", s);
	CHECK (fs_network_place_primary (q)->profile == -1,
	       "an out-of-range category is stored as unknown");
	g_free (s);
	fs_network_place_free (q);

	q = fs_network_place_new ();
	CHECK (fs_network_place_subtitle (q) == NULL &&
	       fs_network_place_subtitle (NULL) == NULL,
	       "not connected: no subtitle, so the caller keeps its own");
	fs_network_place_free (q);
}

static void
test_in_use_sentence (void)
{
	FsNetworkPlace *p = fs_network_place_new ();
	gchar *s;

	p->in_use = PRIV;
	s = fs_network_place_in_use_sentence (p, ENGINE);
	CHECK (g_strcmp0 (s, ENGINE " is applying the Private profile.") == 0,
	       "one profile (got %s)", s);
	g_free (s);

	p->in_use = PRIV | PUB;
	s = fs_network_place_in_use_sentence (p, ENGINE);
	CHECK (g_strcmp0 (s, ENGINE " is applying the Private and Public "
	                     "profiles.") == 0, "two profiles (got %s)", s);
	g_free (s);

	p->in_use = DOM | PRIV | PUB;
	s = fs_network_place_in_use_sentence (p, ENGINE);
	CHECK (g_strcmp0 (s, ENGINE " is applying the Domain, Private and "
	                     "Public profiles.") == 0,
	       "three profiles (got %s)", s);
	g_free (s);

	p->in_use = 0;
	CHECK (fs_network_place_in_use_sentence (p, ENGINE) == NULL,
	       "no profile in use: nothing to say");
	fs_network_place_free (p);
}

static void
test_unguarded (void)
{
	FsNetworkPlace *p = home_with_hyperv ();
	guint all = DOM | PRIV | PUB;
	guint off;
	gchar *s;

	CHECK (fs_network_place_unguarded (p, all, all) == 0,
	       "every profile on: nothing unguarded");
	CHECK (fs_network_place_unguarded (p, all, PRIV | PUB) == 0,
	       "Domain off but not in use: not this network's problem");

	off = fs_network_place_unguarded (p, all, DOM | PRIV);
	CHECK (off == PUB, "Public in use and off: reported (got %#x)", off);
	CHECK (fs_network_place_unguarded (p, PRIV | DOM, DOM | PRIV) == 0,
	       "Public's state unreadable: not reported as off");

	s = fs_network_place_unguarded_sentence (p, off, ENGINE);
	CHECK (g_strcmp0 (s, "The Public profile of " ENGINE " is off, so "
	                     "traffic on Unidentified network (Virtual) is not "
	                     "filtered. Turn it on under Firewall profiles.")
	       == 0, "names the network in the off profile, not the Wi-Fi "
	       "(got %s)", s);
	g_free (s);

	s = fs_network_place_unguarded_sentence (p, PRIV | PUB, ENGINE);
	CHECK (strstr (s, "The Private and Public profiles of " ENGINE
	                  " are off") != NULL &&
	       strstr (s, "HomeNet (Wi-Fi) and Unidentified network "
	                  "(Virtual) is not filtered") != NULL &&
	       g_str_has_suffix (s, "Turn them on under Firewall profiles."),
	       "two profiles off: both named, both networks (got %s)", s);
	g_free (s);
	fs_network_place_free (p);

	/* In use by CurrentProfileTypes, but the network list was empty. */
	p = fs_network_place_new ();
	p->in_use = PUB;
	s = fs_network_place_unguarded_sentence (p, PUB, ENGINE);
	CHECK (strstr (s, "traffic on this network is not filtered") != NULL,
	       "no network listed: \"this network\" (got %s)", s);
	g_free (s);
	fs_network_place_free (p);

	/* Five virtual switches: three named, two counted. */
	p = fs_network_place_new ();
	for (guint i = 0; i < 5; i++) {
		gchar *name = g_strdup_printf ("vSwitch%u", i);

		fs_network_place_add (p, name, FS_PROFILE_PUBLIC, NULL, FALSE);
		g_free (name);
	}
	p->in_use = PUB;
	s = fs_network_place_unguarded_sentence (p, PUB, ENGINE);
	CHECK (strstr (s, "vSwitch0, vSwitch1, vSwitch2 and 2 other "
	                  "networks is not") != NULL &&
	       strstr (s, "vSwitch3") == NULL,
	       "many networks: three named, the rest counted (got %s)", s);
	g_free (s);
	fs_network_place_free (p);
}

static void
test_equal (void)
{
	FsNetworkPlace *a = home_with_hyperv ();
	FsNetworkPlace *b = home_with_hyperv ();

	CHECK (fs_network_place_equal (a, b), "the same place is equal");
	b->in_use = PRIV;
	CHECK (!fs_network_place_equal (a, b), "a profile change is a change");
	b->in_use = a->in_use;
	g_free (((FsNetwork *) g_ptr_array_index (b->networks, 0))->name);
	((FsNetwork *) g_ptr_array_index (b->networks, 0))->name =
		g_strdup ("CafeNet");
	CHECK (!fs_network_place_equal (a, b), "a new network is a change");
	CHECK (fs_network_place_equal (NULL, NULL) &&
	       !fs_network_place_equal (a, NULL), "NULL handling");
	fs_network_place_free (a);
	fs_network_place_free (b);
}

int
main (void)
{
	test_primary_and_subtitle ();
	test_in_use_sentence ();
	test_unguarded ();
	test_equal ();

	g_print ("\n%s: %u failure(s)\n", failures ? "FAILED" : "PASSED",
	         failures);
	return failures ? 1 : 0;
}
