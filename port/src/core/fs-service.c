/*---[ fs-service.c ]---------------------------------------------------
 * Port and service name lookup.
 *--------------------------------------------------------------------*/

#include "core/fs-service.h"
#include "core/fs-i18n.h"

#include <stdlib.h>
#include <string.h>

/* Ported from service.c, with the protocols each service really
 * uses.  This is the one place that says so: the Windows rule
 * translation reads it, and a wrong entry here is a wrong firewall
 * rule there (1.0.6 had NTP as TCP, and every service not on its
 * TCP list became "any protocol, any port").
 *   - DHCP is UDP only (67 server, 68 client).
 *   - DNS answers on UDP and uses TCP for large replies and zone
 *     transfers.
 *   - NTP is UDP 123.
 *   - Samba: the NetBIOS name and datagram services are UDP 137-138,
 *     the session service TCP 139 and direct SMB TCP 445.
 *   - NFS: the portmapper and nfsd listen on both protocols.
 *   - HTTPS includes HTTP/3 (QUIC), which runs over UDP 443.
 *   - BitTorrent peers speak TCP, and uTP and DHT over UDP, on the
 *     same range.
 * The rest are TCP. */
static const FsService user_services[] = {
	{ "BitTorrent", "6881-6889", "6881-6889", "6881-6889" },
	{ "DHCP", "67-68", NULL, "67-68" },
	{ "DNS", "53", "53", "53" },
	{ "FTP", "20-21", "20-21", NULL },
	{ "HTTP", "80", "80", NULL },
	{ "HTTPS", "443", "443", "443" },
	{ "IMAP", "143", "143", NULL },
	{ "NFS", "111 2049", "111,2049", "111,2049" },
	{ "NNTP", "119", "119", NULL },
	{ "NTP", "123", NULL, "123" },
	{ "POP3", "110", "110", NULL },
	{ "Samba (SMB)", "137-139 445", "139,445", "137-138" },
	{ "SMTP", "25", "25", NULL },
	{ "SSH", "22", "22", NULL },
	{ "Telnet", "23", "23", NULL },
	{ "Xwindows", "6000-6015", "6000-6015", NULL }
};

/* Back doors and other ports worth blocking.  Their protocol columns
 * are empty: a block should cover whatever the thing speaks, so they
 * get both protocols, the rule for any name that is not a well-known
 * service.  SSDP is the exception: it is UDP 1900 only. */
static const FsService misc_services[] = {
	{ "DCOM-scm", "135", NULL, NULL },
	{ "PhAse zero", "555", NULL, NULL },
	{ "PC server backdoor", "600", NULL, NULL },
	{ "Mountd bug", "635", NULL, NULL },
	{ "Kazaa", "1214", NULL, NULL },
	{ "Nessus", "1241", NULL, NULL },
	{ "Subseven", "1234,1243,2772,2773", NULL, NULL },
	{ "Trin00", "1524,27444,31335", NULL, NULL },
	{ "SSDP", "1900", NULL, "1900" },
	{ "Backdoor-g/Subseven", "1999", NULL, NULL },
	{ "CPQ-Wbem", "2301", NULL, NULL },
	{ "Master's paradise", "3129", NULL, NULL },
	{ "HotU chat", "3449", NULL, NULL },
	{ "MS IPSec NAT-T", "4500", NULL, NULL },
	{ "eDonkey", "4662", NULL, NULL },
	{ "uPNP", "5000", NULL, NULL },
	{ "SIP", "5060", NULL, NULL },
	{ "SIP over TLS", "5061", NULL, NULL },
	{ "AOL IM", "5190-5193", NULL, NULL },
	{ "pcAnywhere", "5623", NULL, NULL },
	{ "VNC reflector", "5999", NULL, NULL },
	{ "VNC", "5900,5500,5800", NULL, NULL },
	{ "Gnutella", "6346", NULL, NULL },
	{ "Deep throat", "6670", NULL, NULL },
	{ "Sub-7", "6711-6713,6776,16959", NULL, NULL },
	{ "Gatecrasher", "6969", NULL, NULL },
	{ "RealAudio", "6970", NULL, NULL },
	{ "Sub-7 matrix chat", "7215", NULL, NULL },
	{ "Unreal", "7777-7778", NULL, NULL },
	{ "SHOUTcast", "8000", NULL, NULL },
	{ "Teamspeak server", "8767", NULL, NULL },
	{ "Webadmin", "10000", NULL, NULL },
	{ "Cheeseworm", "10008", NULL, NULL },
	{ "Netbus", "12345,12346", NULL, NULL },
	{ "PowWow", "13223", NULL, NULL },
	{ "Teamspeak server", "14534", NULL, NULL },
	{ "Stacheldraht", "16660,60001,65000", NULL, NULL },
	{ "Conducent", "17027", NULL, NULL },
	{ "Kuang2", "17300", NULL, NULL },
	{ "Useradmin", "20000", NULL, NULL },
	{ "Netbus 2 pro", "20034", NULL, NULL },
	{ "Acidkor", "20002", NULL, NULL },
	{ "Girlfriend", "21544", NULL, NULL },
	{ "Evilftp", "23456", NULL, NULL },
	{ "Half-life", "27015", NULL, NULL },
	{ "Backdoor-G or Sub-7", "27374", NULL, NULL },
	{ "Quake", "27910-27961", NULL, NULL },
	{ "Netsphere", "30100", NULL, NULL },
	{ "Back orifice", "31337-31338", NULL, NULL },
	{ "Hack'a'tack", "31789", NULL, NULL },
	{ "Sun-RPC portmap", "32770-32900", NULL, NULL },
	{ "Trinity v3", "33270", NULL, NULL },
	{ "Traceroute", "33434-33600", NULL, NULL },
	{ "Inoculan", "41508", NULL, NULL },
	{ "Teamspeak network", "45647", NULL, NULL },
	{ "Sockets de troi", "50505", NULL, NULL },
	{ "Teamspeak query port", "51234", NULL, NULL },
	{ "Sub-7 spy port", "54283", NULL, NULL },
	{ "Back orifice 2K", "54320-54321", NULL, NULL }
};

const FsService *
fs_service_user_list (guint *count)
{
	if (count != NULL)
		*count = G_N_ELEMENTS (user_services);

	return user_services;
}

const FsService *
fs_service_misc_list (guint *count)
{
	if (count != NULL)
		*count = G_N_ELEMENTS (misc_services);

	return misc_services;
}

/* [ service_name_matches ]
 * A policy row stores the name it was written with: the table's own
 * spelling, its translation (the default policy writes _("DHCP")), or
 * a hand-edited lower-case one. */
static gboolean
service_name_matches (const gchar *name, const gchar *table_name)
{
	return (g_ascii_strcasecmp (name, table_name) == 0 ||
	        g_strcmp0 (name, _(table_name)) == 0);
}

const FsService *
fs_service_find (const gchar *name)
{
	if (name == NULL || *name == '\0')
		return NULL;

	for (guint i = 0; i < G_N_ELEMENTS (user_services); i++) {
		if (service_name_matches (name, user_services[i].name))
			return &user_services[i];
	}

	for (guint i = 0; i < G_N_ELEMENTS (misc_services); i++) {
		if (service_name_matches (name, misc_services[i].name))
			return &misc_services[i];
	}

	return NULL;
}

void
fs_service_expand_ports (const gchar *ports, GHashTable *already_listed,
                         GPtrArray *out)
{
	gchar **tokens;

	if (ports == NULL || out == NULL)
		return;

	tokens = g_strsplit_set (ports, ",", -1);

	for (gint i = 0; tokens[i] != NULL; i++) {
		gchar **words = g_strsplit_set (tokens[i], " ", -1);

		for (gint w = 0; words[w] != NULL; w++) {
			gchar *dash;
			gint start, end;

			if (words[w] == NULL || *words[w] == '\0')
				continue;

			dash = strchr (words[w], '-');

			if (dash != NULL) {
				*dash = '\0';
				start = atoi (words[w]);
				end = atoi (dash + 1);
			} else {
				start = end = atoi (words[w]);
			}

			for (gint port = start; port <= end; port++) {
				if (already_listed != NULL &&
				    g_hash_table_contains (already_listed,
				                           GINT_TO_POINTER (port)))
					continue;

				g_ptr_array_add (out, GINT_TO_POINTER (port));
			}
		}

		g_strfreev (words);
	}

	g_strfreev (tokens);
}

/* [ port_table ]
 * Maps every port in the two tables to its service name.  Built once and
 * cached; values are borrowed from the static tables. */
static GHashTable *
port_table (void)
{
	static GHashTable *table = NULL;

	if (table != NULL)
		return table;

	table = g_hash_table_new (g_direct_hash, g_direct_equal);

	for (guint i = 0; i < G_N_ELEMENTS (user_services); i++) {
		GPtrArray *ports = g_ptr_array_new ();

		fs_service_expand_ports (user_services[i].ports, NULL, ports);

		for (guint p = 0; p < ports->len; p++)
			g_hash_table_insert (table, ports->pdata[p],
			                     (gpointer) user_services[i].name);

		g_ptr_array_unref (ports);
	}

	for (guint i = 0; i < G_N_ELEMENTS (misc_services); i++) {
		GPtrArray *ports = g_ptr_array_new ();

		fs_service_expand_ports (misc_services[i].ports, NULL, ports);

		for (guint p = 0; p < ports->len; p++)
			g_hash_table_insert (table, ports->pdata[p],
			                     (gpointer) misc_services[i].name);

		g_ptr_array_unref (ports);
	}

	return table;
}

gchar *
fs_service_lookup_port (gint port)
{
	const gchar *name;

	if (port <= 0 || port > 65535)
		return NULL;

	name = g_hash_table_lookup (port_table (), GINT_TO_POINTER (port));

	if (name != NULL)
		return g_strdup (name);

	return NULL;
}

gchar *
fs_service_icmp_name (gint type)
{
	switch (type) {
	case 0:  return g_strdup ("Echo reply");
	case 1:  /* fall through */
	case 2:  return g_strdup ("Unassigned");
	case 3:  return g_strdup ("Destination unreachable");
	case 4:  return g_strdup ("Source quench");
	case 5:  return g_strdup ("Redirect");
	case 6:  return g_strdup ("Alternate host address");
	case 7:  return g_strdup ("Unassigned");
	case 8:  return g_strdup ("Echo");
	case 9:  return g_strdup ("Router advertisement");
	case 10: return g_strdup ("Router selection");
	case 11: return g_strdup ("Time exceeded");
	case 12: return g_strdup ("Parameter problem");
	case 13: return g_strdup ("Timestamp");
	case 14: return g_strdup ("Timestamp reply");
	case 15: return g_strdup ("Information request");
	case 16: return g_strdup ("Information reply");
	case 17: return g_strdup ("Address mask request");
	case 18: return g_strdup ("Address mask reply");
	case 19: /* fall through */
	case 20: case 21: case 22: case 23: case 24:
	case 25: case 26: case 27: case 28: case 29:
		return g_strdup ("Reserved");
	case 30: return g_strdup ("Traceroute");
	case 31: return g_strdup ("Datagram conversion error");
	case 32: return g_strdup ("Mobile host redirect");
	case 33: return g_strdup ("IPv6 where-are-you");
	case 34: return g_strdup ("IPv6 I-am-here");
	case 35: return g_strdup ("Mobile registration request");
	case 36: return g_strdup ("Mobile registration reply");
	case 37: case 38: case 39: case 40: case 41: case 42:
	case 43: case 44: case 45: case 46: case 47: case 48:
	case 49: case 50: case 51: case 52: case 53: case 54:
	case 55: case 56: case 57: case 58: case 59: case 60:
	case 61: case 62: case 63: case 64: case 65: case 66:
	case 67: case 68: case 69: case 70: case 71: case 72:
	case 73: case 74: case 75: case 76: case 77: case 78:
	case 79: case 80: case 81: case 82: case 83: case 84:
	case 85: case 86: case 87: case 88: case 89: case 90:
	case 91: case 92: case 93: case 94: case 95: case 96:
	case 97: case 98: case 99: case 100: case 101: case 102:
	case 103: case 104: case 105: case 106: case 107: case 108:
	case 109: case 110: case 111: case 112: case 113: case 114:
	case 115: case 116: case 117: case 118: case 119: case 120:
	case 121: case 122: case 123: case 124: case 125: case 126:
	case 127: case 128: case 129: case 130: case 131: case 132:
	case 133: case 134: case 135: case 136: case 137: case 138:
	case 139: case 140: case 141: case 142: case 143: case 144:
	case 145: case 146: case 147: case 148: case 149: case 150:
	case 151: case 152: case 153: case 154: case 155: case 156:
	case 157: case 158: case 159: case 160: case 161: case 162:
	case 163: case 164: case 165: case 166: case 167: case 168:
	case 169: case 170: case 171: case 172: case 173: case 174:
	case 175: case 176: case 177: case 178: case 179: case 180:
	case 181: case 182: case 183: case 184: case 185: case 186:
	case 187: case 188: case 189: case 190: case 191: case 192:
	case 193: case 194: case 195: case 196: case 197: case 198:
	case 199: case 200: case 201: case 202: case 203: case 204:
	case 205: case 206: case 207: case 208: case 209: case 210:
	case 211: case 212: case 213: case 214: case 215: case 216:
	case 217: case 218: case 219: case 220: case 221: case 222:
	case 223: case 224: case 225: case 226: case 227: case 228:
	case 229: case 230: case 231: case 232: case 233: case 234:
	case 235: case 236: case 237: case 238: case 239: case 240:
	case 241: case 242: case 243: case 244: case 245: case 246:
	case 247: case 248: case 249: case 250: case 251: case 252:
	case 253: case 254: case 255:
		return g_strdup ("Reserved");
	default:
		return NULL;
	}
}