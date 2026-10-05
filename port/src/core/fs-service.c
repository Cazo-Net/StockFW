/*---[ fs-service.c ]---------------------------------------------------
 * Port and service name lookup.
 *--------------------------------------------------------------------*/

#include "core/fs-service.h"
#include "core/fs-i18n.h"

#include <stdlib.h>
#include <string.h>

/* Ported verbatim from service.c. */
static const FsService user_services[] = {
	{ "BitTorrent", "6881-6889" },
	{ "DHCP", "67-68" },
	{ "DNS", "53" },
	{ "FTP", "20-21" },
	{ "HTTP", "80" },
	{ "HTTPS", "443" },
	{ "IMAP", "143" },
	{ "NFS", "111 2049" },
	{ "NNTP", "119" },
	{ "NTP", "123" },
	{ "POP3", "110" },
	{ "Samba (SMB)", "137-139 445" },
	{ "SMTP", "25" },
	{ "SSH", "22" },
	{ "Telnet", "23" },
	{ "Xwindows", "6000-6015" }
};

static const FsService misc_services[] = {
	{ "DCOM-scm", "135" },
	{ "PhAse zero", "555" },
	{ "PC server backdoor", "600" },
	{ "Mountd bug", "635" },
	{ "Kazaa", "1214" },
	{ "Nessus", "1241" },
	{ "Subseven", "1234,1243,2772,2773" },
	{ "Trin00", "1524,27444,31335" },
	{ "SSDP", "1900" },
	{ "Backdoor-g/Subseven", "1999" },
	{ "CPQ-Wbem", "2301" },
	{ "Master's paradise", "3129" },
	{ "HotU chat", "3449" },
	{ "MS IPSec NAT-T", "4500" },
	{ "eDonkey", "4662" },
	{ "uPNP", "5000" },
	{ "SIP", "5060" },
	{ "SIP over TLS", "5061" },
	{ "AOL IM", "5190-5193" },
	{ "pcAnywhere", "5623" },
	{ "VNC reflector", "5999" },
	{ "VNC", "5900,5500,5800" },
	{ "Gnutella", "6346" },
	{ "Deep throat", "6670" },
	{ "Sub-7", "6711-6713,6776,16959" },
	{ "Gatecrasher", "6969" },
	{ "RealAudio", "6970" },
	{ "Sub-7 matrix chat", "7215" },
	{ "Unreal", "7777-7778" },
	{ "SHOUTcast", "8000" },
	{ "Teamspeak server", "8767" },
	{ "Webadmin", "10000" },
	{ "Cheeseworm", "10008" },
	{ "Netbus", "12345,12346" },
	{ "PowWow", "13223" },
	{ "Teamspeak server", "14534" },
	{ "Stacheldraht", "16660,60001,65000" },
	{ "Conducent", "17027" },
	{ "Kuang2", "17300" },
	{ "Useradmin", "20000" },
	{ "Netbus 2 pro", "20034" },
	{ "Acidkor", "20002" },
	{ "Girlfriend", "21544" },
	{ "Evilftp", "23456" },
	{ "Half-life", "27015" },
	{ "Backdoor-G or Sub-7", "27374" },
	{ "Quake", "27910-27961" },
	{ "Netsphere", "30100" },
	{ "Back orifice", "31337-31338" },
	{ "Hack'a'tack", "31789" },
	{ "Sun-RPC portmap", "32770-32900" },
	{ "Trinity v3", "33270" },
	{ "Traceroute", "33434-33600" },
	{ "Inoculan", "41508" },
	{ "Teamspeak network", "45647" },
	{ "Sockets de troi", "50505" },
	{ "Teamspeak query port", "51234" },
	{ "Sub-7 spy port", "54283" },
	{ "Back orifice 2K", "54320-54321" }
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