/*---[ fs-whatif.c ]-----------------------------------------------------
 * The What-If engine.  See fs-whatif.h for the contract; the comments
 * here are about how.
 *
 * Layout of this file:
 *   1. query, context and result plumbing
 *   2. the parser
 *   3. addresses (bytes, not text: 2001:db8::1 == 2001:0db8::1)
 *   4. the rule model shared by both platforms
 *   5. the Linux model: fs-script.c's chains, rule for rule
 *   6. the Windows model: fs-fwrule.c + fs-settings-plan.c
 *   7. evaluating one concrete probe, with its trace
 *   8. under-specified questions: representatives and DEPENDS
 *   9. words
 *  10. actions, and the re-simulation that verifies them
 *  11. the Linux model as iptables text (pinned to the generator)
 *--------------------------------------------------------------------*/

#include "core/fs-whatif.h"
#include "core/fs-fwrule.h"
#include "core/fs-service.h"
#include "core/fs-settings-plan.h"
#include "core/fs-util.h"
#include "core/fs-i18n.h"

#include <gio/gio.h>
#include <string.h>
#include <stdlib.h>

/* The FS_PROFILE_* ids (fs-backend.h), repeated here so the engine
 * does not pull the backend vtable in. */
#define PROFILE_DOMAIN  0
#define PROFILE_PRIVATE 1
#define PROFILE_PUBLIC  2

/* Probe protocols. */
#define P_ANY  0
#define P_TCP  1
#define P_UDP  2
#define P_ICMP 3

/* An evaluation never walks more combinations than this; past it the
 * answer says it was cut short rather than pretend it looked. */
#define MAX_COMBINATIONS 40000

/* ================================================================
 * 1. Plumbing
 * ================================================================ */

GQuark
fs_whatif_error_quark (void)
{
	return g_quark_from_static_string ("fs-whatif-error");
}

static void
piece_free (gpointer data)
{
	FsWhatIfPiece *p = data;

	g_free (p->text);
	g_free (p->meaning);
	g_free (p);
}

FsWhatIfQuery *
fs_whatif_query_new (void)
{
	FsWhatIfQuery *q = g_new0 (FsWhatIfQuery, 1);

	q->pieces = g_ptr_array_new_with_free_func (piece_free);
	q->confidence = 1.0;
	return q;
}

FsWhatIfQuery *
fs_whatif_query_copy (const FsWhatIfQuery *query)
{
	FsWhatIfQuery *q;

	if (query == NULL)
		return NULL;

	q = fs_whatif_query_new ();
	q->text = g_strdup (query->text);
	q->verb = query->verb;
	q->direction = query->direction;
	q->protocol = query->protocol;
	q->port = query->port;
	q->host = g_strdup (query->host);
	q->icmp_type = g_strdup (query->icmp_type);
	q->service = g_strdup (query->service);
	q->confidence = query->confidence;
	q->host_unread = g_strdup (query->host_unread);
	q->host_any_said = query->host_any_said;

	for (guint i = 0; query->pieces != NULL && i < query->pieces->len; i++) {
		const FsWhatIfPiece *src = g_ptr_array_index (query->pieces, i);
		FsWhatIfPiece *p = g_new0 (FsWhatIfPiece, 1);

		p->kind = src->kind;
		p->text = g_strdup (src->text);
		p->meaning = g_strdup (src->meaning);
		g_ptr_array_add (q->pieces, p);
	}

	return q;
}

void
fs_whatif_query_free (FsWhatIfQuery *query)
{
	if (query == NULL)
		return;

	g_free (query->text);
	g_free (query->host);
	g_free (query->icmp_type);
	g_free (query->service);
	g_free (query->host_unread);
	if (query->pieces != NULL)
		g_ptr_array_unref (query->pieces);
	g_free (query);
}

FsWhatIfPlatform
fs_whatif_native_platform (void)
{
#ifdef G_OS_WIN32
	return FS_WHATIF_WINDOWS_BLOCK_WINS;
#else
	return FS_WHATIF_LINUX_FIRST_MATCH;
#endif
}

static void
auto_block_free (gpointer data)
{
	FsWhatIfAutoBlock *ab = data;

	g_free (ab->target);
	g_free (ab);
}

FsWhatIfContext *
fs_whatif_context_new (FsWhatIfPlatform platform, const FsPolicy *policy,
                       const FsSettings *settings)
{
	FsWhatIfContext *ctx = g_new0 (FsWhatIfContext, 1);

	ctx->platform = platform;
	ctx->policy = policy;
	ctx->settings = settings;
	ctx->firewall = FS_WHATIF_FW_UNKNOWN;
	for (gint i = 0; i < 3; i++) {
		ctx->profile_enabled[i] = -1;
		ctx->block_all_inbound[i] = -1;
	}
	ctx->auto_blocks = g_ptr_array_new_with_free_func (auto_block_free);
	ctx->local_addresses = g_ptr_array_new_with_free_func (g_free);
	return ctx;
}

void
fs_whatif_context_free (FsWhatIfContext *ctx)
{
	if (ctx == NULL)
		return;

	g_free (ctx->live_detail);
	g_ptr_array_unref (ctx->auto_blocks);
	g_ptr_array_unref (ctx->local_addresses);
	g_free (ctx);
}

void
fs_whatif_context_add_auto_block (FsWhatIfContext *ctx, const gchar *target,
                                  gint64 expires_unix)
{
	FsWhatIfAutoBlock *ab;

	if (ctx == NULL || target == NULL || *target == '\0')
		return;

	ab = g_new0 (FsWhatIfAutoBlock, 1);
	ab->target = g_strdup (target);
	ab->expires_unix = expires_unix;
	g_ptr_array_add (ctx->auto_blocks, ab);
}

void
fs_whatif_context_add_local_address (FsWhatIfContext *ctx,
                                     const gchar *address)
{
	if (ctx == NULL || address == NULL || *address == '\0')
		return;

	g_ptr_array_add (ctx->local_addresses, g_strdup (address));
}

gboolean
fs_whatif_policy_same (const FsPolicy *a, const FsPolicy *b)
{
	if (a == NULL || b == NULL)
		return a == b;

	for (gint k = 0; k < FS_RULE_N_KINDS; k++) {
		GPtrArray *ra = a->kinds[k];
		GPtrArray *rb = b->kinds[k];

		if (ra->len != rb->len)
			return FALSE;

		for (guint i = 0; i < ra->len; i++) {
			gchar *x = fs_rule_to_csv (g_ptr_array_index (ra, i));
			gchar *y = fs_rule_to_csv (g_ptr_array_index (rb, i));
			gboolean same = (g_strcmp0 (x, y) == 0);

			g_free (x);
			g_free (y);
			if (!same)
				return FALSE;
		}
	}

	return TRUE;
}

const gchar *
fs_whatif_verdict_name (FsWhatIfVerdict verdict)
{
	switch (verdict) {
	case FS_WHATIF_ALLOWED: return "ALLOWED";
	case FS_WHATIF_BLOCKED: return "BLOCKED";
	case FS_WHATIF_DEPENDS: return "DEPENDS";
	default:                return "ERROR";
	}
}

static void
step_free (gpointer data)
{
	FsWhatIfStep *s = data;

	g_free (s->rule);
	g_free (s->detail);
	g_free (s);
}

static void
case_free (gpointer data)
{
	FsWhatIfCase *c = data;

	g_free (c->condition);
	g_free (c->rule);
	g_free (c);
}

static void
action_free (gpointer data)
{
	FsWhatIfAction *a = data;

	g_free (a->label);
	g_free (a->explanation);
	fs_rule_free (a->row);
	g_free (a->target);
	g_free (a->page);
	g_free (a->setting);
	g_free (a);
}

static void
answer_free (gpointer data)
{
	FsWhatIfAnswer *a = data;

	g_free (a->probe);
	g_free (a->reason);
	g_free (a->rule);
	g_ptr_array_unref (a->steps);
	g_ptr_array_unref (a->cases);
	g_ptr_array_unref (a->actions);
	g_free (a);
}

static FsWhatIfAnswer *
answer_new (gboolean inbound)
{
	FsWhatIfAnswer *a = g_new0 (FsWhatIfAnswer, 1);

	a->inbound = inbound;
	a->steps = g_ptr_array_new_with_free_func (step_free);
	a->cases = g_ptr_array_new_with_free_func (case_free);
	a->actions = g_ptr_array_new_with_free_func (action_free);
	a->decided_by = -1;
	a->policy_kind = -1;
	a->policy_index = -1;
	return a;
}

static FsWhatIfResult *
result_new (void)
{
	FsWhatIfResult *r = g_new0 (FsWhatIfResult, 1);

	r->answers = g_ptr_array_new_with_free_func (answer_free);
	r->notes = g_ptr_array_new_with_free_func (g_free);
	r->verdict = FS_WHATIF_ERROR;
	return r;
}

void
fs_whatif_result_free (FsWhatIfResult *result)
{
	if (result == NULL)
		return;

	fs_whatif_query_free (result->query);
	g_ptr_array_unref (result->answers);
	g_ptr_array_unref (result->notes);
	g_free (result->summary);
	g_free (result->error);
	g_free (result);
}

static void
note_add (GPtrArray *notes, gchar *text)
{
	for (guint i = 0; i < notes->len; i++) {
		if (strcmp (g_ptr_array_index (notes, i), text) == 0) {
			g_free (text);
			return;
		}
	}

	g_ptr_array_add (notes, text);
}

const FsWhatIfAction *
fs_whatif_result_create_action (const FsWhatIfResult *r)
{
	if (r == NULL)
		return NULL;

	for (guint i = 0; i < r->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

		for (guint k = 0; k < a->actions->len; k++) {
			const FsWhatIfAction *act = g_ptr_array_index (a->actions, k);

			if ((act->kind == FS_WHATIF_ACT_CREATE_ALLOW ||
			     act->kind == FS_WHATIF_ACT_CREATE_BLOCK) &&
			    act->verified && act->row != NULL)
				return act;
		}
	}

	return NULL;
}

const FsWhatIfAction *
fs_whatif_result_primary_action (const FsWhatIfResult *r)
{
	const FsWhatIfAction *create = fs_whatif_result_create_action (r);

	if (create != NULL || r == NULL)
		return create;

	for (guint i = 0; i < r->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

		for (guint k = 0; k < a->actions->len; k++) {
			const FsWhatIfAction *act = g_ptr_array_index (a->actions, k);

			if (act->kind == FS_WHATIF_ACT_LIFT_SENTINEL)
				return act;
		}
	}

	return NULL;
}

/* ================================================================
 * 2. The parser
 *
 * The grammar is a set of small, separate recognisers over the words
 * of the line; each one that fires leaves a piece behind, so what the
 * engine answers is always what the user can see it read.  Nothing is
 * defaulted: a line with no direction is asked both ways, a line with
 * no host is asked for every host, and so on.
 * ================================================================ */

typedef struct
{
	gchar *text;    /* as typed, trailing sentence punctuation removed */
	gchar *lower;
	gboolean used;  /* consumed by a recogniser                       */
} Tok;

static void
tok_clear (gpointer data)
{
	Tok *t = data;

	g_free (t->text);
	g_free (t->lower);
}

static GArray *
tokenize (const gchar *text)
{
	GArray *toks = g_array_new (FALSE, TRUE, sizeof (Tok));
	const gchar *p = text;

	g_array_set_clear_func (toks, tok_clear);

	while (*p != '\0') {
		const gchar *start;
		const gchar *end;
		Tok t;

		while (*p != '\0' && (g_ascii_isspace (*p) ||
		                      strchr (",;()\"'?!", *p) != NULL))
			p++;
		if (*p == '\0')
			break;

		start = p;
		while (*p != '\0' && !g_ascii_isspace (*p) &&
		       strchr (",;()\"'?!", *p) == NULL)
			p++;
		end = p;

		/* A full stop ends a sentence, not an address. */
		while (end > start && end[-1] == '.')
			end--;
		if (end <= start)
			continue;

		t.text = g_strndup (start, (gsize) (end - start));
		t.lower = g_ascii_strdown (t.text, -1);
		t.used = FALSE;
		g_array_append_val (toks, t);
	}

	return toks;
}

#define TOK(toks, i) (&g_array_index ((toks), Tok, (i)))

static gboolean
tok_is (GArray *toks, gint i, const gchar *word)
{
	return i >= 0 && (guint) i < toks->len &&
	       strcmp (TOK (toks, i)->lower, word) == 0;
}

static gboolean
tok_is_any (GArray *toks, gint i, const gchar * const *words)
{
	for (guint k = 0; words[k] != NULL; k++)
		if (tok_is (toks, i, words[k]))
			return TRUE;
	return FALSE;
}

static void
piece_add (FsWhatIfQuery *q, FsWhatIfPieceKind kind, const gchar *text,
           gchar *meaning)
{
	FsWhatIfPiece *p = g_new0 (FsWhatIfPiece, 1);

	p->kind = kind;
	p->text = g_strdup (text);
	p->meaning = meaning;
	g_ptr_array_add (q->pieces, p);
}

/* [ all_digits ] -- one or more ASCII digits, nothing else. */
static gboolean
all_digits (const gchar *s)
{
	if (s == NULL || *s == '\0')
		return FALSE;
	for (; *s != '\0'; s++)
		if (!g_ascii_isdigit (*s))
			return FALSE;
	return TRUE;
}

/* [ read_port ]
 * A port number as typed.  0 means "not a number at all"; a number
 * that is not a port (0, or above 65535) is an error, never quietly
 * "any port". */
static guint
read_port (const gchar *digits, GError **error)
{
	guint64 v;

	if (!all_digits (digits))
		return 0;

	v = (strlen (digits) > 7) ? G_MAXUINT64
	                          : g_ascii_strtoull (digits, NULL, 10);

	if (v < 1 || v > 65535) {
		g_set_error (error, FS_WHATIF_PARSE_ERROR, FS_WHATIF_ERR_BAD_PORT,
		             _("%s is not a port: ports run from 1 to 65535."),
		             digits);
		return 0;
	}

	return (guint) v;
}

/* [ canonical_host ]
 * An address or a block in one spelling: the address as GLib writes
 * it ("2001:db8::1" for "2001:0db8:0::1") and a block by its network
 * address ("10.0.0.0/8" for "10.1.2.3/8").  NULL when it is not one. */
static gchar *
canonical_host (const gchar *text)
{
	const gchar *slash = strchr (text, '/');
	gchar *addr_text = slash ? g_strndup (text, (gsize) (slash - text))
	                         : g_strdup (text);
	GInetAddress *addr = g_inet_address_new_from_string (addr_text);
	gchar *out = NULL;

	g_free (addr_text);

	if (addr == NULL)
		return NULL;

	if (slash == NULL) {
		out = g_inet_address_to_string (addr);
	} else if (all_digits (slash + 1) && strlen (slash + 1) <= 3) {
		guint bits = (guint) g_inet_address_get_native_size (addr) * 8;
		guint prefix = (guint) g_ascii_strtoull (slash + 1, NULL, 10);

		if (prefix <= bits) {
			guint8 bytes[16];
			GInetAddress *net;
			gchar *s;

			memcpy (bytes, g_inet_address_to_bytes (addr),
			        g_inet_address_get_native_size (addr));
			for (guint b = prefix; b < bits; b++)
				bytes[b / 8] &= (guint8) ~(0x80u >> (b % 8));
			net = g_inet_address_new_from_bytes (
				bytes, g_inet_address_get_family (addr));
			s = g_inet_address_to_string (net);
			out = (prefix == bits) ? g_strdup (s)
			                       : g_strdup_printf ("%s/%u", s, prefix);
			g_free (s);
			g_object_unref (net);
		}
	}

	g_object_unref (addr);
	return out;
}

/* [ looks_numeric_host ]
 * Shapes that are clearly meant as an address: dotted digits, or hex
 * groups with colons.  Tells a mistyped address ("999.1.1.1", an
 * error) from a word. */
static gboolean
looks_numeric_host (const gchar *s)
{
	guint dots = 0, colons = 0;

	for (const gchar *p = s; *p != '\0'; p++) {
		if (*p == '.')
			dots++;
		else if (*p == ':')
			colons++;
		else if (*p == '/')
			continue;
		else if (dots > 0 && !g_ascii_isdigit (*p))
			return FALSE;
		else if (!g_ascii_isxdigit (*p))
			return FALSE;
	}

	return (dots >= 2 && colons == 0) || colons >= 2;
}

typedef struct
{
	const gchar *word;      /* lower case, one or two words           */
	const gchar *name;      /* how it is shown                        */
	guint        port;
	gint         proto;     /* P_TCP, P_UDP, or P_ANY for both        */
} Alias;

/* The names people type.  The service table (fs-service.c) is asked
 * after these; it knows more names but spells them its own way. */
static const Alias aliases[] = {
	{ "ssh", "SSH", 22, P_TCP },
	{ "sftp", "SFTP", 22, P_TCP },
	{ "scp", "SCP", 22, P_TCP },
	{ "rdp", "Remote Desktop", 3389, P_TCP },
	{ "remote desktop", "Remote Desktop", 3389, P_TCP },
	{ "http", "HTTP", 80, P_TCP },
	{ "https", "HTTPS", 443, P_TCP },
	{ "dns", "DNS", 53, P_ANY },
	{ "smb", "SMB", 445, P_TCP },
	{ "samba", "Samba", 445, P_TCP },
	{ "cifs", "SMB", 445, P_TCP },
	{ "file sharing", "SMB", 445, P_TCP },
	{ "ftp", "FTP", 21, P_TCP },
	{ "ftps", "FTPS", 990, P_TCP },
	{ "smtp", "SMTP", 25, P_TCP },
	{ "smtps", "SMTPS", 465, P_TCP },
	{ "submission", "Mail submission", 587, P_TCP },
	{ "imap", "IMAP", 143, P_TCP },
	{ "imaps", "IMAPS", 993, P_TCP },
	{ "pop3", "POP3", 110, P_TCP },
	{ "pop", "POP3", 110, P_TCP },
	{ "pop3s", "POP3S", 995, P_TCP },
	{ "ntp", "NTP", 123, P_UDP },
	{ "dhcp", "DHCP", 67, P_UDP },
	{ "vnc", "VNC", 5900, P_TCP },
	{ "mysql", "MySQL", 3306, P_TCP },
	{ "mariadb", "MariaDB", 3306, P_TCP },
	{ "postgres", "PostgreSQL", 5432, P_TCP },
	{ "postgresql", "PostgreSQL", 5432, P_TCP },
	{ "minecraft", "Minecraft", 25565, P_TCP },
	{ "telnet", "Telnet", 23, P_TCP },
	{ "ldap", "LDAP", 389, P_TCP },
	{ "ldaps", "LDAPS", 636, P_TCP },
	{ "mssql", "SQL Server", 1433, P_TCP },
	{ "sql server", "SQL Server", 1433, P_TCP },
	{ "redis", "Redis", 6379, P_TCP },
	{ "mongodb", "MongoDB", 27017, P_TCP },
	{ "mongo", "MongoDB", 27017, P_TCP },
	{ "snmp", "SNMP", 161, P_UDP },
	{ "syslog", "syslog", 514, P_UDP },
	{ "tftp", "TFTP", 69, P_UDP },
	{ "openvpn", "OpenVPN", 1194, P_UDP },
	{ "wireguard", "WireGuard", 51820, P_UDP },
	{ "ipsec", "IPsec NAT-T", 4500, P_UDP },
	{ "kerberos", "Kerberos", 88, P_ANY },
	{ "nfs", "NFS", 2049, P_ANY },
	{ "irc", "IRC", 6667, P_TCP },
	{ "xmpp", "XMPP", 5222, P_TCP },
	{ "mqtt", "MQTT", 1883, P_TCP },
	{ "ipp", "IPP printing", 631, P_TCP },
	{ "mdns", "mDNS", 5353, P_UDP },
	{ "ssdp", "SSDP", 1900, P_UDP },
	{ "upnp", "SSDP", 1900, P_UDP },
	{ "netbios", "NetBIOS", 137, P_UDP },
	{ "sip", "SIP", 5060, P_UDP },
	{ "rsync", "rsync", 873, P_TCP },
	{ "nntp", "NNTP", 119, P_TCP },
	{ "winrm", "WinRM", 5985, P_TCP },
	{ "teamviewer", "TeamViewer", 5938, P_TCP },
	{ "plex", "Plex", 32400, P_TCP },
	{ "bittorrent", "BitTorrent", 6881, P_ANY },
	{ "torrent", "BitTorrent", 6881, P_ANY }
};

static const gchar *proto_name (gint proto);

/* [ find_phrase ]
 * Token index where a one- or two-word phrase starts, or -1. */
static gint
find_phrase (GArray *toks, const gchar *phrase)
{
	const gchar *space = strchr (phrase, ' ');

	for (guint i = 0; i < toks->len; i++) {
		if (space == NULL) {
			if (strcmp (TOK (toks, i)->lower, phrase) == 0)
				return (gint) i;
		} else if (i + 1 < toks->len &&
		           strncmp (TOK (toks, i)->lower, phrase,
		                    (gsize) (space - phrase)) == 0 &&
		           TOK (toks, i)->lower[space - phrase] == '\0' &&
		           strcmp (TOK (toks, i + 1)->lower, space + 1) == 0) {
			return (gint) i;
		}
	}

	return -1;
}

/* [ find_free_phrase ]
 * Where a run of words (split the way the line is split) starts among
 * tokens no recogniser has taken, or -1; *n_out gets its length.  A
 * service is only ever a whole word of its own: never a piece of a
 * host name ("telnet.example.com") or of another word. */
static gint
find_free_phrase (GArray *toks, const gchar *phrase, guint *n_out)
{
	GArray *words = tokenize (phrase);
	gint found = -1;

	for (guint i = 0; words->len > 0 && i + words->len <= toks->len &&
	                  found < 0; i++) {
		gboolean all = TRUE;

		for (guint k = 0; k < words->len && all; k++) {
			const Tok *t = TOK (toks, i + k);

			all = !t->used &&
			      strcmp (t->lower, TOK (words, k)->lower) == 0;
		}
		if (all)
			found = (gint) i;
	}

	if (n_out != NULL)
		*n_out = words->len;
	g_array_unref (words);
	return found;
}

/* "from me", "to us": this computer, whatever follows. */
static const gchar *self_always[] = {
	"me", "us", "myself", "localhost", "here", NULL
};

/* "this computer", "the local machine", "my own pc": this computer --
 * but "my laptop 192.168.1.20" and "the local network" are not. */
static const gchar *self_nouns[] = {
	"computer", "machine", "pc", "host", "box", "device", "system",
	"server", "laptop", "desktop", "workstation", NULL
};
static const gchar *self_nouns_my[] = {
	"computer", "machine", "pc", NULL
};

/* [ self_at ]
 * How many tokens at i say "this computer" (0: they do not). */
static guint
self_at (GArray *toks, gint i)
{
	gint n;

	if (tok_is_any (toks, i, self_always))
		return 1;

	if (!tok_is (toks, i, "this") && !tok_is (toks, i, "my") &&
	    !tok_is (toks, i, "local"))
		return 0;

	n = i + 1;
	if (tok_is (toks, n, "own"))
		n++;
	if ((guint) n >= toks->len)
		return (guint) (n - i);      /* "from this", "to my own" */
	if (tok_is_any (toks, n, tok_is (toks, i, "my") ? self_nouns_my
	                                              : self_nouns))
		return (guint) (n - i + 1);
	/* "reach my SSH", "this web server": a service already read is
	 * one this computer runs. */
	if (!tok_is (toks, i, "local") && TOK (toks, n)->used)
		return (guint) (n - i);
	return 0;
}

/* Somewhere that is not this computer and could be anyone. */
static const gchar *any_words[] = {
	"internet", "outside", "anywhere", "anyone", "everyone", "everybody",
	"anybody", "world", "wan", "public", "all", NULL
};
static const gchar *any_heads[] = { "any", "all", "every", NULL };
static const gchar *any_tails[] = {
	"host", "hosts", "address", "addresses", "ip", "ips", "computer",
	"computers", "machine", "machines", "one", "where", NULL
};

/* [ any_at ] -- tokens at i saying "anyone" ("any host", "the
 * internet"); 0 when they do not. */
static guint
any_at (GArray *toks, gint i)
{
	if (tok_is_any (toks, i, any_words))
		return 1;
	if (tok_is_any (toks, i, any_heads) && tok_is_any (toks, i + 1, any_tails))
		return 2;
	return 0;
}

/* The local network: other computers, but not "anyone". */
static const gchar *lan_words[] = {
	"lan", "intranet", "subnet", "network", "wifi", "wlan", NULL
};
static const gchar *lan_heads[] = {
	"local", "home", "office", "internal", "private", "my", "our", NULL
};

/* [ lan_at ] -- tokens at i naming the local network; 0 if not. */
static guint
lan_at (GArray *toks, gint i)
{
	if (tok_is_any (toks, i, lan_words))
		return 1;
	if (tok_is_any (toks, i, lan_heads) && tok_is_any (toks, i + 1, lan_words))
		return 2;
	return 0;
}

static gboolean
has_non_ascii (const gchar *s)
{
	for (; *s != '\0'; s++)
		if ((guchar) *s >= 0x80)
			return TRUE;
	return FALSE;
}

/* [ is_port_range_token ] -- "22-80", "8000:8010". */
static gboolean
is_port_range_token (const gchar *s)
{
	const gchar *sep = strpbrk (s, "-:");
	gchar *head;
	gboolean ok;

	if (sep == NULL || sep == s || sep[1] == '\0')
		return FALSE;
	head = g_strndup (s, (gsize) (sep - s));
	ok = all_digits (head) && all_digits (sep + 1);
	g_free (head);
	return ok;
}

/* [ unreadable_host ]
 * A token written as an address that is not one: a pattern, a range,
 * an address with a zone, a block with a bad length, digits that are
 * not 0-9.  Its error, or NULL.  Dropping such a token would answer
 * (and offer a rule) for every host instead of the one meant. */
static gchar *
unreadable_host (const gchar *text, const gchar *lower)
{
	gboolean addressy = (strchr (lower, '.') != NULL ||
	                     strchr (lower, ':') != NULL);
	gboolean digit = FALSE;
	const gchar *cut;

	for (const gchar *p = lower; *p != '\0'; p++)
		if (g_ascii_isdigit (*p))
			digit = TRUE;

	if (strchr (lower, '*') != NULL && (addressy || digit))
		return g_strdup_printf (_("\"%s\" is a pattern, not an address: "
		                          "type one address, or a block such as "
		                          "192.168.1.0/24."), text);

	if (!addressy)
		return NULL;

	if (has_non_ascii (text))
		return g_strdup_printf (_("\"%s\" is not an address I can read: "
		                          "type it with the digits 0-9 (host "
		                          "names are not looked up here)."), text);

	if (strchr (lower, '%') != NULL)
		return g_strdup_printf (_("\"%s\" names a zone: type the address "
		                          "without the %%... part."), text);

	if ((cut = strchr (lower, '-')) != NULL) {
		gchar *head = g_strndup (lower, (gsize) (cut - lower));
		gchar *addr = canonical_host (head);
		gboolean range = (addr != NULL || looks_numeric_host (head));

		g_free (addr);
		g_free (head);
		if (range)
			return g_strdup_printf (_("\"%s\" is a range: type one "
			                          "address, or a block such as "
			                          "10.0.0.0/24."), text);
	}

	if ((cut = strchr (lower, '/')) != NULL) {
		gchar *head = g_strndup (lower, (gsize) (cut - lower));
		gchar *addr = canonical_host (head);
		gboolean block = (addr != NULL || looks_numeric_host (head));

		g_free (addr);
		g_free (head);
		if (block)
			return g_strdup_printf (_("\"%s\" is not a block: the length "
			                          "after / is a number up to 32 (128 "
			                          "for IPv6)."), text);
	}

	return NULL;
}

/* [ port_take ]
 * The line's port.  A second, different port is an error: an answer
 * (and a rule) for the first alone would quietly drop the other. */
static gboolean
port_take (FsWhatIfQuery *q, guint port, const gchar *text,
           gchar *meaning, GError **error)
{
	if (q->port == 0) {
		q->port = port;
		piece_add (q, FS_WHATIF_PIECE_PORT, text, meaning);
		return TRUE;
	}

	g_free (meaning);
	if (q->port == port)
		return TRUE;

	g_set_error (error, FS_WHATIF_PARSE_ERROR, FS_WHATIF_ERR_BAD_PORT,
	             _("Ask about one port at a time: the line names port %u "
	               "and port %u."), q->port, port);
	return FALSE;
}

static void
host_unread_set (FsWhatIfQuery *q, const gchar *text)
{
	if (q->host_unread == NULL)
		q->host_unread = g_strdup (text);
}

/* [ read_tokens ]
 * Hosts, host:port, [v6]:port, tcp/22 and 53/udp.  Errors for an
 * address or port that cannot be one, and for a second host.  Returns
 * the host token. */
static gint
read_tokens (FsWhatIfQuery *q, GArray *toks,
             gint *ignored, GError **error)
{
	gint host_tok = -1;

	for (guint i = 0; i < toks->len; i++) {
		Tok *t = TOK (toks, i);
		gchar *host = NULL;
		guint port = 0;
		gint proto = P_ANY;
		GError *local = NULL;
		gchar *bad;

		if (t->lower[0] == '[') {
			/* [2001:db8::1] or [2001:db8::1]:443 */
			const gchar *close = strchr (t->lower, ']');

			if (close != NULL) {
				gchar *inner = g_strndup (t->text + 1,
				                          (gsize) (close - t->lower - 1));

				host = canonical_host (inner);
				if (host == NULL || strchr (inner, ':') == NULL) {
					g_set_error (&local, FS_WHATIF_PARSE_ERROR,
					             FS_WHATIF_ERR_BAD_HOST,
					             _("\"%s\" is not an IPv6 address."),
					             inner);
					g_clear_pointer (&host, g_free);
				} else if (close[1] == ':') {
					port = read_port (close + 2, &local);
					if (port == 0 && local == NULL)
						g_set_error (&local, FS_WHATIF_PARSE_ERROR,
						             FS_WHATIF_ERR_BAD_PORT,
						             _("\"%s\" is not a port."),
						             close + 2);
				}
				g_free (inner);
			} else {
				g_set_error (&local, FS_WHATIF_PARSE_ERROR,
				             FS_WHATIF_ERR_BAD_HOST,
				             _("\"%s\" is not an address."), t->text);
			}
		} else if (g_str_has_prefix (t->lower, "tcp/") ||
		           g_str_has_prefix (t->lower, "udp/") ||
		           (g_str_has_suffix (t->lower, "/tcp") &&
		            strlen (t->lower) > 4) ||
		           (g_str_has_suffix (t->lower, "/udp") &&
		            strlen (t->lower) > 4)) {
			/* tcp/22, 53/udp */
			gboolean prefix = g_ascii_isalpha (t->lower[0]);
			gchar *num = prefix ? g_strdup (t->lower + 4)
			                    : g_strndup (t->lower,
			                                 strlen (t->lower) - 4);

			if (is_port_range_token (num))
				g_set_error (&local, FS_WHATIF_PARSE_ERROR,
				             FS_WHATIF_ERR_BAD_PORT,
				             _("Ask about one port at a time: \"%s\" is "
				               "a range of ports."), t->text);
			else
				port = read_port (num, &local);
			if (port != 0)
				proto = (strstr (t->lower, "tcp") != NULL) ? P_TCP
				                                           : P_UDP;
			g_free (num);
		} else if ((strchr (t->text, '.') != NULL ||
		            strchr (t->text, ':') != NULL) &&
		           (host = canonical_host (t->text)) != NULL) {
			/* a plain address or block */
		} else if (is_port_range_token (t->lower)) {
			g_set_error (&local, FS_WHATIF_PARSE_ERROR,
			             FS_WHATIF_ERR_BAD_PORT,
			             _("Ask about one port at a time: \"%s\" is a "
			               "range of ports."), t->text);
		} else if ((bad = unreadable_host (t->text, t->lower)) != NULL) {
			g_set_error_literal (&local, FS_WHATIF_PARSE_ERROR,
			                     FS_WHATIF_ERR_BAD_HOST, bad);
			g_free (bad);
		} else {
			const gchar *colon = strrchr (t->text, ':');

			if (colon != NULL && colon == strchr (t->text, ':') &&
			    all_digits (colon + 1)) {
				/* 10.0.0.1:22, :22, local:22 */
				gchar *head = g_strndup (t->lower,
				                         (gsize) (colon - t->text));
				gboolean self = (*head == '\0' ||
				                 strcmp (head, "localhost") == 0 ||
				                 strcmp (head, "local") == 0 ||
				                 strcmp (head, "me") == 0 ||
				                 strcmp (head, "self") == 0 ||
				                 strcmp (head, "this") == 0);
				gchar *addr = self ? NULL : canonical_host (head);

				if (self || (addr != NULL && strchr (head, '.') != NULL)) {
					port = read_port (colon + 1, &local);
					host = addr;
					addr = NULL;
				} else if (looks_numeric_host (head)) {
					g_set_error (&local, FS_WHATIF_PARSE_ERROR,
					             FS_WHATIF_ERR_BAD_HOST,
					             _("\"%s\" is not an address."), head);
				} else if (fs_util_is_valid_host (head)) {
					/* example.com:22 -- a name, not read. */
					piece_add (q, FS_WHATIF_PIECE_IGNORED, t->text,
					           g_strdup (_("host names are not looked "
					                       "up here; type its address")));
					host_unread_set (q, head);
					(*ignored)++;
					t->used = TRUE;
				}
				g_free (addr);
				g_free (head);
			} else if (looks_numeric_host (t->lower) &&
			           !all_digits (t->lower)) {
				g_set_error (&local, FS_WHATIF_PARSE_ERROR,
				             FS_WHATIF_ERR_BAD_HOST,
				             _("\"%s\" is not an address."), t->text);
			} else if (strchr (t->lower, '.') != NULL &&
			           fs_util_is_valid_host (t->text) &&
			           g_ascii_isalpha (t->lower[strlen (t->lower) - 1])) {
				piece_add (q, FS_WHATIF_PIECE_IGNORED, t->text,
				           g_strdup (_("host names are not looked up "
				                       "here; type its address")));
				host_unread_set (q, t->text);
				(*ignored)++;
				t->used = TRUE;
			}
		}

		if (local == NULL && port != 0) {
			t->used = TRUE;
			port_take (q, port, t->text,
			           g_strdup_printf (_("port %u"), port), &local);
		}

		if (local != NULL) {
			g_free (host);
			g_propagate_error (error, local);
			return -1;
		}

		if (host != NULL) {
			if (q->host == NULL) {
				q->host = host;
				host_tok = (gint) i;
				piece_add (q, FS_WHATIF_PIECE_HOST, t->text,
				           g_strdup_printf (strchr (host, '/')
				                            ? _("hosts in %s")
				                            : _("host %s"), host));
			} else if (strcmp (q->host, host) != 0) {
				/* Answering for the first and dropping the second
				 * would answer, and offer a rule for, less than was
				 * asked without saying so. */
				g_set_error (error, FS_WHATIF_PARSE_ERROR,
				             FS_WHATIF_ERR_BAD_HOST,
				             _("Ask about one host at a time: the line "
				               "names %s and %s."), q->host, host);
				g_free (host);
				return -1;
			} else {
				g_free (host);
			}
			t->used = TRUE;
		}

		if (proto != P_ANY && q->protocol == FS_WHATIF_PROTO_ANY) {
			q->protocol = (proto == P_TCP) ? FS_WHATIF_PROTO_TCP
			                               : FS_WHATIF_PROTO_UDP;
			piece_add (q, FS_WHATIF_PIECE_PROTOCOL, t->text,
			           g_strdup (proto_name (proto)));
		}
	}

	return host_tok;
}

/* [ read_port_words ]
 * "port N", "N port", "on N", "tcp N", "port number N". */
static gboolean
read_port_words (FsWhatIfQuery *q, GArray *toks, GError **error)
{
	static const gchar *before[] = {
		"port", "ports", "on", "at", "tcp", "udp", NULL
	};

	for (guint i = 0; i < toks->len; i++) {
		Tok *t = TOK (toks, i);
		const gchar *digits = t->lower;
		gboolean named = FALSE;
		GError *local = NULL;
		guint port;

		if (t->used)
			continue;
		if (digits[0] == '#')
			digits++;
		if (!all_digits (digits))
			continue;

		if (tok_is_any (toks, (gint) i - 1, before))
			named = TRUE;
		else if (tok_is (toks, (gint) i + 1, "port"))
			named = TRUE;
		else if (i >= 2 && tok_is (toks, (gint) i - 2, "port") &&
		         (tok_is (toks, (gint) i - 1, "number") ||
		          tok_is (toks, (gint) i - 1, "no")))
			named = TRUE;

		if (!named)
			continue;

		port = read_port (digits, &local);
		if (local == NULL) {
			t->used = TRUE;
			port_take (q, port, t->text,
			           g_strdup_printf (_("port %u"), port), &local);
		}
		if (local != NULL) {
			g_propagate_error (error, local);
			return FALSE;
		}
	}

	return TRUE;
}

/* A number followed by one of these counts or times something; it is
 * not a port ("for 1 hour", "3 times"). */
static const gchar *count_words[] = {
	"second", "seconds", "sec", "secs", "minute", "minutes", "min", "mins",
	"hour", "hours", "hr", "hrs", "day", "days", "week", "weeks", "month",
	"months", "year", "years", "time", "times", "x", "percent",
	"attempt", "attempts", "try", "tries", "connection", "connections",
	"packet", "packets", "user", "users", "people", "device", "devices",
	"computer", "computers", "host", "hosts", "pc", "pcs", "am", "pm",
	NULL
};

/* [ read_bare_numbers ]
 * A number standing on its own ("allow 8080", "443 to 203.0.113.9") is
 * a port -- unless a count or time word follows it.  Run after the
 * service, so "rdp for 1 hour" stays RDP's port: when the service
 * already gave the port, a different bare number is shown as not used
 * rather than replacing it. */
static gboolean
read_bare_numbers (FsWhatIfQuery *q, GArray *toks, gboolean port_from_service,
                   gint *conflicts, GError **error)
{
	for (guint i = 0; i < toks->len; i++) {
		Tok *t = TOK (toks, i);
		GError *local = NULL;
		guint port;

		if (t->used || !all_digits (t->lower))
			continue;

		if (tok_is_any (toks, (gint) i + 1, count_words)) {
			t->used = TRUE;
			piece_add (q, FS_WHATIF_PIECE_IGNORED, t->text,
			           g_strdup_printf (_("\"%s %s\" counts or times "
			                              "something; it is not a port"),
			                            t->text, TOK (toks, i + 1)->text));
			continue;
		}

		port = read_port (t->lower, &local);
		if (local != NULL) {
			g_propagate_error (error, local);
			return FALSE;
		}
		t->used = TRUE;

		if (port_from_service && q->port != 0 && q->port != port) {
			piece_add (q, FS_WHATIF_PIECE_IGNORED, t->text,
			           g_strdup_printf (_("a number on its own: %s's port "
			                              "%u is used; write \"port %s\" "
			                              "to ask about that port"),
			                            q->service != NULL ? q->service
			                                               : _("the service"),
			                            q->port, t->text));
			(*conflicts)++;
			continue;
		}

		if (!port_take (q, port, t->text,
		                g_strdup_printf (_("port %u (a number on its own "
		                                   "is read as a port)"), port),
		                error))
			return FALSE;
	}

	return TRUE;
}

/* [ read_protocol ] -- tcp/udp/icmp and ICMP's own words. */
static void
read_protocol (FsWhatIfQuery *q, GArray *toks, gint *conflicts)
{
	static const struct {
		const gchar *word;
		gint proto;
		const gchar *icmp;
	} words[] = {
		{ "tcp", P_TCP, NULL },
		{ "udp", P_UDP, NULL },
		{ "icmp", P_ICMP, NULL },
		{ "icmpv6", P_ICMP, NULL },
		{ "ping", P_ICMP, "echo-request" },
		{ "pings", P_ICMP, "echo-request" },
		{ "pinging", P_ICMP, "echo-request" },
		{ "pinged", P_ICMP, "echo-request" },
		{ "echo-request", P_ICMP, "echo-request" },
		{ "echo request", P_ICMP, "echo-request" },
		{ "echo-reply", P_ICMP, "echo-reply" },
		{ "echo reply", P_ICMP, "echo-reply" },
		{ "pong", P_ICMP, "echo-reply" },
		{ "unreachable", P_ICMP, "destination-unreachable" },
		{ "time exceeded", P_ICMP, "time-exceeded" },
		{ "time-exceeded", P_ICMP, "time-exceeded" }
	};
	gint seen = P_ANY;

	for (guint w = 0; w < G_N_ELEMENTS (words); w++) {
		gint at = find_phrase (toks, words[w].word);

		if (at < 0)
			continue;

		if (seen != P_ANY && seen != words[w].proto)
			(*conflicts)++;
		if (seen == P_ANY)
			seen = words[w].proto;

		if (words[w].icmp != NULL && q->icmp_type == NULL) {
			q->icmp_type = g_strdup (words[w].icmp);
			piece_add (q, FS_WHATIF_PIECE_ICMP, TOK (toks, at)->text,
			           g_strdup_printf (_("ICMP %s"), words[w].icmp));
		} else if (words[w].icmp == NULL) {
			piece_add (q, FS_WHATIF_PIECE_PROTOCOL, TOK (toks, at)->text,
			           g_strdup (proto_name (words[w].proto)));
		}
	}

	if (seen != P_ANY) {
		FsWhatIfProto want = seen == P_TCP ? FS_WHATIF_PROTO_TCP
		                   : seen == P_UDP ? FS_WHATIF_PROTO_UDP
		                                   : FS_WHATIF_PROTO_ICMP;

		if (q->protocol != FS_WHATIF_PROTO_ANY && q->protocol != want)
			(*conflicts)++;
		else
			q->protocol = want;
	}
}

/* [ read_service ]
 * A service name: the alias list, then the service table's names for
 * services people run (not its list of old trojan ports: "girlfriend"
 * is a word, not port 21544).  Matched only as whole words no other
 * recogniser took, so a host name ("dns.google") never names a
 * service.  It gives the port when the line named none, and the
 * protocol when the service has exactly one and the line named none. */
static void
read_service (FsWhatIfQuery *q, GArray *toks)
{
	const Alias *best = NULL;
	const FsService *svc = NULL;
	gint best_at = -1;
	guint best_n = 0;
	gsize best_len = 0;
	gint proto = P_ANY;
	gboolean had_port = (q->port != 0);

	for (guint a = 0; a < G_N_ELEMENTS (aliases); a++) {
		guint n = 0;
		gint at = find_free_phrase (toks, aliases[a].word, &n);

		if (at >= 0 && strlen (aliases[a].word) > best_len) {
			best = &aliases[a];
			best_at = at;
			best_n = n;
			best_len = strlen (aliases[a].word);
		}
	}

	if (best == NULL) {
		guint count = 0;
		const FsService *list = fs_service_user_list (&count);

		for (guint i = 0; i < count; i++) {
			guint n = 0;
			gint at = find_free_phrase (toks, list[i].name, &n);

			if (at >= 0 && strlen (list[i].name) > best_len) {
				svc = &list[i];
				best_at = at;
				best_n = n;
				best_len = strlen (list[i].name);
			}
		}
	}

	for (guint k = 0; best_at >= 0 && k < best_n; k++)
		TOK (toks, (guint) best_at + k)->used = TRUE;

	if (best != NULL) {
		q->service = g_strdup (best->name);
		proto = best->proto;
		if (!had_port)
			q->port = best->port;
		piece_add (q, FS_WHATIF_PIECE_SERVICE, TOK (toks, best_at)->text,
		           g_strdup_printf (_("service %s: %s port %u"),
		                            best->name,
		                            best->proto == P_ANY
		                            ? _("TCP or UDP")
		                            : proto_name (best->proto),
		                            had_port ? q->port : best->port));
	} else if (svc != NULL) {
		gchar *spec = fs_fwrule_port_spec (svc->ports);
		guint first = spec ? (guint) g_ascii_strtoull (spec, NULL, 10)
		                   : 0;

		g_free (spec);
		q->service = g_strdup (svc->name);
		proto = (svc->tcp_ports != NULL && svc->udp_ports == NULL)
		        ? P_TCP
		        : (svc->udp_ports != NULL && svc->tcp_ports == NULL)
		        ? P_UDP : P_ANY;
		if (!had_port && first >= 1 && first <= 65535)
			q->port = first;
		piece_add (q, FS_WHATIF_PIECE_SERVICE, svc->name,
		           g_strdup_printf (_("service %s: port %u"),
		                            svc->name, q->port));
	}

	if (q->protocol == FS_WHATIF_PROTO_ANY && q->port != 0 &&
	    proto != P_ANY)
		q->protocol = (proto == P_TCP) ? FS_WHATIF_PROTO_TCP
		                               : FS_WHATIF_PROTO_UDP;
}

/* [ host_follows ]
 * "from my laptop 192.168.1.20": the host comes a few plain words after
 * "from" / "to". */
static gboolean
host_follows (GArray *toks, gint next, gint host_tok)
{
	static const gchar *stop[] = {
		"from", "to", "into", "towards", "and", "or", "but", "on", "at",
		"port", "ports", NULL
	};

	if (host_tok < next || host_tok - next > 3)
		return FALSE;

	for (gint k = next; k < host_tok; k++) {
		const Tok *t = TOK (toks, k);

		if (t->used || tok_is_any (toks, k, stop))
			return FALSE;
		for (const gchar *p = t->lower; *p != '\0'; p++)
			if (!g_ascii_isalpha (*p))
				return FALSE;
	}
	return TRUE;
}

/* [ unread_host_at ]
 * TRUE when the token at i is a host the line named but that is not
 * read: a name already set aside ("server.example.com"), or a one-word
 * machine name with a digit or a hyphen in it ("nas01", "ssh-gw") --
 * plain words ("from bob") are left alone, since they are as likely
 * ordinary English.  Such a name is set aside here. */
static gboolean
unread_host_at (FsWhatIfQuery *q, GArray *toks, gint i)
{
	const Tok *t;
	gboolean marked = FALSE;

	if (i < 0 || (guint) i >= toks->len)
		return FALSE;
	t = TOK (toks, i);

	if (q->host_unread != NULL && strcmp (t->text, q->host_unread) == 0)
		return TRUE;
	if (t->used || all_digits (t->lower) ||
	    !g_ascii_isalpha (t->lower[0]) || !fs_util_is_valid_host (t->text))
		return FALSE;
	for (const gchar *c = t->lower; *c != '\0'; c++)
		if (g_ascii_isdigit (*c) || *c == '-')
			marked = TRUE;
	if (!marked)
		return FALSE;

	piece_add (q, FS_WHATIF_PIECE_IGNORED, t->text,
	           g_strdup (_("host names are not looked up here; type its "
	                       "address")));
	host_unread_set (q, t->text);
	TOK (toks, i)->used = TRUE;
	return TRUE;
}

/* [ read_direction ]
 * Keywords first; then what "from" and "to" point at: "from <host>"
 * is inbound, "to <host>" outbound, and "to me" / "from this computer"
 * the other way round.  "From the internet" / "to anywhere" say the
 * other end is anyone; "from the local network" that it is another
 * computer, but not which.  "Open port 8080 to the internet" exposes
 * this computer: inbound.  A line that says none of this is asked both
 * ways. */
static void
read_direction (FsWhatIfQuery *q, GArray *toks, gint host_tok,
                gboolean exposure_verb, gint *conflicts)
{
	static const gchar *in_words[] = {
		"inbound", "incoming", "ingress", NULL
	};
	static const gchar *out_words[] = {
		"outbound", "outgoing", "egress", NULL
	};
	static const gchar *from_w[] = { "from", NULL };
	static const gchar *to_w[] = {
		"to", "into", "towards", "reach", "reaching", "access",
		"contact", NULL
	};
	static const gchar *articles[] = { "the", "a", "an", NULL };
	gboolean in = FALSE, out = FALSE;
	gboolean keyword;

	for (guint i = 0; i < toks->len; i++) {
		if (tok_is_any (toks, (gint) i, in_words)) {
			in = TRUE;
			piece_add (q, FS_WHATIF_PIECE_DIRECTION, TOK (toks, i)->text,
			           g_strdup (_("inbound")));
		} else if (tok_is_any (toks, (gint) i, out_words)) {
			out = TRUE;
			piece_add (q, FS_WHATIF_PIECE_DIRECTION, TOK (toks, i)->text,
			           g_strdup (_("outbound")));
		}
	}

	if (in && out)
		(*conflicts)++;
	else if (in)
		q->direction = FS_WHATIF_DIR_INBOUND;
	else if (out)
		q->direction = FS_WHATIF_DIR_OUTBOUND;
	keyword = (in || out);

	for (guint i = 0; i < toks->len; i++) {
		gboolean is_from = tok_is_any (toks, (gint) i, from_w);
		gboolean is_to = tok_is_any (toks, (gint) i, to_w);
		gint next = (gint) i + 1;
		FsWhatIfDirection implied = FS_WHATIF_DIR_BOTH;
		const gchar *meaning = NULL;
		guint span = 0;

		if (!is_from && !is_to)
			continue;

		while (tok_is_any (toks, next, articles))
			next++;

		if (host_tok >= 0 && (next == host_tok ||
		                      host_follows (toks, next, host_tok))) {
			implied = is_from ? FS_WHATIF_DIR_INBOUND
			                  : FS_WHATIF_DIR_OUTBOUND;
		} else if (self_at (toks, next) > 0) {
			implied = is_from ? FS_WHATIF_DIR_OUTBOUND
			                  : FS_WHATIF_DIR_INBOUND;
		} else if (host_tok < 0 && unread_host_at (q, toks, next)) {
			/* "from server.example.com": a host, just not read. */
			implied = is_from ? FS_WHATIF_DIR_INBOUND
			                  : FS_WHATIF_DIR_OUTBOUND;
		} else if (host_tok < 0 && (span = any_at (toks, next)) > 0) {
			/* "from the internet", "to anywhere": the far end is
			 * anyone, and which host stays open. */
			q->host_any_said = TRUE;
			if (is_to && exposure_verb) {
				implied = FS_WHATIF_DIR_INBOUND;
				meaning = _("inbound: reachable from any host");
			} else {
				implied = is_from ? FS_WHATIF_DIR_INBOUND
				                  : FS_WHATIF_DIR_OUTBOUND;
				meaning = is_from ? _("inbound, from any host")
				                  : _("outbound, to any host");
			}
		} else if (host_tok < 0 && (span = lan_at (toks, next)) > 0) {
			/* "from the local network": other computers, but which
			 * addresses that is, the line does not say. */
			if (is_to && exposure_verb) {
				implied = FS_WHATIF_DIR_INBOUND;
				meaning = _("inbound: reachable from the local network "
				            "(its addresses are not named)");
			} else {
				implied = is_from ? FS_WHATIF_DIR_INBOUND
				                  : FS_WHATIF_DIR_OUTBOUND;
				meaning = is_from
					? _("inbound, from the local network (its "
					    "addresses are not named)")
					: _("outbound, to the local network (its "
					    "addresses are not named)");
			}
		}

		if (span > 0)
			for (guint k = 0; k < span; k++)
				TOK (toks, (guint) next + k)->used = TRUE;

		if (implied == FS_WHATIF_DIR_BOTH)
			continue;

		if (keyword || (q->direction != FS_WHATIF_DIR_BOTH &&
		                q->direction != implied)) {
			if (implied != q->direction)
				(*conflicts)++;
			continue;
		}

		if (q->direction == FS_WHATIF_DIR_BOTH && meaning != NULL) {
			GString *words = g_string_new (TOK (toks, i)->text);

			for (gint k = (gint) i + 1; k < next + (gint) span; k++)
				g_string_append_printf (words, " %s",
				                        TOK (toks, k)->text);
			piece_add (q, FS_WHATIF_PIECE_DIRECTION, words->str,
			           g_strdup (meaning));
			g_string_free (words, TRUE);
		} else if (q->direction == FS_WHATIF_DIR_BOTH)
			piece_add (q, FS_WHATIF_PIECE_DIRECTION, TOK (toks, i)->text,
			           g_strdup (implied == FS_WHATIF_DIR_INBOUND
			                     ? _("inbound") : _("outbound")));
		q->direction = implied;
	}
}

/* Words that turn a request around: "let nobody in", "don't allow". */
static const gchar *negators[] = {
	"no", "not", "nobody", "noone", "none", "never", "nothing", "neither",
	"nor", "cannot", "dont", "cant", "wont", "doesnt", "isnt", "shouldnt",
	"mustnt", "wouldnt", "couldnt", "didnt", "arent", "aint", "except",
	"excluding", "besides", "unless", "without", "but", NULL
};

/* [ find_negation ] -- the first token that negates, or -1. */
static gint
find_negation (GArray *toks)
{
	for (guint i = 0; i < toks->len; i++) {
		const Tok *t = TOK (toks, i);

		if (tok_is_any (toks, (gint) i, negators)) {
			/* "port no 22" is a port number. */
			if (tok_is (toks, (gint) i, "no") &&
			    (tok_is (toks, (gint) i - 1, "port") ||
			     tok_is (toks, (gint) i - 1, "ports")))
				continue;
			return (gint) i;
		}
		/* "don't", "can't": the apostrophe splits them into "don"
		 * "t"; a typographic one does not. */
		if (strcmp (t->lower, "t") == 0 && i > 0 &&
		    g_str_has_suffix (TOK (toks, i - 1)->lower, "n"))
			return (gint) i;
		if (g_str_has_suffix (t->lower, "n\xe2\x80\x99t"))
			return (gint) i;
	}
	return -1;
}

FsWhatIfQuery *
fs_whatif_parse (const gchar *text, GError **error)
{
	static const gchar *allow_verbs[] = {
		"allow", "permit", "unblock", "open", "let", "accept",
		"enable", "whitelist", "allowlist", "expose", NULL
	};
	static const gchar *block_verbs[] = {
		"block", "deny", "drop", "reject", "close", "forbid",
		"prevent", "stop", "disable", "disallow", "blacklist",
		"blocklist", "unexpose", NULL
	};
	static const gchar *exposure_verbs[] = {
		"open", "close", "expose", "unexpose", NULL
	};
	static const gchar *fillers[] = {
		"please", "i", "want", "to", "would", "like", "you", "can",
		"could", "how", "do", "should", "we", "need", "just", "lets",
		"i'd", "i'll", "will", "go", "and", NULL
	};
	/* A line that starts like this asks; it does not tell. */
	static const gchar *question_words[] = {
		"is", "are", "am", "was", "were", "does", "did", "why", "what",
		"which", "who", "when", "where", "has", "have", NULL
	};
	FsWhatIfQuery *q;
	GArray *toks;
	gchar *trimmed;
	gint host_tok;
	gint conflicts = 0;
	gint ignored = 0;
	gint verb_tok = -1;
	gint first_word = -1;
	gint negation;
	gboolean port_from_service;
	GError *local = NULL;

	trimmed = g_strstrip (g_strdup (text != NULL ? text : ""));
	if (*trimmed == '\0') {
		g_set_error_literal (error, FS_WHATIF_PARSE_ERROR, FS_WHATIF_ERR_EMPTY,
		                     _("Type a connection to check, for example "
		                       "\"allow SSH from 192.168.1.50\"."));
		g_free (trimmed);
		return NULL;
	}

	q = fs_whatif_query_new ();
	q->text = g_strdup (trimmed);
	toks = tokenize (trimmed);

	/* The verb: an imperative at the start, after any politeness
	 * ("let's" and "let us" are politeness too, not "let"). */
	for (guint i = 0; i < toks->len; i++) {
		if (tok_is (toks, (gint) i, "let") &&
		    (tok_is (toks, (gint) i + 1, "s") ||
		     tok_is (toks, (gint) i + 1, "us"))) {
			i++;
			continue;
		}
		if (tok_is_any (toks, (gint) i, fillers))
			continue;

		first_word = (gint) i;
		if (tok_is_any (toks, (gint) i, allow_verbs))
			q->verb = FS_WHATIF_VERB_ALLOW;
		else if (tok_is_any (toks, (gint) i, block_verbs))
			q->verb = FS_WHATIF_VERB_BLOCK;

		if (q->verb != FS_WHATIF_VERB_NONE) {
			verb_tok = (gint) i;
			TOK (toks, i)->used = TRUE;
			piece_add (q, FS_WHATIF_PIECE_VERB, TOK (toks, i)->text,
			           g_strdup (q->verb == FS_WHATIF_VERB_ALLOW
			                     ? _("you want it allowed")
			                     : _("you want it blocked")));
		}
		break;
	}

	/* "let nobody from the internet use RDP", "don't allow telnet":
	 * read word by word these say the opposite of what is meant, so a
	 * request with a negation in it is not guessed at.  A question
	 * ("is port 22 not open?") is still answered. */
	negation = find_negation (toks);
	if (negation >= 0 && !tok_is_any (toks, first_word, question_words)) {
		gboolean verb_word = (verb_tok >= 0);

		for (guint i = 0; i < toks->len && !verb_word; i++)
			verb_word = tok_is_any (toks, (gint) i, allow_verbs) ||
			            tok_is_any (toks, (gint) i, block_verbs);

		if (verb_word) {
			/* "don" "t" were one word, "don't". */
			gchar *neg_words = (strcmp (TOK (toks, negation)->lower,
			                            "t") == 0)
				? g_strdup_printf ("%s'%s",
				                   TOK (toks, negation - 1)->text,
				                   TOK (toks, negation)->text)
				: g_strdup (TOK (toks, negation)->text);

			g_set_error (error, FS_WHATIF_PARSE_ERROR,
			             FS_WHATIF_ERR_UNREADABLE,
			             _("\"%s\" turns the request around, and I would "
			               "rather not guess which way you mean it. Say "
			               "it plainly, for example \"block RDP from the "
			               "internet\", or ask \"can the internet reach "
			               "RDP?\"."),
			             neg_words);
			g_free (neg_words);
			g_array_unref (toks);
			fs_whatif_query_free (q);
			g_free (trimmed);
			return NULL;
		}
	}

	host_tok = read_tokens (q, toks, &ignored, &local);
	if (local == NULL)
		read_port_words (q, toks, &local);
	if (local == NULL) {
		guint before = q->port;

		read_protocol (q, toks, &conflicts);
		read_service (q, toks);
		port_from_service = (before == 0 && q->port != 0);
		read_bare_numbers (q, toks, port_from_service, &conflicts, &local);
	}

	if (local != NULL) {
		g_propagate_error (error, local);
		g_array_unref (toks);
		fs_whatif_query_free (q);
		g_free (trimmed);
		return NULL;
	}

	/* ICMP has no ports. */
	if (q->protocol == FS_WHATIF_PROTO_ICMP && q->port != 0) {
		piece_add (q, FS_WHATIF_PIECE_IGNORED, "port",
		           g_strdup (_("ICMP has no ports; the port is ignored")));
		q->port = 0;
		conflicts++;
	}

	read_direction (q, toks, host_tok,
	                verb_tok >= 0 && tok_is_any (toks, verb_tok,
	                                             exposure_verbs),
	                &conflicts);

	/* Nothing recognisable at all is not a question. */
	{
		guint found = 0;
		gboolean kinds[FS_WHATIF_PIECE_IGNORED + 1];

		memset (kinds, 0, sizeof kinds);
		for (guint i = 0; i < q->pieces->len; i++) {
			const FsWhatIfPiece *p = g_ptr_array_index (q->pieces, i);

			if (p->kind != FS_WHATIF_PIECE_VERB &&
			    p->kind != FS_WHATIF_PIECE_IGNORED && !kinds[p->kind]) {
				kinds[p->kind] = TRUE;
				found++;
			}
		}

		if (found == 0) {
			g_set_error (error, FS_WHATIF_PARSE_ERROR,
			             FS_WHATIF_ERR_UNREADABLE,
			             _("I could not find a port, service, host or "
			               "direction in \"%s\"."), trimmed);
			g_array_unref (toks);
			fs_whatif_query_free (q);
			g_free (trimmed);
			return NULL;
		}

		q->confidence = (found >= 3) ? 0.9 : (found == 2) ? 0.75 : 0.5;
		if (q->verb != FS_WHATIF_VERB_NONE)
			q->confidence += 0.1;
		q->confidence -= 0.25 * conflicts + 0.1 * ignored;
		q->confidence = CLAMP (q->confidence, 0.1, 1.0);
	}

	g_array_unref (toks);
	g_free (trimmed);
	return q;
}

/* ================================================================
 * 3. Addresses
 *
 * Compared as bytes with a prefix length, so "2001:db8::1" and
 * "2001:0db8::1" are the same host, a host inside a block is inside
 * it, and a block inside a bigger block is inside that.  A host NAME
 * is kept as a name: whether it covers an address is a DNS question
 * the answer has to admit it cannot settle on its own.
 * ================================================================ */

typedef enum
{
	ADDR_ANY = 0,       /* no address condition                     */
	ADDR_BLOCK,         /* an address (full prefix) or a block      */
	ADDR_NAME,          /* a host name, looked up at apply time     */
	ADDR_NONE           /* not usable: the rule is left out        */
} AddrKind;

typedef struct
{
	AddrKind kind;
	gint     fam;       /* 4 or 6 (BLOCK only)                      */
	guint8   b[16];
	guint    prefix;
	gchar   *text;      /* as written in the rule, or canonical    */
} Addr;

static void
addr_clear (Addr *a)
{
	g_clear_pointer (&a->text, g_free);
	memset (a, 0, sizeof *a);
}

static void
addr_copy (Addr *dst, const Addr *src)
{
	*dst = *src;
	dst->text = g_strdup (src->text);
}

/* [ addr_parse ] -- a policy target, an address or a block. */
static void
addr_parse (Addr *a, const gchar *text)
{
	const gchar *slash;
	gchar *head;
	GInetAddress *ia;
	FsFamily fam;

	memset (a, 0, sizeof *a);

	if (fs_util_target_is_anyone (text)) {
		a->kind = ADDR_ANY;
		return;
	}

	a->text = g_strdup (text);
	fam = fs_util_target_families (text);

	if (fam == FS_FAMILY_NONE) {
		a->kind = ADDR_NONE;
		return;
	}

	if (fam == FS_FAMILY_BOTH) {
		a->kind = ADDR_NAME;
		return;
	}

	slash = strchr (text, '/');
	head = slash ? g_strndup (text, (gsize) (slash - text)) : g_strdup (text);
	ia = g_inet_address_new_from_string (head);
	g_free (head);

	if (ia == NULL) {
		a->kind = ADDR_NONE;
		return;
	}

	a->kind = ADDR_BLOCK;
	a->fam = (g_inet_address_get_family (ia) == G_SOCKET_FAMILY_IPV6) ? 6 : 4;
	memcpy (a->b, g_inet_address_to_bytes (ia),
	        g_inet_address_get_native_size (ia));
	a->prefix = (a->fam == 6) ? 128 : 32;
	if (slash != NULL)
		a->prefix = (guint) MIN (g_ascii_strtoull (slash + 1, NULL, 10),
		                         (guint64) a->prefix);
	g_object_unref (ia);
}

static guint
addr_bits (const Addr *a)
{
	return a->fam == 6 ? 128 : 32;
}

/* [ addr_contains ] -- every address of inner lies in outer. */
static gboolean
addr_contains (const Addr *outer, const Addr *inner)
{
	if (outer->kind != ADDR_BLOCK || inner->kind != ADDR_BLOCK ||
	    outer->fam != inner->fam || inner->prefix < outer->prefix)
		return FALSE;

	for (guint bit = 0; bit < outer->prefix; bit++) {
		guint8 m = (guint8) (0x80u >> (bit % 8));

		if ((outer->b[bit / 8] & m) != (inner->b[bit / 8] & m))
			return FALSE;
	}

	return TRUE;
}

/* [ addr_host ]
 * One address of a block: its first (last == FALSE) or its last. */
static void
addr_host (Addr *out, const Addr *block, gboolean last)
{
	GInetAddress *ia;

	*out = *block;
	for (guint bit = block->prefix; bit < addr_bits (block); bit++) {
		guint8 m = (guint8) (0x80u >> (bit % 8));

		if (last)
			out->b[bit / 8] |= m;
		else
			out->b[bit / 8] &= (guint8) ~m;
	}
	out->prefix = addr_bits (block);

	ia = g_inet_address_new_from_bytes (out->b, out->fam == 6
	                                    ? G_SOCKET_FAMILY_IPV6
	                                    : G_SOCKET_FAMILY_IPV4);
	out->text = g_inet_address_to_string (ia);
	g_object_unref (ia);
}

static gboolean
addr_equal (const Addr *a, const Addr *b)
{
	if (a->kind != b->kind)
		return FALSE;
	if (a->kind == ADDR_BLOCK)
		return a->fam == b->fam && a->prefix == b->prefix &&
		       memcmp (a->b, b->b, 16) == 0;
	if (a->kind == ADDR_NAME)
		return g_ascii_strcasecmp (a->text, b->text) == 0;
	return TRUE;
}

static gboolean
addr_is_loopback (const Addr *a)
{
	if (a->kind != ADDR_BLOCK)
		return FALSE;
	if (a->fam == 4)
		return a->b[0] == 127;
	for (guint i = 0; i < 15; i++)
		if (a->b[i] != 0)
			return FALSE;
	return a->b[15] == 1;
}

/* [ addr_is_self ]
 * One address of this computer: loopback, or one of the addresses the
 * context knows it has. */
static gboolean
addr_is_self (const FsWhatIfContext *ctx, const Addr *a)
{
	if (a->kind != ADDR_BLOCK || a->prefix != addr_bits (a))
		return FALSE;
	if (addr_is_loopback (a))
		return TRUE;

	for (guint i = 0; ctx != NULL && i < ctx->local_addresses->len; i++) {
		Addr l;
		gboolean same;

		addr_parse (&l, g_ptr_array_index (ctx->local_addresses, i));
		same = (l.kind == ADDR_BLOCK && l.fam == a->fam &&
		        memcmp (l.b, a->b, l.fam == 6 ? 16 : 4) == 0);
		addr_clear (&l);
		if (same)
			return TRUE;
	}
	return FALSE;
}

/* ================================================================
 * 4. The rule model
 *
 * One structure for both platforms.  A Linux rule is one iptables
 * line (fam says which family's chain it is in); a Windows rule is one
 * Windows Firewall rule (fam 0: both).  left_out marks a rule the
 * platform will not carry -- an allow with a port that does not parse,
 * a name Windows cannot take -- so the trace can say so instead of
 * dropping it silently.
 * ================================================================ */

typedef enum
{
	T_ACCEPT,
	T_DROP,
	T_REJECT,
	T_LOG          /* not a verdict: logs and carries on              */
} Target;

typedef struct
{
	gchar          *name;
	FsWhatIfOrigin  origin;
	gint            pkind;          /* FsRuleKind or -1               */
	gint            prow;
	gboolean        inbound;
	Target          target;
	gint            fam;            /* 4 / 6 (Linux), 0 (Windows)     */

	gint            proto;          /* P_ANY / P_TCP / P_UDP / P_ICMP */
	gboolean        icmp6;          /* ipv6-icmp (rendering)          */
	gchar          *icmp;           /* type name, NULL = any          */
	gboolean        has_dport;
	gchar          *dport;          /* normalised spec; NULL with
	                                 * has_dport = matches no port   */
	gchar          *sport;          /* Linux --sport                  */
	gchar          *other_ports;    /* Windows: ports on the ephemeral
	                                 * side -- never this probe      */
	Addr            src;            /* Linux -s                       */
	Addr            dst;            /* Linux -d                       */
	Addr           *remote;         /* Windows remote addresses       */
	guint           n_remote;
	gchar          *in_if;
	gchar          *out_if;
	gchar          *ctstate;
	guint           hl;
	gchar          *limit;
	gchar          *burst;
	guint           profiles;       /* FS_FWP_PROFILE_* mask; 0 = all */
	gchar          *forward_to;     /* "10.0.0.5:80"                  */
	gchar          *not_forwarded;  /* Windows: a forward row's target,
	                                 * which nothing passes traffic to */
	gchar          *left_out;       /* why it is not in force         */
	gboolean        tail;           /* Linux: a settings drop after the
	                                 * policy's allows (broadcast,
	                                 * reserved sources)              */

	/* Rendering (Linux): the text the generator writes. */
	gchar          *r_dport;
	gchar          *r_sport;
	gchar          *r_target;
	gboolean        r_skip_v6;      /* the text form leaves it out    */
} WRule;

static void
wrule_free (gpointer data)
{
	WRule *r = data;

	g_free (r->name);
	g_free (r->icmp);
	g_free (r->dport);
	g_free (r->sport);
	g_free (r->other_ports);
	addr_clear (&r->src);
	addr_clear (&r->dst);
	for (guint i = 0; i < r->n_remote; i++)
		addr_clear (&r->remote[i]);
	g_free (r->remote);
	g_free (r->in_if);
	g_free (r->out_if);
	g_free (r->ctstate);
	g_free (r->limit);
	g_free (r->burst);
	g_free (r->forward_to);
	g_free (r->not_forwarded);
	g_free (r->left_out);
	g_free (r->r_dport);
	g_free (r->r_sport);
	g_free (r->r_target);
	g_free (r);
}

static WRule *
wrule_new (const gchar *name, FsWhatIfOrigin origin, gboolean inbound,
           Target target, const gchar *r_target)
{
	WRule *r = g_new0 (WRule, 1);

	r->name = g_strdup (name);
	r->origin = origin;
	r->pkind = -1;
	r->prow = -1;
	r->inbound = inbound;
	r->target = target;
	r->r_target = g_strdup (r_target);
	return r;
}

/* A DNAT rule of the nat table: what arrives on the external interface
 * for `dport' is sent to `to':`to_port' before INBOUND sees it. */
typedef struct
{
	gchar *name;
	gint   pkind, prow;
	gchar *dport;      /* normalised spec */
	Addr   to;
	guint  to_port;
} Dnat;

static void
dnat_free (gpointer data)
{
	Dnat *d = data;

	g_free (d->name);
	g_free (d->dport);
	addr_clear (&d->to);
	g_free (d);
}

typedef struct
{
	const FsWhatIfContext *ctx;
	FsWhatIfPlatform platform;
	const FsSettings *settings;
	FsSettings       *own_settings;
	const FsPolicy   *policy;
	FsPolicy         *own_policy;

	/* Linux: chains by family; Windows: in[0]/out[0] only. */
	GPtrArray *in[2];        /* WRule*, [0] = IPv4, [1] = IPv6 */
	GPtrArray *out[2];
	GPtrArray *dnat[2];      /* Dnat* */
	const gchar *ext;        /* valid external interface, or NULL */
	const gchar *intf;       /* valid internal interface, or NULL */

	/* Deciders that are not rules of a chain, so the trace and the
	 * cases can name them.  Linux: a forward to another computer with
	 * IP forwarding off goes nowhere.  Windows: traffic to itself is not
	 * filtered; "Block all incoming connections" overrides every allow
	 * (one per profile). */
	WRule     *fwd_gate;
	WRule     *win_loopback;
	WRule     *win_return;
	WRule     *win_shields[3];

	GPtrArray *notes;        /* gchar*: things the model knows */
} Model;

static void
model_free (Model *m)
{
	for (gint f = 0; f < 2; f++) {
		g_ptr_array_unref (m->in[f]);
		g_ptr_array_unref (m->out[f]);
		g_ptr_array_unref (m->dnat[f]);
	}
	g_ptr_array_unref (m->notes);
	g_clear_pointer (&m->fwd_gate, wrule_free);
	g_clear_pointer (&m->win_loopback, wrule_free);
	g_clear_pointer (&m->win_return, wrule_free);
	for (gint p = 0; p < 3; p++)
		g_clear_pointer (&m->win_shields[p], wrule_free);
	fs_settings_free (m->own_settings);
	fs_policy_free (m->own_policy);
	g_free (m);
}

static const gchar *
proto_name (gint proto)
{
	switch (proto) {
	case P_TCP:  return "TCP";
	case P_UDP:  return "UDP";
	case P_ICMP: return "ICMP";
	default:     return _("any protocol");
	}
}

/* [ comment_is_sentinel ]
 * A row Sentinel staged: its comment starts with "Sentinel:" (the
 * same test the Copilot page uses when it lifts one). */
static gboolean
comment_is_sentinel (const gchar *comment)
{
	if (comment == NULL)
		return FALSE;
	while (g_ascii_isspace (*comment))
		comment++;
	return g_str_has_prefix (comment, "Sentinel:");
}

static FsWhatIfOrigin
row_origin (FsRuleKind kind, const FsRule *row)
{
	if (kind == FS_RULE_OUTBOUND_DENY_TO && comment_is_sentinel (row->comment))
		return FS_WHATIF_ORIGIN_SENTINEL;
	return FS_WHATIF_ORIGIN_POLICY;
}

/* ================================================================
 * 5. The Linux model
 *
 * generate_inbound() and generate_outbound() of fs-script.c, rule for
 * rule and in the same order.  The policy rows go through the same
 * checks the generator applies (fs_util_is_valid_port for ports,
 * fs_util_target_families for hosts), and the core suite compares
 * fs_whatif_linux_chain_text() with the generator's own output for a
 * table of policies and settings, so a change to one without the
 * other fails there.  Host names stay names here: the restore form
 * looks them up at apply time, and the answer says "depends on DNS".
 * ================================================================ */

static const gchar *
lin_accept (const FsSettings *s)
{
	return (s != NULL && s->log_allowed) ? FS_SCRIPT_ACCEPT_CHAIN : "ACCEPT";
}

/* [ lin_port ]
 * A row's port as the generator writes it ("67-68" -> "67:68", "022"
 * -> "22": fs_script_port_text, the generator's own function), and the
 * spec the probe is matched against, read from that same text so the
 * two cannot disagree.  A spec of NULL (port 0) matches no connection,
 * as --dport 0 does not.  FALSE when the generator would refuse it. */
static gboolean
lin_port (const gchar *text, gchar **render, gchar **spec)
{
	const gchar *colon;
	guint first, last;

	*spec = NULL;
	*render = fs_script_port_text (text);
	if (*render == NULL)
		return FALSE;

	colon = strchr (*render, ':');
	first = (guint) g_ascii_strtoull (*render, NULL, 10);
	last = colon != NULL ? (guint) g_ascii_strtoull (colon + 1, NULL, 10)
	                     : first;
	if (first < 1)
		first = 1;
	if (last >= first && last <= 65535)
		*spec = (first == last) ? g_strdup_printf ("%u", first)
		                        : g_strdup_printf ("%u-%u", first, last);
	return TRUE;
}

static WRule *
lin_icmp (Model *m, GPtrArray *chain, gint fam, gboolean inbound,
          const gchar *name, FsWhatIfOrigin origin, const gchar *type,
          const gchar *limit)
{
	WRule *r = wrule_new (name, origin, inbound, T_ACCEPT, "ACCEPT");

	r->fam = fam;
	r->proto = P_ICMP;
	r->icmp6 = (fam == 6);
	r->icmp = g_strdup (type);
	r->limit = g_strdup (limit);
	g_ptr_array_add (chain, r);
	(void) m;
	return r;
}

/* [ lin_icmp_rules ] -- append_icmp6_essentials + append_icmp_rules. */
static void
lin_icmp_rules (Model *m, GPtrArray *in, gint fam)
{
	const FsSettings *s = m->settings;
	const FsWhatIfOrigin B = FS_WHATIF_ORIGIN_BUILTIN;
	const FsWhatIfOrigin S = FS_WHATIF_ORIGIN_SETTINGS;
	WRule *r;

	if (fam == 6) {
		static const struct { const gchar *type; guint hl; gboolean ll; }
		essentials[] = {
			{ "packet-too-big", 0, FALSE },
			{ "time-exceeded", 0, FALSE },
			{ "parameter-problem", 0, FALSE },
			{ "router-advertisement", 255, TRUE },
			{ "neighbour-solicitation", 255, FALSE },
			{ "neighbour-advertisement", 255, FALSE },
			{ "130", 1, FALSE }, { "131", 1, FALSE },
			{ "132", 1, FALSE }, { "143", 1, FALSE }
		};

		for (guint i = 0; i < G_N_ELEMENTS (essentials); i++) {
			gchar *name = g_strdup_printf (_("IPv6 essentials: ICMPv6 %s"),
			                               essentials[i].type);

			r = lin_icmp (m, in, 6, TRUE, name, B, essentials[i].type, NULL);
			r->hl = essentials[i].hl;
			if (essentials[i].ll)
				addr_parse (&r->src, "fe80::/10");
			g_free (name);
		}

		r = wrule_new (_("IPv6 essentials: DHCPv6 replies"), B, TRUE,
		               T_ACCEPT, "ACCEPT");
		r->fam = 6;
		r->proto = P_UDP;
		addr_parse (&r->src, "fe80::/10");
		r->sport = g_strdup ("547");
		r->r_sport = g_strdup ("547");
		r->has_dport = TRUE;
		r->dport = g_strdup ("546");
		r->r_dport = g_strdup ("546");
		g_ptr_array_add (in, r);
	}

	if (!s->filter_icmp) {
		lin_icmp (m, in, fam, TRUE,
		          _("ICMP filtering is off: all ICMP is allowed"), S, NULL,
		          "10/s");
		return;
	}

	if (fam == 4) {
		lin_icmp (m, in, 4, TRUE, _("ICMP: time exceeded (always on)"),
		          S, "time-exceeded", NULL);
		lin_icmp (m, in, 4, TRUE, _("ICMP: parameter problem (always on)"),
		          S, "parameter-problem", NULL);
	}

	if (s->icmp_echo_request)
		lin_icmp (m, in, fam, TRUE, _("ICMP: ping requests"), S,
		          "echo-request", "1/s");
	if (s->icmp_echo_reply)
		lin_icmp (m, in, fam, TRUE, _("ICMP: ping replies"), S,
		          "echo-reply", "1/s");

	if (s->icmp_traceroute) {
		r = wrule_new (_("ICMP page: traceroute (UDP 33434)"), S, TRUE,
		               T_ACCEPT, "ACCEPT");
		r->fam = fam;
		r->proto = P_UDP;
		r->has_dport = TRUE;
		r->dport = g_strdup ("33434");
		r->r_dport = g_strdup ("33434");
		g_ptr_array_add (in, r);
	}

	if (s->icmp_mstraceroute)
		lin_icmp (m, in, fam, TRUE, _("ICMP: MS traceroute"), S,
		          "destination-unreachable", NULL);
	if (s->icmp_unreachable)
		lin_icmp (m, in, fam, TRUE, _("ICMP: unreachable"), S,
		          fam == 6 ? "address-unreachable" : "host-unreachable",
		          NULL);

	if (s->icmp_timestamping && fam == 4) {
		lin_icmp (m, in, 4, TRUE, _("ICMP: timestamps"), S,
		          "timestamp-request", NULL);
		lin_icmp (m, in, 4, TRUE, _("ICMP: timestamps"), S,
		          "timestamp-reply", NULL);
	}

	if (s->icmp_masking && fam == 4) {
		lin_icmp (m, in, 4, TRUE, _("ICMP: address masks"), S,
		          "address-mask-request", NULL);
		lin_icmp (m, in, 4, TRUE, _("ICMP: address masks"), S,
		          "address-mask-reply", NULL);
	}

	if (s->icmp_redirection) {
		r = lin_icmp (m, in, fam, TRUE, _("ICMP: redirects"), S,
		              "redirect", "2/s");
		if (fam == 6) {
			addr_parse (&r->src, "fe80::/10");
			r->hl = 255;
		}
	}

	if (s->icmp_source_quenches && fam == 4)
		lin_icmp (m, in, 4, TRUE, _("ICMP: source quench"), S,
		          "source-quench", "2/s");
}

/* [ lin_target ]
 * The generator's gen_addresses() in text form, for one target: the
 * address to match (ANY for everyone), or FALSE when this family's
 * chain gets no rule for it.  *why says why when the row is left out
 * altogether (only reported once, for IPv4, as the generator does). */
static gboolean
lin_target (const gchar *target, gint fam, Addr *out, gchar **why,
            gboolean deny)
{
	FsFamily f;

	*why = NULL;
	memset (out, 0, sizeof *out);

	if (fs_util_target_is_anyone (target))
		return TRUE;

	f = fs_util_target_families (target);

	if (f == FS_FAMILY_NONE) {
		*why = deny
			? g_strdup_printf (_("\"%s\" is not an address or host "
			                     "name, so the policy cannot be applied"),
			                   target)
			: g_strdup_printf (_("\"%s\" is not an address or host "
			                     "name; the rule was left out"), target);
		return FALSE;
	}

	if (f == FS_FAMILY_BOTH) {
		addr_parse (out, target);   /* ADDR_NAME */
		return TRUE;
	}

	if ((fam == 4 && f != FS_FAMILY_IPV4) ||
	    (fam == 6 && f != FS_FAMILY_IPV6))
		return FALSE;

	addr_parse (out, target);
	return TRUE;
}

static gchar *
row_name (FsRuleKind kind, const FsRule *row, gboolean inbound,
          gboolean block, gboolean with_service)
{
	return fs_fwrule_default_name (inbound ? FS_DIR_INBOUND : FS_DIR_OUTBOUND,
	                               block ? FS_ACTION_BLOCK : FS_ACTION_ALLOW,
	                               with_service ? row->service : NULL,
	                               row->target);
	(void) kind;
}

/* A rule standing for a row the platform leaves out. */
static void
add_left_out (GPtrArray *chain, gchar *name, FsWhatIfOrigin origin,
              gint kind, gint row, gboolean inbound, gboolean block,
              gchar *why)
{
	WRule *r = wrule_new (name, origin, inbound, block ? T_DROP : T_ACCEPT,
	                      NULL);

	r->pkind = kind;
	r->prow = row;
	r->left_out = why;
	g_ptr_array_add (chain, r);
	g_free (name);
}

/* [ lin_host_rows ] -- append_host_rules (outbound) and the inbound
 * allow-from loop. */
static void
lin_host_rows (Model *m, GPtrArray *chain, gint fam, FsRuleKind kind,
               gboolean inbound, gboolean block, gboolean src)
{
	GPtrArray *rows = m->policy->kinds[kind];

	for (guint i = 0; i < rows->len; i++) {
		const FsRule *row = g_ptr_array_index (rows, i);
		gchar *why = NULL;
		Addr a;
		WRule *r;

		if (row->target == NULL || *row->target == '\0' ||
		    (!inbound && fs_util_target_is_anyone (row->target))) {
			if (fam == 4)
				add_left_out (chain, row_name (kind, row, inbound,
				                               block, FALSE),
				              row_origin (kind, row), kind, (gint) i,
				              inbound, block,
				              g_strdup (_("names no host, so the "
				                          "generator writes no rule "
				                          "for it")));
			continue;
		}

		if (!lin_target (row->target, fam, &a, &why, block)) {
			if (why != NULL && fam == 4) {
				if (block)
					note_add (m->notes, g_strdup_printf (
						_("The policy cannot be applied as "
						  "saved: %s."), why));
				add_left_out (chain, row_name (kind, row, inbound,
				                               block, FALSE),
				              row_origin (kind, row), kind, (gint) i,
				              inbound, block, why);
			} else {
				g_free (why);
			}
			continue;
		}

		r = wrule_new (NULL, row_origin (kind, row), inbound,
		               block ? T_DROP : T_ACCEPT,
		               block ? "DROP" : lin_accept (m->settings));
		r->name = row_name (kind, row, inbound, block, FALSE);
		r->pkind = kind;
		r->prow = (gint) i;
		r->fam = fam;
		r->r_skip_v6 = (a.kind == ADDR_NAME);
		if (src)
			r->src = a;
		else
			r->dst = a;
		g_ptr_array_add (chain, r);
	}
}

/* [ lin_service_rows ] -- append_service_rules: a tcp and a udp line
 * per row (one only for the "TCP" / "UDP" pseudo-services), matching
 * the row's port as --dport and its target as -s. */
static void
lin_service_rows (Model *m, GPtrArray *chain, gint fam, FsRuleKind kind,
                  gboolean inbound, gboolean block)
{
	GPtrArray *rows = m->policy->kinds[kind];

	for (guint i = 0; i < rows->len; i++) {
		const FsRule *row = g_ptr_array_index (rows, i);
		gchar *render = NULL, *spec = NULL, *why = NULL;
		gboolean tcp = TRUE, udp = TRUE;
		Addr a;

		if (row->service != NULL &&
		    g_ascii_strcasecmp (row->service, "TCP") == 0)
			udp = FALSE;
		else if (row->service != NULL &&
		         g_ascii_strcasecmp (row->service, "UDP") == 0)
			tcp = FALSE;

		if (row->port == NULL || *row->port == '\0') {
			if (fam == 4)
				add_left_out (chain, row_name (kind, row, inbound,
				                               block, TRUE),
				              row_origin (kind, row), kind, (gint) i,
				              inbound, block,
				              g_strdup (_("names no port, so the "
				                          "generator writes no rule "
				                          "for it")));
			continue;
		}

		if (!lin_port (row->port, &render, &spec)) {
			if (fam == 4) {
				if (block)
					note_add (m->notes, g_strdup_printf (
						_("The policy cannot be applied as "
						  "saved: \"%s\" is not a valid port, so "
						  "it cannot be blocked."), row->port));
				add_left_out (chain, row_name (kind, row, inbound,
				                               block, TRUE),
				              row_origin (kind, row), kind, (gint) i,
				              inbound, block,
				              g_strdup_printf (_("\"%s\" is not a valid "
				                                 "port"), row->port));
			}
			continue;
		}

		if (!lin_target (row->target, fam, &a, &why, block)) {
			if (why != NULL && fam == 4) {
				if (block)
					note_add (m->notes, g_strdup_printf (
						_("The policy cannot be applied as "
						  "saved: %s."), why));
				add_left_out (chain, row_name (kind, row, inbound,
				                               block, TRUE),
				              row_origin (kind, row), kind, (gint) i,
				              inbound, block, why);
			} else {
				g_free (why);
			}
			g_free (render);
			g_free (spec);
			continue;
		}

		for (gint p = 0; p < 2; p++) {
			gboolean want = (p == 0) ? tcp : udp;
			gchar *base;
			WRule *r;

			if (!want)
				continue;

			base = row_name (kind, row, inbound, block, TRUE);
			r = wrule_new (NULL, row_origin (kind, row), inbound,
			               block ? T_DROP : T_ACCEPT,
			               block ? "DROP" : lin_accept (m->settings));
			r->name = (tcp && udp)
				? g_strconcat (base, p == 0 ? " (TCP)" : " (UDP)", NULL)
				: g_strdup (base);
			g_free (base);
			r->pkind = kind;
			r->prow = (gint) i;
			r->fam = fam;
			r->proto = (p == 0) ? P_TCP : P_UDP;
			r->has_dport = TRUE;
			r->dport = g_strdup (spec);
			r->r_dport = g_strdup (render);
			addr_copy (&r->src, &a);
			r->r_skip_v6 = (a.kind == ADDR_NAME);
			g_ptr_array_add (chain, r);
		}

		addr_clear (&a);
		g_free (render);
		g_free (spec);
	}
}

/* [ lin_forwards ] -- gen_forward_to: the INBOUND accept for what a
 * forward redirected, and the DNAT itself (nat table, ext only). */
static void
lin_forwards (Model *m, GPtrArray *in, gint fam)
{
	GPtrArray *rows = m->policy->kinds[FS_RULE_INBOUND_FORWARD];

	for (guint i = 0; i < rows->len; i++) {
		const FsRule *row = g_ptr_array_index (rows, i);
		FsFamily f;
		gchar *port_r = NULL, *port_s = NULL, *to_r = NULL, *to_s = NULL;
		gchar *name;
		WRule *r;

		if (row->port == NULL || row->to == NULL || row->to_port == NULL)
			continue;

		name = fs_fwrule_default_name (FS_DIR_INBOUND, FS_ACTION_ALLOW,
		                               row->service, NULL);
		f = fs_util_target_families (row->to);

		if (f == FS_FAMILY_NONE || f == FS_FAMILY_BOTH ||
		    strchr (row->to, '/') != NULL) {
			if (fam == 4)
				add_left_out (in, g_strdup (name),
				              FS_WHATIF_ORIGIN_POLICY,
				              FS_RULE_INBOUND_FORWARD, (gint) i, TRUE,
				              FALSE,
				              g_strdup (_("a forward needs an IP "
				                          "address, not a name or a "
				                          "range")));
			g_free (name);
			continue;
		}

		if ((fam == 4 && f != FS_FAMILY_IPV4) ||
		    (fam == 6 && f != FS_FAMILY_IPV6)) {
			g_free (name);
			continue;
		}

		if (!lin_port (row->port, &port_r, &port_s) ||
		    !lin_port (row->to_port, &to_r, &to_s) ||
		    strchr (to_r, ':') != NULL || to_s == NULL) {
			add_left_out (in, g_strdup (name), FS_WHATIF_ORIGIN_POLICY,
			              FS_RULE_INBOUND_FORWARD, (gint) i, TRUE, FALSE,
			              g_strdup (_("its ports are not valid")));
			g_free (port_r); g_free (port_s);
			g_free (to_r); g_free (to_s);
			g_free (name);
			continue;
		}

		r = wrule_new (name, FS_WHATIF_ORIGIN_POLICY, TRUE, T_ACCEPT,
		               lin_accept (m->settings));
		r->pkind = FS_RULE_INBOUND_FORWARD;
		r->prow = (gint) i;
		r->fam = fam;
		r->proto = P_TCP;
		addr_parse (&r->dst, row->to);
		r->has_dport = TRUE;
		r->dport = g_strdup (to_s);
		r->r_dport = g_strdup (to_r);
		r->ctstate = g_strdup ("DNAT");
		r->forward_to = g_strdup_printf (fam == 6 ? "[%s]:%s" : "%s:%s",
		                                 row->to, to_r);
		g_ptr_array_add (in, r);

		if (m->ext != NULL) {
			Dnat *d = g_new0 (Dnat, 1);

			d->name = g_strdup (name);
			d->pkind = FS_RULE_INBOUND_FORWARD;
			d->prow = (gint) i;
			d->dport = g_strdup (port_s);
			addr_parse (&d->to, row->to);
			d->to_port = (guint) g_ascii_strtoull (to_s, NULL, 10);
			g_ptr_array_add (m->dnat[fam == 6], d);
		}

		g_free (port_r); g_free (port_s);
		g_free (to_r); g_free (to_s);
		g_free (name);
	}
}

static void
lin_inbound (Model *m, gint fam)
{
	const FsSettings *s = m->settings;
	GPtrArray *in = m->in[fam == 6];
	WRule *r;

	lin_icmp_rules (m, in, fam);

	r = wrule_new (_("Return traffic for connections already open"),
	               FS_WHATIF_ORIGIN_BUILTIN, TRUE, T_ACCEPT, "ACCEPT");
	r->fam = fam;
	r->ctstate = g_strdup ("ESTABLISHED,RELATED");
	g_ptr_array_add (in, r);

	r = wrule_new (_("Loopback (this computer to itself)"),
	               FS_WHATIF_ORIGIN_BUILTIN, TRUE, T_ACCEPT, "ACCEPT");
	r->fam = fam;
	r->in_if = g_strdup ("lo");
	g_ptr_array_add (in, r);

	if (s->nat && m->intf != NULL) {
		gchar *name = g_strdup_printf (
			_("Router mode: everything arriving on the internal "
			  "interface %s"), m->intf);

		r = wrule_new (name, FS_WHATIF_ORIGIN_SETTINGS, TRUE, T_ACCEPT,
		               "ACCEPT");
		r->fam = fam;
		r->in_if = g_strdup (m->intf);
		g_ptr_array_add (in, r);
		g_free (name);
	}

	r = wrule_new (_("Invalid packets (malformed, or a reply to nothing "
	                 "this computer sent)"), FS_WHATIF_ORIGIN_BUILTIN, TRUE,
	               T_DROP, "DROP");
	r->fam = fam;
	r->ctstate = g_strdup ("INVALID");
	g_ptr_array_add (in, r);

	lin_host_rows (m, in, fam, FS_RULE_INBOUND_ALLOW_FROM, TRUE, FALSE,
	               TRUE);
	lin_service_rows (m, in, fam, FS_RULE_INBOUND_ALLOW_SERVICE, TRUE,
	                  FALSE);
	lin_forwards (m, in, fam);

	if (s->block_external_broadcast && m->ext != NULL && fam == 4) {
		r = wrule_new (_("Broadcasts arriving from outside"),
		               FS_WHATIF_ORIGIN_SETTINGS, TRUE, T_DROP, "DROP");
		r->fam = 4;
		r->tail = TRUE;
		r->in_if = g_strdup (m->ext);
		addr_parse (&r->dst, "255.255.255.255");
		g_ptr_array_add (in, r);
	}

	if (s->block_internal_broadcast && s->nat && m->intf != NULL &&
	    fam == 4) {
		r = wrule_new (_("Broadcasts arriving on the local network"),
		               FS_WHATIF_ORIGIN_SETTINGS, TRUE, T_DROP, "DROP");
		r->fam = 4;
		r->tail = TRUE;
		r->in_if = g_strdup (m->intf);
		addr_parse (&r->dst, "255.255.255.255");
		g_ptr_array_add (in, r);
	}

	if (s->block_non_routables && m->ext != NULL) {
		static const gchar *v4[] = {
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"127.0.0.0/8", NULL
		};
		static const gchar *v6[] = {
			"::1/128", "::ffff:0:0/96", "2001:db8::/32", NULL
		};
		const gchar **list = (fam == 6) ? v6 : v4;

		for (guint i = 0; list[i] != NULL; i++) {
			gchar *name = g_strdup_printf (
				_("Reserved source %s arriving from outside"), list[i]);

			r = wrule_new (name, FS_WHATIF_ORIGIN_SETTINGS, TRUE, T_DROP,
			               "DROP");
			r->fam = fam;
			r->tail = TRUE;
			r->in_if = g_strdup (m->ext);
			addr_parse (&r->src, list[i]);
			g_ptr_array_add (in, r);
			g_free (name);
		}
	}

	r = wrule_new (_("Default: log"), FS_WHATIF_ORIGIN_DEFAULT, TRUE,
	               T_LOG, s->deny_packets
	               ? "LOG --log-prefix \"STOCKFW-DROP \" --log-level 6"
	               : "LOG --log-prefix \"STOCKFW-REJECT \" --log-level 6");
	r->fam = fam;
	g_ptr_array_add (in, r);

	if (s->deny_packets) {
		r = wrule_new (_("Default: drop silently"),
		               FS_WHATIF_ORIGIN_DEFAULT, TRUE, T_DROP, "DROP");
	} else {
		gchar *t = g_strdup_printf ("REJECT --reject-with %s",
		                            fam == 6 ? "icmp6-addr-unreachable"
		                                     : "icmp-host-unreachable");

		r = wrule_new (_("Default: reject with an error"),
		               FS_WHATIF_ORIGIN_DEFAULT, TRUE, T_REJECT, t);
		g_free (t);
	}
	r->fam = fam;
	g_ptr_array_add (in, r);
}

static void
lin_outbound (Model *m, gint fam)
{
	const FsSettings *s = m->settings;
	GPtrArray *out = m->out[fam == 6];
	WRule *r;

	r = wrule_new (_("Return traffic for connections already open"),
	               FS_WHATIF_ORIGIN_BUILTIN, FALSE, T_ACCEPT, "ACCEPT");
	r->fam = fam;
	r->ctstate = g_strdup ("ESTABLISHED,RELATED");
	g_ptr_array_add (out, r);

	r = wrule_new (_("Loopback (this computer to itself)"),
	               FS_WHATIF_ORIGIN_BUILTIN, FALSE, T_ACCEPT, "ACCEPT");
	r->fam = fam;
	r->out_if = g_strdup ("lo");
	g_ptr_array_add (out, r);

	if (s->filter_icmp)
		lin_icmp (m, out, fam, FALSE,
		          _("Outbound ICMP (allowed while ICMP filtering is on)"),
		          FS_WHATIF_ORIGIN_SETTINGS, NULL, NULL);

	if (fam == 6) {
		static const struct { const gchar *type; guint hl; } ess[] = {
			{ "neighbour-solicitation", 255 },
			{ "neighbour-advertisement", 255 },
			{ "router-solicitation", 255 },
			{ "131", 1 }, { "132", 1 }, { "143", 1 },
			{ "packet-too-big", 0 }
		};

		for (guint i = 0; i < G_N_ELEMENTS (ess); i++) {
			gchar *name = g_strdup_printf (_("IPv6 essentials: ICMPv6 %s"),
			                               ess[i].type);

			r = lin_icmp (m, out, 6, FALSE, name,
			              FS_WHATIF_ORIGIN_BUILTIN, ess[i].type, NULL);
			r->hl = ess[i].hl;
			g_free (name);
		}

		r = wrule_new (_("IPv6 essentials: DHCPv6 requests"),
		               FS_WHATIF_ORIGIN_BUILTIN, FALSE, T_ACCEPT, "ACCEPT");
		r->fam = 6;
		r->proto = P_UDP;
		r->sport = g_strdup ("546");
		r->r_sport = g_strdup ("546");
		r->has_dport = TRUE;
		r->dport = g_strdup ("547");
		r->r_dport = g_strdup ("547");
		g_ptr_array_add (out, r);
	}

	/* Deny rows first, in both modes. */
	lin_host_rows (m, out, fam, FS_RULE_OUTBOUND_DENY_TO, FALSE, TRUE,
	               FALSE);
	lin_host_rows (m, out, fam, FS_RULE_OUTBOUND_DENY_FROM, FALSE, TRUE,
	               TRUE);
	lin_service_rows (m, out, fam, FS_RULE_OUTBOUND_DENY_SERVICE, FALSE,
	                  TRUE);

	if (s->nat && m->ext != NULL) {
		gchar *name = g_strdup_printf (
			_("Router mode: everything leaving on %s"), m->ext);

		r = wrule_new (name, FS_WHATIF_ORIGIN_SETTINGS, FALSE, T_ACCEPT,
		               "ACCEPT");
		r->fam = fam;
		r->out_if = g_strdup (m->ext);
		g_ptr_array_add (out, r);
		g_free (name);
	}

	lin_host_rows (m, out, fam, FS_RULE_OUTBOUND_ALLOW_TO, FALSE, FALSE,
	               FALSE);
	lin_host_rows (m, out, fam, FS_RULE_OUTBOUND_ALLOW_FROM, FALSE, FALSE,
	               TRUE);
	lin_service_rows (m, out, fam, FS_RULE_OUTBOUND_ALLOW_SERVICE, FALSE,
	                  FALSE);

	if (s->restrictive_outbound) {
		r = wrule_new (_("Default: log"), FS_WHATIF_ORIGIN_DEFAULT, FALSE,
		               T_LOG,
		               "LOG --log-prefix \"STOCKFW-DROP \" --log-level 6");
		r->fam = fam;
		r->limit = g_strdup ("20/s");
		r->burst = g_strdup ("40");
		g_ptr_array_add (out, r);

		r = wrule_new (_("Default: drop (restrictive outbound mode)"),
		               FS_WHATIF_ORIGIN_DEFAULT, FALSE, T_DROP, "DROP");
	} else {
		r = wrule_new (_("Default: allow (outbound is open by default)"),
		               FS_WHATIF_ORIGIN_DEFAULT, FALSE, T_ACCEPT,
		               lin_accept (s));
	}
	r->fam = fam;
	g_ptr_array_add (out, r);
}

/* ================================================================
 * 6. The Windows model
 *
 * The policy as fs_fwrule_from_policy() compiles it -- row by row, so
 * every Windows rule knows the row it came from -- plus the settings
 * plan, all inbound and scoped to profiles.  Order does not matter on
 * Windows: any matching block wins, then any allow, then the default.
 * ================================================================ */

static guint
fwp_bit (gint profile)
{
	switch (profile) {
	case PROFILE_DOMAIN:  return FS_FWP_PROFILE_DOMAIN;
	case PROFILE_PRIVATE: return FS_FWP_PROFILE_PRIVATE;
	default:              return FS_FWP_PROFILE_PUBLIC;
	}
}

static const gchar *
profile_name (gint profile)
{
	switch (profile) {
	case PROFILE_DOMAIN:  return _("Domain");
	case PROFILE_PRIVATE: return _("Private");
	case PROFILE_PUBLIC:  return _("Public");
	default:              return _("unknown");
	}
}

/* netsh's "type,code" for the settings plan's ICMP rules. */
static const gchar *
win_icmp_type (const gchar *spec)
{
	static const struct { const gchar *spec; const gchar *name; } map[] = {
		{ "8,any", "echo-request" }, { "0,any", "echo-reply" },
		{ "3,any", "destination-unreachable" },
		{ "3,1", "host-unreachable" },
		{ "11,any", "time-exceeded" }, { "12,any", "parameter-problem" },
		{ "13,any", "timestamp-request" }, { "14,any", "timestamp-reply" },
		{ "17,any", "address-mask-request" },
		{ "18,any", "address-mask-reply" },
		{ "5,any", "redirect" }, { "4,any", "source-quench" }
	};

	for (guint i = 0; spec != NULL && i < G_N_ELEMENTS (map); i++)
		if (strcmp (map[i].spec, spec) == 0)
			return map[i].name;
	return NULL;
}

static void
win_from_fwrule (Model *m, const FsFwRule *fw, FsRuleKind kind, gint row,
                 FsWhatIfOrigin origin)
{
	gboolean inbound = (fw->direction == FS_DIR_INBOUND);
	WRule *r = wrule_new (fw->name, origin, inbound,
	                      fw->action == FS_ACTION_BLOCK ? T_DROP : T_ACCEPT,
	                      NULL);

	r->pkind = kind;
	r->prow = row;
	r->proto = fw->protocol == FS_PROTO_TCP ? P_TCP
	         : fw->protocol == FS_PROTO_UDP ? P_UDP : P_ANY;

	if (inbound) {
		r->has_dport = (fw->local_ports != NULL);
		r->dport = g_strdup (fw->local_ports);
		r->other_ports = g_strdup (fw->remote_ports);
	} else {
		r->has_dport = (fw->remote_ports != NULL);
		r->dport = g_strdup (fw->remote_ports);
		r->other_ports = g_strdup (fw->local_ports);
	}

	if (fw->remote_address != NULL && *fw->remote_address != '\0') {
		r->remote = g_new0 (Addr, 1);
		r->n_remote = 1;
		addr_parse (&r->remote[0], fw->remote_address);

		if (r->remote[0].kind == ADDR_NAME)
			r->left_out = g_strdup_printf (
				_("Windows Firewall takes addresses only: \"%s\" is "
				  "a name, netsh refuses the rule and the apply "
				  "fails"), fw->remote_address);
		else if (r->remote[0].kind == ADDR_NONE)
			r->left_out = g_strdup_printf (
				_("\"%s\" is not an address"), fw->remote_address);
	}

	/* A forward row compiles to an allow of its listen port on this
	 * computer and nothing else: netsh gets no forwarding (no
	 * portproxy, no connection sharing), so the answer must not say the
	 * traffic is passed on. */
	if (fw->forward && fw->forward_address != NULL)
		r->not_forwarded = g_strdup (fw->forward_address);

	g_ptr_array_add (inbound ? m->in[0] : m->out[0], r);
}

static void
win_policy (Model *m)
{
	for (gint kind = 0; kind < FS_RULE_N_KINDS; kind++) {
		GPtrArray *rows = m->policy->kinds[kind];

		for (guint i = 0; i < rows->len; i++) {
			const FsRule *row = g_ptr_array_index (rows, i);
			FsPolicy *one = fs_policy_new ();
			GPtrArray *refused = NULL;
			GList *rules;
			gboolean inbound = (kind == FS_RULE_INBOUND_ALLOW_FROM ||
			                    kind == FS_RULE_INBOUND_ALLOW_SERVICE ||
			                    kind == FS_RULE_INBOUND_FORWARD);
			gboolean block = (kind == FS_RULE_OUTBOUND_DENY_TO ||
			                  kind == FS_RULE_OUTBOUND_DENY_FROM ||
			                  kind == FS_RULE_OUTBOUND_DENY_SERVICE);

			fs_policy_add (one, (FsRule *) row);
			rules = fs_fwrule_from_policy_checked (one, &refused);

			for (GList *l = rules; l != NULL; l = l->next)
				win_from_fwrule (m, l->data, kind, (gint) i,
				                 row_origin (kind, row));

			for (guint k = 0; k < refused->len; k++)
				add_left_out (inbound ? m->in[0] : m->out[0],
				              row_name (kind, row, inbound, block,
				                        row->service != NULL),
				              row_origin (kind, row), kind, (gint) i,
				              inbound, block,
				              g_strdup (g_ptr_array_index (refused, k)));

			if (rules == NULL && refused->len == 0)
				add_left_out (inbound ? m->in[0] : m->out[0],
				              row_name (kind, row, inbound, block,
				                        row->service != NULL),
				              row_origin (kind, row), kind, (gint) i,
				              inbound, block,
				              g_strdup (_("compiles to no Windows rule "
				                          "(a host rule with no host, "
				                          "or a forward with nowhere "
				                          "to go)")));

			if (block && refused->len > 0)
				note_add (m->notes, g_strdup (
					_("A block row of this policy cannot be "
					  "compiled for Windows, so applying the "
					  "policy is refused and the rules in force "
					  "stay as they are.")));

			fs_fwrule_list_free (rules);
			g_ptr_array_unref (refused);
			fs_policy_free (one);
		}
	}
}

static void
win_settings (Model *m)
{
	FsSettingsPlan *plan = fs_settings_plan_new (m->settings);

	for (guint i = 0; i < plan->rules->len; i++) {
		const FsSettingRule *s = g_ptr_array_index (plan->rules, i);
		WRule *r = wrule_new (s->name, FS_WHATIF_ORIGIN_SETTINGS, TRUE,
		                      s->allow ? T_ACCEPT : T_DROP, NULL);

		r->profiles = s->profiles;
		if (s->proto == FS_SETPLAN_PROTO_ICMP) {
			r->proto = P_ICMP;      /* icmpv4 only */
			r->fam = 4;
			r->icmp = g_strdup (win_icmp_type (s->icmp));
		} else if (s->proto == FS_SETPLAN_PROTO_UDP) {
			r->proto = P_UDP;
			r->has_dport = TRUE;
			r->dport = g_strdup_printf ("%u", s->port);
		}

		if (s->remote != NULL) {
			gchar **list = g_strsplit (s->remote, ",", -1);

			r->n_remote = g_strv_length (list);
			r->remote = g_new0 (Addr, r->n_remote);
			for (guint k = 0; k < r->n_remote; k++)
				addr_parse (&r->remote[k], list[k]);
			g_strfreev (list);
		}

		g_ptr_array_add (m->in[0], r);
	}

	fs_settings_plan_free (plan);
}

static Model *
model_build (const FsWhatIfContext *ctx, const FsPolicy *policy)
{
	Model *m = g_new0 (Model, 1);

	m->ctx = ctx;
	m->platform = ctx->platform;
	m->notes = g_ptr_array_new_with_free_func (g_free);

	if (ctx->settings != NULL) {
		m->settings = ctx->settings;
	} else {
		m->own_settings = fs_settings_new ();
		m->settings = m->own_settings;
	}

	if (policy != NULL) {
		m->policy = policy;
	} else {
		m->own_policy = fs_policy_new ();
		m->policy = m->own_policy;
	}

	for (gint f = 0; f < 2; f++) {
		m->in[f] = g_ptr_array_new_with_free_func (wrule_free);
		m->out[f] = g_ptr_array_new_with_free_func (wrule_free);
		m->dnat[f] = g_ptr_array_new_with_free_func (dnat_free);
	}

	if (m->platform == FS_WHATIF_LINUX_FIRST_MATCH) {
		m->ext = fs_util_is_valid_ifname (m->settings->ext_device)
		         ? m->settings->ext_device : NULL;
		m->intf = fs_util_is_valid_ifname (m->settings->int_device)
		          ? m->settings->int_device : NULL;

		for (gint fam = 4; fam <= 6; fam += 2) {
			lin_inbound (m, fam);
			lin_outbound (m, fam);
		}

		/* Only router mode makes StockFW turn IP forwarding on. */
		if (!m->settings->nat)
			m->fwd_gate = wrule_new (
				_("IP forwarding is off (StockFW turns it on only in "
				  "router mode)"), FS_WHATIF_ORIGIN_SETTINGS, TRUE, T_DROP,
				NULL);
	} else {
		win_policy (m);
		win_settings (m);

		m->win_loopback = wrule_new (
			_("Loopback (this computer to itself)"),
			FS_WHATIF_ORIGIN_BUILTIN, TRUE, T_ACCEPT, NULL);
		m->win_return = wrule_new (
			_("Return traffic for connections already open"),
			FS_WHATIF_ORIGIN_BUILTIN, TRUE, T_ACCEPT, NULL);
		for (gint p = 0; p < 3; p++) {
			gchar *name = g_strdup_printf (
				_("Block all incoming connections (%s profile)"),
				profile_name (p));

			m->win_shields[p] = wrule_new (name, FS_WHATIF_ORIGIN_SETTINGS,
			                               TRUE, T_DROP, NULL);
			g_free (name);
		}
	}

	return m;
}

/* ================================================================
 * 7. One concrete probe
 *
 * A probe is one connection with every field known.  The matchers
 * answer "does this rule meet it?" and, when asked, why not -- the
 * trace is built from those reasons.
 * ================================================================ */

typedef struct
{
	gboolean     inbound;
	gint         fam;          /* 4 or 6                               */
	gint         proto;        /* P_TCP / P_UDP / P_ICMP               */
	guint        port;         /* TCP/UDP: the service port            */
	const gchar *icmp;         /* ICMP: the type name                  */
	Addr         host;         /* the other end (borrowed)             */
	const gchar *dns;          /* host is (also) this name's address   */
	Addr         local;        /* outbound: our source; ANY = none of
	                            * the addresses any rule names        */
	const gchar *iface;        /* arrives on / leaves by; NULL unnamed */
	gint         profile;      /* Windows profile, else -1             */
	gint         ct;           /* CT_NEW / CT_REPLY / CT_INVALID       */
	gboolean     self;         /* the other end is this computer       */
	gboolean     fwd_on;       /* Linux, router mode off: IP forwarding
	                            * is on anyway (another program set it) */

	gboolean     dnat;         /* set while evaluating                 */
	Addr         dnat_to;
} Probe;

/* What conntrack makes of a probe.  A TCP/UDP question and an ICMP
 * request are NEW.  An ICMP reply or error is either the answer to
 * something this computer sent (RELATED / ESTABLISHED) or unsolicited,
 * which conntrack calls INVALID. */
enum { CT_NEW = 0, CT_REPLY, CT_INVALID };

/* [ icmp_is_reply ]
 * The ICMP types that only ever answer something: replies, and the
 * errors conntrack ties to the connection they are about. */
static gboolean
icmp_is_reply (const gchar *type)
{
	static const gchar *replies[] = {
		"echo-reply", "timestamp-reply", "address-mask-reply",
		"destination-unreachable", "host-unreachable",
		"address-unreachable", "time-exceeded", "parameter-problem",
		"source-quench", "redirect", "packet-too-big", NULL
	};

	for (guint i = 0; type != NULL && replies[i] != NULL; i++)
		if (strcmp (type, replies[i]) == 0)
			return TRUE;
	return FALSE;
}

typedef struct
{
	gboolean        allowed;
	const WRule    *rule;      /* deciding rule; NULL: Windows default,
	                            * or the firewall is off              */
	FsWhatIfOrigin  origin;
	gboolean        assumed;   /* Windows default assumed             */
	gint            profile;
	const Dnat     *dnat;
} Outcome;

static gboolean
icmp_covers (const gchar *rule_type, const gchar *probe_type)
{
	if (rule_type == NULL)
		return TRUE;
	if (probe_type == NULL)
		return FALSE;
	if (strcmp (rule_type, probe_type) == 0)
		return TRUE;
	return strcmp (rule_type, "destination-unreachable") == 0 &&
	       (strcmp (probe_type, "host-unreachable") == 0 ||
	        strcmp (probe_type, "address-unreachable") == 0);
}

static gchar *
addr_text (const Addr *a)
{
	if (a->kind == ADDR_ANY)
		return g_strdup (_("any host"));
	return g_strdup (a->text != NULL ? a->text : "?");
}

/* [ addr_meets ]
 * Does a rule's address condition meet the probe's address?  A name
 * meets it only when the probe is that name's address (the DNS
 * dimension of the evaluation). */
static gboolean
addr_meets (const Addr *rule, const Addr *probe, const gchar *dns,
            const gchar *what, gchar **why)
{
	if (rule->kind == ADDR_ANY)
		return TRUE;

	if (rule->kind == ADDR_NAME) {
		if (dns != NULL && g_ascii_strcasecmp (dns, rule->text) == 0)
			return TRUE;
		if (why != NULL)
			*why = g_strdup_printf (_("only if %s is an address of %s "
			                          "(depends on DNS at apply time)"),
			                        what, rule->text);
		return FALSE;
	}

	if (rule->kind == ADDR_BLOCK && probe->kind == ADDR_BLOCK &&
	    addr_contains (rule, probe))
		return TRUE;

	if (why != NULL) {
		gchar *p = addr_text (probe);

		*why = (probe->kind == ADDR_BLOCK)
			? g_strdup_printf (_("%s is not %s"), p, rule->text)
			: g_strdup_printf (_("only for %s"), rule->text);
		g_free (p);
	}
	return FALSE;
}

static gboolean
lin_meets (const WRule *r, const Probe *p, gchar **why)
{
	if (r->ctstate != NULL) {
		if (strcmp (r->ctstate, "DNAT") == 0) {
			if (!p->dnat) {
				if (why != NULL)
					*why = g_strdup (_("only for traffic a port "
					                   "forward redirected"));
				return FALSE;
			}
		} else if (g_str_has_prefix (r->ctstate, "ESTABLISHED")) {
			if (p->ct != CT_REPLY) {
				if (why != NULL)
					*why = g_strdup (p->ct == CT_NEW
						? _("only for replies to connections already "
						    "open; this is a new connection")
						: _("only for replies to connections already "
						    "open; this answers none"));
				return FALSE;
			}
		} else if (p->ct != CT_INVALID) {
			if (why != NULL)
				*why = g_strdup (p->ct == CT_NEW
					? _("only for invalid packets; this is a new "
					    "connection")
					: _("only for invalid packets; this answers "
					    "a connection already open"));
			return FALSE;
		}
	}

	if (r->in_if != NULL && g_strcmp0 (r->in_if, p->iface) != 0) {
		if (why != NULL)
			*why = (strcmp (r->in_if, "lo") == 0)
				? g_strdup (_("only for loopback traffic"))
				: g_strdup_printf (_("only for traffic arriving on %s"),
				                   r->in_if);
		return FALSE;
	}

	if (r->out_if != NULL && g_strcmp0 (r->out_if, p->iface) != 0) {
		if (why != NULL)
			*why = (strcmp (r->out_if, "lo") == 0)
				? g_strdup (_("only for loopback traffic"))
				: g_strdup_printf (_("only for traffic leaving by %s"),
				                   r->out_if);
		return FALSE;
	}

	if (r->proto != P_ANY && r->proto != p->proto) {
		if (why != NULL)
			*why = g_strdup_printf (_("only for %s; this is %s"),
			                        proto_name (r->proto),
			                        proto_name (p->proto));
		return FALSE;
	}

	if (r->proto == P_ICMP && !icmp_covers (r->icmp, p->icmp)) {
		if (why != NULL)
			*why = g_strdup_printf (_("only for ICMP %s"), r->icmp);
		return FALSE;
	}

	if (r->sport != NULL) {
		if (why != NULL)
			*why = g_strdup_printf (_("only from source port %s; a new "
			                          "connection comes from a "
			                          "temporary port"), r->sport);
		return FALSE;
	}

	if (r->has_dport &&
	    (r->dport == NULL || p->proto == P_ICMP ||
	     !fs_fwrule_port_spec_covers (r->dport, p->port))) {
		if (why != NULL)
			*why = g_strdup_printf (_("only for port %s"),
			                        r->r_dport ? r->r_dport : "?");
		return FALSE;
	}

	if (p->inbound) {
		if (!addr_meets (&r->src, &p->host, p->dns, _("the sender"), why))
			return FALSE;
		if (r->dst.kind != ADDR_ANY &&
		    !(p->dnat && addr_contains (&r->dst, &p->dnat_to))) {
			if (why != NULL)
				*why = (r->ctstate == NULL)
					? g_strdup_printf (_("only for traffic sent to %s"),
					                   r->dst.text)
					: g_strdup_printf (_("only for traffic forwarded "
					                     "to %s"), r->dst.text);
			return FALSE;
		}
	} else {
		if (!addr_meets (&r->dst, &p->host, p->dns, _("the destination"),
		                 why))
			return FALSE;
		if (r->src.kind != ADDR_ANY &&
		    !(p->local.kind == ADDR_BLOCK &&
		      addr_meets (&r->src, &p->local, NULL, NULL, NULL))) {
			if (why != NULL)
				*why = g_strdup_printf (
					_("only if this computer sends from %s (the "
					  "row's host is matched as the source "
					  "address)"), r->src.text);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
win_meets (const WRule *r, const Probe *p, gchar **why)
{
	if (r->profiles != 0 && (r->profiles & fwp_bit (p->profile)) == 0) {
		if (why != NULL) {
			GString *s = g_string_new (NULL);

			for (gint k = 0; k < 3; k++)
				if (r->profiles & fwp_bit (k))
					g_string_append_printf (s, "%s%s",
					                        s->len ? _(" and ") : "",
					                        profile_name (k));
			*why = g_strdup_printf (_("only on %s networks"), s->str);
			g_string_free (s, TRUE);
		}
		return FALSE;
	}

	if (r->proto == P_ICMP && (p->proto != P_ICMP || p->fam != 4)) {
		if (why != NULL)
			*why = g_strdup (_("only for ICMPv4"));
		return FALSE;
	}

	if (r->proto != P_ANY && r->proto != p->proto) {
		if (why != NULL)
			*why = g_strdup_printf (_("only for %s; this is %s"),
			                        proto_name (r->proto),
			                        proto_name (p->proto));
		return FALSE;
	}

	if (r->proto == P_ICMP && !icmp_covers (r->icmp, p->icmp)) {
		if (why != NULL)
			*why = g_strdup_printf (_("only for ICMP %s"), r->icmp);
		return FALSE;
	}

	if (r->other_ports != NULL) {
		if (why != NULL)
			*why = g_strdup_printf (_("pins the other end's port to %s, "
			                          "which a new connection does not "
			                          "use"), r->other_ports);
		return FALSE;
	}

	if (r->has_dport &&
	    (r->dport == NULL || p->proto == P_ICMP ||
	     !fs_fwrule_port_spec_covers (r->dport, p->port))) {
		if (why != NULL)
			*why = g_strdup_printf (_("only for port %s"),
			                        r->dport ? r->dport : "?");
		return FALSE;
	}

	if (r->n_remote > 0) {
		gboolean any = FALSE;

		for (guint i = 0; i < r->n_remote && !any; i++)
			any = addr_meets (&r->remote[i], &p->host, p->dns, NULL, NULL);

		if (!any) {
			if (why != NULL) {
				GString *s = g_string_new (NULL);
				gchar *h = addr_text (&p->host);

				for (guint i = 0; i < r->n_remote; i++)
					g_string_append_printf (s, "%s%s", i ? ", " : "",
					                        r->remote[i].text);
				*why = g_strdup_printf (_("%s is not %s"), h, s->str);
				g_free (h);
				g_string_free (s, TRUE);
			}
			return FALSE;
		}
	}

	return TRUE;
}

static void
step_add (GPtrArray *steps, FsWhatIfStepKind kind, const WRule *r,
          gchar *detail)
{
	FsWhatIfStep *s;

	if (steps == NULL) {
		g_free (detail);
		return;
	}

	s = g_new0 (FsWhatIfStep, 1);
	s->kind = kind;
	s->origin = r != NULL ? r->origin : FS_WHATIF_ORIGIN_BUILTIN;
	s->rule = g_strdup (r != NULL ? r->name : NULL);
	s->policy_kind = r != NULL ? r->pkind : -1;
	s->policy_index = r != NULL ? r->prow : -1;
	s->allows = (r != NULL && r->target == T_ACCEPT);
	s->detail = detail;
	g_ptr_array_add (steps, s);
}

static void
step_note (GPtrArray *steps, FsWhatIfOrigin origin, const gchar *rule,
           gchar *detail)
{
	FsWhatIfStep *s;

	if (steps == NULL) {
		g_free (detail);
		return;
	}

	s = g_new0 (FsWhatIfStep, 1);
	s->kind = FS_WHATIF_STEP_NOTE;
	s->origin = origin;
	s->rule = g_strdup (rule);
	s->policy_kind = -1;
	s->policy_index = -1;
	s->detail = detail;
	g_ptr_array_add (steps, s);
}

static gchar *
matched_detail (const WRule *r)
{
	GString *s = g_string_new (NULL);

	switch (r->target) {
	case T_ACCEPT: g_string_append (s, _("matches: allows it")); break;
	case T_DROP:   g_string_append (s, _("matches: drops it")); break;
	case T_REJECT: g_string_append (s, _("matches: rejects it with an "
	                                     "error")); break;
	default:       g_string_append (s, _("matches")); break;
	}

	if (r->limit != NULL && r->target == T_ACCEPT)
		g_string_append_printf (s, _(" (at most %s; more than that falls "
		                             "through to the rules below)"),
		                        r->limit);
	if (r->forward_to != NULL)
		g_string_append_printf (s, _(", delivered to %s"), r->forward_to);

	return g_string_free (s, FALSE);
}

static Outcome
eval_linux (Model *m, const Probe *in, gint *decided, GPtrArray *steps)
{
	Outcome o;
	Probe p = *in;
	GPtrArray *chain = p.inbound ? m->in[p.fam == 6] : m->out[p.fam == 6];

	memset (&o, 0, sizeof o);
	o.profile = -1;

	if (p.inbound && p.proto == P_TCP && m->ext != NULL &&
	    g_strcmp0 (p.iface, m->ext) == 0) {
		GPtrArray *nat = m->dnat[p.fam == 6];

		for (guint i = 0; i < nat->len; i++) {
			const Dnat *d = g_ptr_array_index (nat, i);

			if (d->dport != NULL &&
			    fs_fwrule_port_spec_covers (d->dport, p.port)) {
				step_note (steps, FS_WHATIF_ORIGIN_POLICY, d->name,
				           g_strdup_printf (_("the port forward sends it "
				                              "to %s port %u first"),
				                            d->to.text, d->to_port));
				p.dnat = TRUE;
				p.dnat_to = d->to;
				p.port = d->to_port;
				o.dnat = d;

				/* Router mode off: StockFW leaves IP forwarding as
				 * it found it, and with it off what the forward sends
				 * to another computer is dropped by the kernel before
				 * any chain sees it. */
				if (m->fwd_gate != NULL && !p.fwd_on &&
				    !addr_is_self (m->ctx, &d->to)) {
					step_add (steps, FS_WHATIF_STEP_MATCHED, m->fwd_gate,
					          steps ? g_strdup_printf (
					                  _("%s is another computer and IP "
					                    "forwarding is off, so the kernel "
					                    "drops what the forward sends "
					                    "there"), d->to.text) : NULL);
					if (decided != NULL && steps != NULL)
						*decided = (gint) steps->len - 1;
					o.allowed = FALSE;
					o.rule = m->fwd_gate;
					o.origin = m->fwd_gate->origin;
					return o;
				}
				break;
			}
		}
	}

	for (guint i = 0; i < chain->len; i++) {
		const WRule *r = g_ptr_array_index (chain, i);
		gchar *why = NULL;

		if (r->left_out != NULL) {
			step_add (steps, FS_WHATIF_STEP_SKIPPED, r,
			          steps ? g_strdup_printf (_("not in force: %s"),
			                                   r->left_out) : NULL);
			continue;
		}

		if (!lin_meets (r, &p, steps ? &why : NULL)) {
			step_add (steps, FS_WHATIF_STEP_SKIPPED, r, why);
			continue;
		}

		if (r->target == T_LOG) {
			step_note (steps, r->origin, r->name,
			           g_strdup (_("logged; the next rule decides")));
			continue;
		}

		step_add (steps, FS_WHATIF_STEP_MATCHED, r,
		          steps ? matched_detail (r) : NULL);
		if (decided != NULL && steps != NULL)
			*decided = (gint) steps->len - 1;
		o.allowed = (r->target == T_ACCEPT);
		o.rule = r;
		o.origin = r->origin;
		return o;
	}

	/* Unreachable: every chain ends in its default. */
	o.allowed = !p.inbound;
	o.origin = FS_WHATIF_ORIGIN_DEFAULT;
	return o;
}

static FsWhatIfDefault
win_default (const FsWhatIfContext *ctx, gboolean inbound, gint profile,
             gboolean *assumed)
{
	FsWhatIfDefault d = inbound ? ctx->default_inbound[profile]
	                            : ctx->default_outbound[profile];

	*assumed = (d == FS_WHATIF_DEFAULT_UNKNOWN);
	if (*assumed)
		d = inbound ? FS_WHATIF_DEFAULT_BLOCK : FS_WHATIF_DEFAULT_ALLOW;
	return d;
}

static Outcome
eval_windows (Model *m, const Probe *p, gint *decided, GPtrArray *steps)
{
	Outcome o;
	GPtrArray *list = p->inbound ? m->in[0] : m->out[0];
	const WRule *block = NULL;
	const WRule *allow = NULL;
	gint block_step = -1, allow_step = -1;
	FsWhatIfDefault d;

	memset (&o, 0, sizeof o);
	o.profile = p->profile;

	if (m->ctx->profile_enabled[p->profile] == 0) {
		step_note (steps, FS_WHATIF_ORIGIN_STOPPED, NULL,
		           g_strdup_printf (_("Windows Firewall is off for the %s "
		                              "profile: nothing is filtered"),
		                            profile_name (p->profile)));
		if (decided != NULL && steps != NULL)
			*decided = (gint) steps->len - 1;
		o.allowed = TRUE;
		o.origin = FS_WHATIF_ORIGIN_STOPPED;
		return o;
	}

	/* Windows Firewall does not filter what this computer sends to
	 * itself, and lets back in what answers its own traffic. */
	if (p->self || p->ct == CT_REPLY) {
		const WRule *r = p->self ? m->win_loopback : m->win_return;

		step_add (steps, FS_WHATIF_STEP_MATCHED, r,
		          steps ? g_strdup (p->self
		                  ? _("Windows Firewall does not filter traffic "
		                      "this computer sends to itself")
		                  : _("Windows Firewall is stateful: it lets back "
		                      "in what answers this computer's own "
		                      "traffic")) : NULL);
		if (decided != NULL && steps != NULL)
			*decided = (gint) steps->len - 1;
		o.allowed = TRUE;
		o.rule = r;
		o.origin = r->origin;
		return o;
	}

	for (guint i = 0; i < list->len; i++) {
		const WRule *r = g_ptr_array_index (list, i);
		gchar *why = NULL;

		if (r->left_out != NULL) {
			step_add (steps, FS_WHATIF_STEP_SKIPPED, r,
			          steps ? g_strdup_printf (_("not in force: %s"),
			                                   r->left_out) : NULL);
			continue;
		}

		if (!win_meets (r, p, steps ? &why : NULL)) {
			step_add (steps, FS_WHATIF_STEP_SKIPPED, r, why);
			continue;
		}

		step_add (steps, FS_WHATIF_STEP_MATCHED, r,
		          steps ? matched_detail (r) : NULL);

		if (r->target == T_DROP && block == NULL) {
			block = r;
			block_step = steps ? (gint) steps->len - 1 : -1;
		} else if (r->target == T_ACCEPT && allow == NULL) {
			allow = r;
			allow_step = steps ? (gint) steps->len - 1 : -1;
		}
	}

	if (block != NULL) {
		if (allow != NULL)
			step_note (steps, FS_WHATIF_ORIGIN_POLICY, allow->name,
			           g_strdup_printf (_("this allow also matches, but in "
			                              "Windows Firewall a block rule "
			                              "wins over any allow, so '%s' "
			                              "decides"), block->name));
		if (decided != NULL)
			*decided = block_step;
		o.allowed = FALSE;
		o.rule = block;
		o.origin = block->origin;
		return o;
	}

	/* "Block all incoming connections, including those in the list of
	 * allowed apps": Windows ignores every inbound allow. */
	if (p->inbound && m->ctx->block_all_inbound[p->profile] == 1) {
		const WRule *r = m->win_shields[p->profile];

		step_add (steps, FS_WHATIF_STEP_MATCHED, r,
		          steps ? (allow != NULL
		                   ? g_strdup_printf (_("on for the %s profile: "
		                                        "Windows ignores every allow "
		                                        "rule, '%s' too"),
		                                      profile_name (p->profile),
		                                      allow->name)
		                   : g_strdup_printf (_("on for the %s profile: "
		                                        "everything inbound is "
		                                        "blocked"),
		                                      profile_name (p->profile)))
		                : NULL);
		if (decided != NULL && steps != NULL)
			*decided = (gint) steps->len - 1;
		o.allowed = FALSE;
		o.rule = r;
		o.origin = r->origin;
		return o;
	}

	if (allow != NULL) {
		if (decided != NULL)
			*decided = allow_step;
		o.allowed = TRUE;
		o.rule = allow;
		o.origin = allow->origin;
		return o;
	}

	d = win_default (m->ctx, p->inbound, p->profile, &o.assumed);
	step_note (steps, FS_WHATIF_ORIGIN_DEFAULT, NULL,
	           g_strdup_printf (o.assumed
	                            ? _("no rule matches; the %s profile's "
	                                "default %s action decides: %s "
	                                "(Windows' own default, assumed)")
	                            : _("no rule matches; the %s profile's "
	                                "default %s action decides: %s"),
	                            profile_name (p->profile),
	                            p->inbound ? _("inbound") : _("outbound"),
	                            d == FS_WHATIF_DEFAULT_ALLOW ? _("allow")
	                                                         : _("block")));
	if (decided != NULL && steps != NULL)
		*decided = (gint) steps->len - 1;
	o.allowed = (d == FS_WHATIF_DEFAULT_ALLOW);
	o.origin = FS_WHATIF_ORIGIN_DEFAULT;
	return o;
}

static Outcome
eval_probe (Model *m, const Probe *p, gint *decided, GPtrArray *steps)
{
	if (m->ctx->firewall == FS_WHATIF_FW_STOPPED) {
		Outcome o;

		memset (&o, 0, sizeof o);
		o.allowed = TRUE;
		o.origin = FS_WHATIF_ORIGIN_STOPPED;
		o.profile = p->profile;
		step_note (steps, FS_WHATIF_ORIGIN_STOPPED, NULL,
		           g_strdup (_("the firewall is not running: nothing is "
		                       "filtered")));
		if (decided != NULL && steps != NULL)
			*decided = (gint) steps->len - 1;
		return o;
	}

	return (m->platform == FS_WHATIF_LINUX_FIRST_MATCH)
	       ? eval_linux (m, p, decided, steps)
	       : eval_windows (m, p, decided, steps);
}

/* ================================================================
 * 8. Under-specified questions
 *
 * Every field the question left open becomes a list of
 * representatives: one value for "anything no rule names" (the base,
 * listed first) and one inside each region a rule draws on that field
 * -- each port range's first port and the port after it, each address
 * block's first and last address, each ICMP type a rule names, each
 * profile, each host name a rule matches through DNS.  The product of
 * the lists is evaluated; if every combination agrees, that is the
 * answer, otherwise it is DEPENDS and the combinations that disagree
 * with the base are grouped by the rule that decided them.
 * ================================================================ */

enum { D_PROTO, D_PORT, D_ICMP, D_HOST, D_DNS, D_LOCAL, D_IFACE, D_PROFILE,
       D_STATE, D_FWD, D_N };

typedef struct
{
	GArray    *protos;       /* gint */
	GArray    *ports;        /* guint */
	GPtrArray *icmps;        /* const gchar* (static) */
	GArray    *hosts;        /* Addr (owned text) */
	GPtrArray *dns;          /* const gchar* (borrowed from rules), NULL first */
	GArray    *locals;       /* Addr (owned text), ANY first */
	GPtrArray *ifaces;       /* const gchar* */
	GArray    *profiles;     /* gint */
	guint      n_state;      /* 2: ICMP replies are asked both ways --
	                          * answering this computer, and unsolicited */
	guint      n_fwd;        /* 2: whether IP forwarding is on is not
	                          * known (Linux, router mode off, a forward
	                          * to another computer) */
	gboolean   open[D_N];
	gboolean   host_typed;   /* the line named a single host */
	gboolean   host_self;    /* ... and it is this computer */
	gboolean   capped;
} Cands;

static void
addr_array_clear (gpointer data)
{
	addr_clear (data);
}

static void
cands_free (Cands *c)
{
	g_array_unref (c->protos);
	g_array_unref (c->ports);
	g_ptr_array_unref (c->icmps);
	g_array_unref (c->hosts);
	g_ptr_array_unref (c->dns);
	g_array_unref (c->locals);
	g_ptr_array_unref (c->ifaces);
	g_array_unref (c->profiles);
}

static GPtrArray *
chain_of (Model *m, gboolean inbound, gint famidx)
{
	return inbound ? m->in[famidx] : m->out[famidx];
}

static void
port_add (GArray *ports, guint port)
{
	if (port < 1 || port > 65535)
		return;
	for (guint i = 0; i < ports->len; i++)
		if (g_array_index (ports, guint, i) == port)
			return;
	g_array_append_val (ports, port);
}

static void
spec_reps (GArray *ports, const gchar *spec)
{
	gchar **el;

	if (spec == NULL)
		return;

	el = g_strsplit (spec, ",", -1);
	for (guint i = 0; el[i] != NULL; i++) {
		guint lo = (guint) g_ascii_strtoull (el[i], NULL, 10);
		const gchar *dash = strchr (el[i], '-');
		guint hi = dash ? (guint) g_ascii_strtoull (dash + 1, NULL, 10) : lo;

		port_add (ports, lo);
		port_add (ports, hi + 1);
	}
	g_strfreev (el);
}

static gboolean
port_named_by_rules (Model *m, gboolean inbound, guint port)
{
	for (gint f = 0; f < 2; f++) {
		GPtrArray *chain = chain_of (m, inbound, f);

		for (guint i = 0; i < chain->len; i++) {
			const WRule *r = g_ptr_array_index (chain, i);

			if (r->has_dport && r->dport != NULL &&
			    fs_fwrule_port_spec_covers (r->dport, port))
				return TRUE;
		}
		for (guint i = 0; inbound && i < m->dnat[f]->len; i++) {
			const Dnat *d = g_ptr_array_index (m->dnat[f], i);

			if (d->dport != NULL &&
			    fs_fwrule_port_spec_covers (d->dport, port))
				return TRUE;
		}
	}
	return FALSE;
}

/* The remote-side address conditions of a rule. */
static void
rule_remote_addrs (const WRule *r, gboolean inbound, const Addr **out,
                   guint *n)
{
	*n = 0;
	if (r->n_remote > 0) {
		for (guint i = 0; i < r->n_remote && *n < 8; i++)
			out[(*n)++] = &r->remote[i];
	} else {
		const Addr *a = inbound ? &r->src : &r->dst;

		if (a->kind != ADDR_ANY)
			out[(*n)++] = a;
	}
}

static gboolean
host_covered_by_rules (Model *m, const Addr *h)
{
	for (gint dir = 0; dir < 2; dir++)
		for (gint f = 0; f < 2; f++) {
			GPtrArray *chain = chain_of (m, dir == 0, f);

			for (guint i = 0; i < chain->len; i++) {
				const Addr *list[8];
				guint n;

				rule_remote_addrs (g_ptr_array_index (chain, i),
				                   dir == 0, list, &n);
				for (guint k = 0; k < n; k++)
					if (addr_contains (list[k], h))
						return TRUE;
			}
		}
	return FALSE;
}

static void
host_add (GArray *hosts, const Addr *a)
{
	for (guint i = 0; i < hosts->len; i++)
		if (addr_equal (&g_array_index (hosts, Addr, i), a))
			return;
	{
		Addr copy;

		addr_copy (&copy, a);
		g_array_append_val (hosts, copy);
	}
}

/* [ pick_inside ]
 * A host inside `block' that no rule block strictly smaller than it
 * covers -- "most of 10.0.0.0/8" -- or its first address. */
static void
pick_inside (Model *m, const Addr *block, Addr *out)
{
	Addr tries[3];
	gboolean done = FALSE;

	addr_host (&tries[0], block, FALSE);
	addr_host (&tries[1], block, TRUE);
	tries[2] = tries[0];
	tries[2].text = NULL;
	if (block->prefix < addr_bits (block)) {
		GInetAddress *ia;

		tries[2].b[block->prefix / 8] ^= (guint8) (0x80u >> (block->prefix % 8));
		tries[2].b[addr_bits (block) / 8 - 1] |= 1;
		ia = g_inet_address_new_from_bytes (tries[2].b, block->fam == 6
		                                    ? G_SOCKET_FAMILY_IPV6
		                                    : G_SOCKET_FAMILY_IPV4);
		tries[2].text = g_inet_address_to_string (ia);
		g_object_unref (ia);
	} else {
		tries[2].text = g_strdup (tries[0].text);
	}

	for (gint t = 2; t >= 0 && !done; t--) {
		gboolean covered = FALSE;

		for (gint dir = 0; dir < 2 && !covered; dir++)
			for (gint f = 0; f < 2 && !covered; f++) {
				GPtrArray *chain = chain_of (m, dir == 0, f);

				for (guint i = 0; i < chain->len && !covered; i++) {
					const Addr *list[8];
					guint n;

					rule_remote_addrs (g_ptr_array_index (chain, i),
					                   dir == 0, list, &n);
					for (guint k = 0; k < n; k++)
						if (list[k]->kind == ADDR_BLOCK &&
						    list[k]->prefix > block->prefix &&
						    addr_contains (list[k], &tries[t]))
							covered = TRUE;
				}
			}

		if (!covered) {
			addr_copy (out, &tries[t]);
			done = TRUE;
		}
	}

	if (!done)
		addr_copy (out, &tries[0]);

	for (gint t = 0; t < 3; t++)
		g_free (tries[t].text);
}

static const gchar *icmp4_types[] = {
	"echo-request", "echo-reply", "destination-unreachable",
	"host-unreachable", "time-exceeded", "parameter-problem",
	"timestamp-request", "timestamp-reply", "address-mask-request",
	"address-mask-reply", "redirect", "source-quench", NULL
};

/* An ICMP type no rule names. */
#define ICMP_OTHER "other"

/* The IPv6 stand-in for "a host no rule names". */
#define GENERIC_V6_HOST "3fff::200"

static void
cands_build (Model *m, const FsWhatIfQuery *q, gboolean inbound, Cands *c)
{
	const FsWhatIfContext *ctx = m->ctx;

	memset (c, 0, sizeof *c);
	c->protos = g_array_new (FALSE, FALSE, sizeof (gint));
	c->ports = g_array_new (FALSE, FALSE, sizeof (guint));
	c->icmps = g_ptr_array_new ();
	c->hosts = g_array_new (FALSE, TRUE, sizeof (Addr));
	g_array_set_clear_func (c->hosts, addr_array_clear);
	c->dns = g_ptr_array_new ();
	c->locals = g_array_new (FALSE, TRUE, sizeof (Addr));
	g_array_set_clear_func (c->locals, addr_array_clear);
	c->ifaces = g_ptr_array_new ();
	c->profiles = g_array_new (FALSE, FALSE, sizeof (gint));

	/* Protocols. */
	{
		gint list[3];
		guint n = 0;

		switch (q->protocol) {
		case FS_WHATIF_PROTO_TCP:  list[n++] = P_TCP; break;
		case FS_WHATIF_PROTO_UDP:  list[n++] = P_UDP; break;
		case FS_WHATIF_PROTO_ICMP: list[n++] = P_ICMP; break;
		default:
			list[n++] = P_TCP;
			list[n++] = P_UDP;
			if (q->port == 0)
				list[n++] = P_ICMP;
			c->open[D_PROTO] = TRUE;
			break;
		}
		g_array_append_vals (c->protos, list, n);
	}

	/* Ports. */
	if (q->port != 0) {
		port_add (c->ports, q->port);
	} else {
		guint generic = 0;

		for (guint p = 49152; p <= 65535 && generic == 0; p++)
			if (!port_named_by_rules (m, inbound, p))
				generic = p;
		for (guint p = 1024; p < 49152 && generic == 0; p++)
			if (!port_named_by_rules (m, inbound, p))
				generic = p;
		if (generic != 0)
			port_add (c->ports, generic);

		for (gint f = 0; f < 2; f++) {
			GPtrArray *chain = chain_of (m, inbound, f);

			for (guint i = 0; i < chain->len; i++) {
				const WRule *r = g_ptr_array_index (chain, i);

				if (r->has_dport && r->left_out == NULL)
					spec_reps (c->ports, r->dport);
			}
			for (guint i = 0; inbound && i < m->dnat[f]->len; i++)
				spec_reps (c->ports,
				           ((const Dnat *) g_ptr_array_index (
				                   m->dnat[f], i))->dport);
		}
		c->open[D_PORT] = TRUE;
	}

	/* ICMP types. */
	if (q->icmp_type != NULL) {
		for (guint i = 0; icmp4_types[i] != NULL; i++)
			if (strcmp (icmp4_types[i], q->icmp_type) == 0)
				g_ptr_array_add (c->icmps, (gpointer) icmp4_types[i]);
		if (c->icmps->len == 0)
			g_ptr_array_add (c->icmps, (gpointer) ICMP_OTHER);
	} else {
		for (guint i = 0; icmp4_types[i] != NULL; i++)
			g_ptr_array_add (c->icmps, (gpointer) icmp4_types[i]);
		g_ptr_array_add (c->icmps, (gpointer) ICMP_OTHER);
		c->open[D_ICMP] = TRUE;
	}

	/* Hosts. */
	{
		Addr typed;

		memset (&typed, 0, sizeof typed);
		if (q->host != NULL)
			addr_parse (&typed, q->host);

		if (typed.kind == ADDR_BLOCK &&
		    typed.prefix == addr_bits (&typed)) {
			host_add (c->hosts, &typed);
			c->host_typed = TRUE;
			c->host_self = addr_is_self (ctx, &typed);
		} else {
			Addr base;
			static const gchar *generic[] = {
				"198.51.100.200", "203.0.113.200", "192.0.2.200",
				"100.64.10.20", "9.9.9.10", "1.1.1.2", NULL
			};

			memset (&base, 0, sizeof base);
			if (typed.kind == ADDR_BLOCK) {
				pick_inside (m, &typed, &base);
			} else {
				for (guint i = 0; generic[i] != NULL; i++) {
					addr_parse (&base, generic[i]);
					if (!host_covered_by_rules (m, &base))
						break;
					addr_clear (&base);
				}
				if (base.kind != ADDR_BLOCK)
					addr_parse (&base, generic[0]);
			}
			host_add (c->hosts, &base);
			addr_clear (&base);

			/* With no host named, an IPv6 host as well: the two
			 * families have their own chains on Linux and their own
			 * ICMP on Windows.  3fff::/20 is the documentation
			 * prefix no reserved-source rule covers. */
			if (typed.kind != ADDR_BLOCK) {
				addr_parse (&base, GENERIC_V6_HOST);
				host_add (c->hosts, &base);
				addr_clear (&base);
			}

			for (gint f = 0; f < 2; f++) {
				GPtrArray *chain = chain_of (m, inbound, f);

				for (guint i = 0; i < chain->len; i++) {
					const WRule *r = g_ptr_array_index (chain, i);
					const Addr *list[8];
					guint n;

					if (r->left_out != NULL)
						continue;
					rule_remote_addrs (r, inbound, list, &n);
					for (guint k = 0; k < n; k++) {
						Addr rep;

						if (list[k]->kind != ADDR_BLOCK)
							continue;
						for (gint last = 0; last < 2; last++) {
							addr_host (&rep, list[k], last);
							if (typed.kind != ADDR_BLOCK ||
							    addr_contains (&typed, &rep))
								host_add (c->hosts, &rep);
							g_free (rep.text);
						}
					}
				}
			}
			c->open[D_HOST] = TRUE;
		}
		addr_clear (&typed);
	}

	/* Host names a rule matches through DNS. */
	g_ptr_array_add (c->dns, NULL);
	for (gint f = 0; f < 2; f++) {
		GPtrArray *chain = chain_of (m, inbound, f);

		for (guint i = 0; i < chain->len; i++) {
			const WRule *r = g_ptr_array_index (chain, i);
			const Addr *list[8];
			guint n;

			if (r->left_out != NULL)
				continue;
			rule_remote_addrs (r, inbound, list, &n);
			for (guint k = 0; k < n; k++) {
				gboolean seen = FALSE;

				if (list[k]->kind != ADDR_NAME)
					continue;
				for (guint d = 1; d < c->dns->len; d++)
					if (g_ascii_strcasecmp (g_ptr_array_index (c->dns, d),
					                        list[k]->text) == 0)
						seen = TRUE;
				if (!seen)
					g_ptr_array_add (c->dns, list[k]->text);
			}
		}
	}
	c->open[D_DNS] = (c->dns->len > 1);

	/* Our own source address: Linux outbound rows that match -s. */
	{
		Addr none;

		memset (&none, 0, sizeof none);
		if (!inbound && m->platform == FS_WHATIF_LINUX_FIRST_MATCH &&
		    ctx->local_addresses->len > 0) {
			for (guint i = 0; i < ctx->local_addresses->len; i++) {
				Addr a;

				addr_parse (&a, g_ptr_array_index (ctx->local_addresses, i));
				if (a.kind == ADDR_BLOCK)
					host_add (c->locals, &a);
				addr_clear (&a);
			}
		}

		if (c->locals->len == 0) {
			host_add (c->locals, &none);
			for (gint f = 0; !inbound && f < 2; f++) {
				GPtrArray *chain = chain_of (m, FALSE, f);

				for (guint i = 0; i < chain->len; i++) {
					const WRule *r = g_ptr_array_index (chain, i);
					Addr rep;

					if (r->left_out != NULL || r->src.kind != ADDR_BLOCK)
						continue;
					addr_host (&rep, &r->src, FALSE);
					host_add (c->locals, &rep);
					g_free (rep.text);
				}
			}
		}
		c->open[D_LOCAL] = (c->locals->len > 1);
	}

	/* Interfaces (Linux).  A rule that names an interface ("-i v0",
	 * "-o v0", the forwards' "-i v0" in the nat table) only meets what
	 * really arrives on it or leaves by it; which one a connection uses
	 * is routing, not the question.  So the external interface, the
	 * internal one in router mode, and NULL for "any other interface"
	 * are all tried.  Outbound only router mode names one. */
	if (m->platform == FS_WHATIF_LINUX_FIRST_MATCH) {
		gboolean router = (m->settings->nat && m->intf != NULL &&
		                   g_strcmp0 (m->intf, m->ext) != 0);

		if (inbound) {
			/* The common case first: arriving from outside. */
			if (m->ext != NULL)
				g_ptr_array_add (c->ifaces, (gpointer) m->ext);
			else
				g_ptr_array_add (c->ifaces, NULL);
			if (router)
				g_ptr_array_add (c->ifaces, (gpointer) m->intf);
			if (m->ext != NULL)
				g_ptr_array_add (c->ifaces, NULL);
		} else {
			if (m->settings->nat && m->ext != NULL) {
				g_ptr_array_add (c->ifaces, (gpointer) m->ext);
				if (router)
					g_ptr_array_add (c->ifaces, (gpointer) m->intf);
			}
			g_ptr_array_add (c->ifaces, NULL);
		}
		c->open[D_IFACE] = (c->ifaces->len > 1);
	} else {
		g_ptr_array_add (c->ifaces, NULL);
	}

	/* ICMP replies and errors: the answer to something this computer
	 * sent, or unsolicited. */
	c->n_state = 1;
	for (guint i = 0; i < c->protos->len; i++)
		if (g_array_index (c->protos, gint, i) == P_ICMP)
			for (guint k = 0; k < c->icmps->len; k++)
				if (icmp_is_reply (g_ptr_array_index (c->icmps, k)))
					c->n_state = 2;
	c->open[D_STATE] = (c->n_state > 1);

	/* A forward to another computer with router mode off reaches it
	 * only if something else turned IP forwarding on. */
	c->n_fwd = 1;
	if (inbound && m->fwd_gate != NULL)
		for (gint f = 0; f < 2; f++)
			for (guint i = 0; i < m->dnat[f]->len; i++)
				if (!addr_is_self (ctx, &((const Dnat *)
				                   g_ptr_array_index (m->dnat[f], i))->to))
					c->n_fwd = 2;
	c->open[D_FWD] = (c->n_fwd > 1);

	/* Profiles (Windows). */
	if (m->platform == FS_WHATIF_WINDOWS_BLOCK_WINS) {
		static const gint order[] = {
			PROFILE_PUBLIC, PROFILE_PRIVATE, PROFILE_DOMAIN
		};

		for (guint i = 0; i < 3; i++)
			if (ctx->profiles_in_use == 0 ||
			    (ctx->profiles_in_use & (1u << order[i])))
				g_array_append_val (c->profiles, order[i]);
		if (c->profiles->len == 0)
			for (guint i = 0; i < 3; i++)
				g_array_append_val (c->profiles, order[i]);
		c->open[D_PROFILE] = (c->profiles->len > 1);
	} else {
		gint none = -1;

		g_array_append_val (c->profiles, none);
	}

	/* Keep the product bounded: past the cap the host and port lists
	 * are cut (the base is always kept) and the answer says so. */
	for (;;) {
		guint64 per_host = 0;
		guint64 n;

		for (guint i = 0; i < c->protos->len; i++)
			per_host += (g_array_index (c->protos, gint, i) == P_ICMP)
			            ? c->icmps->len : MAX (c->ports->len, 1);
		n = per_host * c->hosts->len * c->dns->len * c->locals->len *
		    c->ifaces->len * c->profiles->len * c->n_state * c->n_fwd;

		if (n <= MAX_COMBINATIONS)
			break;
		c->capped = TRUE;
		if (c->hosts->len >= c->ports->len && c->hosts->len > 1)
			g_array_set_size (c->hosts, c->hosts->len / 2);
		else if (c->ports->len > 1)
			g_array_set_size (c->ports, c->ports->len / 2);
		else
			break;
	}
}

/* [ probe_icmp_name ] -- the same type in ICMPv6's words. */
static const gchar *
probe_icmp_name (const gchar *type, gint fam)
{
	if (fam != 6 || type == NULL)
		return type;
	if (strcmp (type, "host-unreachable") == 0)
		return "address-unreachable";
	if (strcmp (type, "timestamp-request") == 0 ||
	    strcmp (type, "timestamp-reply") == 0 ||
	    strcmp (type, "address-mask-request") == 0 ||
	    strcmp (type, "address-mask-reply") == 0 ||
	    strcmp (type, "source-quench") == 0)
		return ICMP_OTHER;
	return type;
}

static void
probe_fill (Model *m, const Cands *c, gboolean inbound, const guint *ix,
            Probe *p)
{
	memset (p, 0, sizeof *p);
	p->inbound = inbound;
	p->proto = g_array_index (c->protos, gint, ix[D_PROTO]);
	p->port = (p->proto == P_ICMP) ? 0
	          : g_array_index (c->ports, guint, ix[D_PORT]);
	p->host = g_array_index (c->hosts, Addr, ix[D_HOST]);
	p->fam = p->host.fam == 6 ? 6 : 4;
	p->icmp = (p->proto == P_ICMP)
		? probe_icmp_name (g_ptr_array_index (c->icmps, ix[D_ICMP]), p->fam)
		: NULL;
	p->dns = g_ptr_array_index (c->dns, ix[D_DNS]);
	p->local = g_array_index (c->locals, Addr, ix[D_LOCAL]);
	p->iface = g_ptr_array_index (c->ifaces, ix[D_IFACE]);
	p->profile = g_array_index (c->profiles, gint, ix[D_PROFILE]);
	p->ct = CT_NEW;
	if (p->proto == P_ICMP && icmp_is_reply (p->icmp))
		p->ct = (ix[D_STATE] == 0) ? CT_REPLY : CT_INVALID;
	p->fwd_on = (ix[D_FWD] != 0);

	/* What this computer sends to itself -- to 127.0.0.1 or to one of
	 * its own addresses -- goes over loopback. */
	p->self = c->host_self;
	if (m->platform == FS_WHATIF_LINUX_FIRST_MATCH && p->self)
		p->iface = "lo";
}

typedef struct
{
	guint   ix[D_N];
	Outcome o;
} Eval;

/* [ evaluate_all ]
 * Every combination; ICMP probes skip the port list and TCP/UDP probes
 * the ICMP list, so neither multiplies the other. */
static GArray *
evaluate_all (Model *m, const Cands *c, gboolean inbound)
{
	GArray *out = g_array_new (FALSE, FALSE, sizeof (Eval));
	guint len[D_N];
	guint ix[D_N];

	len[D_PROTO] = c->protos->len;
	len[D_PORT] = c->ports->len;
	len[D_ICMP] = c->icmps->len;
	len[D_HOST] = c->hosts->len;
	len[D_DNS] = c->dns->len;
	len[D_LOCAL] = c->locals->len;
	len[D_IFACE] = c->ifaces->len;
	len[D_PROFILE] = c->profiles->len;
	len[D_STATE] = c->n_state;
	len[D_FWD] = c->n_fwd;

	memset (ix, 0, sizeof ix);

	for (;;) {
		gint proto = g_array_index (c->protos, gint, ix[D_PROTO]);
		gboolean skip = (proto == P_ICMP && ix[D_PORT] != 0) ||
		                (proto != P_ICMP && ix[D_ICMP] != 0) ||
		                (proto != P_ICMP && c->ports->len == 0);
		Probe p;

		/* Only an ICMP reply or error has a second conntrack state. */
		if (!skip && ix[D_STATE] != 0) {
			probe_fill (m, c, inbound, ix, &p);
			skip = (p.ct == CT_NEW);
		}

		if (!skip) {
			Eval e;

			memcpy (e.ix, ix, sizeof ix);
			probe_fill (m, c, inbound, ix, &p);
			e.o = eval_probe (m, &p, NULL, NULL);
			g_array_append_val (out, e);
		}

		/* Odometer. */
		{
			gint d = D_N - 1;

			while (d >= 0) {
				if (++ix[d] < MAX (len[d], 1))
					break;
				ix[d] = 0;
				d--;
			}
			if (d < 0)
				break;
		}
	}

	return out;
}

static guint
dim_len (const Cands *c, gint d)
{
	switch (d) {
	case D_PROTO:   return c->protos->len;
	case D_PORT:    return c->ports->len;
	case D_ICMP:    return c->icmps->len;
	case D_HOST:    return c->hosts->len;
	case D_DNS:     return c->dns->len;
	case D_LOCAL:   return c->locals->len;
	case D_IFACE:   return c->ifaces->len;
	case D_STATE:   return c->n_state;
	case D_FWD:     return c->n_fwd;
	default:        return c->profiles->len;
	}
}

/* ================================================================
 * 9. Words
 * ================================================================ */

static const gchar *
icmp_words (const gchar *type)
{
	if (type == NULL || strcmp (type, ICMP_OTHER) == 0)
		return _("of another type");
	if (strcmp (type, "echo-request") == 0)
		return _("echo-request (ping)");
	if (strcmp (type, "echo-reply") == 0)
		return _("echo-reply (the answer to a ping)");
	return type;
}

/* "A", "A and B", "A, B and C". */
static gchar *
join_words (GPtrArray *words)
{
	GString *s = g_string_new (NULL);

	for (guint i = 0; i < words->len; i++) {
		if (i > 0)
			g_string_append (s, (i + 1 == words->len) ? _(" and ") : ", ");
		g_string_append (s, g_ptr_array_index (words, i));
	}

	return g_string_free (s, FALSE);
}

/* fmt with the joined list as its one %s; frees nothing of words. */
static gchar *
fmt_list (const gchar *fmt, GPtrArray *words)
{
	gchar *list = join_words (words);
	gchar *out;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	out = g_strdup_printf (fmt, list);
#pragma GCC diagnostic pop
	g_free (list);
	return out;
}

static gchar *
probe_text (const Probe *p)
{
	GString *s = g_string_new (p->inbound ? _("inbound ") : _("outbound "));
	gchar *h = addr_text (&p->host);

	if (p->proto == P_ICMP)
		g_string_append_printf (s, _("ICMP %s"), icmp_words (p->icmp));
	else
		g_string_append_printf (s, _("%s port %u"), proto_name (p->proto),
		                        p->port);

	g_string_append_printf (s, p->inbound ? _(" from %s") : _(" to %s"), h);

	if (p->dns != NULL)
		g_string_append_printf (s, _(" (as an address of %s)"), p->dns);
	if (!p->inbound && p->local.kind == ADDR_BLOCK)
		g_string_append_printf (s, _(" sent from this computer's address "
		                             "%s"), p->local.text);
	if (p->iface != NULL)
		g_string_append_printf (s, p->inbound ? _(" arriving on %s")
		                                      : _(" leaving by %s"),
		                        p->iface);
	if (p->ct == CT_REPLY)
		g_string_append (s, _(", answering a connection already open"));
	else if (p->ct == CT_INVALID)
		g_string_append (s, _(", unsolicited"));
	if (p->fwd_on)
		g_string_append (s, _(", with IP forwarding on"));
	if (p->profile >= 0)
		g_string_append_printf (s, _(" on a %s network"),
		                        profile_name (p->profile));

	g_free (h);
	return g_string_free (s, FALSE);
}

/* [ query_text ] -- the question, one direction, as a heading. */
static gchar *
query_text (const FsWhatIfQuery *q, gboolean inbound)
{
	GString *s = g_string_new (inbound ? _("Inbound ") : _("Outbound "));
	const gchar *host = q->host != NULL ? q->host : _("any host");

	if (q->protocol == FS_WHATIF_PROTO_ICMP || q->icmp_type != NULL) {
		g_string_append_printf (s, _("ICMP %s"), q->icmp_type != NULL
		                        ? icmp_words (q->icmp_type)
		                        : _("of any type"));
	} else if (q->port != 0) {
		g_string_append_printf (s, _("%s port %u"),
		                        q->protocol == FS_WHATIF_PROTO_TCP ? "TCP"
		                        : q->protocol == FS_WHATIF_PROTO_UDP ? "UDP"
		                        : _("TCP or UDP"), q->port);
	} else {
		g_string_append (s, q->protocol == FS_WHATIF_PROTO_TCP ? _("TCP on any port")
		                    : q->protocol == FS_WHATIF_PROTO_UDP ? _("UDP on any port")
		                    : _("traffic of any kind"));
	}

	if (q->service != NULL)
		g_string_append_printf (s, " (%s)", q->service);

	g_string_append_printf (s, inbound ? _(" from %s to this computer")
	                                   : _(" from this computer to %s"),
	                        host);
	return g_string_free (s, FALSE);
}

/* [ sentinel_expiry ]
 * "it lifts by itself at 14:05 (in 7 minutes)", or NULL when the
 * context does not know when the block lifts. */
static gchar *
sentinel_expiry (const FsWhatIfContext *ctx, const gchar *target,
                 gint64 *expires_out)
{
	gint64 expires = 0;
	gint64 now;
	Addr want;

	if (expires_out != NULL)
		*expires_out = 0;
	if (target == NULL)
		return NULL;

	addr_parse (&want, target);
	for (guint i = 0; i < ctx->auto_blocks->len; i++) {
		const FsWhatIfAutoBlock *ab = g_ptr_array_index (ctx->auto_blocks, i);
		Addr a;
		gboolean same;

		addr_parse (&a, ab->target);
		same = (g_ascii_strcasecmp (ab->target, target) == 0) ||
		       (a.kind == ADDR_BLOCK && addr_equal (&a, &want));
		addr_clear (&a);
		if (same) {
			expires = ab->expires_unix;
			break;
		}
	}
	addr_clear (&want);

	if (expires_out != NULL)
		*expires_out = expires;
	if (expires <= 0)
		return NULL;

	now = ctx->now_unix > 0 ? ctx->now_unix
	                        : g_get_real_time () / G_USEC_PER_SEC;

	if (expires <= now)
		return g_strdup (_("it is due to lift now"));

	{
		GDateTime *dt = g_date_time_new_from_unix_local (expires);
		gchar *hm = dt != NULL ? g_date_time_format (dt, "%H:%M")
		                       : g_strdup ("?");
		gint64 mins = (expires - now + 59) / 60;
		gchar *text = (mins == 1)
			? g_strdup_printf (_("it lifts by itself at %s (in 1 "
			                     "minute)"), hm)
			: g_strdup_printf (_("it lifts by itself at %s (in %"
			                     G_GINT64_FORMAT " minutes)"), hm, mins);

		g_free (hm);
		if (dt != NULL)
			g_date_time_unref (dt);
		return text;
	}
}

static const gchar *
rule_row_target (const Model *m, const WRule *r)
{
	const FsRule *row;

	if (r == NULL || r->pkind < 0 || r->pkind >= FS_RULE_N_KINDS ||
	    r->prow < 0 || (guint) r->prow >= m->policy->kinds[r->pkind]->len)
		return NULL;
	row = g_ptr_array_index (m->policy->kinds[r->pkind], r->prow);
	return row->target;
}

static gchar *
outcome_reason (const Model *m, const Outcome *o, gboolean inbound)
{
	const FsWhatIfContext *ctx = m->ctx;
	const gchar *name = (o->rule != NULL && o->rule->name != NULL)
	                    ? o->rule->name : "?";

	switch (o->origin) {
	case FS_WHATIF_ORIGIN_STOPPED:
		if (ctx->firewall != FS_WHATIF_FW_STOPPED && o->profile >= 0)
			return g_strdup_printf (_("Windows Firewall is off for the "
			                          "%s profile, so nothing is "
			                          "filtered."),
			                        profile_name (o->profile));
		return g_strdup (_("The firewall is not running, so nothing is "
		                   "filtered."));

	case FS_WHATIF_ORIGIN_POLICY:
		if (o->allowed && o->rule != NULL && o->rule->forward_to != NULL)
			return g_strdup_printf (_("Rule '%s' lets it in and "
			                          "forwards it to %s."),
			                        name, o->rule->forward_to);
		if (o->allowed && o->rule != NULL && o->rule->not_forwarded != NULL)
			return g_strdup_printf (_("Rule '%s' lets it in to this "
			                          "computer. It is not forwarded to "
			                          "%s: on Windows StockFW sets up no "
			                          "forwarding."),
			                        name, o->rule->not_forwarded);
		return g_strdup_printf (o->allowed ? _("Rule '%s' allows it.")
		                                   : _("Rule '%s' blocks it."),
		                        name);

	case FS_WHATIF_ORIGIN_SENTINEL: {
		gchar *when = sentinel_expiry (ctx, rule_row_target (m, o->rule),
		                               NULL);
		gchar *text = when != NULL
			? g_strdup_printf (_("Sentinel's automatic block '%s' "
			                     "blocks it; %s."), name, when)
			: g_strdup_printf (_("Sentinel's automatic block '%s' "
			                     "blocks it."), name);

		g_free (when);
		return text;
	}

	case FS_WHATIF_ORIGIN_SETTINGS:
		return g_strdup_printf (o->allowed
		                        ? _("The setting '%s' allows it.")
		                        : _("The setting '%s' blocks it."), name);

	case FS_WHATIF_ORIGIN_BUILTIN:
		return g_strdup_printf (o->allowed
		                        ? _("'%s' always lets it through.")
		                        : _("'%s' always drops it."), name);

	case FS_WHATIF_ORIGIN_DEFAULT:
	default:
		break;
	}

	if (m->platform == FS_WHATIF_WINDOWS_BLOCK_WINS)
		return g_strdup_printf (o->assumed
			? _("No rule matches, so the %s profile's default %s "
			    "action decides: %s (assumed: Windows' own default, "
			    "which StockFW could not read).")
			: _("No rule matches, so the %s profile's default %s "
			    "action decides: %s."),
			profile_name (o->profile),
			inbound ? _("inbound") : _("outbound"),
			o->allowed ? _("allow") : _("block"));

	if (inbound)
		return g_strdup (m->settings->deny_packets
		                 ? _("No rule lets it in, so the default drops "
		                     "it.")
		                 : _("No rule lets it in, so the default "
		                     "rejects it with an error."));

	return g_strdup (o->allowed
	                 ? _("No rule blocks it, and outbound traffic is "
	                     "allowed by default.")
	                 : _("No rule allows it, and restrictive outbound "
	                     "mode drops everything else."));
}

static gchar *
by_text (const Model *m, FsWhatIfOrigin origin, const WRule *r,
         const gchar *group_name)
{
	const gchar *name = group_name != NULL ? group_name
	                    : (r != NULL && r->name != NULL) ? r->name : "?";

	switch (origin) {
	case FS_WHATIF_ORIGIN_POLICY:
		if (r != NULL && r->forward_to != NULL)
			return g_strdup_printf (_("by rule '%s', which forwards it "
			                          "to %s"), name, r->forward_to);
		return g_strdup_printf (_("by rule '%s'"), name);
	case FS_WHATIF_ORIGIN_SENTINEL:
		return g_strdup_printf (_("by Sentinel's automatic block '%s'"),
		                        name);
	case FS_WHATIF_ORIGIN_SETTINGS:
		return g_strdup_printf (_("by the setting '%s'"), name);
	case FS_WHATIF_ORIGIN_BUILTIN:
		return g_strdup_printf (_("by '%s'"), name);
	case FS_WHATIF_ORIGIN_STOPPED:
		return g_strdup (_("because the firewall is off"));
	default:
		return g_strdup (m->platform == FS_WHATIF_WINDOWS_BLOCK_WINS
		                 ? _("by the profile's default action")
		                 : _("by the default"));
	}
}

/* ================================================================
 * 8 (continued). Grouping the combinations into cases
 * ================================================================ */

typedef struct
{
	gboolean        allowed;
	FsWhatIfOrigin  origin;
	const WRule    *rule;       /* the first member's deciding rule   */
	gchar          *name;       /* what the group's rule is called    */
	GArray         *members;    /* guint: indices into the evaluations */
} Group;

static void
group_free (gpointer data)
{
	Group *g = data;

	g_array_unref (g->members);
	g_free (g->name);
	g_free (g);
}

/* [ group_name_add ]
 * The name a group goes by: its rule's -- or, when the lines of one
 * row that decided differ only in a protocol suffix ("... (TCP)" and
 * "... (UDP)"), the part they share, so a case that covers both is not
 * credited to the TCP line alone. */
static void
group_name_add (Group *g, const WRule *r)
{
	gsize n = 0;
	gint depth = 0;
	gsize cut = 0;

	if (r == NULL || r->name == NULL)
		return;
	if (g->name == NULL) {
		g->name = g_strdup (r->name);
		return;
	}
	if (strcmp (g->name, r->name) == 0)
		return;

	while (g->name[n] != '\0' && g->name[n] == r->name[n])
		n++;
	g->name[n] = '\0';

	/* Drop a parenthesis the two names opened and did not close. */
	for (gsize i = 0; i < n; i++) {
		if (g->name[i] == '(') {
			if (depth == 0)
				cut = i;
			depth++;
		} else if (g->name[i] == ')' && depth > 0) {
			depth--;
		}
	}
	if (depth > 0)
		g->name[cut] = '\0';
	g_strchomp (g->name);
}

/* Linux's reserved-source and broadcast drops sit after every allow,
 * just before the default drop: they can only ever agree with it, so
 * for the cases they count as the default. */
static FsWhatIfOrigin
group_origin (const Outcome *o)
{
	if (o->origin == FS_WHATIF_ORIGIN_SETTINGS && o->rule != NULL &&
	    o->rule->tail && !o->allowed)
		return FS_WHATIF_ORIGIN_DEFAULT;
	return o->origin;
}

static gboolean
group_takes (const Group *g, const Outcome *o)
{
	FsWhatIfOrigin origin = group_origin (o);

	if (g->allowed != o->allowed || g->origin != origin)
		return FALSE;

	switch (origin) {
	case FS_WHATIF_ORIGIN_DEFAULT:
	case FS_WHATIF_ORIGIN_STOPPED:
		return TRUE;
	case FS_WHATIF_ORIGIN_POLICY:
	case FS_WHATIF_ORIGIN_SENTINEL:
		/* One row, whichever of its lines (TCP / UDP, IPv4 / IPv6)
		 * decided. */
		if (g->rule != NULL && o->rule != NULL && g->rule->pkind >= 0)
			return g->rule->pkind == o->rule->pkind &&
			       g->rule->prow == o->rule->prow;
		return g->rule == o->rule;
	default:
		return g->rule != NULL && o->rule != NULL &&
		       g_strcmp0 (g->rule->name, o->rule->name) == 0;
	}
}

/* The values a group's members take on one field.  The ICMP type only
 * means something for ICMP members and the port only for the others,
 * so each is collected over those alone. */
static GArray *
group_values (const Cands *c, GArray *evals, const Group *g, gint dim)
{
	GArray *vals = g_array_new (FALSE, FALSE, sizeof (guint));

	for (guint i = 0; i < g->members->len; i++) {
		const Eval *e = &g_array_index (evals, Eval,
		                                g_array_index (g->members, guint, i));
		gboolean icmp = (g_array_index (c->protos, gint, e->ix[D_PROTO]) ==
		                 P_ICMP);
		guint v = e->ix[dim];
		gboolean seen = FALSE;

		if ((dim == D_ICMP && !icmp) || (dim == D_PORT && icmp))
			continue;
		/* The conntrack state only means something for a reply. */
		if (dim == D_STATE &&
		    (!icmp || !icmp_is_reply (g_ptr_array_index (c->icmps,
		                                                  e->ix[D_ICMP]))))
			continue;

		for (guint k = 0; k < vals->len && !seen; k++)
			seen = (g_array_index (vals, guint, k) == v);
		if (!seen)
			g_array_append_val (vals, v);
	}

	return vals;
}

static gboolean
values_have (GArray *vals, guint v)
{
	for (guint k = 0; k < vals->len; k++)
		if (g_array_index (vals, guint, k) == v)
			return TRUE;
	return FALSE;
}

static void
cond_add (GString *s, gchar *part)
{
	if (s->len > 0)
		g_string_append_c (s, ' ');
	g_string_append (s, part);
	g_free (part);
}

/* [ group_condition ]
 * Where a group of combinations differs from the common case, in
 * words: the deciding rule's own condition where it has one ("from
 * 203.0.113.0/24", "on port 22"), otherwise the values themselves
 * ("for UDP", "on Private networks").  dist[] collects the fields
 * that told the groups apart, for the common case's wording. */
static gchar *
group_condition (Model *m, const Cands *c, GArray *evals, const Group *g,
                 gboolean inbound, gboolean *dist_all)
{
	GString *s = g_string_new (NULL);
	const WRule *r = g->rule;
	gboolean dist[D_N];
	gboolean part[D_N];
	GArray *vals[D_N];
	const Eval *first = &g_array_index (evals, Eval,
	                                    g_array_index (g->members, guint, 0));
	gboolean base_icmp = (g_array_index (c->protos, gint, 0) == P_ICMP);
	const Addr *list[8];
	guint n_addr = 0;
	gboolean only_icmp;

	if (r != NULL)
		rule_remote_addrs (r, inbound, list, &n_addr);

	for (gint d = 0; d < D_N; d++) {
		vals[d] = group_values (c, evals, g, d);
		/* dist: the group never takes the common case's value here.
		 * part: the group takes only some of the values. */
		dist[d] = dim_len (c, d) > 1 && vals[d]->len > 0 &&
		          !values_have (vals[d], 0);
		part[d] = dim_len (c, d) > 1 && vals[d]->len > 0 &&
		          vals[d]->len < dim_len (c, d);
	}

	/* Against a TCP / UDP common case its ICMP type means nothing, and
	 * against an ICMP one its port. */
	if (!base_icmp)
		dist[D_ICMP] = part[D_ICMP];
	else
		dist[D_PORT] = part[D_PORT];

	for (gint d = 0; d < D_N; d++)
		dist_all[d] = dist_all[d] || dist[d];

	only_icmp = (vals[D_PROTO]->len == 1 &&
	             g_array_index (c->protos, gint, g_array_index (
	                     vals[D_PROTO], guint, 0)) == P_ICMP);

	/* Protocol: when the group is only some of them ("for ICMP
	 * echo-reply" below says ICMP on its own). */
	if (part[D_PROTO] && !(only_icmp && part[D_ICMP])) {
		GPtrArray *w = g_ptr_array_new ();

		for (guint k = 0; k < vals[D_PROTO]->len; k++)
			g_ptr_array_add (w, (gpointer) proto_name (g_array_index (
				c->protos, gint, g_array_index (vals[D_PROTO], guint, k))));
		cond_add (s, fmt_list (_("for %s"), w));
		g_ptr_array_unref (w);
	}

	if (part[D_ICMP]) {
		if (r != NULL && r->proto == P_ICMP && r->icmp != NULL) {
			cond_add (s, g_strdup_printf (_("for ICMP %s"),
			                              icmp_words (r->icmp)));
		} else {
			GPtrArray *w = g_ptr_array_new ();

			for (guint k = 0; k < vals[D_ICMP]->len && k < 4; k++)
				g_ptr_array_add (w, (gpointer) icmp_words (
					g_ptr_array_index (c->icmps, g_array_index (
						vals[D_ICMP], guint, k))));
			if (vals[D_ICMP]->len > 4)
				g_ptr_array_add (w, (gpointer) _("other types"));
			cond_add (s, fmt_list (_("for ICMP %s"), w));
			g_ptr_array_unref (w);
		}
	}

	/* Port: the deciding rule's own when it has one. */
	if (dim_len (c, D_PORT) > 1 && vals[D_PORT]->len > 0) {
		if (r != NULL && r->has_dport && r->dport != NULL && part[D_PORT])
			cond_add (s, g_strdup_printf (_("on port %s"),
			                              r->r_dport != NULL ? r->r_dport
			                                                 : r->dport));
		else if (dist[D_PORT])
			cond_add (s, g_strdup_printf (_("for example on port %u"),
			                              g_array_index (c->ports, guint,
			                                             first->ix[D_PORT])));
	}

	/* Host: the deciding rule's addresses when it has any. */
	if (dim_len (c, D_HOST) > 1) {
		const Addr *base = &g_array_index (c->hosts, Addr, 0);
		gboolean other_family = TRUE;

		for (guint k = 0; k < vals[D_HOST]->len; k++)
			if (g_array_index (c->hosts, Addr, g_array_index (
				vals[D_HOST], guint, k)).fam == base->fam)
				other_family = FALSE;

		if (n_addr > 0 && part[D_HOST]) {
			GPtrArray *w = g_ptr_array_new ();

			for (guint k = 0; k < n_addr; k++)
				g_ptr_array_add (w, list[k]->text);
			cond_add (s, fmt_list (inbound ? _("from %s") : _("to %s"), w));
			g_ptr_array_unref (w);
		} else if (dist[D_HOST] && other_family) {
			cond_add (s, g_strdup (base->fam == 6 ? _("for IPv4 hosts")
			                                     : _("for IPv6 hosts")));
		} else if (dist[D_HOST]) {
			cond_add (s, g_strdup_printf (inbound
			                              ? _("for example from %s")
			                              : _("for example to %s"),
			                              g_array_index (c->hosts, Addr,
			                                             first->ix[D_HOST]).text));
		}
	}

	if (dist[D_DNS])
		cond_add (s, g_strdup_printf (_("if the host is an address of %s "
		                                "(that depends on DNS)"),
		                              (const gchar *) g_ptr_array_index (
		                                      c->dns, first->ix[D_DNS])));

	if (dim_len (c, D_LOCAL) > 1) {
		const Addr *local = &g_array_index (c->locals, Addr,
		                                    first->ix[D_LOCAL]);

		if (r != NULL && r->src.kind == ADDR_BLOCK && !inbound &&
		    part[D_LOCAL])
			cond_add (s, g_strdup_printf (_("if this computer sends it "
			                                "from %s"), r->src.text));
		else if (dist[D_LOCAL])
			cond_add (s, g_strdup_printf (_("if this computer sends it "
			                                "from %s"),
			                              local->text ? local->text : "?"));
	}

	if (part[D_IFACE]) {
		GPtrArray *w = g_ptr_array_new ();
		gboolean other = FALSE;
		gchar *names;

		for (guint k = 0; k < vals[D_IFACE]->len; k++) {
			const gchar *ifn = g_ptr_array_index (c->ifaces, g_array_index (
				vals[D_IFACE], guint, k));

			if (ifn != NULL)
				g_ptr_array_add (w, (gpointer) ifn);
			else
				other = TRUE;
		}
		names = join_words (w);
		cond_add (s, g_strdup_printf (
			inbound ? _("when it arrives on %s%s%s")
			        : _("when it leaves by %s%s%s"),
			names, (w->len > 0 && other) ? _(" or ") : "",
			other ? _("any other interface") : ""));
		g_free (names);
		g_ptr_array_unref (w);
	}

	if (part[D_STATE])
		cond_add (s, g_strdup (vals[D_STATE]->len == 1 &&
		                       g_array_index (vals[D_STATE], guint, 0) == 0
		                       ? _("when it answers a connection already "
		                           "open")
		                       : _("when it answers no open connection "
		                           "(unsolicited)")));

	if (part[D_FWD])
		cond_add (s, g_strdup (g_array_index (vals[D_FWD], guint, 0) == 0
		                       ? _("when IP forwarding is off")
		                       : _("when IP forwarding is on (another "
		                           "program turned it on)")));

	if (part[D_PROFILE]) {
		GPtrArray *w = g_ptr_array_new ();

		for (guint k = 0; k < vals[D_PROFILE]->len; k++)
			g_ptr_array_add (w, (gpointer) profile_name (g_array_index (
				c->profiles, gint, g_array_index (vals[D_PROFILE],
				                                  guint, k))));
		cond_add (s, fmt_list (_("on %s networks"), w));
		g_ptr_array_unref (w);
	}

	if (s->len == 0) {
		Probe p;
		gchar *t;

		probe_fill (m, c, inbound, first->ix, &p);
		t = probe_text (&p);
		cond_add (s, g_strdup_printf (_("in some cases, for example %s"), t));
		g_free (t);
	}

	for (gint d = 0; d < D_N; d++)
		g_array_unref (vals[d]);

	return g_string_free (s, FALSE);
}

/* The common case's condition: "for most hosts", "on other ports" --
 * or NULL when the other cases differ from it in more than one way,
 * and "in every other case" (said last) is the honest wording. */
static gchar *
base_condition (Model *m, const Cands *c, const FsWhatIfQuery *q,
                const gboolean *dist, gboolean inbound)
{
	gboolean base_icmp = (g_array_index (c->protos, gint, 0) == P_ICMP);
	gint which = -1;
	guint n = 0;

	(void) m;

	for (gint d = 0; d < D_N; d++) {
		if (!dist[d] || (d == D_ICMP && !base_icmp) ||
		    (d == D_PORT && base_icmp))
			continue;
		which = d;
		n++;
	}

	if (n != 1)
		return NULL;

	switch (which) {
	case D_PROTO:
		return g_strdup_printf (_("for %s"), proto_name (
			g_array_index (c->protos, gint, 0)));
	case D_ICMP:
		return g_strdup_printf (_("for ICMP %s"), icmp_words (
			g_ptr_array_index (c->icmps, 0)));
	case D_PORT:
		return g_strdup (_("on other ports"));
	case D_HOST:
		return q->host != NULL
		       ? g_strdup_printf (_("for most of %s"), q->host)
		       : g_strdup (_("for most hosts"));
	case D_DNS:
		if (c->dns->len == 2)
			return g_strdup_printf (_("if the host is not an address "
			                          "of %s"),
			                        (const gchar *)
			                        g_ptr_array_index (c->dns, 1));
		return g_strdup (_("if the host is not an address of any of "
		                   "those names"));
	case D_LOCAL:
		return g_strdup (_("if this computer sends it from another "
		                   "address"));
	case D_IFACE: {
		const gchar *ifn = g_ptr_array_index (c->ifaces, 0);

		return ifn != NULL
		       ? g_strdup_printf (inbound ? _("when it arrives on %s")
		                                  : _("when it leaves by %s"), ifn)
		       : g_strdup (inbound ? _("when it arrives on another "
		                               "interface")
		                           : _("when it leaves by another "
		                               "interface"));
	}
	case D_STATE:
		return g_strdup (_("when it answers a connection already open"));
	case D_FWD:
		return g_strdup (_("when IP forwarding is off, as StockFW leaves "
		                   "it outside router mode"));
	default:
		return g_strdup_printf (_("on %s networks"), profile_name (
			g_array_index (c->profiles, gint, 0)));
	}
}

static FsWhatIfCase *
case_new (FsWhatIfVerdict verdict, gchar *condition, FsWhatIfOrigin origin,
          const WRule *r)
{
	FsWhatIfCase *k = g_new0 (FsWhatIfCase, 1);

	k->verdict = verdict;
	k->condition = condition;
	k->origin = origin;
	k->rule = g_strdup (r != NULL ? r->name : NULL);
	k->policy_kind = r != NULL ? r->pkind : -1;
	k->policy_index = r != NULL ? r->prow : -1;
	return k;
}

#define MAX_CASES 6

/* ================================================================
 * 10. Actions, and the re-simulation that verifies them
 * ================================================================ */

static FsPolicy *
policy_dup (const FsPolicy *p)
{
	FsPolicy *out = fs_policy_new ();

	for (gint k = 0; p != NULL && k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < p->kinds[k]->len; i++)
			g_ptr_array_add (out->kinds[k],
			                 fs_rule_copy (g_ptr_array_index (p->kinds[k], i)));
	return out;
}

static FsPolicy *
policy_plus (const FsPolicy *p, const FsRule *row)
{
	FsPolicy *out = policy_dup (p);

	g_ptr_array_add (out->kinds[row->kind], fs_rule_copy (row));
	return out;
}

static FsPolicy *
policy_without_row (const FsPolicy *p, gint kind, gint index)
{
	FsPolicy *out = policy_dup (p);

	if (kind >= 0 && kind < FS_RULE_N_KINDS && index >= 0 &&
	    (guint) index < out->kinds[kind]->len)
		g_ptr_array_remove_index (out->kinds[kind], (guint) index);
	return out;
}

/* Every Sentinel row for target, as Lift does. */
static FsPolicy *
policy_without_sentinel (const FsPolicy *p, const gchar *target)
{
	FsPolicy *out = policy_dup (p);
	GPtrArray *rows = out->kinds[FS_RULE_OUTBOUND_DENY_TO];

	for (guint i = rows->len; i > 0; i--) {
		const FsRule *row = g_ptr_array_index (rows, i - 1);

		if (comment_is_sentinel (row->comment) && row->target != NULL &&
		    target != NULL && g_ascii_strcasecmp (row->target, target) == 0)
			g_ptr_array_remove_index (rows, i - 1);
	}
	return out;
}

static FsSettings *
settings_dup (const FsSettings *s)
{
	FsSettings *out = fs_settings_new ();

	if (s == NULL)
		return out;

	g_free (out->ext_device);
	g_free (out->int_device);
	*out = *s;
	out->ext_device = g_strdup (s->ext_device);
	out->int_device = g_strdup (s->int_device);
	return out;
}

/* The Preferences switches a fix may name, as the dialog labels them
 * (fs-prefsdialog.c), with the page that holds each: `page' is that
 * page's id in the dialog, which the fix button opens. */
typedef struct
{
	const gchar *key;
	gsize        offset;
	const gchar *label;
	const gchar *where;
	const gchar *page;
	gboolean     icmp;
	const gchar *scope;     /* what else it changes, in words */
	/* Linux only: a block a device scopes.  Preferences offers it only
	 * where it can match (fs-prefsdialog.c, the Protection page), and
	 * the Windows model has no such rule, so no fix may name it there. */
	gboolean     linux_only;
} Flip;

#define SCOPE_ICMP_TYPE N_("It applies to this kind of ICMP from every " \
                           "host, not only the one asked about.")
#define SCOPE_ALL_ICMP  N_("It lets every kind of ICMP in from every host.")
#define SCOPE_EVERYONE  N_("It applies to every host and every port, not " \
                           "only this question.")

#define ICMP_PAGE N_("Preferences > ICMP")
#define ADV_PAGE  N_("Preferences > Protection")

static const Flip flips[] = {
	{ "icmp_echo_request", G_STRUCT_OFFSET (FsSettings, icmp_echo_request),
	  N_("Echo request (ping)"), ICMP_PAGE, "icmp", TRUE,
	  SCOPE_ICMP_TYPE, FALSE },
	{ "icmp_echo_reply", G_STRUCT_OFFSET (FsSettings, icmp_echo_reply),
	  N_("Echo reply"), ICMP_PAGE, "icmp", TRUE,
	  SCOPE_ICMP_TYPE, FALSE },
	{ "icmp_traceroute", G_STRUCT_OFFSET (FsSettings, icmp_traceroute),
	  N_("Traceroute"), ICMP_PAGE, "icmp", TRUE,
	  SCOPE_ICMP_TYPE, FALSE },
	{ "icmp_mstraceroute", G_STRUCT_OFFSET (FsSettings, icmp_mstraceroute),
	  N_("Windows traceroute"), ICMP_PAGE, "icmp", TRUE,
	  SCOPE_ICMP_TYPE, FALSE },
	{ "icmp_unreachable", G_STRUCT_OFFSET (FsSettings, icmp_unreachable),
	  N_("Host unreachable"), ICMP_PAGE, "icmp", TRUE,
	  SCOPE_ICMP_TYPE, FALSE },
	{ "icmp_timestamping", G_STRUCT_OFFSET (FsSettings, icmp_timestamping),
	  N_("Timestamping (IPv4 only)"), ICMP_PAGE, "icmp", TRUE,
	  SCOPE_ICMP_TYPE, FALSE },
	{ "icmp_masking", G_STRUCT_OFFSET (FsSettings, icmp_masking),
	  N_("Address masking (IPv4 only)"), ICMP_PAGE, "icmp", TRUE,
	  SCOPE_ICMP_TYPE, FALSE },
	{ "icmp_redirection", G_STRUCT_OFFSET (FsSettings, icmp_redirection),
	  N_("Redirection"), ICMP_PAGE, "icmp", TRUE,
	  SCOPE_ICMP_TYPE, FALSE },
	{ "icmp_source_quenches",
	  G_STRUCT_OFFSET (FsSettings, icmp_source_quenches),
	  N_("Source quenching (IPv4 only)"), ICMP_PAGE, "icmp", TRUE,
	  SCOPE_ICMP_TYPE, FALSE },
	{ "filter_icmp", G_STRUCT_OFFSET (FsSettings, filter_icmp),
	  N_("Filter ICMP messages"), ICMP_PAGE, "icmp", TRUE,
	  SCOPE_ALL_ICMP, FALSE },
	{ "block_external_broadcast",
	  G_STRUCT_OFFSET (FsSettings, block_external_broadcast),
	  N_("Block broadcasts from the Internet side"), ADV_PAGE, "protection",
	  FALSE, SCOPE_EVERYONE, TRUE },
	{ "block_internal_broadcast",
	  G_STRUCT_OFFSET (FsSettings, block_internal_broadcast),
	  N_("Block broadcasts from the local network"), ADV_PAGE, "protection",
	  FALSE, SCOPE_EVERYONE, TRUE },
	{ "block_non_routables",
	  G_STRUCT_OFFSET (FsSettings, block_non_routables),
	  N_("Block reserved source addresses"),
	  ADV_PAGE, "protection", FALSE,
	  SCOPE_EVERYONE, FALSE }
};

static gboolean
flip_offered (const Flip *f, FsWhatIfPlatform platform)
{
	return !f->linux_only || platform == FS_WHATIF_LINUX_FIRST_MATCH;
}

/* [ fs_whatif_setting_nth ]
 * The i-th Preferences switch a fix may name on this platform (NULL past
 * the last), so a test can hold each label and page to the dialog this
 * build shows. */
const gchar *
fs_whatif_setting_nth (guint i, const gchar **label, const gchar **where,
                       const gchar **page)
{
	FsWhatIfPlatform native = fs_whatif_native_platform ();

	for (guint j = 0; j < G_N_ELEMENTS (flips); j++) {
		if (!flip_offered (&flips[j], native))
			continue;
		if (i-- > 0)
			continue;
		if (label != NULL)
			*label = _(flips[j].label);
		if (where != NULL)
			*where = _(flips[j].where);
		if (page != NULL)
			*page = flips[j].page;
		return flips[j].key;
	}
	return NULL;
}

static const Flip *
flip_find (const gchar *key)
{
	for (guint i = 0; key != NULL && i < G_N_ELEMENTS (flips); i++)
		if (strcmp (flips[i].key, key) == 0)
			return &flips[i];
	return NULL;
}

static gboolean *
flip_field (FsSettings *s, const Flip *f)
{
	return (gboolean *) (gpointer) ((guint8 *) s + f->offset);
}

/* The context as it is once the firewall runs (on every profile). */
static void
ctx_running (const FsWhatIfContext *ctx, FsWhatIfContext *run)
{
	*run = *ctx;
	run->firewall = FS_WHATIF_FW_RUNNING;
	for (gint p = 0; p < 3; p++)
		if (run->profile_enabled[p] == 0)
			run->profile_enabled[p] = 1;
}

static FsWhatIfQuery *
query_one_way (const FsWhatIfQuery *q, gboolean inbound)
{
	FsWhatIfQuery *dq = fs_whatif_query_copy (q);

	dq->direction = inbound ? FS_WHATIF_DIR_INBOUND : FS_WHATIF_DIR_OUTBOUND;
	return dq;
}

/* [ question_check ]
 * The question, one direction, against a policy in a context: how many
 * of its combinations do NOT get want_allowed (0 = all do), and the
 * first of those in words. */
static guint
question_check (const FsWhatIfContext *ctx, const FsPolicy *policy,
                const FsWhatIfQuery *q, gboolean inbound,
                gboolean want_allowed, gchar **example)
{
	Model *m = model_build (ctx, policy);
	Cands c;
	GArray *ev;
	guint wrong = 0;

	if (example != NULL)
		*example = NULL;

	cands_build (m, q, inbound, &c);
	ev = evaluate_all (m, &c, inbound);

	for (guint i = 0; i < ev->len; i++) {
		const Eval *e = &g_array_index (ev, Eval, i);
		Probe p;

		if (e->o.allowed == want_allowed)
			continue;
		probe_fill (m, &c, inbound, e->ix, &p);
		/* An ICMP reply or error answering traffic already let
		 * through follows that traffic, whatever the rows say; a
		 * question that did not name the ICMP type is not about it
		 * (the answer's notes say so). */
		if (p.ct == CT_REPLY && q->icmp_type == NULL)
			continue;
		if (wrong == 0 && example != NULL)
			*example = probe_text (&p);
		wrong++;
	}

	if (ev->len == 0)
		wrong = 1;

	g_array_unref (ev);
	cands_free (&c);
	model_free (m);
	return wrong;
}

/* [ row_implies ]
 * TRUE when the probe is one the row names: its direction, its
 * protocol(s), its port, its host.  A created row may change these and
 * nothing else. */
static gboolean
row_implies (const FsRule *row, const Probe *p)
{
	gboolean inbound = (row->kind == FS_RULE_INBOUND_ALLOW_FROM ||
	                    row->kind == FS_RULE_INBOUND_ALLOW_SERVICE ||
	                    row->kind == FS_RULE_INBOUND_FORWARD);

	if (p->inbound != inbound)
		return FALSE;

	if (row->target != NULL && !fs_util_target_is_anyone (row->target)) {
		Addr t;
		gboolean inside;

		addr_parse (&t, row->target);
		inside = addr_contains (&t, &p->host);
		addr_clear (&t);
		if (!inside)
			return FALSE;
	}

	switch (row->kind) {
	case FS_RULE_INBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
	case FS_RULE_OUTBOUND_DENY_SERVICE: {
		gchar *spec;
		gboolean covers;

		if (p->proto == P_ICMP)
			return FALSE;
		if (row->service != NULL &&
		    g_ascii_strcasecmp (row->service, "TCP") == 0 &&
		    p->proto != P_TCP)
			return FALSE;
		if (row->service != NULL &&
		    g_ascii_strcasecmp (row->service, "UDP") == 0 &&
		    p->proto != P_UDP)
			return FALSE;

		spec = fs_fwrule_port_spec (row->port);
		covers = (spec != NULL && fs_fwrule_port_spec_covers (spec, p->port));
		g_free (spec);
		return covers;
	}

	default:
		return TRUE;
	}
}

/* One address up or down from a /32 or /128. */
static void
addr_step (Addr *a, gint delta)
{
	guint n = (a->fam == 6) ? 16 : 4;
	GInetAddress *ia;

	if (delta > 0) {
		for (gint i = (gint) n - 1; i >= 0; i--)
			if (++a->b[i] != 0)
				break;
	} else {
		for (gint i = (gint) n - 1; i >= 0; i--)
			if (a->b[i]-- != 0)
				break;
	}

	g_free (a->text);
	ia = g_inet_address_new_from_bytes (a->b, a->fam == 6
	                                    ? G_SOCKET_FAMILY_IPV6
	                                    : G_SOCKET_FAMILY_IPV4);
	a->text = g_inet_address_to_string (ia);
	g_object_unref (ia);
}

/* The fixed probes every created row is checked against, besides the
 * representatives of every rule: common ports, hosts in private and
 * public space of both families, and the neighbours of what was asked
 * (the port either side, the addresses just outside the host or block). */
static void
cands_add_fixed (Cands *c, const FsWhatIfQuery *q)
{
	static const guint ports[] = {
		22, 25, 53, 67, 80, 123, 137, 443, 445, 500, 3389, 8080, 33434,
		50000
	};
	static const gchar *hosts[] = {
		"203.0.113.7", "192.168.1.20", "10.1.2.3", "8.8.8.8",
		"2001:db8::7", "3fff::7", NULL
	};

	for (guint i = 0; i < G_N_ELEMENTS (ports); i++)
		port_add (c->ports, ports[i]);
	if (q->port != 0) {
		port_add (c->ports, q->port);
		port_add (c->ports, q->port - 1);
		port_add (c->ports, q->port + 1);
	}

	for (guint i = 0; hosts[i] != NULL; i++) {
		Addr a;

		addr_parse (&a, hosts[i]);
		host_add (c->hosts, &a);
		addr_clear (&a);
	}

	if (q->host != NULL) {
		Addr t;

		addr_parse (&t, q->host);
		if (t.kind == ADDR_BLOCK) {
			for (gint last = 0; last < 2; last++) {
				Addr edge;

				addr_host (&edge, &t, last);
				host_add (c->hosts, &edge);
				addr_step (&edge, last ? 1 : -1);
				host_add (c->hosts, &edge);
				g_free (edge.text);
			}
		}
		addr_clear (&t);
	}
}

/* [ verify_create ]
 * The row added to the policy: the question (its direction) gets
 * exactly the promised verdict, and across every representative of
 * both directions plus the fixed probes, nothing the row does not name
 * changes verdict. */
static gboolean
verify_create (const FsWhatIfContext *ctx, const FsWhatIfQuery *q,
               const FsWhatIfAction *act, gchar **why, gchar **kept)
{
	FsWhatIfContext run;
	FsWhatIfQuery *dq;
	FsPolicy *after;
	gboolean want = (act->kind == FS_WHATIF_ACT_CREATE_ALLOW);
	gboolean ok = TRUE;

	ctx_running (ctx, &run);
	after = policy_plus (ctx->policy, act->row);
	dq = query_one_way (q, act->inbound);

	/* The question itself: every case gets the promised verdict -- but
	 * for an allow, a case a settings block still stops (Windows'
	 * reserved-source block wins over any allow) is the user's own
	 * choice standing, which the explanation then names.  Something
	 * must actually change. */
	{
		Model *ma = model_build (&run, after);
		Cands c;
		GArray *ev;
		GPtrArray *names = g_ptr_array_new ();
		guint wrong = 0, right = 0;
		gchar *example = NULL;

		cands_build (ma, dq, act->inbound, &c);
		ev = evaluate_all (ma, &c, act->inbound);

		for (guint i = 0; i < ev->len; i++) {
			const Eval *e = &g_array_index (ev, Eval, i);
			Probe rp;

			if (e->o.allowed == want) {
				right++;
				continue;
			}

			/* As in question_check: an ICMP reply answering an open
			 * connection follows it, and the line did not ask about
			 * it by type. */
			probe_fill (ma, &c, act->inbound, e->ix, &rp);
			if (rp.ct == CT_REPLY && dq->icmp_type == NULL)
				continue;

			if (want && e->o.origin == FS_WHATIF_ORIGIN_SETTINGS &&
			    e->o.rule != NULL && e->o.rule->target == T_DROP) {
				gboolean seen = FALSE;

				for (guint k = 0; k < names->len && !seen; k++)
					seen = g_strcmp0 (g_ptr_array_index (names, k),
					                  e->o.rule->name) == 0;
				if (!seen)
					g_ptr_array_add (names, e->o.rule->name);
				continue;
			}

			if (wrong++ == 0) {
				Probe p;

				probe_fill (ma, &c, act->inbound, e->ix, &p);
				example = probe_text (&p);
			}
		}

		if (wrong > 0) {
			*why = g_strdup_printf (_("with the row added it would still "
			                          "be %s for %s"),
			                        want ? _("blocked") : _("allowed"),
			                        example != NULL ? example
			                        : _("part of the question"));
			ok = FALSE;
		} else if (right == 0) {
			*why = g_strdup_printf (_("with the row added it would still "
			                          "be %s: %s"),
			                        want ? _("blocked") : _("allowed"),
			                        names->len > 0
			                        ? (const gchar *) g_ptr_array_index (names, 0)
			                        : _("nothing changes"));
			ok = FALSE;
		} else if (names->len > 0 && kept != NULL) {
			GPtrArray *w = g_ptr_array_new ();

			for (guint k = 0; k < names->len; k++)
				g_ptr_array_add (w, g_strdup_printf ("'%s'", (const gchar *)
				                                     g_ptr_array_index (names, k)));
			g_ptr_array_set_free_func (w, g_free);
			*kept = fmt_list (_("except where the setting %s still blocks "
			                    "it"), w);
			g_ptr_array_unref (w);
		}

		g_free (example);
		g_ptr_array_unref (names);
		g_array_unref (ev);
		cands_free (&c);
		model_free (ma);
	}

	if (ok) {
		Model *mb = model_build (&run, ctx->policy);
		Model *ma = model_build (&run, after);

		for (gint dir = 0; dir < 2 && ok; dir++) {
			gboolean inbound = (dir == 0);
			FsWhatIfQuery *open = fs_whatif_query_new ();
			Cands c;
			GArray *eb, *ea;

			cands_build (ma, open, inbound, &c);
			cands_add_fixed (&c, q);
			eb = evaluate_all (mb, &c, inbound);
			ea = evaluate_all (ma, &c, inbound);

			for (guint i = 0; i < ea->len && i < eb->len && ok; i++) {
				const Eval *b = &g_array_index (eb, Eval, i);
				const Eval *a = &g_array_index (ea, Eval, i);
				Probe p;

				if (b->o.allowed == a->o.allowed)
					continue;

				probe_fill (ma, &c, inbound, a->ix, &p);
				if (!row_implies (act->row, &p)) {
					gchar *t = probe_text (&p);

					*why = g_strdup_printf (
						_("it would also change %s from %s to %s"), t,
						b->o.allowed ? _("allowed") : _("blocked"),
						a->o.allowed ? _("allowed") : _("blocked"));
					g_free (t);
					ok = FALSE;
				}
			}

			g_array_unref (eb);
			g_array_unref (ea);
			cands_free (&c);
			fs_whatif_query_free (open);
		}

		model_free (mb);
		model_free (ma);
	}

	fs_whatif_query_free (dq);
	fs_policy_free (after);
	return ok;
}

/* Linux matches an outbound service row's host as the SOURCE (-s): a
 * row "allow/deny TCP 443 to X" would not do that there. */
static gboolean
linux_outbound_service_host (const FsRule *row)
{
	return (row->kind == FS_RULE_OUTBOUND_ALLOW_SERVICE ||
	        row->kind == FS_RULE_OUTBOUND_DENY_SERVICE) &&
	       row->target != NULL && !fs_util_target_is_anyone (row->target);
}

static const gchar *
b6_text (void)
{
	return _("On Linux the generator matches an outbound service row's "
	         "host as this computer's own (source) address, not as the "
	         "destination, so a row for one port to one host would not do "
	         "what it says.");
}

gboolean
fs_whatif_row_is_safe (const FsWhatIfAction *action, gchar **why)
{
	const FsRule *row;
	gchar *w = NULL;
	gboolean allow, service;

	if (why != NULL)
		*why = NULL;

	if (action == NULL || action->row == NULL ||
	    (action->kind != FS_WHATIF_ACT_CREATE_ALLOW &&
	     action->kind != FS_WHATIF_ACT_CREATE_BLOCK)) {
		w = g_strdup (_("it is not a row to create"));
		goto out;
	}

	row = action->row;
	allow = (action->kind == FS_WHATIF_ACT_CREATE_ALLOW);
	service = (row->kind == FS_RULE_INBOUND_ALLOW_SERVICE ||
	           row->kind == FS_RULE_OUTBOUND_ALLOW_SERVICE ||
	           row->kind == FS_RULE_OUTBOUND_DENY_SERVICE);

	if (allow && row->kind != FS_RULE_INBOUND_ALLOW_SERVICE &&
	    row->kind != FS_RULE_OUTBOUND_ALLOW_SERVICE) {
		w = g_strdup (_("an allow is only ever offered as a service row "
		                "(one protocol, one port)"));
		goto out;
	}
	if (!allow && row->kind != FS_RULE_OUTBOUND_DENY_SERVICE &&
	    row->kind != FS_RULE_OUTBOUND_DENY_TO) {
		w = g_strdup (_("a block is only ever offered as an outbound "
		                "deny row"));
		goto out;
	}

	if (row->target == NULL || *row->target == '\0') {
		w = g_strdup (_("it names no host"));
		goto out;
	}

	if (!fs_util_target_is_anyone (row->target)) {
		Addr t;
		gboolean literal;

		addr_parse (&t, row->target);
		literal = (t.kind == ADDR_BLOCK && t.prefix > 0);
		addr_clear (&t);
		if (!literal) {
			w = g_strdup_printf (_("\"%s\" is not one address or block"),
			                     row->target);
			goto out;
		}
	} else if (row->kind == FS_RULE_OUTBOUND_DENY_TO) {
		w = g_strdup (_("it would block every host"));
		goto out;
	}

	if (service) {
		const gchar *p = row->port;

		if (p == NULL || *p == '\0') {
			w = g_strdup (_("it names no port"));
			goto out;
		}
		for (const gchar *k = p; *k != '\0'; k++)
			if (!g_ascii_isdigit (*k)) {
				w = g_strdup_printf (_("\"%s\" is not one port"), p);
				goto out;
			}
		if (strlen (p) > 5 || atoi (p) < 1 || atoi (p) > 65535) {
			w = g_strdup_printf (_("\"%s\" is not a port"), p);
			goto out;
		}
		if (row->service == NULL || *row->service == '\0') {
			w = g_strdup (_("it names no protocol"));
			goto out;
		}
		if (allow && g_ascii_strcasecmp (row->service, "TCP") != 0 &&
		    g_ascii_strcasecmp (row->service, "UDP") != 0) {
			w = g_strdup (_("an offered allow names exactly one protocol, "
			                "TCP or UDP"));
			goto out;
		}
	} else if (row->port != NULL && *row->port != '\0') {
		w = g_strdup (_("a host row takes no port"));
		goto out;
	}

	if (!fs_rule_fields_sane (row)) {
		w = g_strdup (_("its fields would not load back"));
		goto out;
	}

	/* It survives the policy file as it is. */
	{
		gchar *csv = fs_rule_to_csv (row);
		FsRule *back = fs_rule_from_csv (row->kind, csv);
		gboolean same = (back != NULL &&
		                 g_strcmp0 (back->service, row->service) == 0 &&
		                 g_strcmp0 (back->port, row->port) == 0 &&
		                 g_strcmp0 (back->target, row->target) == 0);

		g_free (csv);
		fs_rule_free (back);
		if (!same) {
			w = g_strdup (_("it would not read back the same from the "
			                "policy file"));
			goto out;
		}
	}

	/* Windows compiles it without refusing, and an allow becomes rules
	 * with one protocol and a port. */
	{
		FsPolicy *one = fs_policy_new ();
		GPtrArray *refused = NULL;
		GList *rules;

		fs_policy_add (one, (FsRule *) row);
		rules = fs_fwrule_from_policy_checked (one, &refused);

		if (refused->len > 0)
			w = g_strdup_printf (_("Windows would refuse it: %s"),
			                     (const gchar *) g_ptr_array_index (refused, 0));
		else if (rules == NULL)
			w = g_strdup (_("Windows would get no rule for it"));

		for (GList *l = rules; l != NULL && w == NULL; l = l->next) {
			const FsFwRule *fw = l->data;

			if (allow && ((fw->protocol != FS_PROTO_TCP &&
			               fw->protocol != FS_PROTO_UDP) ||
			              (fw->local_ports == NULL &&
			               fw->remote_ports == NULL)))
				w = g_strdup (_("on Windows it would open more than one "
				                "protocol and port"));
		}

		fs_fwrule_list_free (rules);
		g_ptr_array_unref (refused);
		fs_policy_free (one);
	}

out:
	if (w == NULL)
		return TRUE;
	if (why != NULL)
		*why = w;
	else
		g_free (w);
	return FALSE;
}

/* [ verify_change ]
 * The non-row actions: the question with the change made gets
 * action->gives in every case. */
static gboolean
verify_change (const FsWhatIfContext *ctx, const FsWhatIfQuery *q,
               const FsWhatIfAction *act, gchar **why)
{
	FsWhatIfContext run;
	FsWhatIfQuery *dq;
	FsPolicy *pol = NULL;
	FsSettings *set = NULL;
	gchar *example = NULL;
	guint wrong;

	ctx_running (ctx, &run);

	switch (act->kind) {
	case FS_WHATIF_ACT_LIFT_SENTINEL:
		pol = policy_without_sentinel (ctx->policy, act->target);
		break;
	case FS_WHATIF_ACT_OPEN_RULE:
		pol = policy_without_row (ctx->policy, act->policy_kind,
		                          act->policy_index);
		break;
	case FS_WHATIF_ACT_OPEN_ICMP_SETTINGS:
	case FS_WHATIF_ACT_OPEN_SETTINGS: {
		const Flip *f = flip_find (act->setting);

		if (f == NULL) {
			*why = g_strdup (_("it names no setting"));
			return FALSE;
		}
		set = settings_dup (ctx->settings);
		*flip_field (set, f) = act->setting_on;
		run.settings = set;
		break;
	}
	case FS_WHATIF_ACT_START_FIREWALL:
		break;
	default:
		*why = g_strdup (_("applying the policy changes what is in force, "
		                   "not the answer"));
		return FALSE;
	}

	dq = query_one_way (q, act->inbound);
	wrong = question_check (&run, pol != NULL ? pol : ctx->policy, dq,
	                        act->inbound, act->gives == FS_WHATIF_ALLOWED,
	                        &example);
	if (wrong > 0)
		*why = g_strdup_printf (_("it would still be %s for %s"),
		                        act->gives == FS_WHATIF_ALLOWED
		                        ? _("blocked") : _("allowed"),
		                        example != NULL ? example
		                                        : _("part of the question"));

	g_free (example);
	fs_whatif_query_free (dq);
	fs_policy_free (pol);
	fs_settings_free (set);
	return wrong == 0;
}

static gboolean
action_verify_full (const FsWhatIfContext *ctx, const FsWhatIfQuery *query,
                    const FsWhatIfAction *action, gchar **why, gchar **kept)
{
	gchar *w = NULL;
	gboolean ok;

	if (why != NULL)
		*why = NULL;
	if (kept != NULL)
		*kept = NULL;

	if (ctx == NULL || query == NULL || action == NULL) {
		if (why != NULL)
			*why = g_strdup (_("nothing to check"));
		return FALSE;
	}

	if (action->kind == FS_WHATIF_ACT_CREATE_ALLOW ||
	    action->kind == FS_WHATIF_ACT_CREATE_BLOCK) {
		if (!fs_whatif_row_is_safe (action, &w))
			ok = FALSE;
		else if (ctx->platform == FS_WHATIF_LINUX_FIRST_MATCH &&
		         linux_outbound_service_host (action->row)) {
			w = g_strdup (b6_text ());
			ok = FALSE;
		} else
			ok = verify_create (ctx, query, action, &w, kept);
	} else {
		ok = verify_change (ctx, query, action, &w);
	}

	if (why != NULL)
		*why = w;
	else
		g_free (w);
	return ok;
}

gboolean
fs_whatif_action_verify (const FsWhatIfContext *ctx,
                         const FsWhatIfQuery *query,
                         const FsWhatIfAction *action, gchar **why)
{
	return action_verify_full (ctx, query, action, why, NULL);
}

/* [ create_row ]
 * The one row that would give the question the verdict asked for, as
 * narrow as the question: one protocol and one port for an allow,
 * never a portless or every-port row, and never a row for every host
 * unless the line itself said so ("from anyone", "from the internet").
 * NULL with *why when there is no such row. */
static FsRule *
create_row (const FsWhatIfQuery *q, gboolean inbound, gboolean allow,
            gchar **why)
{
	FsRule *row;
	const gchar *target = q->host != NULL ? q->host : FS_TARGET_ANY;
	gchar *label;

	*why = NULL;

	/* A host the line named but that could not be read: a row for
	 * anyone is not the row that was asked for, in either direction. */
	if (q->host_unread != NULL) {
		*why = g_strdup_printf (_("No rule is offered: \"%s\" is not an "
		                          "address StockFW can read, and a rule "
		                          "for every host is not what was asked. "
		                          "Type its address."), q->host_unread);
		return NULL;
	}

	if (allow) {
		if (q->protocol == FS_WHATIF_PROTO_ICMP || q->icmp_type != NULL)
			return NULL;   /* the ICMP page, not a row */
		if (q->port == 0) {
			*why = g_strdup (_("No rule is offered: the question names no "
			                   "port, and StockFW does not offer a rule "
			                   "that opens every port."));
			return NULL;
		}
		if (q->protocol != FS_WHATIF_PROTO_TCP &&
		    q->protocol != FS_WHATIF_PROTO_UDP) {
			*why = g_strdup_printf (_("No rule is offered: say TCP or UDP "
			                          "(\"tcp %u\"), since an offered "
			                          "allow opens one protocol on one "
			                          "port."), q->port);
			return NULL;
		}
		if (q->host == NULL &&
		    !(q->verb == FS_WHATIF_VERB_ALLOW && q->host_any_said)) {
			*why = g_strdup (inbound
				? _("No rule is offered: the question names no host. "
				    "Say who may connect, for example \"from "
				    "192.168.1.20\" -- or ask to allow it \"from "
				    "anyone\" to open it to every address, the internet "
				    "included.")
				: _("No rule is offered: the question names no host. "
				    "Say where it may go, for example \"to "
				    "203.0.113.9\" -- or ask to allow it \"to "
				    "anywhere\"."));
			return NULL;
		}

		row = fs_rule_new (inbound ? FS_RULE_INBOUND_ALLOW_SERVICE
		                           : FS_RULE_OUTBOUND_ALLOW_SERVICE);
		row->service = g_strdup (q->protocol == FS_WHATIF_PROTO_TCP ? "TCP"
		                                                            : "UDP");
		row->port = g_strdup_printf ("%u", q->port);
		row->target = g_strdup (target);
	} else {
		if (inbound) {
			*why = g_strdup (_("The policy has no inbound block rows: "
			                   "inbound traffic is refused unless a rule "
			                   "or a setting lets it in, so the fix is to "
			                   "change what lets it in."));
			return NULL;
		}

		if (q->port != 0) {
			row = fs_rule_new (FS_RULE_OUTBOUND_DENY_SERVICE);
			row->service = (q->protocol == FS_WHATIF_PROTO_TCP)
				? g_strdup ("TCP")
				: (q->protocol == FS_WHATIF_PROTO_UDP)
				? g_strdup ("UDP")
				: g_strdup_printf ("Port %u", q->port);
			row->port = g_strdup_printf ("%u", q->port);
			row->target = g_strdup (target);
		} else if (q->host != NULL && q->protocol == FS_WHATIF_PROTO_ANY &&
		           q->icmp_type == NULL) {
			row = fs_rule_new (FS_RULE_OUTBOUND_DENY_TO);
			row->target = g_strdup (q->host);
		} else if (q->host != NULL) {
			*why = g_strdup_printf (_("No rule is offered: a policy row "
			                          "cannot block only %s to one host. "
			                          "Ask \"block %s\" to block "
			                          "everything to it."),
			                        q->protocol == FS_WHATIF_PROTO_ICMP
			                        ? _("ICMP")
			                        : q->protocol == FS_WHATIF_PROTO_TCP
			                        ? "TCP" : "UDP", q->host);
			return NULL;
		} else {
			*why = g_strdup (_("No rule is offered: name a port or a "
			                   "host; StockFW does not offer a rule that "
			                   "blocks everything."));
			return NULL;
		}
	}

	label = g_strdup_printf ("What-If: %s %s%s%s", allow ? "allow" : "block",
	                         row->service != NULL ? row->service : "",
	                         row->port != NULL ? " " : "",
	                         row->port != NULL ? row->port : "");
	g_strdelimit (label, ",\"\n\r", ' ');
	row->comment = label;
	return row;
}

static FsWhatIfAction *
action_new (FsWhatIfActionKind kind, gboolean inbound, FsWhatIfVerdict gives)
{
	FsWhatIfAction *a = g_new0 (FsWhatIfAction, 1);

	a->kind = kind;
	a->inbound = inbound;
	a->gives = gives;
	a->policy_kind = -1;
	a->policy_index = -1;
	return a;
}

static const gchar *
kind_words (gint kind)
{
	switch (kind) {
	case FS_RULE_INBOUND_ALLOW_FROM:     return _("Inbound: allow from host");
	case FS_RULE_INBOUND_ALLOW_SERVICE:  return _("Inbound: allow service");
	case FS_RULE_INBOUND_FORWARD:        return _("Inbound: forward");
	case FS_RULE_OUTBOUND_ALLOW_TO:      return _("Outbound: allow to host");
	case FS_RULE_OUTBOUND_ALLOW_FROM:    return _("Outbound: allow from host");
	case FS_RULE_OUTBOUND_ALLOW_SERVICE: return _("Outbound: allow service");
	case FS_RULE_OUTBOUND_DENY_TO:       return _("Outbound: deny to host");
	case FS_RULE_OUTBOUND_DENY_FROM:     return _("Outbound: deny from host");
	case FS_RULE_OUTBOUND_DENY_SERVICE:  return _("Outbound: deny service");
	default:                             return _("Policy");
	}
}

static gchar *
row_words (const FsRule *row)
{
	const gchar *host = fs_util_target_is_anyone (row->target)
	                    ? _("anyone") : row->target;

	switch (row->kind) {
	case FS_RULE_INBOUND_ALLOW_SERVICE:
		return g_strdup_printf (_("inbound %s port %s from %s"),
		                        row->service, row->port, host);
	case FS_RULE_OUTBOUND_ALLOW_SERVICE:
		return g_strdup_printf (_("outbound %s port %s to %s"),
		                        row->service, row->port, host);
	case FS_RULE_OUTBOUND_DENY_SERVICE:
		return g_strdup_printf (_("outbound %s port %s to %s"),
		                        (g_ascii_strcasecmp (row->service, "TCP") == 0 ||
		                         g_ascii_strcasecmp (row->service, "UDP") == 0)
		                        ? row->service : _("TCP and UDP"),
		                        row->port, host);
	default:
		return g_strdup_printf (_("everything outbound to %s"), host);
	}
}

/* Bookkeeping for one answer's fixes. */
typedef struct
{
	gboolean by_default, by_tail, by_settings, by_builtin, by_policy,
	         by_sentinel, icmpish, by_forwarding, by_shields;
	GArray    *rows;        /* gint pairs: kind, index */
	GPtrArray *targets;     /* const gchar*: Sentinel targets */
	const WRule *builtin;
	const WRule *setting;   /* the first settings allow that decided */
} Causes;

static void
causes_collect (Model *m, GArray *ev, gboolean want_allowed, Causes *k)
{
	memset (k, 0, sizeof *k);
	k->rows = g_array_new (FALSE, FALSE, sizeof (gint));
	k->targets = g_ptr_array_new ();

	for (guint i = 0; i < ev->len; i++) {
		const Eval *e = &g_array_index (ev, Eval, i);
		const WRule *r = e->o.rule;

		if (e->o.allowed == want_allowed)
			continue;
		/* An ICMP reply nothing asked for is dropped as invalid by
		 * the connection tracker; no row or setting changes that, and
		 * it is not what a fix is for. */
		if (e->ix[D_STATE] != 0)
			continue;

		switch (e->o.origin) {
		case FS_WHATIF_ORIGIN_DEFAULT:
			k->by_default = TRUE;
			break;

		case FS_WHATIF_ORIGIN_POLICY: {
			gboolean seen = FALSE;

			k->by_policy = TRUE;
			if (r == NULL || r->pkind < 0)
				break;
			for (guint n = 0; n + 1 < k->rows->len && !seen; n += 2)
				seen = g_array_index (k->rows, gint, n) == r->pkind &&
				       g_array_index (k->rows, gint, n + 1) == r->prow;
			if (!seen) {
				g_array_append_val (k->rows, r->pkind);
				g_array_append_val (k->rows, r->prow);
			}
			break;
		}

		case FS_WHATIF_ORIGIN_SENTINEL: {
			const gchar *t = rule_row_target (m, r);
			gboolean seen = FALSE;

			k->by_sentinel = TRUE;
			for (guint n = 0; t != NULL && n < k->targets->len && !seen; n++)
				seen = g_ascii_strcasecmp (g_ptr_array_index (k->targets, n),
				                           t) == 0;
			if (t != NULL && !seen)
				g_ptr_array_add (k->targets, (gpointer) t);
			break;
		}

		case FS_WHATIF_ORIGIN_SETTINGS:
			/* IP forwarding being off, and Windows' "Block all
			 * incoming connections", are not rows or checkboxes a fix
			 * can name here: each gets its own note. */
			if (r != NULL && r == m->fwd_gate) {
				k->by_forwarding = TRUE;
				break;
			}
			if (r != NULL && (r == m->win_shields[0] ||
			                  r == m->win_shields[1] ||
			                  r == m->win_shields[2])) {
				k->by_shields = TRUE;
				break;
			}
			/* A settings drop (reserved sources, broadcasts) is the
			 * background the user chose; a settings allow (ICMP) is
			 * something to change. */
			if (!e->o.allowed) {
				k->by_tail = TRUE;
			} else {
				k->by_settings = TRUE;
				if (k->setting == NULL)
					k->setting = r;
			}
			if (r != NULL && (r->proto == P_ICMP ||
			                  (r->dport != NULL &&
			                   strcmp (r->dport, "33434") == 0)))
				k->icmpish = TRUE;
			break;

		case FS_WHATIF_ORIGIN_BUILTIN:
			k->by_builtin = TRUE;
			if (k->builtin == NULL)
				k->builtin = r;
			break;

		default:
			break;
		}
	}
}

static void
causes_clear (Causes *k)
{
	g_array_unref (k->rows);
	g_ptr_array_unref (k->targets);
}

/* [ running_verdict ]
 * The question, one direction, once the firewall (and every profile)
 * runs: ALLOWED, BLOCKED, or DEPENDS when its cases disagree. */
static FsWhatIfVerdict
running_verdict (const FsWhatIfContext *ctx, const FsWhatIfQuery *q,
                 gboolean inbound)
{
	FsWhatIfContext run;
	Model *m;
	Cands c;
	GArray *ev;
	guint yes = 0, no = 0;

	ctx_running (ctx, &run);
	m = model_build (&run, ctx->policy);
	cands_build (m, q, inbound, &c);
	ev = evaluate_all (m, &c, inbound);

	for (guint i = 0; i < ev->len; i++) {
		if (g_array_index (ev, Eval, i).o.allowed)
			yes++;
		else
			no++;
	}

	g_array_unref (ev);
	cands_free (&c);
	model_free (m);

	if (yes == 0 && no == 0)
		return FS_WHATIF_ERROR;
	return no == 0 ? FS_WHATIF_ALLOWED
	     : yes == 0 ? FS_WHATIF_BLOCKED : FS_WHATIF_DEPENDS;
}

static const gchar *
verdict_words (FsWhatIfVerdict v)
{
	switch (v) {
	case FS_WHATIF_ALLOWED: return _("allowed");
	case FS_WHATIF_BLOCKED: return _("blocked");
	case FS_WHATIF_DEPENDS: return _("allowed in some cases and blocked "
	                                 "in others");
	default:                return _("not known");
	}
}

/* [ answer_actions ]
 * What would give the user what they asked for, each re-simulated. */
static void
answer_actions (const FsWhatIfContext *ctx, Model *m, const FsWhatIfQuery *q,
                gboolean inbound, FsWhatIfAnswer *ans, GArray *evals,
                FsWhatIfResult *res, gboolean first_answer)
{
	gboolean want_allowed = (q->verb != FS_WHATIF_VERB_BLOCK);
	FsWhatIfVerdict want = want_allowed ? FS_WHATIF_ALLOWED
	                                    : FS_WHATIF_BLOCKED;
	GPtrArray *create = g_ptr_array_new ();
	GPtrArray *lift = g_ptr_array_new ();
	GPtrArray *open = g_ptr_array_new ();
	GPtrArray *sett = g_ptr_array_new ();
	GPtrArray *start = g_ptr_array_new ();
	GPtrArray *lists[5];
	gchar *why = NULL;
	gboolean stopped = FALSE;
	gboolean whole;
	FsWhatIfVerdict judged = ans->verdict;
	gboolean reply_type = (q->icmp_type != NULL &&
	                       icmp_is_reply (q->icmp_type));

	lists[0] = create; lists[1] = lift; lists[2] = open;
	lists[3] = sett; lists[4] = start;

	for (guint i = 0; i < evals->len; i++)
		if (g_array_index (evals, Eval, i).o.origin ==
		    FS_WHATIF_ORIGIN_STOPPED)
			stopped = TRUE;
	whole = (ctx->firewall == FS_WHATIF_FW_STOPPED);

	/* With the firewall off, "allowed" is only the firewall being off:
	 * what to change is judged by what the rules do once it runs. */
	if (stopped)
		judged = running_verdict (ctx, q, inbound);

	/* Starting the firewall: for a block, it is (part of) the fix; for
	 * a plain question whose answer is "allowed" only because nothing
	 * is filtered, it is what makes the rules decide. */
	if (stopped && (q->verb == FS_WHATIF_VERB_BLOCK ||
	                (q->verb == FS_WHATIF_VERB_NONE &&
	                 judged != FS_WHATIF_ALLOWED))) {
		FsWhatIfAction *a = action_new (FS_WHATIF_ACT_START_FIREWALL,
		                                inbound, want);
		const gchar *off = whole
			? _("The firewall is not running, so nothing is filtered.")
			: _("Windows Firewall is off for a network profile in use, "
			    "so nothing is filtered there.");

		a->label = g_strdup (whole ? _("Start the firewall")
		                           : _("Turn Windows Firewall on"));
		if (q->verb == FS_WHATIF_VERB_BLOCK) {
			a->verified = verify_change (ctx, q, a, &why);
			a->explanation = a->verified
				? g_strdup_printf (_("%s Once it runs, this is blocked."),
				                   off)
				: g_strdup_printf (_("%s Even once it runs, %s."), off,
				                   why);
		} else {
			/* Not a change to check: this is the simulation of the
			 * rules themselves. */
			a->gives = judged;
			a->verified = (judged != FS_WHATIF_ERROR);
			a->explanation = g_strdup_printf (
				_("%s This is allowed only because of that. Once it "
				  "runs, the rules decide: this is %s."), off,
				verdict_words (judged));
		}
		g_clear_pointer (&why, g_free);
		g_ptr_array_add (start, a);
	}

	if (judged != want &&
	    !(q->verb == FS_WHATIF_VERB_NONE && judged == FS_WHATIF_ALLOWED)) {
		FsWhatIfContext run;
		Model *rm;
		Cands c;
		GArray *ev;
		Causes k;
		const gchar *once = stopped ? _(" once the firewall runs") : "";

		/* What decides once the firewall runs. */
		ctx_running (ctx, &run);
		rm = model_build (&run, m->policy);
		cands_build (rm, q, inbound, &c);
		ev = evaluate_all (rm, &c, inbound);
		causes_collect (rm, ev, want_allowed, &k);

		/* A new row. */
		if (want_allowed) {
			/* A new allow helps only where the default decided.  On
			 * Linux the reserved-source and broadcast drops sit after
			 * every allow, so they are the default by another name;
			 * on Windows such a setting blocks whatever a rule allows,
			 * and a row could change nothing there -- the setting is
			 * the fix (offered below). */
			gboolean eligible = !k.by_policy && !k.by_sentinel &&
			                    !k.by_settings && !k.by_builtin &&
			                    !k.by_forwarding && !k.by_shields &&
			                    (k.by_default ||
			                     (k.by_tail && m->platform ==
			                                   FS_WHATIF_LINUX_FIRST_MATCH));

			if (eligible) {
				FsRule *row = create_row (q, inbound, TRUE, &why);

				if (row == NULL) {
					if (why != NULL)
						note_add (res->notes, why);
					why = NULL;
				} else if (ctx->platform == FS_WHATIF_LINUX_FIRST_MATCH &&
				           linux_outbound_service_host (row)) {
					note_add (res->notes, g_strdup (b6_text ()));
					note_add (res->notes, g_strdup (
						_("So no rule is offered for one port to one "
						  "host here.")));
					fs_rule_free (row);
				} else {
					FsWhatIfAction *a = action_new (
						FS_WHATIF_ACT_CREATE_ALLOW, inbound, want);
					gchar *words = row_words (row);
					gboolean anyone = fs_util_target_is_anyone (row->target);
					gchar *kept = NULL;

					a->row = row;
					a->verified = action_verify_full (ctx, q, a, &why,
					                                  &kept);
					if (a->verified) {
						GString *e = g_string_new (NULL);

						/* Allowed except where a setting still blocks
						 * it is not plain ALLOWED. */
						if (kept != NULL)
							a->gives = FS_WHATIF_DEPENDS;
						a->label = anyone
							? g_strdup_printf (_("Allow %s (every "
							                     "address, the internet "
							                     "included)"), words)
							: g_strdup_printf (_("Allow %s"), words);
						g_string_append_printf (e,
							_("Adds one row to the policy (%s): %s. "
							  "Checked: with it this question is "
							  "allowed%s%s%s, and nothing else "
							  "changes."),
							kind_words (row->kind), words, once,
							kept != NULL ? " " : "",
							kept != NULL ? kept : "");
						if (anyone)
							g_string_append_printf (e,
								_(" Careful: it opens %s port %s to "
								  "every address, the internet "
								  "included."),
								row->service, row->port);
						if (inbound && ctx->platform ==
						    FS_WHATIF_LINUX_FIRST_MATCH)
							g_string_append (e,
								_(" On Linux the row also applies to "
								  "traffic this computer forwards to "
								  "other machines."));
						a->explanation = g_string_free (e, FALSE);
						g_ptr_array_add (create, a);
					} else {
						note_add (res->notes, g_strdup_printf (
							_("A rule allowing %s was considered and not "
							  "offered: %s."), words, why));
						action_free (a);
					}
					g_clear_pointer (&why, g_free);
					g_free (kept);
					g_free (words);
				}
			} else if ((k.by_default || k.by_tail) &&
			           (k.by_policy || k.by_sentinel)) {
				note_add (res->notes, g_strdup (
					_("No allow rule is offered: a block rule decides "
					  "part of this, and an allow added next to it would "
					  "be overruled or would hide it. Change the block "
					  "instead.")));
			}
		} else {
			FsRule *row = create_row (q, inbound, FALSE, &why);

			if (row == NULL) {
				if (why != NULL)
					note_add (res->notes, why);
				why = NULL;
			} else if (ctx->platform == FS_WHATIF_LINUX_FIRST_MATCH &&
			           linux_outbound_service_host (row)) {
				note_add (res->notes, g_strdup (b6_text ()));
				note_add (res->notes, g_strdup (
					_("So no rule is offered for one port to one host "
					  "here.")));
				fs_rule_free (row);
			} else {
				FsWhatIfAction *a = action_new (FS_WHATIF_ACT_CREATE_BLOCK,
				                                inbound, want);
				gchar *words = row_words (row);

				a->row = row;
				a->verified = fs_whatif_action_verify (ctx, q, a, &why);
				if (a->verified) {
					a->label = g_strdup_printf (_("Block %s"), words);
					a->explanation = g_strdup_printf (
						_("Adds one row to the policy (%s): %s. Checked: "
						  "with it this question is blocked%s, and "
						  "nothing else changes."),
						kind_words (row->kind), words, once);
					g_ptr_array_add (create, a);
				} else {
					note_add (res->notes, g_strdup_printf (
						_("A rule blocking %s was considered and not "
						  "offered: %s."), words, why));
					action_free (a);
				}
				g_clear_pointer (&why, g_free);
				g_free (words);
			}
		}

		/* Sentinel's blocks. */
		for (guint i = 0; i < k.targets->len; i++) {
			const gchar *t = g_ptr_array_index (k.targets, i);
			FsWhatIfAction *a = action_new (FS_WHATIF_ACT_LIFT_SENTINEL,
			                                inbound, want);
			gchar *when = sentinel_expiry (ctx, t, &a->expires_unix);

			a->target = g_strdup (t);
			a->label = g_strdup_printf (_("Lift Sentinel's block of %s"), t);
			a->verified = verify_change (ctx, q, a, &why);
			a->explanation = g_strdup_printf (
				_("Sentinel blocked %s automatically%s%s. %s"), t,
				when != NULL ? "; " : "", when != NULL ? when : "",
				a->verified ? _("Lifting it now lets this through.")
				            : why);
			g_clear_pointer (&why, g_free);
			g_free (when);
			g_ptr_array_add (lift, a);
		}

		/* The policy rows that decide. */
		for (guint n = 0; n + 1 < k.rows->len && n < 8; n += 2) {
			gint kind = g_array_index (k.rows, gint, n);
			gint idx = g_array_index (k.rows, gint, n + 1);
			const FsRule *row = g_ptr_array_index (m->policy->kinds[kind],
			                                       (guint) idx);
			FsWhatIfAction *a = action_new (FS_WHATIF_ACT_OPEN_RULE, inbound,
			                                want);
			gchar *name = fs_fwrule_default_name (
				kind <= FS_RULE_INBOUND_FORWARD ? FS_DIR_INBOUND
				                                : FS_DIR_OUTBOUND,
				(kind >= FS_RULE_OUTBOUND_DENY_TO) ? FS_ACTION_BLOCK
				                                   : FS_ACTION_ALLOW,
				row->service, row->target);

			a->policy_kind = kind;
			a->policy_index = idx;
			a->label = g_strdup_printf (_("Open rule '%s'"), name);
			a->verified = verify_change (ctx, q, a, &why);
			a->explanation = g_strdup_printf (
				_("Rule '%s' (%s, row %d) %s it. Edit or remove it on the "
				  "Policy page. %s"), name, kind_words (kind), idx + 1,
				want_allowed ? _("blocks") : _("allows"),
				a->verified
				? (want_allowed ? _("Without it, this is allowed.")
				                : _("Without it, this is blocked."))
				: _("Removing it alone is not enough."));
			g_clear_pointer (&why, g_free);
			g_free (name);
			g_ptr_array_add (open, a);
		}

		/* A Preferences checkbox -- but not for an ICMP reply or error:
		 * what answers this computer's own traffic already comes back,
		 * and the setting would also let in unsolicited ones. */
		if (reply_type && want_allowed &&
		    (k.by_default || k.by_settings || k.by_tail || k.by_builtin)) {
			note_add (res->notes, g_strdup (
				_("A reply or an error that answers traffic this computer "
				  "sent is let back in as return traffic. The ICMP "
				  "settings would also let in ones nothing here asked "
				  "for, so none is offered for this.")));
		} else if (k.by_settings || k.by_tail ||
		           (k.by_default && (q->protocol == FS_WHATIF_PROTO_ICMP ||
		                             q->icmp_type != NULL))) {
			gboolean icmp = k.icmpish || q->protocol == FS_WHATIF_PROTO_ICMP ||
			                q->icmp_type != NULL;
			gboolean found = FALSE;

			for (guint i = 0; i < G_N_ELEMENTS (flips) && !found; i++) {
				const Flip *f = &flips[i];
				const FsSettings *s = rm->settings;
				gboolean now_on = *flip_field ((FsSettings *) s, f);
				FsWhatIfAction *a;
				const gchar *scope;

				if (f->icmp != icmp ||
				    !flip_offered (f, ctx->platform))
					continue;

				a = action_new (f->icmp ? FS_WHATIF_ACT_OPEN_ICMP_SETTINGS
				                        : FS_WHATIF_ACT_OPEN_SETTINGS,
				                inbound, want);
				a->setting = g_strdup (f->key);
				a->setting_on = !now_on;
				a->page = g_strdup (f->page);
				a->verified = verify_change (ctx, q, a, &why);
				g_clear_pointer (&why, g_free);

				if (!a->verified) {
					action_free (a);
					continue;
				}

				/* Turning ICMP filtering back on filters every kind;
				 * turning it off lets every kind in. */
				scope = (strcmp (f->key, "filter_icmp") == 0 &&
				         a->setting_on)
					? _("It filters every kind of ICMP again, for every "
					    "host.")
					: _(f->scope);
				found = TRUE;
				a->label = g_strdup (f->icmp ? _("Open ICMP settings")
				                             : _("Open Protection settings"));
				a->explanation = g_strdup_printf (
					_("Turn %s '%s' on %s. %s Checked: then this "
					  "question is %s."),
					a->setting_on ? _("on") : _("off"), _(f->label),
					_(f->where), scope,
					want_allowed ? _("allowed") : _("blocked"));
				g_ptr_array_add (sett, a);
			}

			if (!found && k.by_settings && k.setting != NULL)
				note_add (res->notes, g_strdup_printf (
					_("The setting '%s' decides part of this, and no "
					  "single Preferences change gives the whole "
					  "question the answer you asked for."),
					k.setting->name));
		}

		if (k.by_builtin && k.builtin != NULL && !reply_type)
			note_add (res->notes, g_strdup_printf (
				_("'%s' is built in: StockFW keeps it so the computer "
				  "keeps working, and no rule or setting changes it."),
				k.builtin->name));

		if (k.by_forwarding && want_allowed)
			note_add (res->notes, g_strdup (
				_("A port forward to another computer needs IP "
				  "forwarding. StockFW turns it on only in router mode "
				  "('Enable Internet connection sharing' on Preferences > "
				  "Firewall > Network Settings); without it the forward "
				  "goes nowhere unless another program turned forwarding "
				  "on.")));

		if (k.by_shields && want_allowed)
			note_add (res->notes, g_strdup (
				_("'Block all incoming connections' is on in Windows "
				  "Firewall, so no allow rule can let this in. Turn it "
				  "off in Windows Security > Firewall & network "
				  "protection for the network in use to let the rules "
				  "decide.")));

		if (inbound && !want_allowed && k.by_default &&
		    m->platform == FS_WHATIF_WINDOWS_BLOCK_WINS)
			note_add (res->notes, g_strdup (
				_("A network profile's default inbound action is Allow. "
				  "Set it to Block in Windows Firewall to refuse what no "
				  "rule allows.")));

		causes_clear (&k);
		g_array_unref (ev);
		cands_free (&c);
		model_free (rm);
	}

	for (guint l = 0; l < G_N_ELEMENTS (lists); l++) {
		for (guint i = 0; i < lists[l]->len; i++)
			g_ptr_array_add (ans->actions, g_ptr_array_index (lists[l], i));
		g_ptr_array_unref (lists[l]);
	}

	/* The saved policy is not the one in force.  Applying it is a fix
	 * only when an apply can go through: with applies on hold (audit-
	 * only testing, the Policy Lock) the apply gate would hold it back
	 * again, and the hold's own note says what lifts it. */
	if (first_answer && (ctx->live == FS_WHATIF_LIVE_FAILED ||
	                     ctx->live == FS_WHATIF_LIVE_STALE)) {
		FsWhatIfAction *a = action_new (FS_WHATIF_ACT_APPLY_POLICY, inbound,
		                                ans->verdict);

		a->label = g_strdup (_("Apply the policy"));
		a->explanation = g_strdup (
			ctx->live == FS_WHATIF_LIVE_FAILED
			? _("The last apply failed, so the rules in force are not the "
			    "saved policy this answer describes.")
			: _("The policy changed after it was last applied, so the "
			    "rules in force are not the saved policy this answer "
			    "describes."));
		g_ptr_array_add (ans->actions, a);
	}
}

/* ================================================================
 * One direction's answer
 * ================================================================ */

/* Did the question leave anything open that the stand-in had to fill
 * in?  ICMP types only count when ICMP is in play, ports only when TCP
 * or UDP is. */
static gboolean
cands_any_open (const Cands *c)
{
	gboolean icmp = FALSE, other = FALSE;

	for (guint i = 0; i < c->protos->len; i++) {
		if (g_array_index (c->protos, gint, i) == P_ICMP)
			icmp = TRUE;
		else
			other = TRUE;
	}

	for (gint d = 0; d < D_N; d++) {
		if (dim_len (c, d) <= 1)
			continue;
		if ((d == D_ICMP && !icmp) || (d == D_PORT && !other))
			continue;
		return TRUE;
	}
	return FALSE;
}

/* Linux outbound service rows that name a host: worth a note, since
 * the generator matches that host as the source (see b6_text). */
static gboolean
model_has_outbound_service_host (const Model *m)
{
	static const FsRuleKind kinds[] = {
		FS_RULE_OUTBOUND_ALLOW_SERVICE, FS_RULE_OUTBOUND_DENY_SERVICE
	};

	for (guint k = 0; k < G_N_ELEMENTS (kinds); k++) {
		GPtrArray *rows = m->policy->kinds[kinds[k]];

		for (guint i = 0; i < rows->len; i++)
			if (linux_outbound_service_host (g_ptr_array_index (rows, i)))
				return TRUE;
	}
	return FALSE;
}

/* [ uniform_reason ]
 * Every case got the same verdict.  When one rule (or the default)
 * decided them all, its reason; when different ones did, each with
 * where it applies, so "blocked" does not hide which block it was. */
static gchar *
uniform_reason (Model *m, const Cands *c, GArray *ev, const FsWhatIfQuery *q,
                gboolean inbound)
{
	const Eval *base = &g_array_index (ev, Eval, 0);
	GPtrArray *groups = g_ptr_array_new_with_free_func (group_free);
	GString *s;
	gboolean dist[D_N];
	GPtrArray *conds;
	gchar *text;

	for (guint i = 0; i < ev->len; i++) {
		const Eval *e = &g_array_index (ev, Eval, i);
		Group *g = NULL;

		for (guint k = 0; k < groups->len && g == NULL; k++)
			if (group_takes (g_ptr_array_index (groups, k), &e->o))
				g = g_ptr_array_index (groups, k);

		if (g == NULL) {
			g = g_new0 (Group, 1);
			g->allowed = e->o.allowed;
			g->origin = group_origin (&e->o);
			g->rule = (g->origin == e->o.origin) ? e->o.rule : NULL;
			g->members = g_array_new (FALSE, FALSE, sizeof (guint));
			g_ptr_array_add (groups, g);
		}
		g_array_append_val (g->members, i);
		if (g->rule != NULL)
			group_name_add (g, e->o.rule);
	}

	if (groups->len <= 1) {
		g_ptr_array_unref (groups);
		return outcome_reason (m, &base->o, inbound);
	}

	memset (dist, 0, sizeof dist);
	conds = g_ptr_array_new_with_free_func (g_free);
	g_ptr_array_add (conds, NULL);
	for (guint i = 1; i < groups->len; i++)
		g_ptr_array_add (conds, group_condition (
			m, c, ev, g_ptr_array_index (groups, i), inbound, dist));
	g_ptr_array_index (conds, 0) = base_condition (m, c, q, dist, inbound);

	s = g_string_new (base->o.allowed ? _("Allowed in every case:")
	                                  : _("Blocked in every case:"));

	for (guint i = 0; i < groups->len && i <= MAX_CASES; i++) {
		const Group *g = g_ptr_array_index (groups, i);
		const gchar *cond = g_ptr_array_index (conds, i);
		gchar *by = by_text (m, g->origin, g->rule, g->name);

		g_string_append_printf (s, "%s %s %s", i == 0 ? "" : ";", by,
		                        cond != NULL ? cond
		                        : _("in every other case"));
		g_free (by);
	}

	g_ptr_array_unref (conds);
	g_string_append_c (s, '.');
	text = g_string_free (s, FALSE);
	g_ptr_array_unref (groups);
	return text;
}

static FsWhatIfAnswer *
answer_build (const FsWhatIfContext *ctx, Model *m, const FsWhatIfQuery *q,
              gboolean inbound, FsWhatIfResult *res, gboolean first)
{
	FsWhatIfAnswer *ans = answer_new (inbound);
	Cands c;
	GArray *ev;
	GPtrArray *groups;
	const Eval *base;
	gboolean assumed = FALSE;

	cands_build (m, q, inbound, &c);
	ev = evaluate_all (m, &c, inbound);
	ans->probe = query_text (q, inbound);

	if (ev->len == 0) {
		ans->verdict = FS_WHATIF_ERROR;
		ans->reason = g_strdup (_("Nothing could be checked for this "
		                          "question."));
		g_array_unref (ev);
		cands_free (&c);
		return ans;
	}

	base = &g_array_index (ev, Eval, 0);
	groups = g_ptr_array_new_with_free_func (group_free);

	for (guint i = 0; i < ev->len; i++) {
		const Eval *e = &g_array_index (ev, Eval, i);
		Group *g = NULL;

		assumed = assumed || e->o.assumed;
		if (e->o.allowed == base->o.allowed)
			continue;

		for (guint k = 0; k < groups->len && g == NULL; k++)
			if (group_takes (g_ptr_array_index (groups, k), &e->o))
				g = g_ptr_array_index (groups, k);

		if (g == NULL) {
			g = g_new0 (Group, 1);
			g->allowed = e->o.allowed;
			g->origin = group_origin (&e->o);
			g->rule = (g->origin == e->o.origin) ? e->o.rule : NULL;
			g->members = g_array_new (FALSE, FALSE, sizeof (guint));
			g_ptr_array_add (groups, g);
		}
		g_array_append_val (g->members, i);
		if (g->rule != NULL)
			group_name_add (g, e->o.rule);
	}

	/* The trace: the common case, step by step. */
	{
		Probe p;
		gint decided = -1;

		probe_fill (m, &c, inbound, base->ix, &p);
		if (cands_any_open (&c)) {
			gchar *t = probe_text (&p);

			step_note (ans->steps, FS_WHATIF_ORIGIN_BUILTIN, NULL,
			           g_strdup_printf (_("Shown for one example of what the "
			                              "question left open: %s. Any other "
			                              "address or port that no rule "
			                              "names gets the same answer."), t));
			g_free (t);
		}
		eval_probe (m, &p, &decided, ans->steps);
		ans->decided_by = decided;
	}

	ans->origin = base->o.origin;
	ans->rule = g_strdup (base->o.rule != NULL ? base->o.rule->name : NULL);
	ans->policy_kind = base->o.rule != NULL ? base->o.rule->pkind : -1;
	ans->policy_index = base->o.rule != NULL ? base->o.rule->prow : -1;

	if (groups->len == 0) {
		ans->verdict = base->o.allowed ? FS_WHATIF_ALLOWED : FS_WHATIF_BLOCKED;
		ans->reason = uniform_reason (m, &c, ev, q, inbound);
	} else {
		gboolean dist[D_N];
		GString *s = g_string_new (NULL);
		GPtrArray *conds = g_ptr_array_new_with_free_func (g_free);
		FsWhatIfCase *k;

		ans->verdict = FS_WHATIF_DEPENDS;
		memset (dist, 0, sizeof dist);

		for (guint i = 0; i < groups->len; i++)
			g_ptr_array_add (conds, group_condition (
				m, &c, ev, g_ptr_array_index (groups, i), inbound, dist));

		gchar *base_cond = base_condition (m, &c, q, dist, inbound);
		gchar *base_by = (base->o.origin != FS_WHATIF_ORIGIN_DEFAULT)
		                 ? by_text (m, base->o.origin, base->o.rule, NULL)
		                 : NULL;
		gchar *base_text;

		k = case_new (base->o.allowed ? FS_WHATIF_ALLOWED : FS_WHATIF_BLOCKED,
		              g_strdup (base_cond != NULL ? base_cond
		                        : _("in every other case")),
		              base->o.origin, base->o.rule);
		g_ptr_array_add (ans->cases, k);
		base_text = g_strdup_printf ("%s %s%s%s",
		                             base->o.allowed ? _("allowed")
		                                             : _("blocked"),
		                             k->condition, base_by ? " " : "",
		                             base_by ? base_by : "");

		/* The common case first when one thing sets the others apart
		 * ("Allowed for most hosts; blocked for 203.0.113.0/24 ..."),
		 * last when it is just everything else. */
		if (base_cond != NULL)
			g_string_append (s, base_text);

		for (guint i = 0; i < groups->len; i++) {
			const Group *g = g_ptr_array_index (groups, i);
			gchar *by;

			k = case_new (g->allowed ? FS_WHATIF_ALLOWED : FS_WHATIF_BLOCKED,
			              g_strdup (g_ptr_array_index (conds, i)),
			              g->origin, g->rule);
			if (g->name != NULL) {
				g_free (k->rule);
				k->rule = g_strdup (g->name);
			}
			g_ptr_array_add (ans->cases, k);

			if (i >= MAX_CASES)
				continue;

			by = by_text (m, g->origin, g->rule, g->name);
			g_string_append_printf (s, "%s%s %s %s", s->len ? "; " : "",
			                        g->allowed ? _("allowed") : _("blocked"),
			                        k->condition, by);
			g_free (by);
		}

		if (groups->len == MAX_CASES + 1)
			g_string_append (s, _("; and 1 more case"));
		else if (groups->len > MAX_CASES)
			g_string_append_printf (s, _("; and %u more cases"),
			                        groups->len - MAX_CASES);
		if (base_cond == NULL)
			g_string_append_printf (s, "; %s", base_text);
		g_string_append_c (s, '.');
		s->str[0] = g_ascii_toupper (s->str[0]);
		g_free (base_cond);
		g_free (base_by);
		g_free (base_text);
		ans->reason = g_string_free (s, FALSE);
		g_ptr_array_unref (conds);
	}

	/* What the answer rests on. */
	if (q->verb == FS_WHATIF_VERB_BLOCK && c.n_state > 1 &&
	    q->icmp_type == NULL)
		note_add (res->notes, g_strdup (
			_("ICMP replies and errors that answer traffic already let "
			  "through still pass: they follow that traffic, and no "
			  "rule blocks them.")));
	if (first && q->host_unread != NULL)
		note_add (res->notes, g_strdup_printf (
			_("\"%s\" is not an address StockFW can read, so it was not "
			  "looked up: this is the answer for every host."),
			q->host_unread));
	if (c.capped)
		note_add (res->notes, g_strdup (
			_("The question left so much open that only part of it was "
			  "checked. Name a port or a host for a complete answer.")));
	if (assumed)
		note_add (res->notes, g_strdup (
			_("StockFW could not read the network profile's default "
			  "action, so Windows' own default was assumed: block "
			  "inbound, allow outbound.")));
	if (base->o.rule != NULL && base->o.rule->limit != NULL &&
	    base->o.allowed && base->o.rule->target == T_ACCEPT)
		note_add (res->notes, g_strdup_printf (
			_("'%s' lets at most %s through; above that rate the rest "
			  "falls to the rules after it."), base->o.rule->name,
			base->o.rule->limit));
	if (!inbound && m->platform == FS_WHATIF_LINUX_FIRST_MATCH &&
	    model_has_outbound_service_host (m))
		note_add (res->notes, g_strdup (b6_text ()));

	answer_actions (ctx, m, q, inbound, ans, ev, res, first);

	g_ptr_array_unref (groups);
	g_array_unref (ev);
	cands_free (&c);
	return ans;
}

static void
context_notes (const FsWhatIfContext *ctx, const Model *m,
               FsWhatIfResult *res)
{
	for (guint i = 0; i < m->notes->len; i++)
		note_add (res->notes, g_strdup (g_ptr_array_index (m->notes, i)));

	if (ctx->platform != fs_whatif_native_platform ())
		note_add (res->notes, g_strdup (
			ctx->platform == FS_WHATIF_LINUX_FIRST_MATCH
			? _("Answered for the Linux firewall: the first matching "
			    "rule decides.")
			: _("Answered for Windows Firewall: a matching block rule "
			    "wins over any allow.")));

	if (ctx->policy == NULL)
		note_add (res->notes, g_strdup (
			_("No policy is loaded: this is the answer for an empty "
			  "policy.")));

	if (ctx->firewall == FS_WHATIF_FW_UNKNOWN)
		note_add (res->notes, g_strdup (
			_("StockFW could not tell whether the firewall is running; "
			  "the answer assumes it is.")));

	if (ctx->platform == FS_WHATIF_LINUX_FIRST_MATCH)
		note_add (res->notes, g_strdup (
			_("Only StockFW's own rules are known here: rules other "
			  "programs (container or VM tools, fail2ban) put ahead of "
			  "StockFW's can also allow or block this.")));

	if (ctx->platform == FS_WHATIF_WINDOWS_BLOCK_WINS) {
		note_add (res->notes, g_strdup (
			_("Only the rules StockFW manages are known here: other "
			  "Windows Firewall rules (from Windows itself or other "
			  "programs) can also allow or block this.")));
		if (ctx->profiles_in_use == 0)
			note_add (res->notes, g_strdup (
				_("StockFW could not tell which network profile is in "
				  "use, so every profile was considered.")));
	} else if (m->ext == NULL && (m->settings->block_non_routables ||
	                              m->settings->block_external_broadcast)) {
		note_add (res->notes, g_strdup (
			_("No valid internet-facing interface is set, so the "
			  "reserved-address and broadcast blocks are not in "
			  "force.")));
	}

	switch (ctx->live) {
	case FS_WHATIF_LIVE_HELD:
		note_add (res->notes, ctx->live_detail != NULL
			? g_strdup_printf (_("Applies are on hold (%s): the rules in "
			                     "force may be older than the saved "
			                     "policy this answer describes."),
			                   ctx->live_detail)
			: g_strdup (_("Applies are on hold: the rules in force may be "
			              "older than the saved policy this answer "
			              "describes.")));
		break;
	case FS_WHATIF_LIVE_FAILED:
		note_add (res->notes, g_strdup (
			_("The last apply failed: the rules in force are not the "
			  "saved policy this answer describes.")));
		break;
	case FS_WHATIF_LIVE_STALE:
		note_add (res->notes, g_strdup (
			_("The policy changed after it was last applied: this answer "
			  "describes the saved policy, not the rules in force.")));
		break;
	case FS_WHATIF_LIVE_UNKNOWN:
		note_add (res->notes, g_strdup (
			_("StockFW has no record that this policy was applied: the "
			  "answer describes the saved policy.")));
		break;
	default:
		break;
	}
}

static gchar *
result_summary (const FsWhatIfContext *ctx, const FsWhatIfQuery *q,
                const FsWhatIfResult *r)
{
	GString *s = g_string_new (NULL);
	/* "Already" and "currently" claim what the computer does now; that
	 * is only true when the saved policy is what is in force. */
	gboolean saved_only = r->stopped_decides ||
	                      ctx->live == FS_WHATIF_LIVE_HELD ||
	                      ctx->live == FS_WHATIF_LIVE_FAILED ||
	                      ctx->live == FS_WHATIF_LIVE_STALE;
	FsWhatIfVerdict want = (q->verb == FS_WHATIF_VERB_BLOCK)
	                       ? FS_WHATIF_BLOCKED : FS_WHATIF_ALLOWED;

	if (q->verb == FS_WHATIF_VERB_BLOCK)
		g_string_append (s, _("You asked to block this. "));
	else if (q->verb == FS_WHATIF_VERB_ALLOW)
		g_string_append (s, _("You asked to allow this. "));

	for (guint i = 0; i < r->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);
		const gchar *v = fs_whatif_verdict_name (a->verdict);

		if (i > 0)
			g_string_append_c (s, ' ');
		if (r->answers->len > 1)
			g_string_append (s, a->inbound ? _("Inbound: ") : _("Outbound: "));

		if (q->verb == FS_WHATIF_VERB_NONE)
			g_string_append_printf (s, "%s. %s", v, a->reason);
		else if (r->stopped_decides)
			g_string_append_printf (s, _("With the firewall off it is %s. "
			                             "%s"), v, a->reason);
		else if (saved_only)
			g_string_append_printf (s, _("The saved policy has it %s. %s"),
			                        v, a->reason);
		else if (a->verdict == want)
			g_string_append_printf (s, _("It is already %s. %s"), v,
			                        a->reason);
		else if (a->verdict == FS_WHATIF_DEPENDS)
			g_string_append_printf (s, _("It is only partly %s now. %s"),
			                        want == FS_WHATIF_ALLOWED ? _("allowed")
			                                                  : _("blocked"),
			                        a->reason);
		else
			g_string_append_printf (s, _("It is currently %s. %s"), v,
			                        a->reason);
	}

	return g_string_free (s, FALSE);
}

/* TRUE when the firewall (or a profile) being off decided any part of
 * the answer. */
static gboolean
stopped_decides (const FsWhatIfResult *r)
{
	for (guint i = 0; i < r->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

		if (a->origin == FS_WHATIF_ORIGIN_STOPPED)
			return TRUE;
		for (guint k = 0; k < a->cases->len; k++)
			if (((const FsWhatIfCase *) g_ptr_array_index (a->cases, k))
			    ->origin == FS_WHATIF_ORIGIN_STOPPED)
				return TRUE;
	}
	return FALSE;
}

/* Each direction's verdict and reason in one line.  Caller frees. */
static gchar *
answers_words (const FsWhatIfResult *r)
{
	GString *s = g_string_new (NULL);

	for (guint i = 0; i < r->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

		if (s->len > 0)
			g_string_append_c (s, ' ');
		if (r->answers->len > 1)
			g_string_append_printf (s, "%s: ", a->inbound ? _("Inbound")
			                                              : _("Outbound"));
		g_string_append_printf (s, "%s. %s",
		                        fs_whatif_verdict_name (a->verdict), a->reason);
	}

	return g_string_free (s, FALSE);
}

FsWhatIfResult *
fs_whatif_simulate (const FsWhatIfContext *ctx, const FsWhatIfQuery *query)
{
	FsWhatIfResult *r = result_new ();
	Model *m;

	if (ctx == NULL || query == NULL) {
		r->error = g_strdup (_("Nothing to simulate."));
		r->summary = g_strdup (r->error);
		return r;
	}

	r->query = fs_whatif_query_copy (query);
	m = model_build (ctx, ctx->policy);

	if (query->direction != FS_WHATIF_DIR_OUTBOUND)
		g_ptr_array_add (r->answers,
		                 answer_build (ctx, m, query, TRUE, r, TRUE));
	if (query->direction != FS_WHATIF_DIR_INBOUND)
		g_ptr_array_add (r->answers,
		                 answer_build (ctx, m, query, FALSE, r,
		                               r->answers->len == 0));

	context_notes (ctx, m, r);

	/* "Allowed, the firewall is off" is true and not the whole story:
	 * say what the rules do once it runs again, first. */
	if (stopped_decides (r)) {
		FsWhatIfContext run;
		FsWhatIfResult *on;
		gchar *words;

		ctx_running (ctx, &run);
		on = fs_whatif_simulate (&run, query);
		r->stopped_decides = TRUE;
		r->verdict_running = on->verdict;
		words = answers_words (on);
		g_ptr_array_insert (r->notes, 0, g_strdup_printf (
			_("Once the firewall runs: %s"), words));
		g_free (words);
		fs_whatif_result_free (on);
	}

	r->verdict = FS_WHATIF_ERROR;
	for (guint i = 0; i < r->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (r->answers, i);

		if (i == 0)
			r->verdict = a->verdict;
		else if (a->verdict != r->verdict)
			r->verdict = FS_WHATIF_DEPENDS;
	}

	if (!r->stopped_decides)
		r->verdict_running = r->verdict;
	r->summary = result_summary (ctx, query, r);
	model_free (m);
	return r;
}

FsWhatIfResult *
fs_whatif_simulate_text (const FsWhatIfContext *ctx, const gchar *text)
{
	GError *error = NULL;
	FsWhatIfQuery *q = fs_whatif_parse (text, &error);
	FsWhatIfResult *r;

	if (q == NULL) {
		r = result_new ();
		r->error = g_strdup (error != NULL ? error->message
		                                   : _("The question could not "
		                                       "be read."));
		r->summary = g_strdup (r->error);
		g_clear_error (&error);
		return r;
	}

	r = fs_whatif_simulate (ctx, q);
	fs_whatif_query_free (q);
	return r;
}

static const gchar *
action_kind_word (FsWhatIfActionKind kind)
{
	switch (kind) {
	case FS_WHATIF_ACT_CREATE_ALLOW:       return "create-allow";
	case FS_WHATIF_ACT_CREATE_BLOCK:       return "create-block";
	case FS_WHATIF_ACT_OPEN_RULE:          return "open-rule";
	case FS_WHATIF_ACT_LIFT_SENTINEL:      return "lift-sentinel";
	case FS_WHATIF_ACT_OPEN_ICMP_SETTINGS: return "icmp-settings";
	case FS_WHATIF_ACT_OPEN_SETTINGS:      return "settings";
	case FS_WHATIF_ACT_START_FIREWALL:     return "start-firewall";
	default:                               return "apply-policy";
	}
}

gchar *
fs_whatif_result_describe (const FsWhatIfResult *result)
{
	GString *s;

	if (result == NULL)
		return g_strdup ("");

	s = g_string_new (NULL);

	if (result->error != NULL) {
		g_string_append_printf (s, "%s\n", result->error);
		return g_string_free (s, FALSE);
	}

	g_string_append_printf (s, "%s\n", result->summary);

	/* What the line was read as, so a misreading shows instead of
	 * hiding behind the verdict. */
	if (result->query != NULL && result->query->pieces->len > 0) {
		GString *read = g_string_new (NULL);

		for (guint i = 0; i < result->query->pieces->len; i++) {
			const FsWhatIfPiece *p =
				g_ptr_array_index (result->query->pieces, i);

			if (read->len > 0)
				g_string_append (read, "; ");
			if (p->kind == FS_WHATIF_PIECE_IGNORED)
				g_string_append_printf (read, _("'%s' not used"), p->text);
			else
				g_string_append (read, p->meaning != NULL ? p->meaning
				                                          : p->text);
		}
		g_string_append_printf (s, _("Read as: %s (confidence %d%%)\n"),
		                        read->str,
		                        (gint) (result->query->confidence * 100.0
		                                + 0.5));
		g_string_free (read, TRUE);
	}

	for (guint i = 0; i < result->answers->len; i++) {
		const FsWhatIfAnswer *a = g_ptr_array_index (result->answers, i);

		g_string_append_printf (s, "\n%s: %s\n", a->probe,
		                        fs_whatif_verdict_name (a->verdict));
		g_string_append_printf (s, "  %s\n", a->reason);

		if (a->steps->len > 0)
			g_string_append (s, _("  How it was decided:\n"));
		for (guint k = 0; k < a->steps->len; k++) {
			const FsWhatIfStep *st = g_ptr_array_index (a->steps, k);
			gboolean decides = ((gint) k == a->decided_by);

			/* Rules that are not about this question would bury the
			 * ones that are: show the policy's rows and what matched. */
			if (st->kind == FS_WHATIF_STEP_SKIPPED &&
			    st->origin != FS_WHATIF_ORIGIN_POLICY &&
			    st->origin != FS_WHATIF_ORIGIN_SENTINEL)
				continue;

			g_string_append_printf (s, "    %s %s%s%s\n",
				decides ? "=>"
				: st->kind == FS_WHATIF_STEP_MATCHED ? "+"
				: st->kind == FS_WHATIF_STEP_NOTE ? "*" : "-",
				st->rule != NULL ? st->rule : "",
				st->rule != NULL && st->detail != NULL ? ": " : "",
				st->detail != NULL ? st->detail : "");
		}

		for (guint k = 0; k < a->actions->len; k++) {
			const FsWhatIfAction *act = g_ptr_array_index (a->actions, k);

			g_string_append_printf (s, "  [%s] %s: %s\n",
			                        action_kind_word (act->kind), act->label,
			                        act->explanation != NULL
			                        ? act->explanation : "");
		}
	}

	if (result->notes->len > 0) {
		g_string_append (s, _("\nGood to know:\n"));
		for (guint i = 0; i < result->notes->len; i++)
			g_string_append_printf (s, "  - %s\n",
			                        (const gchar *) g_ptr_array_index (
			                                result->notes, i));
	}

	return g_string_free (s, FALSE);
}

/* ================================================================
 * 11. The Linux model as iptables text
 *
 * One "-A CHAIN" line per rule, written the way the generator writes
 * it, option for option and in its order.  The core suite compares
 * this with fs_script_generate_*_family() for a table of policies and
 * settings: a change to the generator that is not mirrored in the
 * model above (or the other way round) fails there.
 * ================================================================ */

static void
render_rule (GString *out, const WRule *r, const gchar *chain)
{
	g_string_append_printf (out, "-A %s", chain);

	if (r->in_if != NULL)
		g_string_append_printf (out, " -i %s", r->in_if);
	if (r->out_if != NULL)
		g_string_append_printf (out, " -o %s", r->out_if);
	if (r->src.kind != ADDR_ANY)
		g_string_append_printf (out, " -s %s", r->src.text);
	if (r->dst.kind != ADDR_ANY)
		g_string_append_printf (out, " -d %s", r->dst.text);

	switch (r->proto) {
	case P_TCP:  g_string_append (out, " -p tcp"); break;
	case P_UDP:  g_string_append (out, " -p udp"); break;
	case P_ICMP: g_string_append (out, r->icmp6 ? " -p ipv6-icmp"
	                                            : " -p icmp"); break;
	default:     break;
	}

	if (r->icmp != NULL)
		g_string_append_printf (out, r->icmp6 ? " --icmpv6-type %s"
		                                      : " --icmp-type %s", r->icmp);
	if (r->r_sport != NULL)
		g_string_append_printf (out, " --sport %s", r->r_sport);
	if (r->r_dport != NULL)
		g_string_append_printf (out, " --dport %s", r->r_dport);
	if (r->hl != 0)
		g_string_append_printf (out, " -m hl --hl-eq %u", r->hl);
	if (r->ctstate != NULL)
		g_string_append_printf (out, " -m conntrack --ctstate %s",
		                        r->ctstate);
	if (r->limit != NULL)
		g_string_append_printf (out, " -m limit --limit %s", r->limit);
	if (r->burst != NULL)
		g_string_append_printf (out, " --limit-burst %s", r->burst);

	g_string_append_printf (out, " -j %s\n", r->r_target);
}

gchar *
fs_whatif_linux_chain_text (const FsPolicy *policy, const FsSettings *settings,
                            FsFamily family, gboolean inbound)
{
	FsWhatIfContext *ctx = fs_whatif_context_new (FS_WHATIF_LINUX_FIRST_MATCH,
	                                              policy, settings);
	Model *m = model_build (ctx, policy);
	gboolean v6 = (family == FS_FAMILY_IPV6);
	GPtrArray *chain = inbound ? m->in[v6] : m->out[v6];
	GString *out = g_string_new (NULL);

	for (guint i = 0; i < chain->len; i++) {
		const WRule *r = g_ptr_array_index (chain, i);

		if (r->left_out != NULL || (v6 && r->r_skip_v6))
			continue;
		render_rule (out, r, inbound ? "INBOUND" : "OUTBOUND");
	}

	model_free (m);
	fs_whatif_context_free (ctx);
	return g_string_free (out, FALSE);
}
