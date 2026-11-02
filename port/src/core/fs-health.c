/*---[ fs-health.c ]-----------------------------------------------------
 * Policy health check.  See fs-health.h for what is checked and how a
 * fix is verified.
 *--------------------------------------------------------------------*/

#include "core/fs-health.h"
#include "core/fs-fwrule.h"
#include "core/fs-iprange.h"
#include "core/fs-util.h"
#include "core/fs-audit.h"
#include "core/fs-i18n.h"

#include <string.h>
#include <stdlib.h>

/* The probe that stands for "somewhere on the internet". */
#define FS_HEALTH_OUTSIDE   "203.0.113.10"

/* A port range wider than this, open to anyone, is a broad allow. */
#define FS_HEALTH_BROAD_SPAN 100

/* Inbound ports that should never face the internet. */
static const struct { guint port; const gchar *name; } risky_ports[] = {
	{ 21,    "FTP" },
	{ 23,    "Telnet" },
	{ 135,   "Windows RPC" },
	{ 139,   "NetBIOS" },
	{ 445,   "SMB file sharing" },
	{ 1433,  "SQL Server" },
	{ 2375,  "the Docker API" },
	{ 3306,  "MySQL" },
	{ 3389,  "RDP" },
	{ 5432,  "PostgreSQL" },
	{ 5900,  "VNC" },
	{ 6379,  "Redis" },
	{ 9200,  "Elasticsearch" },
	{ 27017, "MongoDB" },
};

/* ---- names -------------------------------------------------------- */

const gchar *
fs_health_kind_name (FsHealthKind kind)
{
	switch (kind) {
	case FS_HEALTH_DUPLICATE:   return "duplicate";
	case FS_HEALTH_SHADOWED:    return "shadowed";
	case FS_HEALTH_UNREACHABLE: return "unreachable";
	case FS_HEALTH_NO_EFFECT:   return "no_effect";
	case FS_HEALTH_BROAD:       return "broad";
	case FS_HEALTH_RISKY_OPEN:  return "risky_open";
	case FS_HEALTH_NO_FAMILY:   return "no_family";
	case FS_HEALTH_FAMILY_GAP:  return "family_gap";
	default:                    return "unknown";
	}
}

const gchar *
fs_health_rule_kind_name (FsRuleKind kind)
{
	switch (kind) {
	case FS_RULE_INBOUND_ALLOW_FROM:     return "inbound_allow_from";
	case FS_RULE_INBOUND_ALLOW_SERVICE:  return "inbound_allow_service";
	case FS_RULE_INBOUND_FORWARD:        return "inbound_forward";
	case FS_RULE_OUTBOUND_ALLOW_TO:      return "outbound_allow_to";
	case FS_RULE_OUTBOUND_ALLOW_FROM:    return "outbound_allow_from";
	case FS_RULE_OUTBOUND_ALLOW_SERVICE: return "outbound_allow_service";
	case FS_RULE_OUTBOUND_DENY_TO:       return "outbound_deny_to";
	case FS_RULE_OUTBOUND_DENY_FROM:     return "outbound_deny_from";
	case FS_RULE_OUTBOUND_DENY_SERVICE:  return "outbound_deny_service";
	default:                             return "unknown";
	}
}

const gchar *
fs_health_severity_name (FsCopilotSeverity severity)
{
	switch (severity) {
	case FS_COPILOT_CRITICAL: return "critical";
	case FS_COPILOT_WARNING:  return "warning";
	default:                  return "info";
	}
}

/* ---- port sets ---------------------------------------------------- */

typedef struct { guint lo, hi; } PortRange;

/* A netsh port spec ("22", "67-68", "137-139,445") as ranges, or NULL
 * for "every port" (a NULL spec). */
static GArray *
ports_from_spec (const gchar *spec)
{
	GArray *out;
	gchar **parts;

	if (spec == NULL)
		return NULL;

	out = g_array_new (FALSE, FALSE, sizeof (PortRange));
	parts = g_strsplit (spec, ",", -1);
	for (guint i = 0; parts[i] != NULL; i++) {
		PortRange r;
		gchar *dash = strchr (parts[i], '-');

		r.lo = (guint) strtoul (parts[i], NULL, 10);
		r.hi = dash != NULL ? (guint) strtoul (dash + 1, NULL, 10) : r.lo;
		if (r.lo >= 1 && r.hi >= r.lo && r.hi <= 65535)
			g_array_append_val (out, r);
	}
	g_strfreev (parts);
	return out;
}

/* TRUE when every port of b lies in a (NULL = every port). */
static gboolean
ports_cover (const GArray *a, const GArray *b)
{
	if (a == NULL)
		return TRUE;
	if (b == NULL)
		return FALSE;

	for (guint i = 0; i < b->len; i++) {
		const PortRange *rb = &g_array_index (b, PortRange, i);
		guint p = rb->lo;

		/* Walk b's range through a's ranges (they may touch). */
		while (p <= rb->hi) {
			gboolean moved = FALSE;

			for (guint j = 0; j < a->len; j++) {
				const PortRange *ra = &g_array_index (a, PortRange, j);

				if (p >= ra->lo && p <= ra->hi) {
					if (ra->hi >= rb->hi)
						goto next;
					p = ra->hi + 1;
					moved = TRUE;
				}
			}
			if (!moved)
				return FALSE;
		}
next:
		;
	}
	return TRUE;
}

static guint
ports_lowest (const GArray *p)
{
	guint lo = 65535;

	for (guint i = 0; p != NULL && i < p->len; i++)
		lo = MIN (lo, g_array_index (p, PortRange, i).lo);
	return lo;
}

static guint
ports_highest (const GArray *p)
{
	guint hi = 0;

	for (guint i = 0; p != NULL && i < p->len; i++)
		hi = MAX (hi, g_array_index (p, PortRange, i).hi);
	return hi;
}

static guint
ports_span (const GArray *p)
{
	guint n = 0;

	if (p == NULL)
		return 65535;
	for (guint i = 0; i < p->len; i++) {
		const PortRange *r = &g_array_index (p, PortRange, i);

		n += r->hi - r->lo + 1;
	}
	return n;
}

static gboolean
ports_contain (const GArray *p, guint port)
{
	if (p == NULL)
		return TRUE;
	for (guint i = 0; i < p->len; i++) {
		const PortRange *r = &g_array_index (p, PortRange, i);

		if (port >= r->lo && port <= r->hi)
			return TRUE;
	}
	return FALSE;
}

/* ---- footprints --------------------------------------------------- */

/* A row as CSV without the empty comment field the serialiser leaves
 * at the end ("RDP, 3389, Anyone" rather than "RDP, 3389, Anyone, "):
 * what the user sees and what fs_rule_from_csv reads back the same. */
static gchar *
row_csv (const FsRule *row)
{
	gchar *c = fs_rule_to_csv (row);
	gsize n = strlen (c);

	while (n > 0 && (c[n - 1] == ' ' || c[n - 1] == ','))
		c[--n] = '\0';
	return c;
}

typedef enum { ADDR_ANY, ADDR_V4, ADDR_V6, ADDR_NAME } AddrKind;

/* One protocol with its ports. */
typedef struct
{
	FsRuleProtocol proto;          /* ANY, TCP or UDP                  */
	GArray        *ports;          /* PortRange, NULL = every port     */
} Elem;

/* What one policy row matches. */
typedef struct
{
	FsRuleKind  kind;
	guint       index;
	const FsRule *row;
	gboolean    inbound;
	gboolean    allow;
	gboolean    local_side;        /* matches OUR address (outbound *_FROM) */
	gboolean    forward;
	AddrKind    addr;
	FsRange4    r4;
	FsRange6    r6;
	GPtrArray  *elems;             /* Elem*; empty = compiles to nothing */
	gchar      *norm;              /* normalised fields, for duplicates */
	gchar      *csv;
} Foot;

static void
elem_free (gpointer data)
{
	Elem *e = data;

	if (e->ports != NULL)
		g_array_unref (e->ports);
	g_free (e);
}

static void
foot_free (gpointer data)
{
	Foot *f = data;

	g_ptr_array_unref (f->elems);
	g_free (f->norm);
	g_free (f->csv);
	g_free (f);
}

static gboolean
kind_is_inbound (FsRuleKind k)
{
	return k == FS_RULE_INBOUND_ALLOW_FROM ||
	       k == FS_RULE_INBOUND_ALLOW_SERVICE ||
	       k == FS_RULE_INBOUND_FORWARD;
}

static gboolean
kind_is_allow (FsRuleKind k)
{
	return k != FS_RULE_OUTBOUND_DENY_TO &&
	       k != FS_RULE_OUTBOUND_DENY_FROM &&
	       k != FS_RULE_OUTBOUND_DENY_SERVICE;
}

static gboolean
kind_is_service (FsRuleKind k)
{
	return k == FS_RULE_INBOUND_ALLOW_SERVICE ||
	       k == FS_RULE_OUTBOUND_ALLOW_SERVICE ||
	       k == FS_RULE_OUTBOUND_DENY_SERVICE ||
	       k == FS_RULE_INBOUND_FORWARD;
}

/* The address text a row matches on its own side. */
static const gchar *
row_address (const FsRule *row)
{
	return row->target;
}

static gchar *
addr_canonical (const gchar *text, AddrKind *kind, FsRange4 *r4,
                FsRange6 *r6)
{
	FsAddrFamily fam;

	if (fs_util_target_is_anyone (text)) {
		*kind = ADDR_ANY;
		return g_strdup ("anyone");
	}

	fam = fs_range_parse (text, r4, r6, NULL, NULL);
	if (fam == FS_AF_V4) {
		*kind = ADDR_V4;
		return fs_range4_to_string (r4);
	}
	if (fam == FS_AF_V6) {
		*kind = ADDR_V6;
		return fs_range6_to_string (r6);
	}

	*kind = ADDR_NAME;
	return g_ascii_strdown (text, -1);
}

static Foot *
foot_new (FsRuleKind kind, guint index, const FsRule *row)
{
	Foot *f = g_new0 (Foot, 1);
	gchar *addr;
	gchar *spec = NULL;

	f->kind = kind;
	f->index = index;
	f->row = row;
	f->inbound = kind_is_inbound (kind);
	f->allow = kind_is_allow (kind);
	f->forward = kind == FS_RULE_INBOUND_FORWARD;
	f->local_side = kind == FS_RULE_OUTBOUND_ALLOW_FROM ||
	                kind == FS_RULE_OUTBOUND_DENY_FROM;
	f->elems = g_ptr_array_new_with_free_func (elem_free);
	f->csv = row_csv (row);

	addr = addr_canonical (row_address (row), &f->addr, &f->r4, &f->r6);

	if (kind_is_service (kind)) {
		/* The protocols and ports exactly as the Windows translation
		 * compiles them (the What-If engine reads the same rules). */
		FsPolicy *one = fs_policy_new ();
		GList *rules = NULL, *l;
		FsRule *copy = fs_rule_copy (row);

		if (kind == FS_RULE_INBOUND_FORWARD) {
			/* The forward's exposed port is the row's port. */
			g_free (copy->to);
			copy->to = g_strdup (row->to != NULL && *row->to
			                     ? row->to : "192.0.2.1");
			if (copy->to_port == NULL || *copy->to_port == '\0') {
				g_free (copy->to_port);
				copy->to_port = g_strdup (row->port);
			}
		}
		g_ptr_array_add (one->kinds[kind], copy);
		fs_fwrule_expand_checked (one, &rules, NULL);
		for (l = rules; l != NULL; l = l->next) {
			FsFwRule *r = l->data;
			Elem *e = g_new0 (Elem, 1);
			const gchar *p = r->local_ports != NULL ? r->local_ports
			                                        : r->remote_ports;

			e->proto = r->protocol;
			e->ports = ports_from_spec (p);
			g_ptr_array_add (f->elems, e);
		}
		fs_fwrule_list_free (rules);
		fs_policy_free (one);
		spec = fs_fwrule_port_spec (row->port);
	} else {
		Elem *e = g_new0 (Elem, 1);

		e->proto = FS_PROTO_ANY;
		e->ports = NULL;
		g_ptr_array_add (f->elems, e);
	}

	f->norm = g_strdup_printf ("%d|%s|%s|%s|%s|%s", (int) kind,
	                           row->service != NULL
	                           ? row->service : "",
	                           spec != NULL ? spec
	                           : (row->port != NULL ? row->port : ""),
	                           addr,
	                           row->to != NULL ? row->to : "",
	                           row->to_port != NULL ? row->to_port : "");
	{
		gchar *low = g_ascii_strdown (f->norm, -1);

		g_free (f->norm);
		f->norm = low;
	}
	g_free (spec);
	g_free (addr);
	return f;
}

static gint
u128_cmp (FsU128 a, FsU128 b)
{
	if (a.hi != b.hi)
		return a.hi < b.hi ? -1 : 1;
	if (a.lo != b.lo)
		return a.lo < b.lo ? -1 : 1;
	return 0;
}

/* Every address of b inside a.  Names never cover and are never
 * covered. */
static gboolean
addr_covers (const Foot *a, const Foot *b)
{
	if (a->addr == ADDR_NAME || b->addr == ADDR_NAME)
		return FALSE;
	if (a->addr == ADDR_ANY)
		return TRUE;
	if (b->addr == ADDR_ANY)
		return FALSE;
	if (a->addr != b->addr)
		return FALSE;
	if (a->addr == ADDR_V4)
		return a->r4.start <= b->r4.start && a->r4.end >= b->r4.end;
	return u128_cmp (a->r6.start, b->r6.start) <= 0 &&
	       u128_cmp (a->r6.end, b->r6.end) >= 0;
}

static gboolean
proto_covers (FsRuleProtocol a, FsRuleProtocol b)
{
	return a == FS_PROTO_ANY || a == b;
}

/* [ foot_covers ] -- A matches everything B matches. */
static gboolean
foot_covers (const Foot *a, const Foot *b)
{
	if (a->inbound != b->inbound || a->local_side != b->local_side ||
	    a->forward || b->forward)
		return FALSE;
	if (b->elems->len == 0 || a->elems->len == 0)
		return FALSE;
	if (!addr_covers (a, b))
		return FALSE;

	for (guint i = 0; i < b->elems->len; i++) {
		const Elem *eb = g_ptr_array_index (b->elems, i);
		gboolean found = FALSE;

		for (guint j = 0; j < a->elems->len && !found; j++) {
			const Elem *ea = g_ptr_array_index (a->elems, j);

			found = proto_covers (ea->proto, eb->proto) &&
			        ports_cover (ea->ports, eb->ports);
		}
		if (!found)
			return FALSE;
	}
	return TRUE;
}

/* ---- probes ------------------------------------------------------- */

typedef struct
{
	gboolean        inbound;
	FsWhatIfProto   proto;
	guint           port;
	gchar          *host;          /* NULL = open                      */
	gboolean        in_scope;
	FsWhatIfVerdict expected;      /* for out-of-scope probes          */
} Probe;

static void
probe_free (gpointer data)
{
	Probe *p = data;

	g_free (p->host);
	g_free (p);
}

static gchar *
probe_text (const Probe *p)
{
	const gchar *proto = p->proto == FS_WHATIF_PROTO_TCP ? "TCP"
	                   : p->proto == FS_WHATIF_PROTO_UDP ? "UDP" : "IP";
	GString *s = g_string_new (p->inbound ? "Inbound " : "Outbound ");

	g_string_append (s, proto);
	if (p->port != 0)
		g_string_append_printf (s, " port %u", p->port);
	if (p->host != NULL)
		g_string_append_printf (s, p->inbound ? " from %s" : " to %s",
		                        p->host);
	return g_string_free (s, FALSE);
}

static void
probes_add (GPtrArray *probes, gboolean inbound, FsWhatIfProto proto,
            guint port, const gchar *host, gboolean in_scope)
{
	Probe *p;

	for (guint i = 0; i < probes->len; i++) {
		p = g_ptr_array_index (probes, i);
		if (p->inbound == inbound && p->proto == proto &&
		    p->port == port && g_strcmp0 (p->host, host) == 0)
			return;
	}
	p = g_new0 (Probe, 1);
	p->inbound = inbound;
	p->proto = proto;
	p->port = port;
	p->host = g_strdup (host);
	p->in_scope = in_scope;
	p->expected = FS_WHATIF_BLOCKED;
	g_ptr_array_add (probes, p);
}

static gboolean
v4_is_private (guint32 a)
{
	return (a >> 24) == 10 ||
	       (a >> 20) == ((172u << 4) | 1u) ||
	       (a >> 16) == ((192u << 8) | 168u);
}

static gchar *
v4_text (guint32 a)
{
	return g_strdup_printf ("%u.%u.%u.%u", a >> 24, (a >> 16) & 255,
	                        (a >> 8) & 255, a & 255);
}

/* A host inside the prefix to stand for "a machine on the LAN". */
static gchar *
lan_probe_host (const gchar *prefix)
{
	FsRange4 r;

	if (prefix == NULL ||
	    fs_range_parse (prefix, &r, NULL, NULL, NULL) != FS_AF_V4)
		return NULL;
	if (r.end - r.start >= 21)
		return v4_text (r.start + 20);
	return v4_text (r.start);
}

/* The hosts that stand for "the LAN": one inside the prefix, and one
 * next to each private IPv4 address this computer has. */
static GPtrArray *
lan_hosts (const FsWhatIfContext *ctx, const gchar *prefix)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (g_free);
	gchar *h = lan_probe_host (prefix);

	if (h != NULL)
		g_ptr_array_add (out, h);

	for (guint i = 0; ctx->local_addresses != NULL &&
	                  i < ctx->local_addresses->len; i++) {
		guint32 a;
		guint32 n;
		gchar *t;
		gboolean dup = FALSE;

		if (fs_addr_parse (g_ptr_array_index (ctx->local_addresses, i),
		                   &a, NULL) != FS_AF_V4 || !v4_is_private (a))
			continue;
		n = (a & 0xffffff00u) | 20u;
		if (n == a)
			n = (a & 0xffffff00u) | 21u;
		t = v4_text (n);
		for (guint j = 0; j < out->len; j++)
			dup = dup || g_strcmp0 (g_ptr_array_index (out, j), t) == 0;
		if (dup)
			g_free (t);
		else
			g_ptr_array_add (out, t);
	}
	return out;
}

/* The protocols and ports of a row to probe: the corners of each
 * element (lowest and highest port, TCP and UDP where it allows
 * either).  A row with no port is probed on TCP 22, TCP 443, UDP 53. */
static void
row_corner_ports (const Foot *f, GArray *protos, GArray *ports)
{
	for (guint i = 0; i < f->elems->len; i++) {
		const Elem *e = g_ptr_array_index (f->elems, i);
		FsWhatIfProto pr[2];
		guint np = 0;

		if (e->proto == FS_PROTO_TCP || e->proto == FS_PROTO_ANY)
			pr[np++] = FS_WHATIF_PROTO_TCP;
		if (e->proto == FS_PROTO_UDP || e->proto == FS_PROTO_ANY)
			pr[np++] = FS_WHATIF_PROTO_UDP;

		for (guint k = 0; k < np; k++) {
			guint c[3];
			guint nc = 0;

			if (e->ports == NULL) {
				c[nc++] = pr[k] == FS_WHATIF_PROTO_TCP ? 22 : 53;
				if (pr[k] == FS_WHATIF_PROTO_TCP)
					c[nc++] = 443;
			} else {
				c[nc++] = ports_lowest (e->ports);
				if (ports_highest (e->ports) != c[0])
					c[nc++] = ports_highest (e->ports);
			}
			for (guint j = 0; j < nc; j++) {
				g_array_append_val (protos, pr[k]);
				g_array_append_val (ports, c[j]);
			}
		}
	}
}

/* The addresses of a row to probe: first and last of a range; for
 * Anyone, the outside host and the LAN hosts; NULL (open) for a name
 * or for a row on our own side. */
static GPtrArray *
row_corner_hosts (const Foot *f, GPtrArray *lan)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (g_free);

	if (f->local_side || f->addr == ADDR_NAME) {
		g_ptr_array_add (out, NULL);
	} else if (f->addr == ADDR_ANY) {
		g_ptr_array_add (out, g_strdup (FS_HEALTH_OUTSIDE));
		for (guint i = 0; i < lan->len; i++)
			g_ptr_array_add (out, g_strdup (g_ptr_array_index (lan, i)));
	} else if (f->addr == ADDR_V4) {
		g_ptr_array_add (out, v4_text (f->r4.start));
		if (f->r4.end != f->r4.start)
			g_ptr_array_add (out, v4_text (f->r4.end));
	} else {
		FsRange6 one = { f->r6.start, f->r6.start };

		g_ptr_array_add (out, fs_range6_to_string (&one));
		if (u128_cmp (f->r6.start, f->r6.end) != 0) {
			one.start = one.end = f->r6.end;
			g_ptr_array_add (out, fs_range6_to_string (&one));
		}
	}
	return out;
}

static void
probes_for_row (GPtrArray *probes, const Foot *f, GPtrArray *lan)
{
	GArray *protos = g_array_new (FALSE, FALSE, sizeof (FsWhatIfProto));
	GArray *ports = g_array_new (FALSE, FALSE, sizeof (guint));
	GPtrArray *hosts = row_corner_hosts (f, lan);

	row_corner_ports (f, protos, ports);
	for (guint i = 0; i < protos->len; i++)
		for (guint h = 0; h < hosts->len; h++)
			probes_add (probes, f->inbound,
			            g_array_index (protos, FsWhatIfProto, i),
			            g_array_index (ports, guint, i),
			            g_ptr_array_index (hosts, h), TRUE);

	g_ptr_array_unref (hosts);
	g_array_unref (protos);
	g_array_unref (ports);
}

/* A context like ctx (platform, settings, Windows profiles, our
 * addresses) over another policy, with the firewall running and no
 * Sentinel blocks: the check is about the saved policy. */
static FsWhatIfContext *
ctx_for (const FsWhatIfContext *ctx, const FsPolicy *policy)
{
	FsWhatIfContext *c = fs_whatif_context_new (ctx->platform, policy,
	                                            ctx->settings);

	c->firewall = FS_WHATIF_FW_RUNNING;
	c->profiles_in_use = ctx->profiles_in_use;
	for (gint i = 0; i < 3; i++) {
		c->profile_enabled[i] = ctx->profile_enabled[i];
		c->default_inbound[i] = ctx->default_inbound[i];
		c->default_outbound[i] = ctx->default_outbound[i];
	}
	c->live = FS_WHATIF_LIVE_YES;
	for (guint i = 0; ctx->local_addresses != NULL &&
	                  i < ctx->local_addresses->len; i++)
		fs_whatif_context_add_local_address (
			c, g_ptr_array_index (ctx->local_addresses, i));
	c->now_unix = ctx->now_unix;
	return c;
}

static FsWhatIfVerdict
ask (const FsWhatIfContext *c, const Probe *p)
{
	FsWhatIfQuery *q = fs_whatif_query_new ();
	FsWhatIfResult *r;
	FsWhatIfVerdict v;

	q->text = probe_text (p);
	q->direction = p->inbound ? FS_WHATIF_DIR_INBOUND
	                          : FS_WHATIF_DIR_OUTBOUND;
	q->protocol = p->proto;
	q->port = p->port;
	q->host = g_strdup (p->host);
	r = fs_whatif_simulate (c, q);
	v = r->verdict;
	fs_whatif_result_free (r);
	fs_whatif_query_free (q);
	return v;
}

static void
check_free (gpointer data)
{
	FsHealthCheck *c = data;

	g_free (c->probe);
	g_free (c);
}

/* [ verify_fix ]
 * Runs every probe against both policies and records the table.
 * In-scope probes must keep their verdict; out-of-scope probes must go
 * from ALLOWED to their expected verdict.  TRUE when all of them do. */
static gboolean
verify_fix (const FsWhatIfContext *ctx, const FsPolicy *before,
            const FsPolicy *after, GPtrArray *probes, GPtrArray *checks)
{
	FsWhatIfContext *cb = ctx_for (ctx, before);
	FsWhatIfContext *ca = ctx_for (ctx, after);
	gboolean ok = probes->len > 0;

	for (guint i = 0; i < probes->len; i++) {
		const Probe *p = g_ptr_array_index (probes, i);
		FsHealthCheck *c = g_new0 (FsHealthCheck, 1);

		c->probe = probe_text (p);
		c->in_scope = p->in_scope;
		c->before = ask (cb, p);
		c->after = ask (ca, p);
		if (p->in_scope) {
			c->expected = c->before;
			ok = ok && c->after == c->before;
		} else {
			c->expected = p->expected;
			ok = ok && c->before == FS_WHATIF_ALLOWED &&
			     c->after == p->expected;
		}
		g_ptr_array_add (checks, c);
	}

	fs_whatif_context_free (cb);
	fs_whatif_context_free (ca);
	return ok;
}

/* ---- findings ----------------------------------------------------- */

void
fs_health_finding_free (FsHealthFinding *f)
{
	if (f == NULL)
		return;
	g_free (f->rule_csv);
	g_free (f->other_csv);
	g_free (f->title);
	g_free (f->why);
	g_free (f->evidence);
	g_free (f->whatif_line);
	g_free (f->fix_label);
	g_free (f->fix_before);
	g_free (f->fix_after);
	if (f->checks != NULL)
		g_ptr_array_unref (f->checks);
	g_free (f->no_fix_reason);
	g_free (f);
}

static FsHealthFinding *
finding_new (FsHealthKind kind, FsCopilotSeverity sev, const Foot *f)
{
	FsHealthFinding *h = g_new0 (FsHealthFinding, 1);

	h->kind = kind;
	h->severity = sev;
	h->policy_kind = f != NULL ? (gint) f->kind : -1;
	h->policy_index = f != NULL ? (gint) f->index : -1;
	h->other_kind = -1;
	h->other_index = -1;
	h->rule_csv = f != NULL ? g_strdup (f->csv) : NULL;
	h->checks = g_ptr_array_new_with_free_func (check_free);
	h->fix = FS_HEALTH_FIX_NONE;
	return h;
}

static FsPolicy *
policy_copy (const FsPolicy *p)
{
	FsPolicy *c = fs_policy_new ();

	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < p->kinds[k]->len; i++)
			g_ptr_array_add (c->kinds[k],
			                 fs_rule_copy (g_ptr_array_index (p->kinds[k], i)));
	return c;
}

/* A removal: verdicts at the row's corners must not change. */
static void
offer_removal (FsHealthFinding *h, const FsWhatIfContext *ctx,
               const Foot *f, GPtrArray *lan, const gchar *label)
{
	FsPolicy *fixed = policy_copy (ctx->policy);
	GPtrArray *probes = g_ptr_array_new_with_free_func (probe_free);

	g_ptr_array_remove_index (fixed->kinds[f->kind], f->index);
	probes_for_row (probes, f, lan);

	h->fix_before = g_strdup (f->csv);
	h->fix_after = NULL;
	h->verified = verify_fix (ctx, ctx->policy, fixed, probes, h->checks);
	if (h->verified) {
		h->fix = FS_HEALTH_FIX_REMOVE;
		h->fix_label = g_strdup (label);
	} else {
		h->no_fix_reason = g_strdup (
			_("Removing the row would change a What-If verdict (see the "
			  "checks), so no fix is offered."));
	}

	g_ptr_array_unref (probes);
	fs_policy_free (fixed);
}

/* A narrowing to the LAN: LAN probes keep their verdict, the outside
 * probe goes from ALLOWED to BLOCKED. */
static void
offer_narrowing (FsHealthFinding *h, const FsWhatIfContext *ctx,
                 const Foot *f, GPtrArray *lan, const gchar *prefix)
{
	FsPolicy *fixed;
	FsRule *row;
	GPtrArray *probes;
	GArray *protos, *ports;
	gchar *after;

	if (prefix == NULL) {
		h->no_fix_reason = g_strdup (
			_("The local network's address is not known, so there is "
			  "nothing safe to narrow this rule to."));
		return;
	}

	fixed = policy_copy (ctx->policy);
	row = g_ptr_array_index (fixed->kinds[f->kind], f->index);
	g_free (row->target);
	row->target = g_strdup (prefix);
	after = row_csv (row);

	probes = g_ptr_array_new_with_free_func (probe_free);
	protos = g_array_new (FALSE, FALSE, sizeof (FsWhatIfProto));
	ports = g_array_new (FALSE, FALSE, sizeof (guint));
	row_corner_ports (f, protos, ports);
	for (guint i = 0; i < protos->len; i++) {
		FsWhatIfProto pr = g_array_index (protos, FsWhatIfProto, i);
		guint port = g_array_index (ports, guint, i);

		for (guint j = 0; j < lan->len; j++)
			probes_add (probes, f->inbound, pr, port,
			            g_ptr_array_index (lan, j), TRUE);
		/* One probe outside the new scope, at the row's first port. */
		if (i == 0)
			probes_add (probes, f->inbound, pr, port,
			            FS_HEALTH_OUTSIDE, FALSE);
	}

	h->fix_before = g_strdup (f->csv);
	h->fix_after = after;
	h->verified = verify_fix (ctx, ctx->policy, fixed, probes, h->checks);
	if (h->verified) {
		h->fix = FS_HEALTH_FIX_REPLACE;
		h->fix_label = g_strdup_printf (_("Narrow to %s"), prefix);
	} else {
		h->no_fix_reason = g_strdup (
			_("Narrowing to the local network did not give the promised "
			  "verdicts (see the checks), so no fix is offered."));
	}

	g_array_unref (protos);
	g_array_unref (ports);
	g_ptr_array_unref (probes);
	fs_policy_free (fixed);
}

static gchar *
row_whatif_line (const Foot *f)
{
	const Elem *e = f->elems->len > 0 ? g_ptr_array_index (f->elems, 0)
	                                  : NULL;
	const gchar *proto = e == NULL ? "tcp"
	                   : e->proto == FS_PROTO_UDP ? "udp" : "tcp";
	guint port = e != NULL && e->ports != NULL ? ports_lowest (e->ports)
	                                           : 443;
	const gchar *host = f->addr == ADDR_ANY ? FS_HEALTH_OUTSIDE
	                  : f->row->target;

	if (f->local_side)
		return g_strdup_printf ("outbound %s port %u", proto, port);
	if (f->inbound)
		return g_strdup_printf ("inbound %s port %u from %s", proto,
		                        port, host);
	return g_strdup_printf ("outbound %s port %u to %s", proto, port, host);
}

static const gchar *
risky_name (const Foot *f, guint *port_out)
{
	for (guint i = 0; i < G_N_ELEMENTS (risky_ports); i++)
		for (guint j = 0; j < f->elems->len; j++) {
			const Elem *e = g_ptr_array_index (f->elems, j);

			if (e->ports != NULL &&
			    ports_contain (e->ports, risky_ports[i].port)) {
				*port_out = risky_ports[i].port;
				return risky_ports[i].name;
			}
		}
	return NULL;
}

static gboolean
foot_has_port (const Foot *f, guint port)
{
	for (guint j = 0; j < f->elems->len; j++) {
		const Elem *e = g_ptr_array_index (f->elems, j);

		if (e->ports != NULL && ports_contain (e->ports, port))
			return TRUE;
	}
	return FALSE;
}

static guint
foot_span (const Foot *f)
{
	guint n = 0;

	for (guint j = 0; j < f->elems->len; j++) {
		const Elem *e = g_ptr_array_index (f->elems, j);

		n = MAX (n, ports_span (e->ports));
	}
	return n;
}

/* [ outside_allowed ]
 * The premise of an "open to the internet" finding, asked of the
 * What-If engine: does an internet host reach the row's first port?
 * On Windows an allow-from Anyone compiles to nothing at all, so the
 * row opens nothing there and is not reported as open. */
static gboolean
outside_allowed (const FsWhatIfContext *ctx, const Foot *f)
{
	GArray *protos = g_array_new (FALSE, FALSE, sizeof (FsWhatIfProto));
	GArray *ports = g_array_new (FALSE, FALSE, sizeof (guint));
	FsWhatIfContext *c;
	gboolean open = FALSE;

	row_corner_ports (f, protos, ports);
	c = ctx_for (ctx, ctx->policy);
	if (protos->len > 0) {
		Probe p;

		memset (&p, 0, sizeof p);
		p.inbound = f->inbound;
		p.proto = g_array_index (protos, FsWhatIfProto, 0);
		p.port = g_array_index (ports, guint, 0);
		p.host = (gchar *) FS_HEALTH_OUTSIDE;
		open = ask (c, &p) == FS_WHATIF_ALLOWED;
	}
	fs_whatif_context_free (c);
	g_array_unref (protos);
	g_array_unref (ports);
	return open;
}

static gint
cmp_findings (gconstpointer a, gconstpointer b)
{
	const FsHealthFinding *x = *(FsHealthFinding * const *) a;
	const FsHealthFinding *y = *(FsHealthFinding * const *) b;

	if (x->severity != y->severity)
		return (gint) y->severity - (gint) x->severity;
	if (x->policy_kind != y->policy_kind)
		return x->policy_kind - y->policy_kind;
	return x->policy_index - y->policy_index;
}

static gchar *
derive_prefix (const FsWhatIfContext *ctx)
{
	for (guint i = 0; ctx->local_addresses != NULL &&
	                  i < ctx->local_addresses->len; i++) {
		gchar *p = fs_health_lan_prefix (
			g_ptr_array_index (ctx->local_addresses, i),
			"255.255.255.0");

		if (p != NULL)
			return p;
	}
	return NULL;
}

GPtrArray *
fs_health_check (const FsWhatIfContext *ctx, const gchar *lan_prefix)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (
		(GDestroyNotify) fs_health_finding_free);
	GPtrArray *feet;
	GPtrArray *lan;
	gchar *prefix;
	gboolean restrictive;
	gboolean names_resolved;
	GHashTable *reported;
	FsHealthFinding *h;

	if (ctx == NULL || ctx->policy == NULL)
		return out;

	prefix = lan_prefix != NULL ? g_strdup (lan_prefix)
	                            : derive_prefix (ctx);
	lan = lan_hosts (ctx, prefix);
	restrictive = ctx->settings != NULL &&
	              ctx->settings->restrictive_outbound;
	names_resolved = ctx->platform == FS_WHATIF_LINUX_FIRST_MATCH;
	reported = g_hash_table_new (g_direct_hash, g_direct_equal);

	feet = g_ptr_array_new_with_free_func (foot_free);
	for (gint k = 0; k < FS_RULE_N_KINDS; k++)
		for (guint i = 0; i < ctx->policy->kinds[k]->len; i++)
			g_ptr_array_add (feet, foot_new ((FsRuleKind) k, i,
				g_ptr_array_index (ctx->policy->kinds[k], i)));

	/* 1. Exact duplicates: the later copy goes. */
	for (guint b = 0; b < feet->len; b++) {
		Foot *fb = g_ptr_array_index (feet, b);

		for (guint a = 0; a < b; a++) {
			Foot *fa = g_ptr_array_index (feet, a);

			if (g_strcmp0 (fa->norm, fb->norm) != 0)
				continue;
			h = finding_new (FS_HEALTH_DUPLICATE, FS_COPILOT_INFO, fb);
			h->other_kind = (gint) fa->kind;
			h->other_index = (gint) fa->index;
			h->other_csv = g_strdup (fa->csv);
			h->title = g_strdup_printf (_("Duplicate rule: %s"), fb->csv);
			h->why = g_strdup (
				_("The same rule is in the policy twice. The second copy "
				  "changes nothing."));
			h->evidence = g_strdup_printf (
				_("Row %u of %s equals row %u."), fb->index + 1,
				fs_health_rule_kind_name (fb->kind), fa->index + 1);
			offer_removal (h, ctx, fb, lan, _("Remove the later copy"));
			g_ptr_array_add (out, h);
			g_hash_table_add (reported, fb);
			break;
		}
	}

	/* 2. Covered by a row with the same action (shadowed), or an
	 *    allow covered by a deny (unreachable). */
	for (guint b = 0; b < feet->len; b++) {
		Foot *fb = g_ptr_array_index (feet, b);

		if (g_hash_table_contains (reported, fb))
			continue;
		for (guint a = 0; a < feet->len; a++) {
			Foot *fa = g_ptr_array_index (feet, a);
			gboolean mutual;

			if (a == b || g_hash_table_contains (reported, fa) ||
			    !foot_covers (fa, fb))
				continue;
			/* Two rows that cover each other: only the later one is
			 * the redundant one. */
			mutual = foot_covers (fb, fa);
			if (mutual && a > b)
				continue;

			if (fa->allow == fb->allow) {
				h = finding_new (FS_HEALTH_SHADOWED, FS_COPILOT_INFO, fb);
				h->title = g_strdup_printf (
					_("Redundant rule: %s"), fb->csv);
				h->why = g_strdup_printf (
					_("Everything this row matches, the row \"%s\" already "
					  "matches with the same action, so this row never "
					  "decides anything."), fa->csv);
				offer_removal (h, ctx, fb, lan, _("Remove this rule"));
			} else if (fb->allow && !fa->allow) {
				h = finding_new (FS_HEALTH_UNREACHABLE,
				                 FS_COPILOT_WARNING, fb);
				h->title = g_strdup_printf (
					_("Allow rule can never take effect: %s"), fb->csv);
				h->why = g_strdup_printf (
					_("The deny \"%s\" matches everything this allow "
					  "matches, and %s, so the allow never decides. "
					  "Decide which of the two you mean."), fa->csv,
					ctx->platform == FS_WHATIF_WINDOWS_BLOCK_WINS
					? _("on Windows a block wins over any allow")
					: _("on Linux the outbound denies are checked first"));
				h->no_fix_reason = g_strdup (
					_("Only you can tell which of the two rules is "
					  "meant, so nothing is changed automatically."));
				h->whatif_line = row_whatif_line (fb);
			} else {
				continue;
			}
			h->other_kind = (gint) fa->kind;
			h->other_index = (gint) fa->index;
			h->other_csv = g_strdup (fa->csv);
			h->evidence = g_strdup_printf (
				_("Row %u of %s is covered by row %u of %s: the same "
				  "direction, every protocol and port, every address."),
				fb->index + 1, fs_health_rule_kind_name (fb->kind),
				fa->index + 1, fs_health_rule_kind_name (fa->kind));
			g_ptr_array_add (out, h);
			g_hash_table_add (reported, fb);
			break;
		}
	}

	/* 3. Outbound allows while outbound is open: one finding. */
	if (!restrictive) {
		guint n = 0;
		Foot *first = NULL;

		for (guint b = 0; b < feet->len; b++) {
			Foot *fb = g_ptr_array_index (feet, b);

			if (!fb->inbound && fb->allow) {
				if (first == NULL)
					first = fb;
				n++;
			}
		}
		if (n > 0) {
			h = finding_new (FS_HEALTH_NO_EFFECT, FS_COPILOT_INFO, first);
			h->title = n == 1
				? g_strdup (_("1 outbound allow rule has no effect in "
				              "this mode"))
				: g_strdup_printf (_("%u outbound allow rules have no "
				                     "effect in this mode"), n);
			h->why = g_strdup (
				_("Outbound traffic is allowed by default (restrictive "
				  "outbound is off in the Firewall preferences), so "
				  "outbound allow rows change nothing until it is "
				  "turned on. This is expected for the default policy."));
			h->evidence = g_strdup_printf (_("First one: %s"), first->csv);
			h->no_fix_reason = g_strdup (
				_("Nothing to fix: the rows take effect when restrictive "
				  "outbound is turned on."));
			g_ptr_array_add (out, h);
		}
	}

	/* 4. Inbound allows open to anyone. */
	for (guint b = 0; b < feet->len; b++) {
		Foot *fb = g_ptr_array_index (feet, b);
		const gchar *name;
		guint port = 0;

		if (!fb->inbound || fb->addr != ADDR_ANY ||
		    g_hash_table_contains (reported, fb))
			continue;

		if (fb->forward) {
			name = risky_name (fb, &port);
			if (name == NULL)
				continue;
			h = finding_new (FS_HEALTH_RISKY_OPEN, FS_COPILOT_WARNING, fb);
			h->title = g_strdup_printf (
				_("%s (%u) is forwarded from the internet"), name, port);
			h->why = g_strdup_printf (
				_("A port forward exposes %s on port %u to any host. "
				  "Port forwards cannot be limited to a source here."),
				name, port);
			h->evidence = g_strdup_printf (_("Forward row %u: %s"),
			                               fb->index + 1, fb->csv);
			h->no_fix_reason = g_strdup (
				_("A forward has no source field to narrow; remove it on "
				  "the Policy page if it is not needed."));
			g_ptr_array_add (out, h);
			continue;
		}

		if (!outside_allowed (ctx, fb))
			continue;

		if (fb->kind == FS_RULE_INBOUND_ALLOW_FROM) {
			h = finding_new (FS_HEALTH_BROAD, FS_COPILOT_CRITICAL, fb);
			h->title = g_strdup (
				_("Every port is open to any host on the internet"));
			h->why = g_strdup (
				_("An inbound allow from Anyone admits every protocol on "
				  "every port."));
		} else if ((name = risky_name (fb, &port)) != NULL) {
			h = finding_new (FS_HEALTH_RISKY_OPEN, FS_COPILOT_CRITICAL, fb);
			h->title = g_strdup_printf (
				_("%s (%u) is open to the internet"), name, port);
			h->why = g_strdup_printf (
				_("Inbound allow from Anyone on port %u. %s is a common "
				  "target of break-in attempts and is rarely meant to "
				  "face the internet."), port, name);
		} else if (foot_has_port (fb, 22)) {
			h = finding_new (FS_HEALTH_RISKY_OPEN, FS_COPILOT_INFO, fb);
			h->title = g_strdup (_("SSH (22) is open to the internet"));
			h->why = g_strdup (
				_("Inbound allow from Anyone on port 22. That can be "
				  "intended; if it is, use key logins only."));
		} else if (foot_span (fb) > FS_HEALTH_BROAD_SPAN) {
			h = finding_new (FS_HEALTH_BROAD, FS_COPILOT_WARNING, fb);
			h->title = g_strdup_printf (
				_("%u ports are open to any host"), foot_span (fb));
			h->why = g_strdup_printf (
				_("An inbound allow from Anyone over more than %u ports."),
				FS_HEALTH_BROAD_SPAN);
		} else {
			continue;
		}
		h->evidence = g_strdup_printf (_("Row %u of %s: %s"),
		                               fb->index + 1,
		                               fs_health_rule_kind_name (fb->kind),
		                               fb->csv);
		h->whatif_line = row_whatif_line (fb);
		offer_narrowing (h, ctx, fb, lan, prefix);
		g_ptr_array_add (out, h);
	}

	/* Outbound allow to Anyone while outbound is restrictive. */
	if (restrictive) {
		for (guint b = 0; b < feet->len; b++) {
			Foot *fb = g_ptr_array_index (feet, b);

			if (fb->kind != FS_RULE_OUTBOUND_ALLOW_TO ||
			    fb->addr != ADDR_ANY ||
			    g_hash_table_contains (reported, fb))
				continue;
			h = finding_new (FS_HEALTH_BROAD, FS_COPILOT_WARNING, fb);
			h->title = g_strdup (
				_("Outbound allow to any host undoes restrictive "
				  "outbound"));
			h->why = g_strdup (
				_("Restrictive outbound is on, but this row allows every "
				  "outbound connection to any host."));
			h->evidence = g_strdup_printf (_("Row %u of %s: %s"),
			                               fb->index + 1,
			                               fs_health_rule_kind_name (fb->kind),
			                               fb->csv);
			h->no_fix_reason = g_strdup (
				_("Narrowing it to the local network would cut this "
				  "computer off from the internet, so nothing is "
				  "changed automatically."));
			g_ptr_array_add (out, h);
		}
	}

	/* 5. Denies that reach no address family on this platform. */
	for (guint b = 0; b < feet->len; b++) {
		Foot *fb = g_ptr_array_index (feet, b);
		gchar *detail = NULL;

		if (fb->allow)
			continue;
		if (fs_rule_coverage (fb->row, names_resolved, &detail) !=
		    FS_FAMILY_NONE) {
			g_free (detail);
			continue;
		}
		h = finding_new (FS_HEALTH_NO_FAMILY, FS_COPILOT_WARNING, fb);
		h->title = g_strdup_printf (_("Deny rule blocks nothing: %s"),
		                            fb->csv);
		h->why = detail != NULL ? detail
		         : g_strdup (_("The rule reaches no address family."));
		h->evidence = g_strdup_printf (_("Row %u of %s: %s"),
		                               fb->index + 1,
		                               fs_health_rule_kind_name (fb->kind),
		                               fb->csv);
		h->no_fix_reason = g_strdup (
			_("Replace the host name with its address on the Policy "
			  "page."));
		g_ptr_array_add (out, h);
	}

	g_ptr_array_sort (out, cmp_findings);

	g_hash_table_unref (reported);
	g_ptr_array_unref (feet);
	g_ptr_array_unref (lan);
	g_free (prefix);
	return out;
}

gchar *
fs_health_lan_prefix (const gchar *ip, const gchar *netmask)
{
	guint32 a, m;
	guint bits = 0;

	if (ip == NULL || netmask == NULL ||
	    fs_addr_parse (ip, &a, NULL) != FS_AF_V4 ||
	    fs_addr_parse (netmask, &m, NULL) != FS_AF_V4 ||
	    !v4_is_private (a))
		return NULL;

	while (bits < 32 && (m & (0x80000000u >> bits)) != 0)
		bits++;
	if (bits < 8)
		return NULL;
	{
		guint32 net = bits == 32 ? a
		            : a & ~((guint32) 0xffffffffu >> bits);
		gchar *t = v4_text (net);
		gchar *p = g_strdup_printf ("%s/%u", t, bits);

		g_free (t);
		return p;
	}
}

gboolean
fs_health_finding_same (const FsHealthFinding *a, const FsHealthFinding *b)
{
	if (a == NULL || b == NULL)
		return FALSE;
	if (a->kind != b->kind || a->fix != b->fix ||
	    a->verified != b->verified ||
	    a->policy_kind != b->policy_kind ||
	    g_strcmp0 (a->fix_before, b->fix_before) != 0 ||
	    g_strcmp0 (a->fix_after, b->fix_after) != 0 ||
	    a->checks->len != b->checks->len)
		return FALSE;
	for (guint i = 0; i < a->checks->len; i++) {
		const FsHealthCheck *x = g_ptr_array_index (a->checks, i);
		const FsHealthCheck *y = g_ptr_array_index (b->checks, i);

		if (g_strcmp0 (x->probe, y->probe) != 0 ||
		    x->before != y->before || x->after != y->after ||
		    x->expected != y->expected)
			return FALSE;
	}
	return TRUE;
}

/* ---- applying ------------------------------------------------------ */

void
fs_health_undo_free (FsHealthUndo *u)
{
	if (u == NULL)
		return;
	g_free (u->before_csv);
	g_free (u->after_csv);
	g_free (u->anchor_csv);
	g_free (u->label);
	g_free (u);
}

static gint
find_row (const FsPolicy *policy, FsRuleKind kind, const gchar *csv,
          gint hint)
{
	GPtrArray *rows = policy->kinds[kind];
	gint found = -1;

	if (hint >= 0 && (guint) hint < rows->len) {
		gchar *c = row_csv (g_ptr_array_index (rows, hint));
		gboolean same = g_strcmp0 (c, csv) == 0;

		g_free (c);
		if (same)
			return hint;
	}
	for (guint i = 0; i < rows->len; i++) {
		gchar *c = row_csv (g_ptr_array_index (rows, i));

		if (g_strcmp0 (c, csv) == 0)
			found = (gint) i;   /* the last copy */
		g_free (c);
	}
	return found;
}

gboolean
fs_health_fix_apply (FsPolicy *policy, const FsHealthFinding *f,
                     FsHealthUndo **undo, gchar **why)
{
	GPtrArray *rows;
	gint idx;
	FsRule *old;
	FsHealthUndo *u;

	if (undo != NULL)
		*undo = NULL;
	if (policy == NULL || f == NULL || !f->verified ||
	    f->fix == FS_HEALTH_FIX_NONE || f->fix_before == NULL ||
	    f->policy_kind < 0 || f->policy_kind >= FS_RULE_N_KINDS) {
		if (why != NULL)
			*why = g_strdup (_("this finding has no verified fix"));
		return FALSE;
	}

	rows = policy->kinds[f->policy_kind];
	idx = find_row (policy, (FsRuleKind) f->policy_kind, f->fix_before,
	                f->policy_index);
	if (idx < 0) {
		if (why != NULL)
			*why = g_strdup (_("the rule is no longer in the policy"));
		return FALSE;
	}

	u = g_new0 (FsHealthUndo, 1);
	u->kind = f->fix;
	u->rule_kind = (FsRuleKind) f->policy_kind;
	u->index = idx;
	u->before_csv = g_strdup (f->fix_before);
	u->after_csv = g_strdup (f->fix_after);
	u->label = g_strdup (f->fix_label);
	if (idx > 0)
		u->anchor_csv = row_csv (g_ptr_array_index (rows, idx - 1));

	if (f->fix == FS_HEALTH_FIX_REMOVE) {
		old = g_ptr_array_steal_index (rows, (guint) idx);
		if (!fs_policy_save (policy)) {
			g_ptr_array_insert (rows, idx, old);
			fs_health_undo_free (u);
			if (why != NULL)
				*why = g_strdup (_("the policy could not be saved"));
			return FALSE;
		}
		fs_rule_free (old);
	} else {
		FsRule *nrow = fs_rule_from_csv ((FsRuleKind) f->policy_kind,
		                                 f->fix_after);

		if (nrow == NULL) {
			fs_health_undo_free (u);
			if (why != NULL)
				*why = g_strdup (_("the new row does not parse"));
			return FALSE;
		}
		old = g_ptr_array_index (rows, idx);
		rows->pdata[idx] = nrow;
		if (!fs_policy_save (policy)) {
			rows->pdata[idx] = old;
			fs_rule_free (nrow);
			fs_health_undo_free (u);
			if (why != NULL)
				*why = g_strdup (_("the policy could not be saved"));
			return FALSE;
		}
		fs_rule_free (old);
	}

	{
		gchar *detail = g_strdup_printf ("%s: %s -> %s",
		                                 fs_health_kind_name (f->kind),
		                                 f->fix_before,
		                                 f->fix_after != NULL
		                                 ? f->fix_after : "(removed)");
		fs_audit_log ("copilot health fix", detail);
		g_free (detail);
	}

	if (undo != NULL)
		*undo = u;
	else
		fs_health_undo_free (u);
	return TRUE;
}

gboolean
fs_health_undo_apply (FsPolicy *policy, const FsHealthUndo *u, gchar **why)
{
	GPtrArray *rows;
	FsRule *row;
	gint idx;

	if (policy == NULL || u == NULL)
		return FALSE;
	rows = policy->kinds[u->rule_kind];
	row = fs_rule_from_csv (u->rule_kind, u->before_csv);
	if (row == NULL) {
		if (why != NULL)
			*why = g_strdup (_("the old row does not parse"));
		return FALSE;
	}

	if (u->kind == FS_HEALTH_FIX_REPLACE) {
		FsRule *old;

		/* By content: the row the fix wrote, wherever it is now. */
		idx = find_row (policy, u->rule_kind, u->after_csv, u->index);
		if (idx < 0) {
			fs_rule_free (row);
			if (why != NULL)
				*why = g_strdup (_("the changed rule is no longer in "
				                   "the policy"));
			return FALSE;
		}
		old = g_ptr_array_index (rows, idx);
		rows->pdata[idx] = row;
		if (!fs_policy_save (policy)) {
			rows->pdata[idx] = old;
			fs_rule_free (row);
			if (why != NULL)
				*why = g_strdup (_("the policy could not be saved"));
			return FALSE;
		}
		fs_rule_free (old);
	} else {
		/* Back after the row that preceded it. */
		if (u->anchor_csv == NULL) {
			idx = 0;
		} else {
			gint a = find_row (policy, u->rule_kind, u->anchor_csv,
			                   u->index - 1);

			idx = a >= 0 ? a + 1 : MIN (u->index, (gint) rows->len);
		}
		g_ptr_array_insert (rows, idx, row);
		if (!fs_policy_save (policy)) {
			g_ptr_array_remove_index (rows, (guint) idx);
			if (why != NULL)
				*why = g_strdup (_("the policy could not be saved"));
			return FALSE;
		}
	}

	{
		gchar *detail = g_strdup_printf ("%s (%s)", u->before_csv,
		                                 u->label != NULL ? u->label : "");
		fs_audit_log ("copilot health fix undone", detail);
		g_free (detail);
	}
	return TRUE;
}
