/*---[ fs-intelwin.c ]---------------------------------------------------
 * The threat-intel rule set on Windows: plan, read back, in force.
 * See fs-intelwin.h and docs/1.0.7-threat-intel-design.md, section 11.
 * Pure: no Windows header, no COM, so it builds and is tested on every
 * platform.
 *--------------------------------------------------------------------*/

#include "core/fs-intelwin.h"
#include "core/fs-i18n.h"

#include <stdlib.h>
#include <string.h>

/* Digests are the first 32 hex digits of a SHA-256, like the rule
 * set's own (fs_intel_ruleset_digest). */
#define HASH_LEN     32u
#define GEN_LEN      9u
/* A description shows at most this many characters of a list's name. */
#define LABEL_MAX    80

/* NET_FW_* values the read-back checks, spelled out so this file needs
 * no Windows header. */
#define FW_ACTION_BLOCK   0
#define FW_PROTOCOL_ANY   256
#define FW_PROFILE_ALL3   (FS_INTELWIN_PROFILE_DOMAIN | \
                           FS_INTELWIN_PROFILE_PRIVATE | \
                           FS_INTELWIN_PROFILE_PUBLIC)

/* ============================================================ helpers */

static gchar *
hash32 (const gchar *text)
{
	gchar *full = g_compute_checksum_for_string (G_CHECKSUM_SHA256, text,
	                                             -1);

	full[HASH_LEN] = '\0';
	return full;
}

static gboolean
is_lower_hex (const gchar *text, gsize len)
{
	for (gsize i = 0; i < len; i++)
		if (!g_ascii_isxdigit (text[i]) || g_ascii_isupper (text[i]))
			return FALSE;
	return text[len] == '\0';
}

static const gchar *
dir_word (FsIntelWinDir dir)
{
	return dir == FS_INTELWIN_IN ? "in" : "out";
}

/* A list's name for a description: valid UTF-8, no control characters
 * and no '|' (the firewall's own storage separates fields with it), at
 * most LABEL_MAX characters; the id when there is nothing usable. */
static gchar *
clean_label (const gchar *label, const gchar *id)
{
	GString *out;
	glong n = 0;

	if (label == NULL || !g_utf8_validate (label, -1, NULL))
		return g_strdup (id);
	out = g_string_new (NULL);
	for (const gchar *p = label; *p != '\0' && n < LABEL_MAX;
	     p = g_utf8_next_char (p), n++) {
		gunichar c = g_utf8_get_char (p);

		if (c < 0x20 || c == 0x7f || c == '|' ||
		    (c >= 0x80 && c < 0xa0))
			g_string_append_c (out, ' ');
		else
			g_string_append_unichar (out, c);
	}
	g_strstrip (out->str);
	if (out->str[0] == '\0') {
		g_string_free (out, TRUE);
		return g_strdup (id);
	}
	return g_string_free (out, FALSE);
}

/* ========================================================= generations */

gboolean
fs_intelwin_gen_is_valid (const gchar *gen)
{
	return gen != NULL && strlen (gen) == GEN_LEN && gen[0] == 'g' &&
	       is_lower_hex (gen + 1, GEN_LEN - 1);
}

gchar *
fs_intelwin_gen_new (guint32 seed, const gchar *const *taken)
{
	for (guint32 i = 0;; i++) {
		gchar *gen = g_strdup_printf ("g%08x", seed + i * 0x9e3779b9u);
		gboolean used = FALSE;

		for (guint t = 0; taken != NULL && taken[t] != NULL; t++)
			if (strcmp (taken[t], gen) == 0)
				used = TRUE;
		if (!used)
			return gen;
		g_free (gen);
	}
}

/* ================================================================ plan */

static void
rule_free (gpointer p)
{
	FsIntelWinRule *r = p;

	g_free (r->name);
	g_free (r->description);
	g_free (r->remote);
	g_free (r);
}

void
fs_intelwin_plan_free (FsIntelWinPlan *plan)
{
	if (plan == NULL)
		return;
	g_free (plan->gen);
	g_free (plan->digest);
	g_free (plan->plan);
	if (plan->rules != NULL)
		g_ptr_array_unref (plan->rules);
	g_free (plan);
}

/* One chunk of a family's intervals: its RemoteAddresses text and the
 * same intervals as a set (for the plan hash). */
typedef struct
{
	GString    *remote;
	FsRangeSet *set;
	guint       tokens;
} Chunk;

static void
chunk_free (gpointer p)
{
	Chunk *c = p;

	g_string_free (c->remote, TRUE);
	fs_range_set_free (c->set);
	g_free (c);
}

/* Splits one family of `ranges' into chunks of at most max_tokens
 * tokens and max_chars characters (a single token longer than
 * max_chars stands alone). */
static GPtrArray *
chunks_of (const FsRangeSet *ranges, FsAddrFamily fam, guint max_tokens,
           guint max_chars)
{
	GPtrArray *out = g_ptr_array_new_with_free_func (chunk_free);
	guint n = fam == FS_AF_V4 ? ranges->v4->len : ranges->v6->len;
	Chunk *cur = NULL;

	for (guint i = 0; i < n; i++) {
		gchar *token;
		gsize len;

		if (fam == FS_AF_V4)
			token = fs_range4_to_string (
				&g_array_index (ranges->v4, FsRange4, i));
		else
			token = fs_range6_to_string (
				&g_array_index (ranges->v6, FsRange6, i));
		len = strlen (token);
		if (cur != NULL &&
		    (cur->tokens >= max_tokens ||
		     cur->remote->len + 1 + len > max_chars))
			cur = NULL;
		if (cur == NULL) {
			cur = g_new0 (Chunk, 1);
			cur->remote = g_string_new (NULL);
			cur->set = fs_range_set_new ();
			g_ptr_array_add (out, cur);
		}
		if (cur->tokens > 0)
			g_string_append_c (cur->remote, ',');
		g_string_append (cur->remote, token);
		cur->tokens++;
		if (fam == FS_AF_V4) {
			const FsRange4 *r = &g_array_index (ranges->v4,
			                                    FsRange4, i);

			fs_range_set_add4 (cur->set, r->start, r->end);
		} else {
			const FsRange6 *r = &g_array_index (ranges->v6,
			                                    FsRange6, i);

			fs_range_set_add6 (cur->set, r->start, r->end);
		}
		g_free (token);
	}
	return out;
}

/* The plan hash's input for one rule: "<name>\t<in|out>\n" and its
 * addresses in the stored text form. */
typedef struct
{
	gchar *name;
	gchar *text;
} HashItem;

static void
hash_item_free (gpointer p)
{
	HashItem *h = p;

	g_free (h->name);
	g_free (h->text);
	g_free (h);
}

static void
hash_item_add (GPtrArray *items, const gchar *name, FsIntelWinDir dir,
               FsRangeSet *set)
{
	HashItem *h = g_new0 (HashItem, 1);
	gchar *ranges;

	fs_range_set_normalize (set);
	ranges = fs_range_set_to_text (set);
	h->name = g_strdup (name);
	h->text = g_strdup_printf ("%s\t%s\n%s", name, dir_word (dir), ranges);
	g_free (ranges);
	g_ptr_array_add (items, h);
}

static gint
hash_item_cmp (gconstpointer a, gconstpointer b)
{
	const HashItem *x = *(HashItem *const *) a;
	const HashItem *y = *(HashItem *const *) b;

	return strcmp (x->name, y->name);
}

/* SHA-256 (first 32 hex digits) of "sfw:<digest>\n" followed by every
 * rule's item in name order: the same answer for the plan and for the
 * rules read back, whatever order either comes in. */
static gchar *
plan_hash (const gchar *digest, GPtrArray *items)
{
	GString *text = g_string_new (NULL);
	gchar *hash;

	g_ptr_array_sort (items, hash_item_cmp);
	g_string_append_printf (text, "sfw:%s\n", digest);
	for (guint i = 0; i < items->len; i++)
		g_string_append (text,
		                 ((HashItem *) g_ptr_array_index (items, i))->text);
	hash = hash32 (text->str);
	g_string_free (text, TRUE);
	return hash;
}

static gchar *
manifest_name (const gchar *gen)
{
	return g_strdup_printf ("%s%s %s", FS_INTELWIN_PREFIX,
	                        FS_INTELWIN_MANIFEST, gen);
}

FsIntelWinPlan *
fs_intelwin_plan (const FsIntelRuleset *ruleset, const gchar *gen,
                  guint max_tokens, guint max_chars)
{
	FsIntelWinPlan *plan;
	GPtrArray *items;
	GHashTable *seen_ids;

	g_return_val_if_fail (ruleset != NULL, NULL);
	if (!fs_intelwin_gen_is_valid (gen) || max_tokens == 0 ||
	    max_chars == 0)
		return NULL;

	/* What fs_intel_ruleset_add() guarantees, checked again: ids are
	 * printed into rule names. */
	seen_ids = g_hash_table_new (g_str_hash, g_str_equal);
	for (guint i = 0; i < ruleset->sets->len; i++) {
		const FsIntelSet *s = g_ptr_array_index (ruleset->sets, i);

		if (!fs_intel_id_is_valid (s->id) || s->ranges == NULL ||
		    (s->dir != FS_INTEL_DIR_IN && s->dir != FS_INTEL_DIR_OUT &&
		     s->dir != FS_INTEL_DIR_BOTH) ||
		    g_hash_table_contains (seen_ids, s->id)) {
			g_hash_table_destroy (seen_ids);
			return NULL;
		}
		g_hash_table_add (seen_ids, s->id);
	}
	g_hash_table_destroy (seen_ids);

	plan = g_new0 (FsIntelWinPlan, 1);
	plan->gen = g_strdup (gen);
	plan->digest = fs_intel_ruleset_digest (ruleset);
	plan->rules = g_ptr_array_new_with_free_func (rule_free);
	if (ruleset->sets->len == 0)
		return plan;   /* the empty rule set: no rule at all */

	items = g_ptr_array_new_with_free_func (hash_item_free);
	for (guint i = 0; i < ruleset->sets->len; i++) {
		const FsIntelSet *s = g_ptr_array_index (ruleset->sets, i);
		static const FsIntelWinDir dirs[] = { FS_INTELWIN_IN,
		                                      FS_INTELWIN_OUT };
		static const FsAddrFamily fams[] = { FS_AF_V4, FS_AF_V6 };
		gchar *label = clean_label (s->label, s->id);
		gchar *description = g_strdup_printf (
			_("%s: a StockFW threat-intel blocklist (%s). Managed by "
			  "StockFW: changes made here are undone at the next "
			  "apply."), label, fs_intel_dir_to_string (s->dir));

		for (guint d = 0; d < G_N_ELEMENTS (dirs); d++) {
			if ((s->dir & (dirs[d] == FS_INTELWIN_IN
			               ? FS_INTEL_DIR_IN : FS_INTEL_DIR_OUT)) == 0)
				continue;
			for (guint f = 0; f < G_N_ELEMENTS (fams); f++) {
				GPtrArray *chunks = chunks_of (s->ranges, fams[f],
				                               max_tokens,
				                               max_chars);

				for (guint c = 0; c < chunks->len; c++) {
					Chunk *ch = g_ptr_array_index (chunks, c);
					FsIntelWinRule *r = g_new0 (FsIntelWinRule, 1);

					r->name = g_strdup_printf (
						"%s%s %s IPv%d %u/%u %s",
						FS_INTELWIN_PREFIX, s->id,
						dir_word (dirs[d]), (int) fams[f],
						c + 1, chunks->len, gen);
					r->description = g_strdup (description);
					r->dir = dirs[d];
					r->family = fams[f];
					r->enabled = TRUE;
					r->remote = g_strdup (ch->remote->str);
					r->tokens = ch->tokens;
					hash_item_add (items, r->name, r->dir, ch->set);
					g_ptr_array_add (plan->rules, r);
				}
				g_ptr_array_unref (chunks);
			}
		}
		g_free (description);
		g_free (label);
	}

	plan->plan = plan_hash (plan->digest, items);
	{
		FsIntelWinRule *m = g_new0 (FsIntelWinRule, 1);

		m->name = manifest_name (gen);
		m->description = g_strdup_printf (
			_("StockFW threat intel: records which blocklists are "
			  "loaded. Disabled on purpose: it blocks nothing. "
			  "sfw:%s plan:%s rules:%u"), plan->digest, plan->plan,
			plan->rules->len);
		m->dir = FS_INTELWIN_IN;
		m->family = FS_AF_NONE;
		m->enabled = FALSE;
		m->remote = g_strdup (FS_INTELWIN_MANIFEST_REMOTE);
		m->tokens = 1;
		g_ptr_array_add (plan->rules, m);
	}
	g_ptr_array_unref (items);
	return plan;
}

/* =========================================================== read back */

/* "a.b.c.d/m.m.m.m" with a contiguous mask -> "a.b.c.d/n"; anything
 * else is returned as it is.  Caller frees. */
static gchar *
dotted_mask_to_prefix (const gchar *token)
{
	const gchar *slash = strchr (token, '/');
	guint32 mask = 0, addr;
	guint bits = 0;
	gchar *base;
	FsU128 unused;

	if (slash == NULL || strchr (slash + 1, '.') == NULL)
		return g_strdup (token);
	base = g_strndup (token, (gsize) (slash - token));
	if (fs_addr_parse (base, &addr, &unused) != FS_AF_V4 ||
	    fs_addr_parse (slash + 1, &mask, &unused) != FS_AF_V4) {
		g_free (base);
		return g_strdup (token);   /* fails to parse below */
	}
	while (bits < 32 && (mask & (0x80000000u >> bits)) != 0)
		bits++;
	if (bits < 32 && (mask << bits) != 0) {
		g_free (base);
		return g_strdup ("-");     /* a mask with holes: refused */
	}
	{
		gchar *out = g_strdup_printf ("%s/%u", base, bits);

		g_free (base);
		return out;
	}
}

gboolean
fs_intelwin_parse_remote (const gchar *text, FsRangeSet *into)
{
	FsRangeSet *got;
	gchar **tokens;
	gboolean ok = TRUE;

	if (text == NULL || *text == '\0')
		return FALSE;
	got = fs_range_set_new ();
	tokens = g_strsplit (text, ",", -1);
	for (guint i = 0; tokens[i] != NULL && ok; i++) {
		gchar *t = g_strstrip (tokens[i]);
		gchar *plain;

		if (*t == '\0') {
			ok = FALSE;
			break;
		}
		plain = dotted_mask_to_prefix (t);
		ok = fs_range_set_add_text (got, plain);
		g_free (plain);
	}
	g_strfreev (tokens);
	if (ok) {
		for (guint i = 0; i < got->v4->len; i++) {
			const FsRange4 *r = &g_array_index (got->v4, FsRange4, i);

			fs_range_set_add4 (into, r->start, r->end);
		}
		for (guint i = 0; i < got->v6->len; i++) {
			const FsRange6 *r = &g_array_index (got->v6, FsRange6, i);

			fs_range_set_add6 (into, r->start, r->end);
		}
	}
	fs_range_set_free (got);
	return ok;
}

FsIntelWinSeen *
fs_intelwin_seen_new (void)
{
	return g_new0 (FsIntelWinSeen, 1);
}

void
fs_intelwin_seen_free (gpointer p)
{
	FsIntelWinSeen *s = p;

	if (s == NULL)
		return;
	g_free (s->name);
	g_free (s->description);
	g_free (s->grouping);
	g_free (s->local_addresses);
	g_free (s->remote_addresses);
	g_free (s->local_ports);
	g_free (s->remote_ports);
	g_free (s->application);
	g_free (s->service);
	g_free (s->interface_types);
	g_free (s);
}

gboolean
fs_intelwin_in_group (const gchar *grouping)
{
	return grouping != NULL && strcmp (grouping, FS_INTELWIN_GROUP) == 0;
}

void
fs_intelwin_read_clear (FsIntelWinRead *read)
{
	if (read == NULL)
		return;
	g_clear_pointer (&read->digest, g_free);
	g_clear_pointer (&read->gen, g_free);
	g_clear_pointer (&read->why, g_free);
	g_clear_pointer (&read->gens, g_ptr_array_unref);
	read->live = FS_INTEL_LIVE_UNKNOWN;
	read->ours = 0;
}

const gchar *
fs_intelwin_name_gen (const gchar *name)
{
	const gchar *space;

	if (name == NULL || !g_str_has_prefix (name, FS_INTELWIN_PREFIX))
		return NULL;
	space = strrchr (name, ' ');
	if (space == NULL || !fs_intelwin_gen_is_valid (space + 1))
		return NULL;
	return space + 1;
}

gchar *
fs_intelwin_name_key (const gchar *name)
{
	return name != NULL ? g_utf8_casefold (name, -1) : NULL;
}

guint
fs_intelwin_count_gen (const GPtrArray *seen, const gchar *gen)
{
	guint n = 0;

	for (guint i = 0; seen != NULL && gen != NULL && i < seen->len; i++) {
		const FsIntelWinSeen *s = g_ptr_array_index (seen, i);

		if (fs_intelwin_in_group (s->grouping) &&
		    g_strcmp0 (fs_intelwin_name_gen (s->name), gen) == 0)
			n++;
	}
	return n;
}

/* An address rule's name: "SFW-TI <id> <in|out> IPv<4|6> <i>/<n> <gen>".
 * Fills the direction and family it claims. */
static gboolean
name_parse (const gchar *name, FsIntelWinDir *dir, FsAddrFamily *fam)
{
	gchar **w;
	gboolean ok;
	guint64 i = 0, n = 0;
	gchar *end_i = NULL, *end_n = NULL, *slash;

	if (!g_str_has_prefix (name, FS_INTELWIN_PREFIX))
		return FALSE;
	w = g_strsplit (name + strlen (FS_INTELWIN_PREFIX), " ", -1);
	ok = g_strv_length (w) == 5 && fs_intel_id_is_valid (w[0]) &&
	     (strcmp (w[1], "in") == 0 || strcmp (w[1], "out") == 0) &&
	     (strcmp (w[2], "IPv4") == 0 || strcmp (w[2], "IPv6") == 0) &&
	     fs_intelwin_gen_is_valid (w[4]);
	if (ok) {
		slash = strchr (w[3], '/');
		ok = slash != NULL && g_ascii_isdigit (w[3][0]) &&
		     g_ascii_isdigit (slash[1]);
		if (ok) {
			i = g_ascii_strtoull (w[3], &end_i, 10);
			n = g_ascii_strtoull (slash + 1, &end_n, 10);
			ok = end_i == slash && *end_n == '\0' && i >= 1 &&
			     i <= n && n <= 100000;
		}
	}
	if (ok) {
		*dir = strcmp (w[1], "in") == 0 ? FS_INTELWIN_IN
		                                : FS_INTELWIN_OUT;
		*fam = strcmp (w[2], "IPv4") == 0 ? FS_AF_V4 : FS_AF_V6;
	}
	g_strfreev (w);
	return ok;
}

/* "... sfw:<32 hex> plan:<32 hex> rules:<n>" at the end of the
 * manifest's description. */
static gboolean
manifest_parse (const gchar *description, gchar **digest, gchar **plan,
                guint *rules)
{
	const gchar *at;
	gchar **w;
	gboolean ok;

	if (description == NULL)
		return FALSE;
	at = g_strrstr (description, "sfw:");
	if (at == NULL)
		return FALSE;
	w = g_strsplit (at, " ", -1);
	ok = g_strv_length (w) == 3 &&
	     strlen (w[0]) == 4 + HASH_LEN && is_lower_hex (w[0] + 4, HASH_LEN) &&
	     g_str_has_prefix (w[1], "plan:") &&
	     strlen (w[1]) == 5 + HASH_LEN && is_lower_hex (w[1] + 5, HASH_LEN) &&
	     g_str_has_prefix (w[2], "rules:") && g_ascii_isdigit (w[2][6]);
	if (ok) {
		gchar *end = NULL;
		guint64 n = g_ascii_strtoull (w[2] + 6, &end, 10);

		ok = end != NULL && *end == '\0' && n <= G_MAXUINT;
		if (ok) {
			*digest = g_strdup (w[0] + 4);
			*plan = g_strdup (w[1] + 5);
			*rules = (guint) n;
		}
	}
	g_strfreev (w);
	return ok;
}

static gboolean
empty_or (const gchar *value, const gchar *allowed)
{
	return value == NULL || *value == '\0' ||
	       (allowed != NULL && g_ascii_strcasecmp (value, allowed) == 0);
}

/* What is wrong with one address rule, or NULL when it blocks exactly
 * what its name and addresses say, everywhere.  Fills `set' with its
 * addresses. */
static const gchar *
rule_fault (const FsIntelWinSeen *s, FsIntelWinDir dir, FsAddrFamily fam,
            FsRangeSet *set)
{
	if (!s->enabled)
		return _("it is disabled");
	if (s->action != FW_ACTION_BLOCK)
		return _("it no longer blocks");
	if (s->direction != (gint) dir)
		return _("its direction was changed");
	if ((s->profiles & FW_PROFILE_ALL3) != FW_PROFILE_ALL3)
		return _("it no longer applies to every profile");
	if (s->protocol != FW_PROTOCOL_ANY)
		return _("it was limited to one protocol");
	if (!empty_or (s->local_addresses, "*") ||
	    !empty_or (s->local_ports, "*") ||
	    !empty_or (s->remote_ports, "*"))
		return _("it was limited to some addresses or ports");
	if (!empty_or (s->application, NULL) || !empty_or (s->service, NULL))
		return _("it was limited to one program or service");
	if (!empty_or (s->interface_types, "All") || s->interfaces)
		return _("it was limited to some network adapters");
	if (s->conditions)
		return _("it was limited to some users, computers or apps");
	if (!fs_intelwin_parse_remote (s->remote_addresses, set))
		return _("its addresses were changed");
	fs_range_set_normalize (set);
	if ((fam == FS_AF_V4 ? set->v6->len : set->v4->len) != 0 ||
	    fs_range_set_is_empty (set))
		return _("its addresses were changed");
	return NULL;
}

static void
partial (FsIntelWinRead *out, gchar *why)
{
	out->live = FS_INTEL_LIVE_PARTIAL;
	g_free (out->why);
	out->why = why;
	g_clear_pointer (&out->digest, g_free);
	g_clear_pointer (&out->gen, g_free);
}

void
fs_intelwin_read (const GPtrArray *seen, FsIntelWinRead *out)
{
	GPtrArray *ours = g_ptr_array_new ();
	GPtrArray *items = NULL;
	const FsIntelWinSeen *manifest = NULL;
	gchar *digest = NULL, *plan = NULL, *again = NULL, *mname = NULL;
	guint rules = 0, manifests = 0;
	const gchar *gen;

	g_return_if_fail (out != NULL);
	memset (out, 0, sizeof *out);
	out->gens = g_ptr_array_new_with_free_func (g_free);

	for (guint i = 0; seen != NULL && i < seen->len; i++) {
		const FsIntelWinSeen *s = g_ptr_array_index (seen, i);

		if (fs_intelwin_in_group (s->grouping))
			g_ptr_array_add (ours, (gpointer) s);
	}
	out->ours = ours->len;
	if (ours->len == 0) {
		out->live = FS_INTEL_LIVE_ABSENT;
		goto done;
	}

	/* Every rule StockFW writes ends with its generation. */
	for (guint i = 0; i < ours->len; i++) {
		const FsIntelWinSeen *s = g_ptr_array_index (ours, i);
		const gchar *g = fs_intelwin_name_gen (s->name);
		gboolean known = FALSE;

		if (g == NULL) {
			partial (out, g_strdup_printf (
				_("The rule \"%s\" is in StockFW's blocklist group, "
				  "but StockFW did not write it."),
				s->name != NULL ? s->name : ""));
			goto done;
		}
		for (guint k = 0; k < out->gens->len; k++)
			if (strcmp (g_ptr_array_index (out->gens, k), g) == 0)
				known = TRUE;
		if (!known)
			g_ptr_array_add (out->gens, g_strdup (g));
	}
	if (out->gens->len > 1) {
		partial (out, g_strdup (
			_("Blocklist rules from two different applies are "
			  "loaded: an earlier one was not fully removed.")));
		goto done;
	}
	gen = g_ptr_array_index (out->gens, 0);

	mname = manifest_name (gen);
	for (guint i = 0; i < ours->len; i++) {
		const FsIntelWinSeen *s = g_ptr_array_index (ours, i);

		if (strcmp (s->name, mname) == 0) {
			manifest = s;
			manifests++;
		}
	}
	if (manifests != 1 ||
	    !manifest_parse (manifest->description, &digest, &plan, &rules)) {
		partial (out, g_strdup (
			_("The rule that records which blocklists are loaded is "
			  "missing or was changed.")));
		goto done;
	}

	items = g_ptr_array_new_with_free_func (hash_item_free);
	for (guint i = 0; i < ours->len; i++) {
		const FsIntelWinSeen *s = g_ptr_array_index (ours, i);
		FsIntelWinDir dir;
		FsAddrFamily fam;
		FsRangeSet *set;
		const gchar *fault;

		if (s == manifest)
			continue;
		if (!name_parse (s->name, &dir, &fam)) {
			partial (out, g_strdup_printf (
				_("The rule \"%s\" is in StockFW's blocklist group, "
				  "but StockFW did not write it."), s->name));
			goto done;
		}
		set = fs_range_set_new ();
		fault = rule_fault (s, dir, fam, set);
		if (fault != NULL) {
			partial (out, g_strdup_printf (
				_("The blocklist rule \"%s\" was changed outside "
				  "StockFW: %s."), s->name, fault));
			fs_range_set_free (set);
			goto done;
		}
		hash_item_add (items, s->name, dir, set);
		fs_range_set_free (set);
	}
	again = plan_hash (digest, items);
	if (items->len != rules || strcmp (again, plan) != 0) {
		partial (out, g_strdup (
			_("Some blocklist rules were removed, added or edited "
			  "outside StockFW.")));
		goto done;
	}
	out->live = FS_INTEL_LIVE_PRESENT;
	out->digest = digest;
	out->gen = g_strdup (gen);
	digest = NULL;

done:
	if (items != NULL)
		g_ptr_array_unref (items);
	g_free (again);
	g_free (digest);
	g_free (plan);
	g_free (mname);
	g_ptr_array_free (ours, TRUE);
}

/* ============================================================ in force */

static const gchar *
profile_name (guint index)
{
	switch (index) {
	case 0:  return _("Domain");
	case 1:  return _("Private");
	default: return _("Public");
	}
}

/* "Public", "Private and Public", "Domain, Private and Public". */
static gchar *
profile_list (const gboolean *which)
{
	GPtrArray *names = g_ptr_array_new ();
	GString *out = g_string_new (NULL);

	for (guint i = 0; i < 3; i++)
		if (which[i])
			g_ptr_array_add (names, (gpointer) profile_name (i));
	for (guint i = 0; i < names->len; i++) {
		if (i > 0)
			g_string_append (out, i + 1 == names->len ? _(" and ")
			                                          : ", ");
		g_string_append (out, g_ptr_array_index (names, i));
	}
	g_ptr_array_free (names, TRUE);
	return g_string_free (out, FALSE);
}

gchar *
fs_intelwin_not_in_force (const FsIntelWinForce *f)
{
	gboolean off[3] = { FALSE, FALSE, FALSE };
	gboolean excluded[3] = { FALSE, FALSE, FALSE };
	gboolean unread[3] = { FALSE, FALSE, FALSE };
	guint in_use = 0, n_off = 0, n_excluded = 0, n_unread = 0;
	gchar *names, *out;

	g_return_val_if_fail (f != NULL, NULL);

	if (f->service_known && !f->service_running)
		return g_strdup (_("The Windows Firewall service (MpsSvc) is "
		                   "not running, so no firewall rule is in "
		                   "force, the blocklists included."));
	/* What cannot be read is never taken as "on": the engine would
	 * then report the blocklists as enforced (design 11.6, review W5). */
	if (!f->policy_read || !f->gp_read)
		return g_strdup (_("StockFW cannot read whether Windows Firewall "
		                   "is on for the network in use, so it does not "
		                   "report the blocklists as in force."));
	if (f->gp_override)
		return g_strdup (_("Group Policy manages Windows Firewall on "
		                   "this computer and does not apply rules "
		                   "added on it, so the blocklist rules are not "
		                   "in force."));

	for (guint i = 0; i < 3; i++) {
		if ((f->current & (1L << i)) == 0)
			continue;
		in_use++;
		if (f->enabled[i] == 0) {
			off[i] = TRUE;
			n_off++;
		} else if (f->enabled[i] != 1) {
			unread[i] = TRUE;
			n_unread++;
		} else if (f->enabled[i] == 1 && f->excluded[i] > 0) {
			excluded[i] = TRUE;
			n_excluded++;
		}
	}
	if (n_off > 0) {
		names = profile_list (off);
		if (n_off == in_use)
			out = g_strdup_printf (
				n_off == 1
				? _("Windows Firewall is off for the %s profile, "
				    "which the network in use has, so the "
				    "blocklists block nothing.")
				: _("Windows Firewall is off for the %s profiles, "
				    "which the networks in use have, so the "
				    "blocklists block nothing."), names);
		else
			out = g_strdup_printf (
				n_off == 1
				? _("Windows Firewall is off for the %s profile, "
				    "which a network in use has, so the blocklists "
				    "block nothing on that network.")
				: _("Windows Firewall is off for the %s profiles, "
				    "which networks in use have, so the blocklists "
				    "block nothing on those networks."), names);
		g_free (names);
		return out;
	}
	if (n_unread > 0) {
		names = profile_list (unread);
		out = g_strdup_printf (
			n_unread == 1
			? _("StockFW cannot read whether Windows Firewall is on "
			    "for the %s profile, which a network in use has, so "
			    "it does not report the blocklists as in force there.")
			: _("StockFW cannot read whether Windows Firewall is on "
			    "for the %s profiles, which networks in use have, so "
			    "it does not report the blocklists as in force there."),
			names);
		g_free (names);
		return out;
	}
	if (n_excluded > 0) {
		names = profile_list (excluded);
		out = g_strdup_printf (
			_("Some network adapters are excluded from Windows "
			  "Firewall's %s settings, so the blocklists do not "
			  "filter them."), names);
		g_free (names);
		return out;
	}
	return NULL;
}
