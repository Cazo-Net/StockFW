/*---[ fs-intelset.c ]---------------------------------------------------
 * The threat-intel rule set and its nftables rendering.  See
 * fs-intelset.h; the design is docs/design/1.0.7-threat-intel-design.md,
 * section 7.
 *
 * Everything here is text in, text out.  Running nft is fs-nftset.c's
 * job and deciding what to block is fs-intel.c's, so every byte this
 * file hands the kernel can be checked without root.
 *--------------------------------------------------------------------*/

#include "core/fs-intelset.h"

#include <string.h>

/* Ids are at most this long: "s_<id>_6" stays far below nft's name
 * limit and "STOCKFW-TI <id> " below the 127-byte log prefix [N7]. */
#define ID_MAX_LEN 40

/* The digest is this many hex digits of the SHA-256. */
#define DIGEST_LEN 32

/* ========================================================= directions */

const gchar *
fs_intel_dir_to_string (FsIntelDir dir)
{
	switch (dir) {
	case FS_INTEL_DIR_IN:
		return "in";
	case FS_INTEL_DIR_OUT:
		return "out";
	case FS_INTEL_DIR_BOTH:
		return "both";
	default:
		return NULL;
	}
}

gboolean
fs_intel_dir_from_string (const gchar *text, FsIntelDir *dir)
{
	FsIntelDir value;

	if (g_strcmp0 (text, "in") == 0)
		value = FS_INTEL_DIR_IN;
	else if (g_strcmp0 (text, "out") == 0)
		value = FS_INTEL_DIR_OUT;
	else if (g_strcmp0 (text, "both") == 0)
		value = FS_INTEL_DIR_BOTH;
	else
		return FALSE;

	if (dir != NULL)
		*dir = value;
	return TRUE;
}

static gboolean
dir_is_valid (FsIntelDir dir)
{
	return dir == FS_INTEL_DIR_IN || dir == FS_INTEL_DIR_OUT ||
	       dir == FS_INTEL_DIR_BOTH;
}

/* ================================================================ ids */

gboolean
fs_intel_id_is_valid (const gchar *id)
{
	gsize n;

	if (id == NULL)
		return FALSE;

	/* Checked byte by byte, never with the locale's ctype: an id is
	 * printed verbatim into the script, so only these bytes are safe. */
	for (n = 0; id[n] != '\0'; n++) {
		gchar c = id[n];

		if (n >= ID_MAX_LEN)
			return FALSE;
		if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
			continue;
		if (c == '-' && n > 0)
			continue;
		return FALSE;
	}
	return n > 0;
}

/* ============================================================ rule set */

static void
intel_set_free (gpointer data)
{
	FsIntelSet *set = data;

	if (set == NULL)
		return;
	g_free (set->id);
	g_free (set->label);
	fs_range_set_free (set->ranges);
	g_free (set);
}

FsIntelRuleset *
fs_intel_ruleset_new (void)
{
	FsIntelRuleset *ruleset = g_new0 (FsIntelRuleset, 1);

	ruleset->sets = g_ptr_array_new_with_free_func (intel_set_free);
	return ruleset;
}

void
fs_intel_ruleset_free (FsIntelRuleset *ruleset)
{
	if (ruleset == NULL)
		return;
	g_ptr_array_unref (ruleset->sets);
	g_free (ruleset);
}

const FsIntelSet *
fs_intel_ruleset_find (const FsIntelRuleset *ruleset, const gchar *id)
{
	if (ruleset == NULL || id == NULL)
		return NULL;

	for (guint i = 0; i < ruleset->sets->len; i++) {
		const FsIntelSet *set = g_ptr_array_index (ruleset->sets, i);

		if (g_strcmp0 (set->id, id) == 0)
			return set;
	}
	return NULL;
}

gboolean
fs_intel_ruleset_add (FsIntelRuleset *ruleset, const gchar *id,
                      const gchar *label, FsIntelDir dir,
                      FsRangeSet *ranges)
{
	FsIntelSet *set;

	/* Refused, never cleaned up [N7]: a mangled id would make two
	 * lists share a set, a log prefix or a counter. */
	if (ruleset == NULL || !fs_intel_id_is_valid (id) ||
	    !dir_is_valid (dir) || fs_intel_ruleset_find (ruleset, id) != NULL) {
		fs_range_set_free (ranges);
		return FALSE;
	}

	set = g_new0 (FsIntelSet, 1);
	set->id = g_strdup (id);
	set->label = g_strdup (label != NULL ? label : id);
	set->dir = dir;
	set->ranges = ranges != NULL ? ranges : fs_range_set_new ();

	/* nft refuses overlapping intervals ("conflicting intervals") and
	 * that fails the whole transaction; normalizing an already
	 * normalized set is cheap insurance. */
	fs_range_set_normalize (set->ranges);

	g_ptr_array_add (ruleset->sets, set);
	return TRUE;
}

guint
fs_intel_ruleset_count4 (const FsIntelRuleset *ruleset)
{
	guint total = 0;

	for (guint i = 0; ruleset != NULL && i < ruleset->sets->len; i++) {
		const FsIntelSet *set = g_ptr_array_index (ruleset->sets, i);

		total += fs_range_set_count4 (set->ranges);
	}
	return total;
}

guint
fs_intel_ruleset_count6 (const FsIntelRuleset *ruleset)
{
	guint total = 0;

	for (guint i = 0; ruleset != NULL && i < ruleset->sets->len; i++) {
		const FsIntelSet *set = g_ptr_array_index (ruleset->sets, i);

		total += fs_range_set_count6 (set->ranges);
	}
	return total;
}

gchar *
fs_intel_ruleset_digest (const FsIntelRuleset *ruleset)
{
	GChecksum *sum = g_checksum_new (G_CHECKSUM_SHA256);
	gchar *digest;

	/* The canonical form: "<id>\t<dir>\n" and then the stored text
	 * form of the ranges, per set in order.  Range lines never hold a
	 * tab, so no two rule sets share a form.  The label is left out:
	 * renaming a list changes nothing in the kernel. */
	for (guint i = 0; ruleset != NULL && i < ruleset->sets->len; i++) {
		const FsIntelSet *set = g_ptr_array_index (ruleset->sets, i);
		const gchar *dir = fs_intel_dir_to_string (set->dir);
		gchar *text = fs_range_set_to_text (set->ranges);

		g_checksum_update (sum, (const guchar *) (set->id != NULL ?
		                                          set->id : ""), -1);
		g_checksum_update (sum, (const guchar *) "\t", 1);
		g_checksum_update (sum, (const guchar *) (dir != NULL ?
		                                          dir : "?"), -1);
		g_checksum_update (sum, (const guchar *) "\n", 1);
		g_checksum_update (sum, (const guchar *) text, -1);
		g_free (text);
	}

	digest = g_strndup (g_checksum_get_string (sum), DIGEST_LEN);
	g_checksum_free (sum);
	return digest;
}

/* ========================================================= nft script */

gchar *
fs_intelset_nft_set_name (const gchar *id, FsAddrFamily family)
{
	gchar *name;

	if (!fs_intel_id_is_valid (id) ||
	    (family != FS_AF_V4 && family != FS_AF_V6))
		return NULL;

	/* '-' is not allowed in an nft set name; '_' is not allowed in an
	 * id, so the mapping cannot make two ids collide. */
	name = g_strdup_printf ("s_%s_%c", id, family == FS_AF_V4 ? '4' : '6');
	g_strdelimit (name, "-", '_');
	return name;
}

gchar *
fs_intelset_nft_clear_script (void)
{
	/* Declaring the table first makes the delete succeed when it is
	 * not there, so clearing twice is not an error.  Nothing else in
	 * the ruleset is named, so nothing else is touched. */
	return g_strdup ("table inet " FS_INTEL_NFT_TABLE " {}\n"
	                 "delete table inet " FS_INTEL_NFT_TABLE "\n");
}

/* fs_intel_ruleset_add() refuses everything the script cannot carry,
 * but the struct is public: a set filled in by hand is checked again,
 * since its id goes into the script verbatim [N7]. */
static gboolean
ruleset_is_renderable (const FsIntelRuleset *ruleset)
{
	for (guint i = 0; i < ruleset->sets->len; i++) {
		const FsIntelSet *set = g_ptr_array_index (ruleset->sets, i);

		if (set == NULL || !fs_intel_id_is_valid (set->id) ||
		    !dir_is_valid (set->dir))
			return FALSE;
		for (guint k = 0; k < i; k++) {
			const FsIntelSet *other = g_ptr_array_index (ruleset->sets, k);

			if (strcmp (other->id, set->id) == 0)
				return FALSE;
		}
	}
	return TRUE;
}

static guint
family_count (const FsIntelSet *set, FsAddrFamily family)
{
	return family == FS_AF_V4 ? fs_range_set_count4 (set->ranges) :
	                            fs_range_set_count6 (set->ranges);
}

/* One blocking rule, as the pair section 7 asks for: first the log
 * (rate limited, so a flood cannot fill the journal; its prefix is how
 * an event is tied to the list), then the verdict with the counter and
 * the id as the comment the counters are read back by. */
static void
append_block (GString *out, const gchar *match, gboolean reject,
              const gchar *id)
{
	g_string_append_printf (out,
		"\t\t%s limit rate 10/second burst 20 packets "
		"log prefix \"" FS_INTEL_LOG_MARKER " %s \" level info\n",
		match, id);
	g_string_append_printf (out, "\t\t%s counter %s comment \"%s\"\n",
		match,
		reject ? "reject with icmpx type admin-prohibited" : "drop",
		id);
}

typedef enum
{
	CHAIN_INPUT,
	CHAIN_OUTPUT,
	CHAIN_FORWARD
} Chain;

/* The rules one set adds to one chain, for one family [N0, S6, P1].
 * IN and OUT match only packets of connections the listed address
 * (IN) or this side (OUT) started -- "ct direction original" -- so the
 * replies of the other direction still pass, as with Windows' stateful
 * rules.  BOTH matches every packet.  Drops are silent; an outbound
 * block rejects, so a local program fails at once instead of hanging. */
static void
append_set_rules (GString *out, Chain chain, const FsIntelSet *set,
                  FsAddrFamily family)
{
	const gchar *fam = family == FS_AF_V4 ? "ip" : "ip6";
	gboolean from = set->dir == FS_INTEL_DIR_IN ||
	                set->dir == FS_INTEL_DIR_BOTH;
	gboolean to = set->dir == FS_INTEL_DIR_OUT ||
	              set->dir == FS_INTEL_DIR_BOTH;
	const gchar *state = set->dir == FS_INTEL_DIR_BOTH ?
	                     "" : " ct direction original";
	gchar *name = fs_intelset_nft_set_name (set->id, family);
	gchar *match;

	if (from && (chain == CHAIN_INPUT || chain == CHAIN_FORWARD)) {
		match = g_strdup_printf ("%s saddr @%s%s", fam, name, state);
		append_block (out, match, FALSE, set->id);
		g_free (match);
	}
	if (to && (chain == CHAIN_OUTPUT || chain == CHAIN_FORWARD)) {
		match = g_strdup_printf ("%s daddr @%s%s", fam, name, state);
		append_block (out, match, TRUE, set->id);
		g_free (match);
	}
	g_free (name);
}

/* `add element' statements for one set and family, FS_INTEL_NFT_CHUNK
 * elements each: every line stays a sane length, and they all still
 * belong to the one transaction. */
static void
append_elements (GString *out, const FsIntelSet *set, FsAddrFamily family)
{
	guint n = family_count (set, family);
	gchar *name = fs_intelset_nft_set_name (set->id, family);

	for (guint i = 0; i < n; i += FS_INTEL_NFT_CHUNK) {
		guint end = MIN (n, i + FS_INTEL_NFT_CHUNK);

		g_string_append_printf (out, "add element inet "
		                        FS_INTEL_NFT_TABLE " %s { ", name);
		for (guint k = i; k < end; k++) {
			gchar *text = family == FS_AF_V4 ?
				fs_range4_to_string (&g_array_index (
					set->ranges->v4, FsRange4, k)) :
				fs_range6_to_string (&g_array_index (
					set->ranges->v6, FsRange6, k));

			if (k > i)
				g_string_append (out, ", ");
			g_string_append (out, text);
			g_free (text);
		}
		g_string_append (out, " }\n");
	}
	g_free (name);
}

gchar *
fs_intelset_nft_script (const FsIntelRuleset *ruleset)
{
	static const struct
	{
		Chain        chain;
		const gchar *name;
		const gchar *loopback;
	} chains[] = {
		/* Never block this computer talking to itself, even through
		 * a listed address it holds [S5]. */
		{ CHAIN_INPUT,   "input",   "iif \"lo\" accept" },
		{ CHAIN_OUTPUT,  "output",  "oif \"lo\" accept" },
		{ CHAIN_FORWARD, "forward", NULL },
	};
	static const FsAddrFamily families[] = { FS_AF_V4, FS_AF_V6 };
	GString *out;
	gchar *digest;

	g_return_val_if_fail (ruleset != NULL, NULL);

	if (!ruleset_is_renderable (ruleset))
		return NULL;

	/* Create if missing, delete, re-create: one `nft -f' transaction,
	 * so the old table stays in force unless the new one loads whole. */
	out = g_string_new (NULL);
	g_string_append (out, "table inet " FS_INTEL_NFT_TABLE " {}\n"
	                      "delete table inet " FS_INTEL_NFT_TABLE "\n");
	if (ruleset->sets->len == 0)
		return g_string_free (out, FALSE);

	/* The comment is how the state check knows this table is the one
	 * StockFW applied [S10].  Each chain carries it too: nft 1.0.9
	 * fetches every set element to list tables (seconds for a large
	 * country), but lists chains without them, so the live check reads
	 * the chains (design 13.7). */
	digest = fs_intel_ruleset_digest (ruleset);
	g_string_append_printf (out, "table inet " FS_INTEL_NFT_TABLE " {\n"
	                        "\tcomment \"" FS_INTEL_DIGEST_TAG "%s\"\n",
	                        digest);

	/* A family with no addresses gets no set at all: nft refuses an
	 * empty element list [N7]. */
	for (guint i = 0; i < ruleset->sets->len; i++) {
		const FsIntelSet *set = g_ptr_array_index (ruleset->sets, i);

		for (guint f = 0; f < G_N_ELEMENTS (families); f++) {
			gchar *name;

			if (family_count (set, families[f]) == 0)
				continue;
			name = fs_intelset_nft_set_name (set->id, families[f]);
			g_string_append_printf (out,
				"\tset %s { type %s; flags interval; }\n", name,
				families[f] == FS_AF_V4 ? "ipv4_addr" : "ipv6_addr");
			g_free (name);
		}
	}

	/* Every rule on its own line: nft 1.0.9 refuses a rule followed by
	 * the closing brace on the same line [N7].  The three chains are
	 * always there, so every reader sees one shape. */
	/* Each chain carries the digest too: `nft -j list chains' reads it
	 * in milliseconds, where listing the table's comment loads every
	 * set element (seconds at 240k intervals). */
	for (guint c = 0; c < G_N_ELEMENTS (chains); c++) {
		g_string_append_printf (out, "\tchain %s {\n"
		                        "\t\tcomment \"" FS_INTEL_DIGEST_TAG "%s\"\n"
		                        "\t\ttype filter hook %s priority filter - 10; "
		                        "policy accept;\n",
		                        chains[c].name, digest, chains[c].name);
		if (chains[c].loopback != NULL)
			g_string_append_printf (out, "\t\t%s\n", chains[c].loopback);

		for (guint i = 0; i < ruleset->sets->len; i++) {
			const FsIntelSet *set = g_ptr_array_index (ruleset->sets, i);

			for (guint f = 0; f < G_N_ELEMENTS (families); f++)
				if (family_count (set, families[f]) > 0)
					append_set_rules (out, chains[c].chain, set,
					                  families[f]);
		}
		g_string_append (out, "\t}\n");
	}
	g_string_append (out, "}\n");
	g_free (digest);

	for (guint i = 0; i < ruleset->sets->len; i++) {
		const FsIntelSet *set = g_ptr_array_index (ruleset->sets, i);

		for (guint f = 0; f < G_N_ELEMENTS (families); f++)
			append_elements (out, set, families[f]);
	}

	return g_string_free (out, FALSE);
}

/* ============================================================ counters */

/* Decimal digits at *p into *value, advancing *p.  FALSE when there is
 * no digit or the number does not fit 64 bits. */
static gboolean
parse_u64 (const gchar **p, guint64 *value)
{
	const gchar *s = *p;
	guint64 v = 0;

	if (*s < '0' || *s > '9')
		return FALSE;
	for (; *s >= '0' && *s <= '9'; s++) {
		guint d = (guint) (*s - '0');

		if (v > (G_MAXUINT64 - d) / 10)
			return FALSE;
		v = v * 10 + d;
	}
	*value = v;
	*p = s;
	return TRUE;
}

static guint64
add_saturated (guint64 a, guint64 b)
{
	return a > G_MAXUINT64 - b ? G_MAXUINT64 : a + b;
}

/* `needle' as a word of `line': at its start or after a blank. */
static const gchar *
find_word (const gchar *line, const gchar *needle)
{
	for (const gchar *p = strstr (line, needle); p != NULL;
	     p = strstr (p + 1, needle))
		if (p == line || p[-1] == ' ' || p[-1] == '\t')
			return p;
	return NULL;
}

/* One line of `nft list chain' output, NUL-terminated on its own. */
static void
parse_counter_line (GHashTable *table, const gchar *line)
{
	static const gchar counter_word[] = "counter packets ";
	static const gchar bytes_word[] = " bytes ";
	static const gchar comment_word[] = "comment \"";
	const gchar *p, *id_start, *id_end;
	guint64 packets, bytes;
	FsIntelCounter *entry;
	gchar *id;

	p = find_word (line, counter_word);
	if (p == NULL)
		return;
	p += strlen (counter_word);
	if (!parse_u64 (&p, &packets) || !g_str_has_prefix (p, bytes_word))
		return;
	p += strlen (bytes_word);
	if (!parse_u64 (&p, &bytes) || (*p != '\0' && !g_ascii_isspace (*p)))
		return;

	/* The rule's own comment, on this line: nft prints it last. */
	id_start = find_word (p, comment_word);
	if (id_start == NULL)
		return;
	id_start += strlen (comment_word);
	id_end = strchr (id_start, '"');
	if (id_end == NULL)
		return;

	id = g_strndup (id_start, (gsize) (id_end - id_start));
	if (!fs_intel_id_is_valid (id)) {
		g_free (id);
		return;
	}

	entry = g_hash_table_lookup (table, id);
	if (entry == NULL) {
		entry = g_new0 (FsIntelCounter, 1);
		g_hash_table_insert (table, id, entry);
	} else {
		g_free (id);
	}
	entry->packets = add_saturated (entry->packets, packets);
	entry->bytes = add_saturated (entry->bytes, bytes);
}

GHashTable *
fs_intelset_nft_parse_counters (const gchar *listing)
{
	GHashTable *table = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                           g_free, g_free);
	gchar **lines;

	if (listing == NULL)
		return table;

	/* Line by line, so a rule without a comment can never borrow the
	 * next rule's. */
	lines = g_strsplit (listing, "\n", -1);
	for (guint i = 0; lines[i] != NULL; i++)
		parse_counter_line (table, lines[i]);
	g_strfreev (lines);
	return table;
}

/* =========================================================== live table */

/* A strict, small JSON scanner: just enough to walk `nft -j list
 * tables' and find one object in it.  Every value is checked for
 * syntax; strings are compared byte for byte and a string holding an
 * escape never equals a name we look for (nft prints plain names). */

#define JSON_MAX_DEPTH 32

typedef struct
{
	const gchar *p;
	const gchar *end;
} Json;

typedef struct
{
	const gchar *text;   /* raw bytes between the quotes */
	gsize        len;
	gboolean     plain;  /* no escapes: the bytes are the value */
} JsonString;

typedef gboolean (*JsonMemberFunc) (Json *js, const JsonString *key,
                                    guint depth, gpointer data);
typedef gboolean (*JsonElementFunc) (Json *js, guint depth, gpointer data);

static gboolean json_value (Json *js, guint depth);

static void
json_skip_blanks (Json *js)
{
	while (js->p < js->end && (*js->p == ' ' || *js->p == '\t' ||
	                           *js->p == '\n' || *js->p == '\r'))
		js->p++;
}

/* Consumes `c' (after blanks) when it is next. */
static gboolean
json_take (Json *js, gchar c)
{
	json_skip_blanks (js);
	if (js->p < js->end && *js->p == c) {
		js->p++;
		return TRUE;
	}
	return FALSE;
}

static gboolean
json_peek (Json *js, gchar c)
{
	json_skip_blanks (js);
	return js->p < js->end && *js->p == c;
}

static gboolean
json_string (Json *js, JsonString *out)
{
	const gchar *start;
	gboolean plain = TRUE;

	if (!json_take (js, '"'))
		return FALSE;
	start = js->p;
	while (js->p < js->end) {
		guchar c = (guchar) *js->p;

		if (c == '"') {
			if (out != NULL) {
				out->text = start;
				out->len = (gsize) (js->p - start);
				out->plain = plain;
			}
			js->p++;
			return TRUE;
		}
		if (c < 0x20)
			return FALSE;
		if (c == '\\') {
			plain = FALSE;
			if (++js->p >= js->end)
				return FALSE;
			if (*js->p == 'u') {
				for (guint k = 1; k <= 4; k++)
					if (js->p + k >= js->end ||
					    !g_ascii_isxdigit (js->p[k]))
						return FALSE;
				js->p += 4;
			} else if (strchr ("\"\\/bfnrt", *js->p) == NULL) {
				return FALSE;
			}
		}
		js->p++;
	}
	return FALSE;
}

static gboolean
json_digits (Json *js)
{
	const gchar *start = js->p;

	while (js->p < js->end && g_ascii_isdigit (*js->p))
		js->p++;
	return js->p > start;
}

static gboolean
json_number (Json *js)
{
	if (js->p < js->end && *js->p == '-')
		js->p++;
	if (js->p < js->end && *js->p == '0')
		js->p++;
	else if (!json_digits (js))
		return FALSE;
	if (js->p < js->end && *js->p == '.') {
		js->p++;
		if (!json_digits (js))
			return FALSE;
	}
	if (js->p < js->end && (*js->p == 'e' || *js->p == 'E')) {
		js->p++;
		if (js->p < js->end && (*js->p == '+' || *js->p == '-'))
			js->p++;
		if (!json_digits (js))
			return FALSE;
	}
	return TRUE;
}

static gboolean
json_word (Json *js, const gchar *word)
{
	gsize n = strlen (word);

	if ((gsize) (js->end - js->p) < n || strncmp (js->p, word, n) != 0)
		return FALSE;
	js->p += n;
	return TRUE;
}

/* An object; `member' (NULL: skip them all) is handed each key and
 * must consume its value. */
static gboolean
json_object (Json *js, guint depth, JsonMemberFunc member, gpointer data)
{
	if (depth >= JSON_MAX_DEPTH || !json_take (js, '{'))
		return FALSE;
	if (json_take (js, '}'))
		return TRUE;
	do {
		JsonString key;

		if (!json_string (js, &key) || !json_take (js, ':'))
			return FALSE;
		if (member != NULL ? !member (js, &key, depth + 1, data) :
		                     !json_value (js, depth + 1))
			return FALSE;
	} while (json_take (js, ','));
	return json_take (js, '}');
}

static gboolean
json_array (Json *js, guint depth, JsonElementFunc element, gpointer data)
{
	if (depth >= JSON_MAX_DEPTH || !json_take (js, '['))
		return FALSE;
	if (json_take (js, ']'))
		return TRUE;
	do {
		if (element != NULL ? !element (js, depth + 1, data) :
		                      !json_value (js, depth + 1))
			return FALSE;
	} while (json_take (js, ','));
	return json_take (js, ']');
}

static gboolean
json_value (Json *js, guint depth)
{
	json_skip_blanks (js);
	if (js->p >= js->end)
		return FALSE;
	switch (*js->p) {
	case '{':
		return json_object (js, depth, NULL, NULL);
	case '[':
		return json_array (js, depth, NULL, NULL);
	case '"':
		return json_string (js, NULL);
	case 't':
		return json_word (js, "true");
	case 'f':
		return json_word (js, "false");
	case 'n':
		return json_word (js, "null");
	default:
		return json_number (js);
	}
}

static gboolean
json_string_is (const JsonString *s, const gchar *literal)
{
	return s->plain && s->len == strlen (literal) &&
	       memcmp (s->text, literal, s->len) == 0;
}

/* The members of one {"table": {...}} that matter. */
typedef struct
{
	JsonString family, name, comment;
	gboolean   has_family, has_name, has_comment;
} LiveTable;

typedef struct
{
	gboolean listing;   /* a top-level "nftables" list was read whole */
	gboolean found;
	gchar   *digest;
} LiveScan;

static gboolean
live_table_member (Json *js, const JsonString *key, guint depth,
                   gpointer data)
{
	LiveTable *t = data;
	JsonString *slot;
	gboolean *has;

	if (json_string_is (key, "family")) {
		slot = &t->family;
		has = &t->has_family;
	} else if (json_string_is (key, "name")) {
		slot = &t->name;
		has = &t->has_name;
	} else if (json_string_is (key, "comment")) {
		slot = &t->comment;
		has = &t->has_comment;
	} else {
		return json_value (js, depth);
	}

	/* A value that is not a string matches nothing. */
	if (!json_peek (js, '"')) {
		*has = FALSE;
		return json_value (js, depth);
	}
	*has = json_string (js, slot);
	return *has;
}

/* "sfw:" and the digest's 32 lower-case hex digits; anything else in
 * the comment is not a digest StockFW wrote. */
static gchar *
digest_from_comment (const JsonString *comment)
{
	gsize tag = strlen (FS_INTEL_DIGEST_TAG);

	if (!comment->plain || comment->len != tag + DIGEST_LEN ||
	    strncmp (comment->text, FS_INTEL_DIGEST_TAG, tag) != 0)
		return NULL;
	for (gsize i = tag; i < comment->len; i++) {
		gchar c = comment->text[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
			return NULL;
	}
	return g_strndup (comment->text + tag, DIGEST_LEN);
}

/* One member of an element of the "nftables" array: only "table" with
 * an object value is looked into. */
static gboolean
live_item_member (Json *js, const JsonString *key, guint depth,
                  gpointer data)
{
	LiveScan *live = data;
	LiveTable t;

	if (!json_string_is (key, "table") || !json_peek (js, '{'))
		return json_value (js, depth);

	memset (&t, 0, sizeof t);
	if (!json_object (js, depth, live_table_member, &t))
		return FALSE;

	if (!live->found && t.has_family && t.has_name &&
	    json_string_is (&t.family, "inet") &&
	    json_string_is (&t.name, FS_INTEL_NFT_TABLE)) {
		live->found = TRUE;
		if (t.has_comment)
			live->digest = digest_from_comment (&t.comment);
	}
	return TRUE;
}

static gboolean
live_item (Json *js, guint depth, gpointer data)
{
	if (!json_peek (js, '{'))
		return json_value (js, depth);
	return json_object (js, depth, live_item_member, data);
}

static gboolean
live_top_member (Json *js, const JsonString *key, guint depth,
                 gpointer data)
{
	LiveScan *live = data;

	if (!json_string_is (key, "nftables") || !json_peek (js, '['))
		return json_value (js, depth);
	if (!json_array (js, depth, live_item, data))
		return FALSE;
	live->listing = TRUE;
	return TRUE;
}

FsIntelLive
fs_intelset_nft_parse_live_state (const gchar *json, gchar **digest)
{
	LiveScan live = { FALSE, FALSE, NULL };
	Json js;
	gboolean ok;

	if (digest != NULL)
		*digest = NULL;
	if (json == NULL)
		return FS_INTEL_LIVE_UNKNOWN;

	/* {"nftables": [{"metainfo": {...}}, {"table": {...}}, ...]}.
	 * Only that position counts: a set or chain object that happens to
	 * carry the same family and name is not the table. */
	js.p = json;
	js.end = json + strlen (json);
	ok = json_object (&js, 0, live_top_member, &live);
	json_skip_blanks (&js);

	/* Text that is not one whole listing says nothing reliable about
	 * the kernel: "cannot tell", never "the table is missing", which
	 * the state check would report as not loaded [S10]. */
	if (!ok || js.p != js.end || !live.listing) {
		g_free (live.digest);
		return FS_INTEL_LIVE_UNKNOWN;
	}
	if (!live.found)
		return FS_INTEL_LIVE_ABSENT;

	if (digest != NULL)
		*digest = live.digest;
	else
		g_free (live.digest);
	return FS_INTEL_LIVE_PRESENT;
}

/* ---- the same from `nft -j list chains' ---------------------------- */

typedef struct
{
	JsonString family, table, comment;
	gboolean   has_family, has_table, has_comment;
} LiveChain;

typedef struct
{
	gboolean listing;
	guint    chains;     /* chains of table inet stockfw_intel        */
	guint    tagged;     /* ... that carry a digest comment           */
	gboolean mixed;      /* two chains carry different digests        */
	gchar   *digest;
} ChainScan;

static gboolean
live_chain_member (Json *js, const JsonString *key, guint depth,
                   gpointer data)
{
	LiveChain *c = data;
	JsonString *slot;
	gboolean *has;

	if (json_string_is (key, "family")) {
		slot = &c->family;
		has = &c->has_family;
	} else if (json_string_is (key, "table")) {
		slot = &c->table;
		has = &c->has_table;
	} else if (json_string_is (key, "comment")) {
		slot = &c->comment;
		has = &c->has_comment;
	} else {
		return json_value (js, depth);
	}
	if (!json_peek (js, '"')) {
		*has = FALSE;
		return json_value (js, depth);
	}
	*has = json_string (js, slot);
	return *has;
}

static gboolean
chain_item_member (Json *js, const JsonString *key, guint depth,
                   gpointer data)
{
	ChainScan *scan = data;
	LiveChain c;
	gchar *d;

	if (!json_string_is (key, "chain") || !json_peek (js, '{'))
		return json_value (js, depth);

	memset (&c, 0, sizeof c);
	if (!json_object (js, depth, live_chain_member, &c))
		return FALSE;
	if (!c.has_family || !c.has_table ||
	    !json_string_is (&c.family, "inet") ||
	    !json_string_is (&c.table, FS_INTEL_NFT_TABLE))
		return TRUE;
	scan->chains++;
	d = c.has_comment ? digest_from_comment (&c.comment) : NULL;
	if (d == NULL)
		return TRUE;
	scan->tagged++;
	if (scan->digest == NULL)
		scan->digest = d;
	else {
		if (strcmp (scan->digest, d) != 0)
			scan->mixed = TRUE;
		g_free (d);
	}
	return TRUE;
}

static gboolean
chain_item (Json *js, guint depth, gpointer data)
{
	if (!json_peek (js, '{'))
		return json_value (js, depth);
	return json_object (js, depth, chain_item_member, data);
}

static gboolean
chain_top_member (Json *js, const JsonString *key, guint depth,
                  gpointer data)
{
	ChainScan *scan = data;

	if (!json_string_is (key, "nftables") || !json_peek (js, '['))
		return json_value (js, depth);
	if (!json_array (js, depth, chain_item, data))
		return FALSE;
	scan->listing = TRUE;
	return TRUE;
}

FsIntelLive
fs_intelset_nft_parse_live_chains (const gchar *json, gchar **digest)
{
	ChainScan scan = { FALSE, 0, 0, FALSE, NULL };
	Json js;
	gboolean ok;

	if (digest != NULL)
		*digest = NULL;
	if (json == NULL)
		return FS_INTEL_LIVE_UNKNOWN;
	js.p = json;
	js.end = json + strlen (json);
	ok = json_object (&js, 0, chain_top_member, &scan);
	json_skip_blanks (&js);
	if (!ok || js.p != js.end || !scan.listing) {
		g_free (scan.digest);
		return FS_INTEL_LIVE_UNKNOWN;
	}
	if (scan.chains == 0)
		return FS_INTEL_LIVE_ABSENT;
	/* One digest, on every chain: anything else is not a table this
	 * StockFW wrote whole (a chain added or replaced by hand). */
	if (scan.mixed || scan.tagged != scan.chains)
		g_clear_pointer (&scan.digest, g_free);
	if (digest != NULL)
		*digest = scan.digest;
	else
		g_free (scan.digest);
	return FS_INTEL_LIVE_PRESENT;
}

gboolean
fs_intelset_nft_parse_live (const gchar *json, gchar **digest)
{
	return fs_intelset_nft_parse_live_state (json, digest) ==
	       FS_INTEL_LIVE_PRESENT;
}
