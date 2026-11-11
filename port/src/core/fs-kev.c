/*---[ fs-kev.c ]-------------------------------------------------------
 * CISA Known Exploited Vulnerabilities (KEV) Parser Implementation
 *--------------------------------------------------------------------*/

#include "core/fs-kev.h"
#include <json-glib/json-glib.h>
#include <string.h>
#include <time.h>

static void
fs_kev_entry_free (FsKevEntry *entry)
{
	if (!entry) return;
	g_free (entry->cve_id);
	g_free (entry->vendor_project);
	g_free (entry->product);
	g_free (entry->vulnerability_name);
	g_free (entry->date_added);
	g_free (entry->short_description);
	g_free (entry->required_action);
	g_free (entry->due_date);
	g_free (entry->ransomware_use);
	g_free (entry);
}

FsKevCatalog *
fs_kev_parse (const gchar *json_data, gsize len, GError **error)
{
	JsonParser *parser;
	JsonNode *root;
	JsonObject *root_obj;
	JsonArray *vulnerabilities;
	FsKevCatalog *catalog;
	GError *local_error = NULL;

	if (!json_data || len == 0) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
		             "Empty CISA KEV JSON feed");
		return NULL;
	}

	parser = json_parser_new ();
	if (!json_parser_load_from_data (parser, json_data, (gssize)len, &local_error)) {
		g_propagate_error (error, local_error);
		g_object_unref (parser);
		return NULL;
	}

	root = json_parser_get_root (parser);
	if (!root || !JSON_NODE_HOLDS_OBJECT (root)) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
		             "CISA KEV root is not a JSON object");
		g_object_unref (parser);
		return NULL;
	}

	root_obj = json_node_get_object (root);
	if (!json_object_has_member (root_obj, "vulnerabilities")) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
		             "CISA KEV feed missing 'vulnerabilities' array");
		g_object_unref (parser);
		return NULL;
	}

	vulnerabilities = json_object_get_array_member (root_obj, "vulnerabilities");
	catalog = g_new0 (FsKevCatalog, 1);
	catalog->entries = g_ptr_array_new_with_free_func ((GDestroyNotify) fs_kev_entry_free);
	catalog->total_count = json_array_get_length (vulnerabilities);
	catalog->fetched_at = (gint64) time (NULL);

	for (guint i = 0; i < catalog->total_count; i++) {
		JsonObject *v_obj = json_array_get_object_element (vulnerabilities, i);
		FsKevEntry *entry = g_new0 (FsKevEntry, 1);

		entry->cve_id = g_strdup (json_object_get_string_member_with_default (v_obj, "cveID", ""));
		entry->vendor_project = g_strdup (json_object_get_string_member_with_default (v_obj, "vendorProject", ""));
		entry->product = g_strdup (json_object_get_string_member_with_default (v_obj, "product", ""));
		entry->vulnerability_name = g_strdup (json_object_get_string_member_with_default (v_obj, "vulnerabilityName", ""));
		entry->date_added = g_strdup (json_object_get_string_member_with_default (v_obj, "dateAdded", ""));
		entry->short_description = g_strdup (json_object_get_string_member_with_default (v_obj, "shortDescription", ""));
		entry->required_action = g_strdup (json_object_get_string_member_with_default (v_obj, "requiredAction", ""));
		entry->due_date = g_strdup (json_object_get_string_member_with_default (v_obj, "dueDate", ""));
		entry->ransomware_use = g_strdup (json_object_get_string_member_with_default (v_obj, "knownRansomwareCampaignUse", ""));

		g_ptr_array_add (catalog->entries, entry);
	}

	g_object_unref (parser);
	return catalog;
}

void
fs_kev_catalog_free (FsKevCatalog *catalog)
{
	if (!catalog) return;
	if (catalog->entries) {
		g_ptr_array_free (catalog->entries, TRUE);
	}
	g_free (catalog);
}

static gboolean
ascii_case_contains (const gchar *haystack, const gchar *needle)
{
	if (!haystack || !needle) return FALSE;
	gchar *h = g_ascii_strdown (haystack, -1);
	gchar *n = g_ascii_strdown (needle, -1);
	gboolean found = (strstr (h, n) != NULL);
	g_free (h);
	g_free (n);
	return found;
}

gboolean
fs_kev_matches_product (const FsKevEntry *entry, const gchar *query)
{
	if (!entry || !query) return FALSE;
	return (ascii_case_contains (entry->product, query) ||
	        ascii_case_contains (entry->vendor_project, query) ||
	        ascii_case_contains (entry->cve_id, query));
}

GPtrArray *
fs_kev_cross_reference (const FsKevCatalog *catalog, const gchar *const *installed_products)
{
	GPtrArray *matches;

	if (!catalog || !catalog->entries || !installed_products)
		return g_ptr_array_new ();

	matches = g_ptr_array_new_with_free_func (NULL);

	for (guint i = 0; i < catalog->entries->len; i++) {
		FsKevEntry *entry = g_ptr_array_index (catalog->entries, i);
		gboolean matched = FALSE;

		for (const gchar *const *p = installed_products; *p != NULL; p++) {
			if (fs_kev_matches_product (entry, *p)) {
				matched = TRUE;
				break;
			}
		}

		if (matched) {
			g_ptr_array_add (matches, entry);
		}
	}

	return matches;
}
