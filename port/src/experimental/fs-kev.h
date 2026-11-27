/*---[ fs-kev.h ]-------------------------------------------------------
 * CISA Known Exploited Vulnerabilities (KEV) Feed Parser & Copilot Integration
 * Part of StockFW Phase v1.1 (The Proactive Shield)
 *
 * Ingests CISA's official JSON vulnerability feed offline, tracks active
 * zero-days and CVEs, and feeds findings into StockFW's Copilot layer.
 *--------------------------------------------------------------------*/
#ifndef FS_KEV_H
#define FS_KEV_H

#include <glib.h>
#include <json-glib/json-glib.h>

G_BEGIN_DECLS

typedef struct
{
	gchar *cve_id;
	gchar *vendor_project;
	gchar *product;
	gchar *vulnerability_name;
	gchar *date_added;
	gchar *short_description;
	gchar *required_action;
	gchar *due_date;
	gchar *ransomware_use;
} FsKevEntry;

typedef struct
{
	GPtrArray *entries; /* FsKevEntry* */
	gint64     fetched_at;
	guint      total_count;
} FsKevCatalog;

/* Parse CISA KEV JSON body */
FsKevCatalog *fs_kev_parse (const gchar *json_data, gsize len, GError **error);
void          fs_kev_catalog_free (FsKevCatalog *catalog);

/* Check if a given software product/vendor matches installed software or active threats */
gboolean      fs_kev_matches_product (const FsKevEntry *entry, const gchar *query);

/* Cross-reference catalog entries against installed software / active apps or products */
GPtrArray    *fs_kev_cross_reference (const FsKevCatalog *catalog, const gchar *const *installed_products);

G_END_DECLS

#endif /* FS_KEV_H */
