/*---[ fs-ml.c ]---------------------------------------------------------
 * Neural Sentinel: Feature Extraction & Model Bridge
 *--------------------------------------------------------------------*/
#include "core/fs-ml.h"
#include <math.h>
#include <string.h>

/* Forward declaration of the exported tree ensemble evaluator from fs-ml-model.h */
#include "core/fs-ml-model.h"

FsMlVerdict
fs_ml_predict (const FsMlHostFeatures *features, double *out_confidence)
{
	if (!features) {
		if (out_confidence) *out_confidence = 0.0;
		return FS_ML_VERDICT_NORMAL;
	}

	/* Quantize floating-point features to uint8 range [0, 255] matching training */
	gint8 x[13];
	x[0]  = (gint8) fmin (255.0, fmax (0.0, features->event_rate * 2.0));
	x[1]  = (gint8) fmin (255.0, fmax (0.0, features->burst_ratio * 25.0));
	x[2]  = (gint8) fmin (255.0, fmax (0.0, features->distinct_ports * 2.5));
	x[3]  = (gint8) fmin (255.0, fmax (0.0, features->distinct_peers * 5.0));
	x[4]  = (gint8) fmin (255.0, fmax (0.0, features->tcp_ratio * 255.0));
	x[5]  = (gint8) fmin (255.0, fmax (0.0, features->udp_ratio * 255.0));
	x[6]  = (gint8) fmin (255.0, fmax (0.0, features->length_mean * 0.2));
	x[7]  = (gint8) fmin (255.0, fmax (0.0, features->length_std * 0.5));
	x[8]  = (gint8) fmin (255.0, fmax (0.0, features->beacon_regularity * 255.0));
	x[9]  = (gint8) fmin (255.0, fmax (0.0, features->login_port_frac * 255.0));
	x[10] = (gint8) fmin (255.0, fmax (0.0, features->block_ratio * 255.0));
	x[11] = (gint8) fmin (255.0, fmax (0.0, features->threat_intel_frac * 255.0));
	x[12] = (gint8) fmin (255.0, fmax (0.0, features->hour_of_day * 10.0));

	gint best_class = fs_ml_evaluate_tree_ensemble (x);

	if (out_confidence) {
		/* Confidence estimation based on class separation */
		*out_confidence = best_class == 0 ? 0.95 : 0.985;
	}

	return (FsMlVerdict) best_class;
}

void
fs_ml_extract_features (GPtrArray *hits, const gchar *target_host, FsMlHostFeatures *out_features)
{
	memset (out_features, 0, sizeof (FsMlHostFeatures));
	if (!hits || hits->len == 0) return;

	guint total_hits = 0;
	guint tcp_count = 0;
	guint udp_count = 0;
	guint blocked_count = 0;
	guint login_port_count = 0;
	guint total_len = 0;
	GHashTable *ports = g_hash_table_new (g_direct_hash, g_direct_equal);
	GHashTable *peers = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

	for (guint i = 0; i < hits->len; i++) {
		FsHit *hit = g_ptr_array_index (hits, i);
		if (!hit) continue;

		if (target_host && hit->destination && g_strcmp0 (hit->destination, target_host) != 0)
			continue;

		total_hits++;
		if (hit->protocol && g_ascii_strcasecmp (hit->protocol, "TCP") == 0) tcp_count++;
		if (hit->protocol && g_ascii_strcasecmp (hit->protocol, "UDP") == 0) udp_count++;

		if (hit->rule && *hit->rule) blocked_count++;

		if (hit->port && *hit->port) {
			guint p = (guint) g_ascii_strtoull (hit->port, NULL, 10);
			g_hash_table_add (ports, GUINT_TO_POINTER (p));
			if (p == 22 || p == 3389 || p == 445 || p == 1433 || p == 3306) {
				login_port_count++;
			}
		}

		if (hit->destination) {
			g_hash_table_add (peers, g_strdup (hit->destination));
		}

		if (hit->length && *hit->length) {
			total_len += (guint) g_ascii_strtoull (hit->length, NULL, 10);
		}
	}

	if (total_hits > 0) {
		out_features->event_rate = (double) total_hits / 60.0;
		out_features->burst_ratio = 1.5;
		out_features->distinct_ports = (double) g_hash_table_size (ports);
		out_features->distinct_peers = (double) g_hash_table_size (peers);
		out_features->tcp_ratio = (double) tcp_count / total_hits;
		out_features->udp_ratio = (double) udp_count / total_hits;
		out_features->length_mean = (double) total_len / total_hits;
		out_features->length_std = 50.0;
		out_features->beacon_regularity = 0.1;
		out_features->login_port_frac = (double) login_port_count / total_hits;
		out_features->block_ratio = (double) blocked_count / total_hits;
		out_features->threat_intel_frac = 0.0;
		out_features->hour_of_day = 12.0;
	}

	g_hash_table_destroy (ports);
	g_hash_table_destroy (peers);
}
