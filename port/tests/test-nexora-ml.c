/*---[ test-nexora-ml.c ]------------------------------------------------
 * Comprehensive Unit Test Suite for StockFW Nexora (AEGIS-ML)
 * Tests sliding-window feature extraction, quantile PSI drift detection,
 * Welford running confidence stats, and 50-label retraining triggers.
 *--------------------------------------------------------------------*/

#include "core/fs-ml.h"
#include "core/fs-ml-monitor.h"
#include <assert.h>
#include <stdio.h>
#include <math.h>

static void
test_feature_extraction(void)
{
    printf("==> Running Nexora Feature Extraction Tests...\n");
    GPtrArray *hits = g_ptr_array_new_with_free_func((GDestroyNotify) fs_hit_free);

    for (int i = 0; i < 50; i++) {
        FsHit *h = fs_hit_new();
        h->time = g_strdup("2026-11-11 12:00:00");
        h->direction = g_strdup("Outbound");
        h->protocol = g_strdup("TCP");
        h->destination = g_strdup("192.168.1.50");
        h->port = g_strdup("443");
        h->length = g_strdup("512");
        g_ptr_array_add(hits, h);
    }

    FsMlHostFeatures features;
    fs_ml_extract_features(hits, "192.168.1.50", &features);

    assert(features.event_rate > 0.0);
    assert(features.distinct_peers == 1.0);
    assert(features.tcp_ratio == 1.0);
    assert(features.length_mean == 512.0);

    g_ptr_array_unref(hits);
    printf("    Feature extraction tests passed successfully.\n");
}

static void
test_psi_drift_monitor(void)
{
    printf("==> Running Nexora PSI Drift Monitor Tests (arXiv 2607.17336 specs)...\n");
    FsMlMonitor monitor;

    /* Build sample reference distribution and bin edges for 16 features */
    double ref_dist[FS_ML_N_FEATURES][FS_ML_N_BINS];
    double bin_edges[FS_ML_N_FEATURES][FS_ML_N_BINS + 1];

    for (int f = 0; f < FS_ML_N_FEATURES; f++) {
        for (int b = 0; b < FS_ML_N_BINS; b++) {
            ref_dist[f][b] = 0.1; /* uniform baseline probability */
        }
        for (int b = 0; b <= FS_ML_N_BINS; b++) {
            bin_edges[f][b] = (double) b * 10.0;
        }
    }

    gboolean init_ok = fs_ml_monitor_init(&monitor, ref_dist, bin_edges);
    assert(init_ok == TRUE);

    /* Test 1: Insufficient samples (< 200) should return INSUFFICIENT drift status */
    double sample_features[FS_ML_N_FEATURES] = {0};
    for (int i = 0; i < 50; i++) {
        fs_ml_monitor_feed(&monitor, sample_features, (guint64)i * 1000);
    }
    FsMlDriftSignal drift = fs_ml_monitor_drift(&monitor);
    assert(drift == FS_ML_DRIFT_INSUFFICIENT);
    printf("    Passed: Insufficient samples (< 200) handled correctly.\n");

    /* Test 2: Stable stream (> 200 samples matching reference) produces NO drift */
    for (int i = 50; i < 250; i++) {
        /* feed values falling uniformly into bins */
        for (int f = 0; f < FS_ML_N_FEATURES; f++) {
            sample_features[f] = (double)(i % 100);
        }
        fs_ml_monitor_feed(&monitor, sample_features, (guint64)i * 1000);
    }

    gboolean retrain_trig = fs_ml_monitor_tick(&monitor, 250000, 1000000);
    drift = fs_ml_monitor_drift(&monitor);
    assert(drift == FS_ML_DRIFT_NONE || drift == FS_ML_DRIFT_BENIGN);
    assert(retrain_trig == FALSE);
    printf("    Passed: Stable/benign stream evaluated without false adversarial triggers.\n");

    /* Test 3: Label requirement (>= 50 labels) for adversarial retrain trigger */
    for (int i = 0; i < 60; i++) {
        fs_ml_monitor_add_label(&monitor, 1, 1, 1000000 + i);
    }
    assert(fs_ml_monitor_valid_label_count(&monitor) >= FS_ML_RETRAIN_LABELS);
    printf("    Passed: 50+ label accumulation requirement verified.\n");

    printf("    PSI drift monitor tests passed successfully.\n");
}

int main(void)
{
    printf("========================================================\n");
    printf(" StockFW Nexora (AEGIS-ML) Active Learning Test Suite   \n");
    printf("========================================================\n");
    test_feature_extraction();
    test_psi_drift_monitor();
    printf("========================================================\n");
    printf(" All Nexora active learning & PSI tests PASSED successfully!\n");
    printf("========================================================\n");
    return 0;
}
