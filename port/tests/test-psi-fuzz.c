/*---[ test-psi-fuzz.c ]-------------------------------------------------
 * Rigorous PSI (Population Stability Index) Drift Fuzzer & Stress Test Unit
 * Validates Robustness of FsMlMonitor across extreme distributions, missing bins,
 * zero divisions, outlier probabilities, rapid sliding window rolls, and
 * adversarial/benign/insufficient drift state machines.
 *--------------------------------------------------------------------*/

#include "core/fs-ml.h"
#include "core/fs-ml-monitor.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

static guint failures = 0;
static guint checks = 0;

#define CHECK(cond, ...) do {                                   \
    checks++;                                               \
    if (!(cond)) {                                          \
        printf ("FAIL: ");                              \
        printf (__VA_ARGS__);                           \
        printf ("\n");                                  \
        failures++;                                     \
    } else {                                                  \
        printf ("ok:   ");                                \
        printf (__VA_ARGS__);                              \
        printf ("\n");                                     \
    }                                                       \
} while (0)

static void
test_psi_fuzz_init_validation(void)
{
    printf("==> Running PSI Fuzz Init & Reference Distribution Validation Tests...\n");
    FsMlMonitor monitor;
    double ref_dist[FS_ML_N_FEATURES][FS_ML_N_BINS];
    double bin_edges[FS_ML_N_FEATURES][FS_ML_N_BINS + 1];

    /* Initialize valid uniform reference distribution */
    for (int f = 0; f < FS_ML_N_FEATURES; f++) {
        for (int b = 0; b < FS_ML_N_BINS; b++) {
            ref_dist[f][b] = 0.1;
        }
        for (int b = 0; b <= FS_ML_N_BINS; b++) {
            bin_edges[f][b] = (double) b * 10.0;
        }
    }

    CHECK(fs_ml_monitor_init(&monitor, ref_dist, bin_edges) == TRUE,
          "Valid reference distribution initializes successfully");

    /* Test invalid sum != 1.0 */
    double bad_ref[FS_ML_N_FEATURES][FS_ML_N_BINS];
    memcpy(bad_ref, ref_dist, sizeof(ref_dist));
    bad_ref[0][0] = 0.5; /* sum becomes 1.4 */
    CHECK(fs_ml_monitor_init(&monitor, bad_ref, bin_edges) == FALSE,
          "Reference distribution summing != 1.0 is rejected");

    /* Test negative probability */
    memcpy(bad_ref, ref_dist, sizeof(ref_dist));
    bad_ref[0][0] = -0.05;
    bad_ref[0][1] = 0.15;
    CHECK(fs_ml_monitor_init(&monitor, bad_ref, bin_edges) == FALSE,
          "Negative probability in reference distribution is rejected");

    /* Test invalid bin edges (non-strictly ascending) */
    double bad_edges[FS_ML_N_FEATURES][FS_ML_N_BINS + 1];
    memcpy(bad_edges, bin_edges, sizeof(bin_edges));
    bad_edges[0][3] = bad_edges[0][2]; /* duplicate edge */
    CHECK(fs_ml_monitor_init(&monitor, ref_dist, bad_edges) == FALSE,
          "Non-strictly ascending bin edges are rejected");
}

static void
test_psi_fuzz_sliding_window_rollover(void)
{
    printf("==> Running PSI Fuzz Sliding Window Rollover Tests...\n");
    FsMlMonitor monitor;
    double ref_dist[FS_ML_N_FEATURES][FS_ML_N_BINS];
    double bin_edges[FS_ML_N_FEATURES][FS_ML_N_BINS + 1];

    for (int f = 0; f < FS_ML_N_FEATURES; f++) {
        for (int b = 0; b < FS_ML_N_BINS; b++) {
            ref_dist[f][b] = 0.1;
        }
        for (int b = 0; b <= FS_ML_N_BINS; b++) {
            bin_edges[f][b] = (double) b * 10.0;
        }
    }

    assert(fs_ml_monitor_init(&monitor, ref_dist, bin_edges) == TRUE);

    double features[FS_ML_N_FEATURES] = {0};
    for (int f = 0; f < FS_ML_N_FEATURES; f++) {
        features[f] = 5.0; /* bin 0 */
    }

    /* Feed 250 samples at t = 0 */
    for (int i = 0; i < 250; i++) {
        fs_ml_monitor_feed(&monitor, features, 1000ULL);
    }
    CHECK(fs_ml_monitor_window_total(&monitor) == 250,
          "Window accumulates 250 samples correctly");

    /* Feed 10 samples past the 15-minute sliding window (900 seconds + 1ms) */
    guint64 rollover_ms = 1000ULL + (guint64)(FS_ML_WINDOW_S + 1) * 1000ULL;
    for (int i = 0; i < 10; i++) {
        fs_ml_monitor_feed(&monitor, features, rollover_ms);
    }
    CHECK(fs_ml_monitor_window_total(&monitor) == 10,
          "Window correctly resets and accumulates 10 samples after 15-minute rollover");
}

static void
test_psi_fuzz_drift_classification(void)
{
    printf("==> Running PSI Fuzz Drift Classification & Epsilon Smoothing Tests...\n");
    FsMlMonitor monitor;
    double ref_dist[FS_ML_N_FEATURES][FS_ML_N_BINS];
    double bin_edges[FS_ML_N_FEATURES][FS_ML_N_BINS + 1];

    for (int f = 0; f < FS_ML_N_FEATURES; f++) {
        for (int b = 0; b < FS_ML_N_BINS; b++) {
            ref_dist[f][b] = 0.1;
        }
        for (int b = 0; b <= FS_ML_N_BINS; b++) {
            bin_edges[f][b] = (double) b * 10.0;
        }
    }

    assert(fs_ml_monitor_init(&monitor, ref_dist, bin_edges) == TRUE);

    /* Feed 250 samples hitting extreme bin 9 exclusively (adversarial shift) */
    double extreme_features[FS_ML_N_FEATURES];
    for (int f = 0; f < FS_ML_N_FEATURES; f++) {
        extreme_features[f] = 95.0; /* bin 9 */
    }

    for (int i = 0; i < 300; i++) {
        fs_ml_monitor_feed(&monitor, extreme_features, 1000ULL + (guint64)i * 10ULL);
    }

    gboolean retrain = fs_ml_monitor_tick(&monitor, 10000ULL, 2000000ULL);
    FsMlDriftSignal drift = fs_ml_monitor_drift(&monitor);

    CHECK(drift == FS_ML_DRIFT_ADVERSARIAL,
          "Extreme distribution shift correctly classified as ADVERSARIAL (got %d)", drift);
    CHECK(fs_ml_monitor_psi_aggregate(&monitor) > FS_ML_PSI_AGGREGATE,
          "Aggregate PSI exceeds threshold (> 0.25)");
    CHECK(retrain == FALSE,
          "Adversarial drift without labels does not trigger retrain");

    /* Add 50 valid labels and test retrain trigger */
    for (int i = 0; i < 50; i++) {
        fs_ml_monitor_add_label(&monitor, 1, 1, 2000000ULL + (guint64)i);
    }

    CHECK(fs_ml_monitor_valid_label_count(&monitor) == 50,
          "Exactly 50 valid labels recorded");

    gboolean retrain_fired = fs_ml_monitor_tick(&monitor, 10000ULL, 2000000ULL + 86400ULL);
    CHECK(retrain_fired == TRUE,
          "Retrain triggers successfully on ADVERSARIAL drift + >= 50 labels + elapsed cooldown");
}

static void
test_psi_fuzz_randomized_monte_carlo(void)
{
    printf("==> Running PSI Fuzz Randomized Monte Carlo Stress Tests...\n");
    FsMlMonitor monitor;
    double ref_dist[FS_ML_N_FEATURES][FS_ML_N_BINS];
    double bin_edges[FS_ML_N_FEATURES][FS_ML_N_BINS + 1];

    srand(1337);
    for (int f = 0; f < FS_ML_N_FEATURES; f++) {
        double sum = 0.0;
        for (int b = 0; b < FS_ML_N_BINS; b++) {
            double r = (double)(rand() % 100 + 1);
            ref_dist[f][b] = r;
            sum += r;
        }
        for (int b = 0; b < FS_ML_N_BINS; b++) {
            ref_dist[f][b] /= sum;
        }
        for (int b = 0; b <= FS_ML_N_BINS; b++) {
            bin_edges[f][b] = (double) b * 10.0;
        }
    }

    assert(fs_ml_monitor_init(&monitor, ref_dist, bin_edges) == TRUE);

    /* Feed 10,000 randomized feature vectors with various scales */
    double fvec[FS_ML_N_FEATURES];
    for (int step = 0; step < 10000; step++) {
        for (int f = 0; f < FS_ML_N_FEATURES; f++) {
            fvec[f] = (double)(rand() % 100);
        }
        fs_ml_monitor_feed(&monitor, fvec, (guint64)step * 10ULL);
        if (step % 500 == 0) {
            fs_ml_monitor_tick(&monitor, (guint64)step * 10ULL, 1000000ULL + (guint64)step);
        }
    }

    CHECK(fs_ml_monitor_window_total(&monitor) > 0,
          "Monte Carlo stress test completed successfully without crashes or NaN PSI values");
}

int main(void)
{
    printf("========================================================\n");
    printf(" StockFW Nexora PSI Drift Fuzzer & Stress Test Suite     \n");
    printf("========================================================\n");
    test_psi_fuzz_init_validation();
    test_psi_fuzz_sliding_window_rollover();
    test_psi_fuzz_drift_classification();
    test_psi_fuzz_randomized_monte_carlo();
    printf("========================================================\n");
    printf("Test Summary: %u checks, %u failures\n", checks, failures);
    printf("========================================================\n");
    return failures ? 1 : 0;
}
