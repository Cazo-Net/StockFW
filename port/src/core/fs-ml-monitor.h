/*---[ fs-ml-monitor.h ]------------------------------------------------
 * PSI drift monitoring and retrain trigger for StockFW Nexora (AEGIS-ML).
 *
 * Continuous monitoring (every 5s tick):
 *   - Accumulates feature vectors into a 15-minute sliding window
 *   - Computes per-feature PSI against the reference (training-time) distribution
 *   - Tracks prediction confidence via Welford's running mean/variance
 *   - Classifies drift: none | benign | adversarial | insufficient_data
 *
 * Triggered retraining (rare batch job):
 *   - Fires when drift == adversarial AND new labels >= 50
 *   - Or on a monthly schedule
 *   - Or via manual CLI: stockfw copilot retrain
 *
 * Bounded state: ~4 KB total. No dynamic allocation after init.
 * No network calls. No OS calls. GLib only.
 *--------------------------------------------------------------------*/
#ifndef FS_ML_MONITOR_H
#define FS_ML_MONITOR_H

#pragma once

#include <glib.h>
#include <stdint.h>

/* Number of features in the sentinel's feature vector. */
#define FS_ML_N_FEATURES      16
/* Number of quantile bins per feature for PSI. */
#define FS_ML_N_BINS          10
/* Sliding window length in seconds (15 minutes). */
#define FS_ML_WINDOW_S        900
/* Bucket size in seconds (10s, matching fs_activity.c). */
#define FS_ML_BUCKET_S        10
/* Number of buckets in the window. */
#define FS_ML_N_BUCKETS       (FS_ML_WINDOW_S / FS_ML_BUCKET_S)
/* Minimum events in window before PSI is computed. */
#define FS_ML_MIN_SAMPLES     200
/* Per-feature PSI threshold for "action" (above: this feature is drifting). */
#define FS_ML_PSI_FEATURE     0.15
/* Aggregate PSI threshold for "action" (above: overall drift is significant). */
#define FS_ML_PSI_AGGREGATE   0.25
/* Watch threshold (below action, above none). */
#define FS_ML_PSI_WATCH       0.10
/* Minimum new labels required to trigger retrain on adversarial drift. */
#define FS_ML_RETRAIN_LABELS  50
/* Maximum labels to track (bounded). */
#define FS_ML_MAX_LABELS      256
/* Minimum interval between retrain triggers (24 hours). */
#define FS_ML_RETRAIN_COOLDOWN_S  86400
/* Monthly schedule interval. */
#define FS_ML_RETRAIN_SCHEDULE_S  2592000

/* Drift signal classification. */
typedef enum {
    FS_ML_DRIFT_INSUFFICIENT = 0,  /* < FS_ML_MIN_SAMPLES in window */
    FS_ML_DRIFT_NONE           = 1,  /* all features < FS_ML_PSI_WATCH */
    FS_ML_DRIFT_BENIGN         = 2,  /* 1 feature in [WATCH, FEATURE) */
    FS_ML_DRIFT_ADVERSARIAL    = 3,  /* >= 2 features >= FEATURE, or aggregate > AGGREGATE */
} FsMlDriftSignal;

/* A single labeled event (for retrain trigger counting). */
typedef struct {
    int      class_id;     /* 0=NORMAL, 1=SCAN, 2=BRUTE, 3=BEACON */
    guint64  epoch;        /* Unix seconds */
    guint8   source;       /* 0=copilot, 1=user, 2=sentinel */
} FsMlLabel;

/* The monitor state. Stack-allocated or embedded in FsCopilot. ~4 KB. */
typedef struct {
    double   ref_dist[FS_ML_N_FEATURES][FS_ML_N_BINS];
    double   bin_edges[FS_ML_N_FEATURES][FS_ML_N_BINS + 1];

    guint32  window_counts[FS_ML_N_FEATURES][FS_ML_N_BINS];
    guint64  window_total;
    guint64  window_start_ms;

    double   feat_mean[FS_ML_N_FEATURES];
    double   feat_m2[FS_ML_N_FEATURES];
    guint64  feat_count[FS_ML_N_FEATURES];

    double   conf_mean;
    double   conf_m2;
    guint64  conf_count;
    guint32  conf_low_count;

    double   psi[FS_ML_N_FEATURES];
    double   psi_aggregate;
    FsMlDriftSignal drift;

    FsMlLabel labels[FS_ML_MAX_LABELS];
    guint32   label_count;
    guint32   label_head;
    guint64   last_retrain_epoch;
    guint64   last_schedule_epoch;

    gboolean  initialized;
} FsMlMonitor;

gboolean fs_ml_monitor_init(FsMlMonitor *m,
                            const double ref_dist[FS_ML_N_FEATURES][FS_ML_N_BINS],
                            const double bin_edges[FS_ML_N_FEATURES][FS_ML_N_BINS + 1]);

void fs_ml_monitor_feed(FsMlMonitor *m,
                        const double features[FS_ML_N_FEATURES],
                        guint64 now_ms);

void fs_ml_monitor_record_confidence(FsMlMonitor *m, double confidence);
void fs_ml_monitor_add_label(FsMlMonitor *m, int class_id, guint8 source, guint64 epoch);
gboolean fs_ml_monitor_tick(FsMlMonitor *m, guint64 now_ms, guint64 now_epoch);

FsMlDriftSignal fs_ml_monitor_drift(const FsMlMonitor *m);
double          fs_ml_monitor_psi_feature(const FsMlMonitor *m, int feature);
double          fs_ml_monitor_psi_aggregate(const FsMlMonitor *m);
guint64         fs_ml_monitor_window_total(const FsMlMonitor *m);
guint32         fs_ml_monitor_label_count(const FsMlMonitor *m);
guint32         fs_ml_monitor_valid_label_count(const FsMlMonitor *m);
double          fs_ml_monitor_conf_mean(const FsMlMonitor *m);
double          fs_ml_monitor_conf_std(const FsMlMonitor *m);
double          fs_ml_monitor_conf_low_fraction(const FsMlMonitor *m);

void fs_ml_monitor_reset_reference(FsMlMonitor *m,
                                   const double ref_dist[FS_ML_N_FEATURES][FS_ML_N_BINS],
                                   const double bin_edges[FS_ML_N_FEATURES][FS_ML_N_BINS + 1]);

void fs_ml_monitor_mark_retrained(FsMlMonitor *m, guint64 now_epoch);
const char *fs_ml_monitor_drift_str(FsMlDriftSignal s);

G_END_DECLS

#endif /* FS_ML_MONITOR_H */
