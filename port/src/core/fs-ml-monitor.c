/*---[ fs-ml-monitor.c ]------------------------------------------------
 * PSI drift monitoring and retrain trigger implementation.
 *--------------------------------------------------------------------*/

#include "core/fs-ml-monitor.h"
#include <math.h>
#include <string.h>

gboolean
fs_ml_monitor_init(FsMlMonitor *m,
                   const double ref_dist[FS_ML_N_FEATURES][FS_ML_N_BINS],
                   const double bin_edges[FS_ML_N_FEATURES][FS_ML_N_BINS + 1])
{
    int f, b;

    g_return_val_if_fail(m != NULL, FALSE);
    g_return_val_if_fail(ref_dist != NULL, FALSE);
    g_return_val_if_fail(bin_edges != NULL, FALSE);

    for (f = 0; f < FS_ML_N_FEATURES; f++) {
        double sum = 0.0;
        for (b = 0; b < FS_ML_N_BINS; b++) {
            if (ref_dist[f][b] < 0.0 || ref_dist[f][b] > 1.0)
                return FALSE;
            sum += ref_dist[f][b];
        }
        if (fabs(sum - 1.0) > 0.01)
            return FALSE;

        for (b = 0; b < FS_ML_N_BINS; b++) {
            if (bin_edges[f][b] >= bin_edges[f][b + 1])
                return FALSE;
        }
    }

    memset(m, 0, sizeof(*m));
    for (f = 0; f < FS_ML_N_FEATURES; f++) {
        for (b = 0; b < FS_ML_N_BINS; b++) {
            m->ref_dist[f][b] = ref_dist[f][b];
            m->bin_edges[f][b] = bin_edges[f][b];
        }
        m->bin_edges[f][FS_ML_N_BINS] = bin_edges[f][FS_ML_N_BINS];
    }

    m->drift = FS_ML_DRIFT_INSUFFICIENT;
    m->initialized = TRUE;
    return TRUE;
}

static inline guint32
bin_lookup(const double edges[FS_ML_N_BINS + 1], double value)
{
    int b;
    for (b = 0; b < FS_ML_N_BINS; b++) {
        if (value < edges[b + 1])
            return (guint32) b;
    }
    return FS_ML_N_BINS - 1;
}

void
fs_ml_monitor_feed(FsMlMonitor *m,
                   const double features[FS_ML_N_FEATURES],
                   guint64 now_ms)
{
    int f;

    g_return_if_fail(m != NULL && m->initialized);
    g_return_if_fail(features != NULL);

    if (m->window_total > 0 &&
        (now_ms - m->window_start_ms) > (guint64) FS_ML_WINDOW_S * 1000) {
        memset(m->window_counts, 0, sizeof(m->window_counts));
        memset(m->feat_mean, 0, sizeof(m->feat_mean));
        memset(m->feat_m2, 0, sizeof(m->feat_m2));
        memset(m->feat_count, 0, sizeof(m->feat_count));
        m->window_total = 0;
    }

    if (m->window_total == 0)
        m->window_start_ms = now_ms;

    m->window_total++;

    for (f = 0; f < FS_ML_N_FEATURES; f++) {
        guint32 bin = bin_lookup(m->bin_edges[f], features[f]);
        m->window_counts[f][bin]++;

        guint64 n = m->feat_count[f] + 1;
        double delta = features[f] - m->feat_mean[f];
        m->feat_mean[f] += delta / (double) n;
        m->feat_m2[f] += delta * (features[f] - m->feat_mean[f]);
        m->feat_count[f] = n;
    }
}

void
fs_ml_monitor_record_confidence(FsMlMonitor *m, double confidence)
{
    g_return_if_fail(m != NULL && m->initialized);
    g_return_if_fail(confidence >= 0.0 && confidence <= 1.0);

    guint64 n = m->conf_count + 1;
    double delta = confidence - m->conf_mean;
    m->conf_mean += delta / (double) n;
    m->conf_m2 += delta * (confidence - m->conf_mean);
    m->conf_count = n;

    if (confidence < 0.5)
        m->conf_low_count++;
}

void
fs_ml_monitor_add_label(FsMlMonitor *m, int class_id, guint8 source, guint64 epoch)
{
    g_return_if_fail(m != NULL && m->initialized);
    g_return_if_fail(class_id >= 0 && class_id <= 3);

    if (m->label_count < FS_ML_MAX_LABELS) {
        m->labels[m->label_head].class_id = class_id;
        m->labels[m->label_head].epoch = epoch;
        m->labels[m->label_head].source = source;
        m->label_head = (m->label_head + 1) % FS_ML_MAX_LABELS;
        m->label_count++;
    } else {
        m->labels[m->label_head].class_id = class_id;
        m->labels[m->label_head].epoch = epoch;
        m->labels[m->label_head].source = source;
        m->label_head = (m->label_head + 1) % FS_ML_MAX_LABELS;
    }
}

static double
psi_one_feature(const double ref[FS_ML_N_BINS],
                const guint32 counts[FS_ML_N_BINS],
                guint64 total)
{
    double psi = 0.0;
    int b;
    const double eps = 1e-4;

    for (b = 0; b < FS_ML_N_BINS; b++) {
        double actual = (double) counts[b] / (double) total;
        double expected = ref[b];

        if (actual < eps) actual = eps;
        if (expected < eps) expected = eps;

        psi += (actual - expected) * log(actual / expected);
    }
    return psi;
}

gboolean
fs_ml_monitor_tick(FsMlMonitor *m, guint64 now_ms, guint64 now_epoch)
{
    int f;
    int features_above_watch = 0;
    int features_above_action = 0;

    g_return_val_if_fail(m != NULL && m->initialized, FALSE);

    if (m->window_total < FS_ML_MIN_SAMPLES) {
        m->drift = FS_ML_DRIFT_INSUFFICIENT;
        m->psi_aggregate = 0.0;
        return FALSE;
    }

    m->psi_aggregate = 0.0;
    for (f = 0; f < FS_ML_N_FEATURES; f++) {
        m->psi[f] = psi_one_feature(m->ref_dist[f], m->window_counts[f],
                                    m->window_total);
        m->psi_aggregate += m->psi[f];

        if (m->psi[f] >= FS_ML_PSI_WATCH)
            features_above_watch++;
        if (m->psi[f] >= FS_ML_PSI_FEATURE)
            features_above_action++;
    }

    if (features_above_action >= 2 || m->psi_aggregate > FS_ML_PSI_AGGREGATE)
        m->drift = FS_ML_DRIFT_ADVERSARIAL;
    else if (features_above_watch >= 1)
        m->drift = FS_ML_DRIFT_BENIGN;
    else
        m->drift = FS_ML_DRIFT_NONE;

    gboolean should_retrain = FALSE;

    if (m->drift == FS_ML_DRIFT_ADVERSARIAL &&
        fs_ml_monitor_valid_label_count(m) >= FS_ML_RETRAIN_LABELS &&
        (now_epoch - m->last_retrain_epoch) >= FS_ML_RETRAIN_COOLDOWN_S) {
        should_retrain = TRUE;
    }

    if ((now_epoch - m->last_schedule_epoch) >= FS_ML_RETRAIN_SCHEDULE_S &&
        (now_epoch - m->last_retrain_epoch) >= FS_ML_RETRAIN_COOLDOWN_S) {
        should_retrain = TRUE;
    }

    if (should_retrain) {
        m->last_retrain_epoch = now_epoch;
        m->last_schedule_epoch = now_epoch;
    }

    return should_retrain;
}

FsMlDriftSignal
fs_ml_monitor_drift(const FsMlMonitor *m)
{
    g_return_val_if_fail(m != NULL, FS_ML_DRIFT_INSUFFICIENT);
    return m->drift;
}

double
fs_ml_monitor_psi_feature(const FsMlMonitor *m, int feature)
{
    g_return_val_if_fail(m != NULL, 0.0);
    g_return_val_if_fail(feature >= 0 && feature < FS_ML_N_FEATURES, 0.0);
    return m->psi[feature];
}

double
fs_ml_monitor_psi_aggregate(const FsMlMonitor *m)
{
    g_return_val_if_fail(m != NULL, 0.0);
    return m->psi_aggregate;
}

guint64
fs_ml_monitor_window_total(const FsMlMonitor *m)
{
    g_return_val_if_fail(m != NULL, 0);
    return m->window_total;
}

guint32
fs_ml_monitor_label_count(const FsMlMonitor *m)
{
    g_return_val_if_fail(m != NULL, 0);
    return m->label_count;
}

guint32
fs_ml_monitor_valid_label_count(const FsMlMonitor *m)
{
    guint32 valid = 0;
    guint32 i;

    g_return_val_if_fail(m != NULL, 0);

    for (i = 0; i < m->label_count && i < FS_ML_MAX_LABELS; i++) {
        /* Count labels originating from trusted or confirmed sources:
         * source 0 = copilot rule match, source 1 = user confirmation, source 2 = confirmed auto-block */
        if (m->labels[i].source <= 2 && m->labels[i].class_id >= 0 && m->labels[i].class_id <= 3) {
            valid++;
        }
    }
    return valid;
}

double
fs_ml_monitor_conf_mean(const FsMlMonitor *m)
{
    g_return_val_if_fail(m != NULL, 0.0);
    g_return_val_if_fail(m->conf_count > 0, 0.0);
    return m->conf_mean;
}

double
fs_ml_monitor_conf_std(const FsMlMonitor *m)
{
    g_return_val_if_fail(m != NULL, 0.0);
    g_return_val_if_fail(m->conf_count > 1, 0.0);
    return sqrt(m->conf_m2 / (double)(m->conf_count - 1));
}

double
fs_ml_monitor_conf_low_fraction(const FsMlMonitor *m)
{
    g_return_val_if_fail(m != NULL, 0.0);
    g_return_val_if_fail(m->conf_count > 0, 0.0);
    return (double) m->conf_low_count / (double) m->conf_count;
}

void
fs_ml_monitor_reset_reference(FsMlMonitor *m,
                              const double ref_dist[FS_ML_N_FEATURES][FS_ML_N_BINS],
                              const double bin_edges[FS_ML_N_FEATURES][FS_ML_N_BINS + 1])
{
    int f, b;

    g_return_if_fail(m != NULL && m->initialized);

    for (f = 0; f < FS_ML_N_FEATURES; f++) {
        for (b = 0; b < FS_ML_N_BINS; b++) {
            m->ref_dist[f][b] = ref_dist[f][b];
            m->bin_edges[f][b] = bin_edges[f][b];
        }
        m->bin_edges[f][FS_ML_N_BINS] = bin_edges[f][FS_ML_N_BINS];
    }

    memset(m->window_counts, 0, sizeof(m->window_counts));
    memset(m->feat_mean, 0, sizeof(m->feat_mean));
    memset(m->feat_m2, 0, sizeof(m->feat_m2));
    memset(m->feat_count, 0, sizeof(m->feat_count));
    m->window_total = 0;
    m->drift = FS_ML_DRIFT_INSUFFICIENT;
    m->psi_aggregate = 0.0;
}

void
fs_ml_monitor_mark_retrained(FsMlMonitor *m, guint64 now_epoch)
{
    g_return_if_fail(m != NULL);
    m->last_retrain_epoch = now_epoch;
    m->last_schedule_epoch = now_epoch;
    m->label_count = 0;
    m->label_head = 0;
    memset(m->labels, 0, sizeof(m->labels));
}

const char *
fs_ml_monitor_drift_str(FsMlDriftSignal s)
{
    switch (s) {
    case FS_ML_DRIFT_INSUFFICIENT: return "insufficient_data";
    case FS_ML_DRIFT_NONE:         return "none";
    case FS_ML_DRIFT_BENIGN:       return "benign";
    case FS_ML_DRIFT_ADVERSARIAL:  return "adversarial";
    default:                       return "unknown";
    }
}
