/*---[ fs-ml.h ]---------------------------------------------------------
 * StockFW Nexora / AEGIS-ML: Behavioral Anomaly & TinyML Threat Detection Engine
 * Part of StockFW Phase v1.2 (The Neural Sentinel)
 *
 * Evaluates host network activity windows against a quantized decision-tree
 * ensemble in <0.05ms with zero cloud dependency and zero telemetry.
 *--------------------------------------------------------------------*/
#ifndef FS_ML_H
#define FS_ML_H

#include <glib.h>
#include "core/fs-types.h"

G_BEGIN_DECLS

typedef enum
{
	FS_ML_VERDICT_NORMAL = 0,
	FS_ML_VERDICT_SCAN,
	FS_ML_VERDICT_BRUTE,
	FS_ML_VERDICT_BEACON
} FsMlVerdict;

typedef struct
{
	double event_rate;        /* events per sliding window           */
	double burst_ratio;       /* max burst vs average rate           */
	double distinct_ports;    /* distinct ports touched              */
	double distinct_peers;    /* distinct remote IPs touched         */
	double tcp_ratio;         /* TCP event fraction                  */
	double udp_ratio;         /* UDP event fraction                  */
	double length_mean;       /* average packet/hit length           */
	double length_std;        /* standard deviation of lengths       */
	double beacon_regularity; /* inter-arrival regularity            */
	double login_port_frac;   /* fraction hitting login ports        */
	double block_ratio;       /* fraction of blocked events          */
	double threat_intel_frac; /* fraction hitting threat intel rules */
	double hour_of_day;       /* 0 - 23                              */
} FsMlHostFeatures;

/* Evaluate feature vector against the embedded quantized GBDT model */
FsMlVerdict fs_ml_predict (const FsMlHostFeatures *features, double *out_confidence);

/* Extract features from a sliding window of FsHit events for a specific remote host */
void fs_ml_extract_features (GPtrArray *hits, const gchar *target_host, FsMlHostFeatures *out_features);

G_END_DECLS

#endif /* FS_ML_H */
