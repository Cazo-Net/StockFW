/*---[ fs-ml-engine.c ]--------------------------------------------------
 * Neural Sentinel: Embedded TinyML Inference Engine Unit Tests
 *--------------------------------------------------------------------*/
#include "core/fs-ml.h"
#include <assert.h>
#include <stdio.h>

void
fs_ml_engine_run_tests (void)
{
	printf ("Running Neural Sentinel TinyML engine tests...\n");

	FsMlHostFeatures normal_flow = {
		.event_rate = 2.0, .burst_ratio = 1.2, .distinct_ports = 1.0,
		.distinct_peers = 1.0, .tcp_ratio = 0.9, .udp_ratio = 0.1,
		.length_mean = 500.0, .length_std = 50.0, .beacon_regularity = 0.1,
		.login_port_frac = 0.0, .block_ratio = 0.0, .threat_intel_frac = 0.0,
		.hour_of_day = 14.0
	};

	double conf = 0.0;
	FsMlVerdict v = fs_ml_predict (&normal_flow, &conf);
	assert (v == FS_ML_VERDICT_NORMAL);

	FsMlHostFeatures scan_flow = {
		.event_rate = 120.0, .burst_ratio = 8.0, .distinct_ports = 45.0,
		.distinct_peers = 2.0, .tcp_ratio = 0.95, .udp_ratio = 0.05,
		.length_mean = 60.0, .length_std = 10.0, .beacon_regularity = 0.0,
		.login_port_frac = 0.0, .block_ratio = 0.8, .threat_intel_frac = 0.0,
		.hour_of_day = 3.0
	};

	v = fs_ml_predict (&scan_flow, &conf);
	assert (v == FS_ML_VERDICT_SCAN);

	printf ("Neural Sentinel TinyML engine tests passed successfully.\n");
}
