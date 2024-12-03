/* SPDX-License-Identifier: GPL-2.0 */
#ifndef INCLUDE__PERF_XUANTIE_NTRACE_H__
#define INCLUDE__PERF_XUANTIE_NTRACE_H__

#define XUANTIE_NTRACE_PMU_NAME		"xuantie_ntrace"
#define XUANTIE_NTRACE_AUXTRACE_PRIV_SIZE	sizeof(u64)

union perf_event;
struct perf_session;
struct perf_pmu;

struct auxtrace_record *xuantie_ntrace_recording_init(int *err,
						struct perf_pmu *xuantie_ntrace_pmu);

int xuantie_ntrace_process_auxtrace_info(union perf_event *event,
				   struct perf_session *session);

#endif
