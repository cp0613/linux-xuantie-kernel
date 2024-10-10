/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __XUANTIE_NTRACE_H__
#define __XUANTIE_NTRACE_H__

#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/types.h>
#include <linux/perf_event.h>

enum XUANTIE_NTRACE_COMPONENT_TYPE {
	XUANTIE_NTRACE_ENCODER = 0,
	XUANTIE_NTRACE_FUNNEL,
	XUANTIE_NTRACE_SINK_SMEM,
};

struct xuantie_io_port {
	bool is_input; // input=1, ouput=0
	u32 endpoint_num;
	enum XUANTIE_NTRACE_COMPONENT_TYPE type;
	u64 base_addr;
};

struct xuantie_ntrace_encoder {
	//
	u32 cpu;
	const char *trace_type;
	const char *insn_mode;
	bool send_context;
	//
	bool enable_src;
	u32 src_id;
	u32 src_bits;
	//
	const char *inst_sync_mode;
	u32 inst_sync_value;
	bool enable_cpu_trigger;
	//
	bool enable_timestamp;
	bool timestamp_runindebugmode;
	const char *timestamp_source;
	u32 timestamp_prescale;
	u32 timestamp_bits;
};

struct xuantie_ntrace_funnel {
	;
};

struct xuantie_ntrace_sink_smem {
	u64 start_addr;
	u64 limit_addr;
	const char *working_mode;
	const char *format;
};

struct xuantie_ntrace_component {
	enum XUANTIE_NTRACE_COMPONENT_TYPE type;
	resource_size_t reg_base;
	resource_size_t reg_size;
	struct list_head list;

	union {
		struct xuantie_ntrace_encoder encoder;
		struct xuantie_ntrace_funnel funnel;
		struct xuantie_ntrace_sink_smem sink;
	};

	u32 in_num;
	u32 out_num;
	struct xuantie_io_port **in;
	struct xuantie_io_port **out;
};

extern struct list_head xuantie_ntrace_controllers;

struct xuantie_ntrace_pmu {
	struct pmu		pmu;
	u32			caps[32];
};

/**
 * struct ntrace - per-cpu ntrace context
 * @handle:		perf output handle
 */
struct xuantie_ntrace {
	struct perf_output_handle handle;
};

static inline const char *xuantie_ntrace_type2str(enum XUANTIE_NTRACE_COMPONENT_TYPE type)
{
	switch (type) {
	case XUANTIE_NTRACE_ENCODER:
		return "encoder";
	case XUANTIE_NTRACE_FUNNEL:
		return "funnel";
	case XUANTIE_NTRACE_SINK_SMEM:
		return "sink_smem";
	default:
		return "none";
	}
} 

static inline int count_device_node_child(struct device_node *parent)
{
	struct device_node *child;
	int count = 0;
	for_each_child_of_node(parent, child) {
		count++;
	}
	return count;
}

static inline int get_list_count(struct list_head *head)
{
	u32 count = 0;
	struct list_head *pos;
	list_for_each(pos, head) {
		count++;
	}
	return count;
}

#endif /* __XUANTIE_NTRACE_H__ */
