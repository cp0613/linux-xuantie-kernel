/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __XUANTIE_NTRACE_H__
#define __XUANTIE_NTRACE_H__

#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/types.h>
#include <linux/perf_event.h>

#include "xt_ntrace_control_interface.h"

enum XUANTIE_NTRACE_COMPONENT_TYPE {
	XUANTIE_NTRACE_ENCODER = 0,
	XUANTIE_NTRACE_FUNNEL,
	XUANTIE_NTRACE_SINK_SMEM,
};

struct xuantie_io_port {
	bool is_input; // input=1, output=0
	u32 endpoint_num;
	enum XUANTIE_NTRACE_COMPONENT_TYPE type;
	u64 base_addr;
};

struct xuantie_ntrace_encoder {
	//
	u32 cpu;
	u32 trace_format;
	u32 inst_mode;
	bool send_context;
	//
	bool inhibit_src;
	u32 src_id;
	//
	u32 inst_sync_mode;
	u32 inst_sync_max;
	bool inst_trigger_enable;
	//
	bool enable_timestamp;
	bool timestamp_runindebugmode;
	u32 timestamp_mode;
	u32 timestamp_prescale;
};

struct xuantie_ntrace_funnel {
	;
};

struct xuantie_ntrace_sink_smem {
	u64 start_addr;
	u64 limit_addr;
	void __iomem *vaddr;
	const char *working_mode;
	const char *format;
};

struct xuantie_ntrace_component {
	enum XUANTIE_NTRACE_COMPONENT_TYPE type;
	u64 reg_base;
	u64 reg_size;
	struct list_head list;

	union {
		struct xuantie_ntrace_encoder encoder;
		struct xuantie_ntrace_funnel funnel;
		struct xuantie_ntrace_sink_smem sink;
	};

	union {
		struct xt_trace_sink_control_info sink_info;
		struct xt_trace_funnel_control_info funnel_info;
		struct xt_trace_encoder_control_info encoder_info;
	};

	u32 in_num;
	u32 out_num;
	struct xuantie_io_port **in;
	struct xuantie_io_port **out;
};

extern struct list_head xuantie_ntrace_controllers;

struct xuantie_saved_conifg {
	u32 _size;
	u32 inst_mode;
	u32 src_bits;
	u32 timestamp_bits;
	u32 trace_ram_wrap;
	u32 _align;
};

#define XUANTIE_NTRACE_ADDR_MASK GENMASK(63, 0)
enum XUANTIE_NTRACE_MODE_TYPE {
	XUANTIE_NTRACE_PRIV_MODE_EXCL_NONE = 0,
	XUANTIE_NTRACE_PRIV_MODE_EXCL_KERN,
	XUANTIE_NTRACE_PRIV_MODE_EXCL_USER,
};

struct xuantie_ntrace_filter_attr {
	u64 start_addr;
	u64 stop_addr;
	u32 priv_mode; // user&kernel
};

struct xuantie_ntrace_pmu {
	struct pmu		pmu;
	u32			caps[32];
	struct perf_output_handle handle;
	struct perf_sample_data data;
	struct xuantie_ntrace_filter_attr filter_attr;
};

/**
 * struct xuantie_ntrace_aux_buf - Descriptor of the AUX buffer of xuantie_ntrace
 * @length:   size of the AUX buffer
 * @nr_pages: number of pages of the AUX buffer
 * @base:     start address of AUX buffer
 * @pos:      position in the AUX buffer to commit traced data
 */
struct xuantie_ntrace_aux_buf {
	unsigned long length;
	unsigned long nr_pages;
	void *base;
	unsigned long pos;
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
