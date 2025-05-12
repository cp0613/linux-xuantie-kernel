// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/bitfield.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/perf_event.h>

#include "xuantie_ntrace.h"
#include "xt_ntrace_control_interface.h"

#define TEST_SRAM_SINK	0
#define TEST_LOG_ON		0

LIST_HEAD(xuantie_ntrace_controllers);
static struct xuantie_ntrace_pmu xuantie_ntrace_pmu;
static bool trace_componnet_detected;

// Function Declaration
static void xuantie_ntrace_event_start(struct perf_event *event, int flags);

PMU_FORMAT_ATTR(start_addr, "config:0-63");
PMU_FORMAT_ATTR(stop_addr,  "config1:0-63");

static struct attribute *xuantie_ntrace_filter_attrs[] = {
	&format_attr_start_addr.attr,
	&format_attr_stop_addr.attr,
	NULL
};

static struct attribute_group xuantie_ntrace_filter_attr_group = {
	.name = "format",
	.attrs = xuantie_ntrace_filter_attrs,
};

static const struct attribute_group *xuantie_ntrace_attr_groups[] = {
	&xuantie_ntrace_filter_attr_group,
	NULL
};

static void xuantue_ntrace_init_filter_attrs(struct perf_event *event)
{
	xuantie_ntrace_pmu.filter_attr.start_addr = event->attr.config;
	xuantie_ntrace_pmu.filter_attr.stop_addr  = event->attr.config1;

	if (event->attr.exclude_kernel)
		xuantie_ntrace_pmu.filter_attr.priv_mode = XUANTIE_NTRACE_PRIV_MODE_EXCL_KERN;
	else if (event->attr.exclude_user)
		xuantie_ntrace_pmu.filter_attr.priv_mode = XUANTIE_NTRACE_PRIV_MODE_EXCL_USER;
	else
		xuantie_ntrace_pmu.filter_attr.priv_mode = XUANTIE_NTRACE_PRIV_MODE_EXCL_NONE;

	pr_info("start_addr=0x%llx stop_addr=0x%llx priv_mode=%d\n",
		xuantie_ntrace_pmu.filter_attr.start_addr,
		xuantie_ntrace_pmu.filter_attr.stop_addr,
		xuantie_ntrace_pmu.filter_attr.priv_mode);
}

static int console_msg_out(const char *str)
{
	pr_info("%s", str);
	return 0;
}

static void
build_encoder_config_info(struct xuantie_ntrace_component *component,
			  struct xt_trace_encoder_config_info *encoder_config)
{
	memset(encoder_config, 0, sizeof(struct xt_trace_encoder_config_info));

	encoder_config->inst_mode = component->encoder.inst_mode;
	encoder_config->sennd_context = component->encoder.send_context;
	encoder_config->inst_trigger_enable =
		component->encoder.inst_trigger_enable;
	encoder_config->inst_stall_ena = component->encoder.stall_enable;
	encoder_config->inhibit_src = component->encoder.inhibit_src;
	encoder_config->inst_sync_mode = component->encoder.inst_sync_mode;
	encoder_config->inst_sync_max = component->encoder.inst_sync_max;
	encoder_config->record_format = 1; // 6MDO+2MESO

	// inst feature: all false
	encoder_config->inst_no_addr_diff = false;
	encoder_config->inst_no_trap_addr = false;
	encoder_config->inst_en_sequential_tail_jump = false;
	encoder_config->inst_en_implicit_return = false;
	encoder_config->inst_en_branch_prediction = false;
	encoder_config->inst_en_jump_target_cache = false;
	encoder_config->inst_implicit_return_mode = 0;
	encoder_config->inst_en_repeated_history = false;
	encoder_config->inst_en_all_jumps = false;
	encoder_config->inst_extend_addr_msb = false;

	encoder_config->src_id = component->encoder.src_id;
	encoder_config->src_bits = component->encoder_info.default_src_bits;

	// data trace: disable
	encoder_config->data_trace_enable = false;

	// enable timestamp
	if (component->encoder_info.support_timestamp_enable &&
	    component->encoder.enable_timestamp) {
		encoder_config->timestamp_enable = true;
		encoder_config->timestamp_run_in_debugmode = false;
		encoder_config->timestamp_type = 1; // timestamp_external
		encoder_config->timestamp_prescale =
			component->encoder.timestamp_prescale;
	}
}

static void build_filter_one(struct xt_trace_encoder_filter_config_info *filter_config)
{
	u32 priv_filter_value = FILTER_U_MODE | FILTER_S_HS_MODE; /* only u+s */
	bool comparator_enable = false;
	u32 prim_func = COMPFUNCTION_ALWAYS_TRUE;
	u32 second_func = COMPFUNCTION_ALWAYS_TRUE;

	if (xuantie_ntrace_pmu.filter_attr.start_addr
	|| xuantie_ntrace_pmu.filter_attr.stop_addr) {
		comparator_enable = true;

		if (xuantie_ntrace_pmu.filter_attr.start_addr == 0
		&& xuantie_ntrace_pmu.filter_attr.stop_addr != 0) {
			// equal to comparator_enable = true
			prim_func = COMPFUNCTION_ALWAYS_TRUE;
			second_func = COMPFUNCTION_EQUAL;
		} else if (xuantie_ntrace_pmu.filter_attr.start_addr != 0
		&& xuantie_ntrace_pmu.filter_attr.stop_addr == 0) {
			prim_func = COMPFUNCTION_EQUAL;
			second_func = COMPFUNCTION_LESS_THAN;
		} else {
			prim_func = COMPFUNCTION_EQUAL;
			second_func = COMPFUNCTION_EQUAL;
		}
	} else
		comparator_enable = false;

	if (xuantie_ntrace_pmu.filter_attr.priv_mode == XUANTIE_NTRACE_PRIV_MODE_EXCL_KERN)
		priv_filter_value = FILTER_U_MODE;
	else if (xuantie_ntrace_pmu.filter_attr.priv_mode == XUANTIE_NTRACE_PRIV_MODE_EXCL_USER)
		priv_filter_value = FILTER_S_HS_MODE;
	else
		priv_filter_value = FILTER_U_MODE | FILTER_S_HS_MODE;

	memset(filter_config, 0, sizeof(struct xt_trace_encoder_filter_config_info));

	filter_config->filter_i = 0;
	filter_config->filter_match_privilege = true;
	filter_config->filter_match_ecause = false;
	filter_config->filter_match_interrupt = false;
	filter_config->match_privilege_value = priv_filter_value;
	filter_config->match_value_interrupt = 0;
	filter_config->match_chioce_ecause = 0;
	filter_config->filter_match_dtype = false;
	filter_config->filter_match_dsize = false;
	filter_config->match_value_dtype = 0;
	filter_config->match_value_dsize = 0;

	// comparator 1
	filter_config->comparator1_enable = comparator_enable;
	filter_config->comp1_filter_number = 0;
	// config
	filter_config->comp1_primary_input = COMPTYPE_IADDR;       // p_iaddr
	filter_config->comp1_primary_function = prim_func;
	filter_config->comp1_primary_notify = false;
	filter_config->comp1_secondary_input = COMPTYPE_IADDR;     // s_iaddr
	filter_config->comp1_secondary_function = second_func;
	filter_config->comp1_secondary_notify = false;
	// start with primary true, end with secondary true
	filter_config->comp1_match_mode = COMPMATCHMODE_PRIMARY_TRUE_UNTIL_SECOND_TRUE;
	filter_config->comp1_primary_match_low_value = xuantie_ntrace_pmu.filter_attr.start_addr;
	filter_config->comp1_primary_match_high_value = 0x0;
	filter_config->comp1_secondary_match_low_value = xuantie_ntrace_pmu.filter_attr.stop_addr;
	filter_config->comp1_secondary_match_high_value = 0x0;

	// comparator 2
	filter_config->comparator2_enable = false;
	// filter_config->comp2_filter_number;
	////config
	// filter_config->comp2_primary_input;
	// filter_config->comp2_primary_function;
	// filter_config->comp2_primary_notify;
	// filter_config->comp2_secondary_input;
	// filter_config->comp2_secondary_function;
	// filter_config->comp2_secondary_notify;
	// filter_config->comp2_match_mode;
	// filter_config->comp2_primary_match_low_value;
	// filter_config->comp2_primary_match_high_value;
	// filter_config->comp2_secondary_match_low_value;
	// filter_config->comp2_secondary_match_high_value;

	// comparator 3
	filter_config->comparator3_enable = false;
	// filter_config->comp3_filter_number;
	////config
	// filter_config->comp3_primary_input;
	// filter_config->comp3_primary_function;
	// filter_config->comp3_primary_notify;
	// filter_config->comp3_secondary_input;
	// filter_config->comp3_secondary_function;
	// filter_config->comp3_secondary_notify;
	// filter_config->comp3_match_mode;
	// filter_config->comp3_primary_match_low_value;
	// filter_config->comp3_primary_match_high_value;
	// filter_config->comp3_secondary_match_low_value;
	// filter_config->comp3_secondary_match_high_value;
}

static void
build_funnel_config_info(struct xuantie_ntrace_component *component,
			 struct xt_trace_funnel_config_info *funnel_config)
{
	funnel_config->disable_input = 0;
}

static void
build_sink_config_info(struct xuantie_ntrace_component *component,
		       struct xt_trace_sink_config_info *sink_config)
{
	memset(sink_config, 0, sizeof(struct xt_trace_sink_config_info));

#if TEST_SRAM_SINK
	sink_config->component_type = TRCOMP_RAMSINK;
	sink_config->type = TRACE_SRAM_SINK;        // configure to SMEM Sink
	sink_config->ram_sink_stop_on_wrap = false; // the circular buffer gets full
	sink_config->ram_sink_mem_format = 0;       // plain bytes
	sink_config->ram_sink_start = 0;
	sink_config->ram_sink_limit = 0x7fc;
	sink_config->ram_sink_write_point = 0;
#else
	sink_config->component_type = TRCOMP_RAMSINK;
	sink_config->type = TRACE_SMEM_SINK;        // configure to SMEM Sink
	sink_config->ram_sink_stop_on_wrap = false; // the circular buffer gets full
	sink_config->ram_sink_mem_format = 0;       // plain bytes
	sink_config->ram_sink_start = component->sink.start_addr;
	sink_config->ram_sink_limit = (component->sink.limit_addr & 0xffffff00) - 4;
	component->sink.limit_addr = component->sink.limit_addr & 0xffffff00;
	sink_config->ram_sink_write_point = component->sink.start_addr;
#endif

	////for pib sink
	// sink_config->pib_sink_mode;
	// sink_config->pib_sink_clk_center;
	// sink_config->pib_sink_divider;
	//
	////for atb bridge
	// sink_config->atb_bridge_id;
	//
	////common config
	// sink_config->sink_async_freq;
}

void xuantie_build_saved_config(struct xuantie_saved_conifg *config,
				struct xuantie_ntrace_component *component,
				int wrap)
{
	memset(config, 0, sizeof(struct xuantie_saved_conifg));

	/* Save encoder info. */
	config->_size = sizeof(struct xuantie_saved_conifg);
	config->inst_mode = component->encoder.inst_mode;
	if (!component->encoder.inhibit_src)
		config->src_bits = component->encoder_info.default_src_bits;
	else
		config->src_bits = 0;
	if (component->encoder.enable_timestamp)
		config->timestamp_bits = component->encoder_info.timestamp_width;
	else
		config->timestamp_bits = 0;

	/* Save trRamWrap. */
	config->trace_ram_wrap = wrap;
}

static int trace_register_write(u64 addr, u32 value)
{
	iowrite32(value, (void __iomem *)(unsigned long)addr);
#if TEST_LOG_ON
	pr_info("--->write 0x%llx with 0x%x\n", addr, value);
#endif
	return 0;
}

static int trace_register_read(u64 addr, u32 *value)
{
	*value = ioread32((void __iomem *)(unsigned long)addr);
#if TEST_LOG_ON
	pr_info("--->read 0x%llx get 0x%x\n", addr, *value);
#endif
	return 0;
}

static int xuantie_ntrace_event_init(struct perf_event *event)
{
	if (event->attr.type != xuantie_ntrace_pmu.pmu.type)
		return -ENOENT;

	xuantue_ntrace_init_filter_attrs(event);

	return 0;
}

static int xuantie_ntrace_event_add(struct perf_event *event, int flags)
{
	struct xuantie_ntrace_component *component;
	struct xuantie_ntrace_aux_buf *buf;
	bool encoder_find = false;
	bool funnel_find = false;
	bool sink_find = false;

	// pr_info("%s:%d flags=%d\n", __func__, __LINE__, flags);

	/* Set interfaces needed for Trace Control Lib. */
	xt_trace_control_init_rw_trace_interface(console_msg_out,
						 trace_register_write,
						 trace_register_read, NULL);

	/* Detect all Trace Components.  */
	if (trace_componnet_detected == false) {
		list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
			if (component->type == XUANTIE_NTRACE_ENCODER) {
				xt_init_trace_encoder_control_info(&component->encoder_info, component->reg_base);
				if (xt_trace_detect_trace_encoder(&component->encoder_info)) {
					pr_info("Failed to detect trace encoder with base addr 0x%llx.\n",
						component->encoder_info.base_addr);
					return -1;
				}
				encoder_find = true;
			} else if (component->type == XUANTIE_NTRACE_FUNNEL) {
				xt_init_trace_funnel_control_info(&component->funnel_info, component->reg_base);
				if (xt_trace_detect_trace_funnel(&component->funnel_info)) {
					pr_info("Failed to detect trace funnel with base addr 0x%llx.\n",
						component->funnel_info.base_addr);
					return -1;
				}
				funnel_find = true;
			} else if (component->type == XUANTIE_NTRACE_SINK_SMEM) {
				xt_init_trace_sink_control_info(&component->sink_info, component->reg_base);
				if (xt_trace_detect_trace_sink(&component->sink_info)) {
					pr_info("Failed to detect trace sink with base addr 0x%llx.\n",
						component->sink_info.base_addr);
					return -1;
				}
				sink_find = true;
			} else {
				pr_info("Unknown NTrace Component with type %d, base addr 0x%llx.\n",
					component->type, component->reg_base);
				return -1;
			}
		}
		if (!encoder_find || !funnel_find || !sink_find) {
			pr_info("There is no encoder or funnel or sink find, please check DTS file.\n");
			return -1;
		}
	}

	/* Mark all components have been detected.  */
	trace_componnet_detected = true;

	/* Config components. */
	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_ENCODER) {
			struct xt_trace_encoder_config_info encoder_config;
			struct xt_trace_encoder_filter_config_info filter_config;

			build_encoder_config_info(component, &encoder_config);
			if (xt_trace_encoder_config(&component->encoder_info,
						    &encoder_config)) {
				pr_info("Failed to config trace encoder with base addr 0x%llx.\n",
					component->encoder_info.base_addr);
				goto error_end;
			}

			//always use fiter 0, pass M-mode
			build_filter_one(&filter_config);
			if (xt_trace_filter_config(&component->encoder_info, &filter_config))
				goto error_end;
		} else if (component->type == XUANTIE_NTRACE_FUNNEL) {
			struct xt_trace_funnel_config_info funnel_config;

			build_funnel_config_info(component, &funnel_config);
			if (xt_trace_funnel_config(&component->funnel_info,
						   &funnel_config)) {
				pr_info("Failed to config trace funnel with base addr 0x%llx.\n",
					component->funnel_info.base_addr);
				goto error_end;
			}
		} else {
			struct xt_trace_sink_config_info sink_config;

			build_sink_config_info(component, &sink_config);
			if (xt_trace_sink_config(&component->sink_info,
						 &sink_config)) {
				pr_info("Failed to config trace sink with base addr 0x%llx.\n",
					component->sink_info.base_addr);
				goto error_end;
			}
		}
	}

	/* Enable the Sink. */
	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_SINK_SMEM) {
			if (xt_trace_sink_enable(&component->sink_info)) {
				pr_info("Failed to enable trace sink with base addr 0x%llx.\n",
					component->sink_info.base_addr);
				goto error_end;
			}
		}
	}

	/* Enable all Level2 Funnels. */
	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_FUNNEL
			&& component->funnel.level == LEVEL2_FUNNEL) {
			if (xt_trace_funnel_enable(&component->funnel_info)) {
				pr_info("Failed to enable trace funnel with base addr 0x%llx.\n",
					component->funnel_info.base_addr);
				goto error_end;
			}
		}
	}

	/* Enable all Level1 Funnels. */
	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_FUNNEL
			&& component->funnel.level == LEVEL1_FUNNEL) {
			if (xt_trace_funnel_enable(&component->funnel_info)) {
				pr_info("Failed to enable trace funnel with base addr 0x%llx.\n",
					component->funnel_info.base_addr);
				goto error_end;
			}
		}
	}

	if (flags & PERF_EF_START) {
		buf = perf_aux_output_begin(&xuantie_ntrace_pmu.handle, event);
		if (!buf) {
			pr_info("%s:%d perf_aux_output_begin failed\n", __func__, __LINE__);
			event->hw.state = PERF_HES_STOPPED;
			goto error_end;
		}
		buf->pos = xuantie_ntrace_pmu.handle.head % buf->length;
		// pr_info("base=%px length=%ld nr_pages=%d pos=%ld\n", buf->base, buf->length, buf->nr_pages, buf->pos);

		xuantie_ntrace_event_start(event, 0);
	}

	return 0;

error_end:
	/* Close all ntrace components. */
	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_ENCODER) {
			xt_trace_encoder_close(
				&component->encoder_info,
				component->encoder.enable_timestamp);
		} else if (component->type == XUANTIE_NTRACE_FUNNEL) {
			xt_trace_funnel_close(&component->funnel_info);
		} else {
			xt_trace_sink_close(&component->sink_info);
		}
	}

	return -1;
}

static void xuantie_ntrace_event_del(struct perf_event *event, int flags)
{
	u64 trace_write_point = 0;
	u64 trace_data_section0_start = 0;
	u32 trace_data_section0_size = 0;
	u64 trace_data_section1_start = 0;
	u32 trace_data_section1_size = 0;
	struct xuantie_ntrace_component *component;
	struct xuantie_ntrace_component *component_sink = NULL;
	struct xuantie_ntrace_component *component_encoder = NULL;
	struct xuantie_saved_conifg config;
	struct xuantie_ntrace_aux_buf *buf;

	// pr_info("%s:%d flags=%d\n", __func__, __LINE__, flags);

	/* Disable and close all funnels and encoders, just disable the sink. */
	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_ENCODER) {
			xt_trace_encoder_disable(
				&component->encoder_info,
				component->encoder.enable_timestamp);

			xt_trace_encoder_close(
				&component->encoder_info,
				component->encoder.enable_timestamp);

			component_encoder = component;
		} else if (component->type == XUANTIE_NTRACE_FUNNEL
			    && component->funnel.level == LEVEL1_FUNNEL) {
			xt_trace_funnel_disable(&component->funnel_info);
			xt_trace_funnel_close(&component->funnel_info);
		} else if (component->type == XUANTIE_NTRACE_FUNNEL
			    && component->funnel.level == LEVEL2_FUNNEL) {
			xt_trace_funnel_disable(&component->funnel_info);
			xt_trace_funnel_close(&component->funnel_info);
		} else if (component->type == XUANTIE_NTRACE_SINK_SMEM) {
			component_sink = component;
			xt_trace_sink_disable(&component->sink_info);
		}
	}

	/* Get Trace data size. */
	if (xt_trace_ram_sink_get_data_size(&component_sink->sink_info,
					    &trace_write_point)) {
		pr_info("Failed to get data size in ram sink with base addr 0x%llx.\n",
			component->sink_info.base_addr);
		return;
	}
#if TEST_SRAM_SINK
	if (trace_write_point & 0x1) {
		trace_data_section0_start = trace_write_point & 0xfffffffffffffffc;
		trace_data_section0_size = 0x800 - trace_data_section0_start;
		trace_data_section1_start = 0;
		trace_data_section1_size = trace_data_section0_start;
	} else {
		trace_data_section0_start = component_sink->sink.start_addr;
		trace_data_section0_size =
			trace_write_point - component_sink->sink.start_addr;
	}
#else
	if (trace_write_point & 0x1) {
		trace_data_section0_start = trace_write_point & 0xfffffffffffffffc;
		trace_data_section0_size =
			component_sink->sink.limit_addr - trace_data_section0_start;
		trace_data_section1_start = component_sink->sink.start_addr;
		trace_data_section1_size =
			trace_data_section0_start - component_sink->sink.start_addr;
	} else {
		trace_data_section0_start = component_sink->sink.start_addr;
		trace_data_section0_size =
			trace_write_point - component_sink->sink.start_addr;
	}
#endif

	// make start to offset
	trace_data_section0_start = trace_data_section0_start - component_sink->sink.start_addr;
	trace_data_section1_start = trace_data_section1_start - component_sink->sink.start_addr;

	buf = perf_get_aux(&xuantie_ntrace_pmu.handle);
	if (!buf) {
		xt_trace_sink_close(&component_sink->sink_info);
		return;
	}

	/* Build saved config */
	xuantie_build_saved_config(&config, component_encoder, trace_write_point & 0x1);

	/* If the aux buf space will insufficient, ignoring tail data */
	if ((trace_data_section0_size + trace_data_section1_size + sizeof(struct xuantie_saved_conifg)) > (buf->length - buf->pos)) {
		pr_info("Insufficient space in aux map buf, ignoring tail data\n");
		perf_aux_output_skip(&xuantie_ntrace_pmu.handle, buf->length - buf->pos);
		buf->pos = 0;
	}

	/* Save trace config to Perf.data. */
	memcpy(buf->base + buf->pos, &config, sizeof(struct xuantie_saved_conifg));
	buf->pos += sizeof(struct xuantie_saved_conifg);

	/* Read Trace data. */
#if TEST_SRAM_SINK
	int i = 0;
	unsigned char trace_buf[0x600];

	if (trace_data_section0_size) {
		if (xt_trace_read_data_from_sram_sink(component_sink->sink_info.base_addr,
				trace_data_section0_start,  trace_data_section0_size,
				trace_buf) < 0) {
			pr_info("fail to read trace_data_section0_size 0x%x\n",
				trace_data_section0_size);
			return;
		}
	}
	if (trace_data_section1_size) {
		if (xt_trace_read_data_from_sram_sink(component_sink->sink_info.base_addr,
				trace_data_section1_start,  trace_data_section1_size,
				trace_buf+trace_data_section0_size) < 0) {
			pr_info("fail to read trace_data_section0_size 0x%x\n",
				trace_data_section0_size);
			return;
		}
	}

	pr_info("trace get data: ");
	for (i = 0 ; i < (trace_data_section0_size + trace_data_section1_size); i++)
		pr_info(" 0x%x", (int)trace_buf[i]);

	/*Save Trace data to Perf.data. */
	memcpy(buf->base + buf->pos, trace_buf,
		trace_data_section0_size + trace_data_section1_size);
	buf->pos += trace_data_section0_size + trace_data_section1_size;
#else
	if (trace_data_section0_size) {
		memcpy(buf->base + buf->pos,
				component_sink->sink.vaddr +
					trace_data_section0_start,
				trace_data_section0_size);
		buf->pos += trace_data_section0_size;
	}
	if (trace_data_section1_size) {
		memcpy(buf->base + buf->pos,
				component_sink->sink.vaddr +
					trace_data_section1_start,
				trace_data_section1_size);
		buf->pos += trace_data_section1_size;
	}
#endif

	perf_aux_output_end(&xuantie_ntrace_pmu.handle, trace_data_section0_size +
		trace_data_section1_size + sizeof(struct xuantie_saved_conifg));

	/* Close the SINK.  */
	xt_trace_sink_close(&component_sink->sink_info);
}

static void xuantie_ntrace_event_start(struct perf_event *event, int flags)
{
	struct xuantie_ntrace_component *component;
	int found_encoder = 0;
	u32 hartid = cpuid_to_hartid_map(event->cpu);

	//pr_info("%s:%d on_cpu=%d cpu=%d[hart%d] flags=%d\n", __func__, __LINE__,
	//	event->oncpu, event->cpu, hartid, flags);

	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_ENCODER) {
			if (component->encoder.cpu == hartid) {
				if (xt_trace_encoder_enable(
					    &component->encoder_info,
					    component->encoder.enable_timestamp))
					pr_info("Failed enable encoder for hart %d\n", hartid);
				else {
					found_encoder = 1;
					break;
				}
			}
		}
	}

	//check found_encoder
}

static void xuantie_ntrace_event_stop(struct perf_event *event, int flags)
{
	struct xuantie_ntrace_component *component;
	u32 hartid = cpuid_to_hartid_map(event->cpu);

	//pr_info("%s:%d on_cpu=%d cpu=%d[hart%d] flags=%d\n", __func__, __LINE__,
	//	event->oncpu, event->cpu, hartid, flags);

	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_ENCODER) {
			if (component->encoder.cpu == hartid) {
				if (xt_trace_encoder_disable(
					    &component->encoder_info,
					    component->encoder.enable_timestamp))
					pr_info("Failed disenable encoder for hart %d\n",
						hartid);
				else
					break;
			}
		}
	}
}

/*
 * aux_buffer_setup() - Setup AUX buffer for diagnostic mode sampling
 * @event:	Event the buffer is setup for, event->cpu == -1 means current
 * @pages:	Array of pointers to buffer pages passed from perf core
 * @nr_pages:	Total pages
 * @snapshot:	Flag for snapshot mode
 *
 * This is the callback when setup an event using AUX buffer. Perf tool can
 * trigger this by an additional mmap() call on the event. Unlike the buffer
 * for basic samples, AUX buffer belongs to the event. It is scheduled with
 * the task among online cpus when it is a per-thread event.
 *
 * Return the private AUX buffer structure if success or NULL if fails.
 */
static void *xuantie_ntrace_buffer_setup_aux(struct perf_event *event, void **pages,
					 int nr_pages, bool overwrite)
{
	struct xuantie_ntrace_aux_buf *buf;
	struct page **pagelist;
	int i;

	// pr_info("%s:%d\n", __func__, __LINE__);

	if (overwrite) {
		pr_warn("Overwrite mode is not supported\n");
		return NULL;
	}

	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return NULL;

	pagelist = kcalloc(nr_pages, sizeof(*pagelist), GFP_KERNEL);
	if (!pagelist)
		goto err;

	for (i = 0; i < nr_pages; i++)
		pagelist[i] = virt_to_page(pages[i]);

	buf->base = vmap(pagelist, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!buf->base) {
		kfree(pagelist);
		goto err;
	}

	buf->nr_pages = nr_pages;
	buf->length = nr_pages * PAGE_SIZE;
	buf->pos = 0;

	pr_info("nr_pages=%ld length=%ld\n", buf->nr_pages, buf->length);

	kfree(pagelist);
	return buf;
err:
	kfree(buf);
	return NULL;
}

/*
 * Callback when freeing AUX buffers.
 */
static void xuantie_ntrace_buffer_free_aux(void *aux)
{
	struct xuantie_ntrace_aux_buf *buf = aux;

	// pr_info("%s:%d\n", __func__, __LINE__);

	vunmap(buf->base);
	kfree(buf);
}

static void xuantie_ntrace_event_read(struct perf_event *event)
{
	// pr_info("%s:%d\n", __func__, __LINE__);
}

static void xuantie_ntrace_event_enable(struct pmu *pmu)
{
	// pr_info("%s:%d\n", __func__, __LINE__);
}

static void xuantie_ntrace_event_disable(struct pmu *pmu)
{
	// pr_info("%s:%d\n", __func__, __LINE__);
}

static void xuantie_ntrace_event_filters_sync(struct perf_event *event)
{
	// pr_info("%s:%d\n", __func__, __LINE__);
}

static int xuantie_ntrace_event_filters_validate(struct list_head *filters)
{
	// pr_info("%s:%d\n", __func__, __LINE__);
	return 0;
}

static __init int xuantie_ntrace_init(void)
{
	struct xuantie_ntrace_component *component;
	int ret = 0;

	if (get_list_count(&xuantie_ntrace_controllers) == 0)
		return -ENXIO;

	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		pr_info("type=%s in_num=%d out_num=%d\n",
			xuantie_ntrace_type2str(component->type),
			component->in_num, component->out_num);
		for (int i = 0; i < component->in_num; i++) {
			pr_info("\t in[%d] type=%s base_addr=0x%llx\n", i,
				xuantie_ntrace_type2str(component->in[i]->type),
				component->in[i]->base_addr);
		}
		for (int j = 0; j < component->out_num; j++) {
			pr_info("\t out[%d] type=%s base_addr=0x%llx\n", j,
				xuantie_ntrace_type2str(
					component->out[j]->type),
				component->out[j]->base_addr);
		}
	}

	trace_componnet_detected = false;

	xuantie_ntrace_pmu.pmu.module = THIS_MODULE,
	xuantie_ntrace_pmu.pmu.capabilities = PERF_PMU_CAP_EXCLUSIVE |
					      PERF_PMU_CAP_ITRACE;
	xuantie_ntrace_pmu.pmu.task_ctx_nr	= perf_sw_context;
	xuantie_ntrace_pmu.pmu.attr_groups	= xuantie_ntrace_attr_groups;
	xuantie_ntrace_pmu.pmu.event_init	= xuantie_ntrace_event_init;
	xuantie_ntrace_pmu.pmu.setup_aux	= xuantie_ntrace_buffer_setup_aux;
	xuantie_ntrace_pmu.pmu.free_aux		= xuantie_ntrace_buffer_free_aux;
	xuantie_ntrace_pmu.pmu.start		= xuantie_ntrace_event_start;
	xuantie_ntrace_pmu.pmu.stop			= xuantie_ntrace_event_stop;
	xuantie_ntrace_pmu.pmu.add			= xuantie_ntrace_event_add;
	xuantie_ntrace_pmu.pmu.del			= xuantie_ntrace_event_del;
	xuantie_ntrace_pmu.pmu.read			= xuantie_ntrace_event_read;
	xuantie_ntrace_pmu.pmu.pmu_enable	= xuantie_ntrace_event_enable;
	xuantie_ntrace_pmu.pmu.pmu_disable	= xuantie_ntrace_event_disable;
	xuantie_ntrace_pmu.pmu.addr_filters_sync =
		xuantie_ntrace_event_filters_sync;
	xuantie_ntrace_pmu.pmu.addr_filters_validate =
		xuantie_ntrace_event_filters_validate;

	ret = perf_pmu_register(&xuantie_ntrace_pmu.pmu, "xuantie_ntrace", -1);
	//pr_info("%s:%d perf_pmu_register ret=%d\n", __func__, __LINE__, ret);
	return ret;
}
late_initcall(xuantie_ntrace_init);
