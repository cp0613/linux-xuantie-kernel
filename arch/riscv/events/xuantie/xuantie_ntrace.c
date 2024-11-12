// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/bits.h>
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
	encoder_config->inst_stall_ena = false;
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
		encoder_config->timestamp_run_in_debugmode =
			component->encoder.timestamp_runindebugmode;
		encoder_config->timestamp_type = 1; // timestamp_external
		encoder_config->timestamp_prescale =
			component->encoder.timestamp_prescale;
	}
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

	if (TEST_SRAM_SINK) {
		sink_config->component_type = TRCOMP_RAMSINK;
		sink_config->type = TRACE_SRAM_SINK;        // configure to SMEM Sink
		sink_config->ram_sink_stop_on_wrap = false; // the circular buffer gets full
		sink_config->ram_sink_mem_format = 0;       // plain bytes
		sink_config->ram_sink_start = 0;
		sink_config->ram_sink_limit = 0x7fc;
		sink_config->ram_sink_write_point = 0;
	} else {
		sink_config->component_type = TRCOMP_RAMSINK;
		sink_config->type = TRACE_SMEM_SINK;        // configure to SMEM Sink
		sink_config->ram_sink_stop_on_wrap = false; // the circular buffer gets full
		sink_config->ram_sink_mem_format = 0;       // plain bytes
		sink_config->ram_sink_start = component->sink.start_addr;
		sink_config->ram_sink_limit = (component->sink.limit_addr & 0xffffff00) - 4;
		component->sink.limit_addr = component->sink.limit_addr & 0xffffff00;
		sink_config->ram_sink_write_point = component->sink.start_addr;
	}

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

static int trace_register_write(u64 addr, u32 value)
{
	iowrite32(value, (void __iomem *)(unsigned long)addr);
#ifdef TEST_LOG_ON
	pr_info("--->write 0x%llx with 0x%x\n", addr, value);
#endif
	return 0;
}

static int trace_register_read(u64 addr, u32 *value)
{
	*value = ioread32((void __iomem *)(unsigned long)addr);
#ifdef TEST_LOG_ON
	pr_info("--->read 0x%llx get 0x%x\n", addr, *value);
#endif
	return 0;
}

static const struct attribute_group *xuantie_ntrace_event_attr_groups[] = {
	NULL,
};

static int xuantie_ntrace_event_init(struct perf_event *event)
{
	pr_info("%s:%d\n", __func__, __LINE__);
	return 0;
}

static int xuantie_ntrace_event_add(struct perf_event *event, int mode)
{
	struct xuantie_ntrace_component *component;

	pr_info("%s:%d\n", __func__, __LINE__);

	/* Set interfaces needed for Trace Control Lib. */
	xt_trace_control_init_rw_trace_interface(console_msg_out,
						 trace_register_write,
						 trace_register_read, NULL);

	/* Detect all Trace Components.  */
	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_ENCODER) {
			xt_init_trace_encoder_control_info(
				&component->encoder_info, component->reg_base);
			if (xt_trace_detect_trace_encoder(
				    &component->encoder_info)) {
				pr_info("Failed to detect trace encoder with base addr 0x%llx.\n",
					(u64)component->encoder_info.base_addr);
				return -1;
			}
		} else if (component->type == XUANTIE_NTRACE_FUNNEL) {
			xt_init_trace_funnel_control_info(
				&component->funnel_info, component->reg_base);
			if (xt_trace_detect_trace_funnel(
				    &component->funnel_info)) {
				pr_info("Failed to detect trace funnel with base addr 0x%llx.\n",
					(u64)component->funnel_info.base_addr);
				return -1;
			}
		} else if (component->type == XUANTIE_NTRACE_SINK_SMEM) {
			xt_init_trace_sink_control_info(&component->sink_info,
							component->reg_base);
			if (xt_trace_detect_trace_sink(&component->sink_info)) {
				pr_info("Failed to detect trace sink with base addr 0x%llx.\n",
					(u64)component->sink_info.base_addr);
				return -1;
			}
		} else {
			pr_info("Unknown NTrace Component with type %d, base addr 0x%llx.\n",
				component->type, (u64)component->reg_base);
			return -1;
		}
	}

	/* Config components. */
	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_ENCODER) {
			struct xt_trace_encoder_config_info encoder_config;

			build_encoder_config_info(component, &encoder_config);
			if (xt_trace_encoder_config(&component->encoder_info,
						    &encoder_config)) {
				pr_info("Failed to config trace encoder with base addr 0x%llx.\n",
					component->encoder_info.base_addr);
				goto error_end;
			}

			//FIXME: add filter?
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

	/* Enable all Funnels. */
	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_FUNNEL) {
			if (xt_trace_funnel_enable(&component->funnel_info)) {
				pr_info("Failed to enable trace funnel with base addr 0x%llx.\n",
					component->funnel_info.base_addr);
				goto error_end;
			}
		}
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

static void xuantie_ntrace_event_del(struct perf_event *event, int mode)
{
	u64 trace_write_point = 0;
	u64 trace_data_section0_start = 0;
	u32 trace_data_section0_size = 0;
	u64 trace_data_section1_start = 0;
	u32 trace_data_section1_size = 0;
	struct xuantie_ntrace_component *component;
	struct xuantie_ntrace_component *component_sink;
	struct xuantie_ntrace_component *component_encoder;
	struct xuantie_saved_conifg config;

	pr_info("%s:%d\n", __func__, __LINE__);

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
		} else if (component->type == XUANTIE_NTRACE_FUNNEL) {
			xt_trace_funnel_disable(&component->funnel_info);
			xt_trace_funnel_close(&component->funnel_info);
		} else {
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
	if (TEST_SRAM_SINK) {
		if (trace_write_point & 0x1) {
			trace_data_section0_start = trace_write_point & 0xfffffffffffffffc;
			trace_data_section0_size = 0x800 - trace_data_section0_start;
			trace_data_section1_start = 0;
			trace_data_section1_size = trace_data_section0_start;
		} else {
			trace_data_section0_start = 0;
			trace_data_section0_size = trace_write_point;
		}
	} else {
		if (trace_write_point & 0x1) {
			trace_data_section0_start = trace_write_point & 0xfffffffffffffffc;
			trace_data_section0_size =
				component_sink->sink.limit_addr - trace_data_section0_start;
			trace_data_section1_start = component_sink->sink.start_addr;
			trace_data_section1_size =
				trace_data_section0_start - component_sink->sink.start_addr;
		} else {
			trace_data_section0_start = 0;
			trace_data_section0_size = trace_write_point;
		}
	}

	/* Build saved config and save it to Perf.data. */
	xuantie_build_saved_config(&config, component, trace_write_point & 0x1);

	/* Read Trace data. */
	if (TEST_SRAM_SINK) {
		int i = 0;
		unsigned char buf[0x800];

		if (trace_data_section0_size) {
			if (xt_trace_read_data_from_sram_sink(component_sink->sink_info.base_addr,
					trace_data_section0_start,  trace_data_section0_size,
					buf) < 0) {
				pr_info("fail to read trace_data_section0_size 0x%x\n",
					trace_data_section0_size);
				return;
			}
		}
		if (trace_data_section1_size) {
			if (xt_trace_read_data_from_sram_sink(component_sink->sink_info.base_addr,
					trace_data_section1_start,  trace_data_section1_size,
					buf+trace_data_section0_size) < 0) {
				pr_info("fail to read trace_data_section0_size 0x%x\n",
					trace_data_section0_size);
				return;
			}
		}

		pr_info("trace get data: ");
		for (i = 0 ; i < (trace_data_section0_size + trace_data_section1_size); i++)
			pr_info(" 0x%x", (int)buf[i]);
	}

	/*Save Trace data to Perf.data. */

	/* Close the SINK.  */
	xt_trace_sink_close(&component_sink->sink_info);
}

static void xuantie_ntrace_event_start(struct perf_event *event, int mode)
{
	struct xuantie_ntrace_component *component;
	int found_encoder = 0;

	pr_info("%s:%d on_cpu=%d cpu=%d\n", __func__, __LINE__, event->oncpu,
		event->cpu);

	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_ENCODER) {
			if (component->encoder.cpu == event->cpu) {
				if (xt_trace_encoder_enable(
					    &component->encoder_info,
					    component->encoder.enable_timestamp))
					pr_info("Failed enable encoder for cpu %d\n",
						event->cpu);
				else {
					found_encoder = 1;
					break;
				}
			}
		}
	}

	//check found_encoder
}

static void xuantie_ntrace_event_stop(struct perf_event *event, int mode)
{
	struct xuantie_ntrace_component *component;

	pr_info("%s:%d on_cpu=%d cpu=%d\n", __func__, __LINE__, event->oncpu,
		event->cpu);

	list_for_each_entry(component, &xuantie_ntrace_controllers, list) {
		if (component->type == XUANTIE_NTRACE_ENCODER) {
			if (component->encoder.cpu == event->oncpu) {
				if (xt_trace_encoder_disable(
					    &component->encoder_info,
					    component->encoder.enable_timestamp))
					pr_info("Failed disenable encoder for cpu %d\n",
						event->cpu);
				else
					break;
			}
		}
	}
}

static void xuantie_ntrace_event_read(struct perf_event *event)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static void xuantie_ntrace_event_enable(struct pmu *pmu)
{
	//pr_info("%s:%d\n", __func__, __LINE__);
}

static void xuantie_ntrace_event_disable(struct pmu *pmu)
{
	//pr_info("%s:%d\n", __func__, __LINE__);
}

static void xuantie_ntrace_event_filters_sync(struct perf_event *event)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static int xuantie_ntrace_event_filters_validate(struct list_head *filters)
{
	pr_info("%s:%d\n", __func__, __LINE__);
	return 0;
}

static __init int xuantie_ntrace_init(void)
{
	struct xuantie_ntrace_component *component;
	int ret = 0;

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

	xuantie_ntrace_pmu.pmu.module = THIS_MODULE,
	xuantie_ntrace_pmu.pmu.name = "xuantie_ntrace",
	xuantie_ntrace_pmu.pmu.capabilities = PERF_PMU_CAP_EXCLUSIVE |
					      PERF_PMU_CAP_ITRACE;
	xuantie_ntrace_pmu.pmu.attr_groups	= xuantie_ntrace_event_attr_groups;
	xuantie_ntrace_pmu.pmu.task_ctx_nr	= perf_sw_context;
	xuantie_ntrace_pmu.pmu.event_init	= xuantie_ntrace_event_init;
	xuantie_ntrace_pmu.pmu.add			= xuantie_ntrace_event_add;
	xuantie_ntrace_pmu.pmu.del			= xuantie_ntrace_event_del;
	xuantie_ntrace_pmu.pmu.start		= xuantie_ntrace_event_start;
	xuantie_ntrace_pmu.pmu.stop			= xuantie_ntrace_event_stop;
	xuantie_ntrace_pmu.pmu.read			= xuantie_ntrace_event_read;
	xuantie_ntrace_pmu.pmu.pmu_enable	= xuantie_ntrace_event_enable;
	xuantie_ntrace_pmu.pmu.pmu_disable	= xuantie_ntrace_event_disable;
	// xuantie_ntrace_pmu.pmu.setup_aux	= xuantie_ntrace_buffer_setup_aux;
	// xuantie_ntrace_pmu.pmu.free_aux		= xuantie_ntrace_buffer_free_aux;
	xuantie_ntrace_pmu.pmu.addr_filters_sync =
		xuantie_ntrace_event_filters_sync;
	xuantie_ntrace_pmu.pmu.addr_filters_validate =
		xuantie_ntrace_event_filters_validate;

	ret = perf_pmu_register(&xuantie_ntrace_pmu.pmu, "xuantie_ntrace", -1);
	pr_info("%s:%d ret=%d\n", __func__, __LINE__, ret);
	return ret;
}
late_initcall(xuantie_ntrace_init);
