// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>

#include "xuantie_ntrace.h"

static const struct of_device_id xuantie_ntrace_encoder_of_match[] = {
	{
		.compatible = "xuantie_ntrace,encoder-controller",
	},
	{},
};

static int __init xuantie_ntrace_encoder_init(void)
{
	struct xuantie_ntrace_component *component;
	struct device_node *node, *child_node, *port_node;
	struct xuantie_io_port *io_port;
	resource_size_t base, size;
	u32 reg[4];
	const char *str_tmp;
	int port_nr;
	int ret;
	static const char * const trace_format[] = {"E-trace", "N-Trace", "Reserved2",
		"Reserved2", "Reserved2", "Reserved2", "Reserved2", "Reserved2", "Vendor-Specific"};
	static const char * const inst_sync_mode[] = {"Off", "Count Trace Messages/packets",
		"Count Hart Clock Cycles", "Count Instruction 16-bit half-words"};
	static const char * const insn_mode[] = {"INST Trace disable", "Protocol defined1",
		"Protocol defined2", "Branch Trace",	"Protocol defined4", "Protocol defined5",
		"Branch History Trace", "Vendor-defined"};
	static const char * const timestamp_mode[] = {"None", "External", "Internal System",
		"Internal Core", "Shared", "Vendor-Specific5", "Vendor-Specific6",
		"Vendor-Specific7"};

	for_each_matching_node(node, xuantie_ntrace_encoder_of_match) {
		if (!of_device_is_available(node)) {
			of_node_put(node);
			continue;
		}

		component = kzalloc(sizeof(*component), GFP_KERNEL);
		if (!component)
			return -ENOMEM;
		component->type = XUANTIE_NTRACE_ENCODER;

		ret = of_property_read_u32_array(node, "reg", &reg[0], 4);
		if (ret) {
			pr_err("Failed to read 'reg'\n");
			of_node_put(node);
			return ret;
		}
		base = (resource_size_t)((u64)reg[0] << 32) | reg[1];
		size = (resource_size_t)((u64)reg[2] << 32) | reg[3];
		pr_info("base=0x%llx size=0x%llx\n", (u64)base, (u64)size);
		component->reg_base = (unsigned long)ioremap(base, size);
		component->reg_size = size;
		pr_info("reg_base=0x%llx reg_size=0x%llx\n",
			(u64)component->reg_base, (u64)component->reg_size);

		ret = of_property_read_u32(node, "cpu",
					   &component->encoder.cpu);
		if (ret) {
			pr_err("Failed to read 'cpu'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("cpu=%d\n", component->encoder.cpu);

		ret = of_property_read_u32(node, "trace_encoder_format",
					      &component->encoder.trace_format);
		if (ret) {
			pr_err("Failed to read 'trace_encoder_format'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.trace_format &= 0x7;
		pr_info("trace_encoder_format=%d(%s)\n", component->encoder.trace_format,
				trace_format[component->encoder.trace_format]);

		ret = of_property_read_u32(node, "trace_encoder_inst_mode",
					      &component->encoder.inst_mode);
		if (ret) {
			pr_err("Failed to read 'trace_encoder_inst_mode'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.inst_mode &= 7;
		pr_info("trace_encoder_inst_mode=%d(%s)\n", component->encoder.inst_mode,
			insn_mode[component->encoder.inst_mode]);

		ret = of_property_read_string(node, "trace_encoder_context", &str_tmp);
		if (ret) {
			pr_err("Failed to read 'trace_encoder_context'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.send_context = strcmp(str_tmp, "true") == 0;
		pr_info("trace_encoder_context=%d\n", component->encoder.send_context);

		ret = of_property_read_string(node, "trace_encoder_inhibit_src", &str_tmp);
		if (ret) {
			pr_err("Failed to read 'trace_encoder_inhibit_src'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.inhibit_src = strcmp(str_tmp, "true") == 0;
		pr_info("trace_encoder_inhibit_src=%d\n", component->encoder.inhibit_src);

		ret = of_property_read_u32(node, "trace_encoder_src_id",
					   &component->encoder.src_id);
		if (ret) {
			pr_err("Failed to read 'trace_encoder_src_id'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("trace_encoder_src_id=%d\n", component->encoder.src_id);

		ret = of_property_read_u32(node, "trace_encoder_inst_sync_mode",
			&component->encoder.inst_sync_mode);
		if (ret) {
			pr_err("Failed to read 'trace_encoder_inst_sync_mode'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.inst_sync_mode &= 3;
		pr_info("trace_encoder_inst_sync_mode=%d(%s)\n", component->encoder.inst_sync_mode,
			inst_sync_mode[component->encoder.inst_sync_mode]);

		ret = of_property_read_u32(node, "trace_encoder_inst_sync_max",
					   &component->encoder.inst_sync_max);
		if (ret) {
			pr_err("Failed to read 'trace_encoder_inst_sync_max'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("trace_encoder_inst_sync_max=0x%x\n",
			component->encoder.inst_sync_max);

		ret = of_property_read_string(node, "trace_encoder_inst_trigger_enable",
					      &str_tmp);
		if (ret) {
			pr_err("Failed to read 'trace_encoder_inst_trigger_enable'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.inst_trigger_enable = strcmp(str_tmp, "true") == 0;
		pr_info("trace_encoder_inst_trigger_enable=%d\n",
			component->encoder.inst_trigger_enable);

		ret = of_property_read_string(node, "trace_timestamp_enable",
					      &str_tmp);
		if (ret) {
			pr_err("Failed to read 'trace_timestamp_enable'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.enable_timestamp = strcmp(str_tmp, "true") ==
						      0;
		pr_info("trace_timestamp_enable=%d\n",
			component->encoder.enable_timestamp);

		ret = of_property_read_string(node, "trace_timestamp_runindebugmode",
					      &str_tmp);
		if (ret) {
			pr_err("Failed to read 'trace_timestamp_runindebugmode'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.timestamp_runindebugmode =
			strcmp(str_tmp, "true") == 0;
		pr_info("trace_timestamp_runindebugmode=%d\n",
			component->encoder.timestamp_runindebugmode);

		ret = of_property_read_u32(
			node, "trace_timestamp_mode",
			&component->encoder.timestamp_mode);
		if (ret) {
			pr_err("Failed to read 'trace_timestamp_mode'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.timestamp_mode &= 7;
		pr_info("trace_timestamp_mode=%d(%s)\n", component->encoder.timestamp_mode,
			timestamp_mode[component->encoder.timestamp_mode]);

		ret = of_property_read_u32(node, "trace_timestamp_prescale",
					   &component->encoder.timestamp_prescale);
		if (ret) {
			pr_err("Failed to read 'trace_timestamp_prescale'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("trace_timestamp_prescale=%d\n",
			component->encoder.timestamp_prescale);

		child_node = of_get_child_by_name(node, "output_port");
		if (!child_node) {
			pr_err("Failed to find 'output_port'\n");
			of_node_put(node);
			return -ENODEV;
		}
		component->out_num = count_device_node_child(child_node);
		if (component->out_num) {
			component->out = krealloc_array(component->out,
							component->out_num,
							sizeof(*component->out),
							GFP_KERNEL);
			if (!component->out)
				return -ENOMEM;
			port_nr = 0;

			for_each_child_of_node(child_node, port_node) {
				if (!of_device_is_available(port_node)) {
					of_node_put(child_node);
					continue;
				}
				pr_info("Found output_port: %pOF\n", port_node);
				const struct device_node *endpoint_node =
					of_parse_phandle(port_node, "endpoint",
							 0);
				pr_info("\t endpoint: %pOF\n", endpoint_node);

				of_property_read_u32_array(
					(struct device_node *)endpoint_node,
					"reg", &reg[0], 4);

				io_port =
					kmalloc(sizeof(struct xuantie_io_port),
						GFP_KERNEL);
				io_port->is_input = false;
				io_port->endpoint_num = port_nr;
				io_port->type = XUANTIE_NTRACE_FUNNEL;
				io_port->base_addr = ((u64)reg[0] << 32) |
						     reg[1];
				component->out[port_nr] = io_port;
				port_nr++;
			}
		}

		INIT_LIST_HEAD(&component->list);
		list_add_tail(&component->list, &xuantie_ntrace_controllers);
	}

	pr_info("xuantie_ntrace_controllers=%d\n",
		get_list_count(&xuantie_ntrace_controllers));

	return ret;
}
device_initcall(xuantie_ntrace_encoder_init);
