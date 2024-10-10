// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>

#include "xuantie_ntrace.h"

static const struct of_device_id xuantie_ntrace_encoder_of_match[] = {
	{.compatible = "xuantie_ntrace,encoder-controller",},
	{},
};

static int __init xuantie_ntrace_encoder_init(void)
{
	struct xuantie_ntrace_component *component;
	struct device_node *node, *child_node, *port_node;
	struct xuantie_io_port *io_port;
	u32 reg[4];
	const char *str_tmp;
	int port_nr;
	int ret;

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
		component->reg_base = ((resource_size_t)reg[0] << 32) | reg[1];
		component->reg_size = ((resource_size_t)reg[2] << 32) | reg[3];
		pr_info("reg_base=0x%llx reg_size=0x%llx\n", component->reg_base, component->reg_size);

		ret = of_property_read_u32(node, "cpu", &component->encoder.cpu);
		if (ret) {
			pr_err("Failed to read 'cpu'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("cpu=%d\n", component->encoder.cpu);

		ret = of_property_read_string(node, "trace_type", &component->encoder.trace_type);
		if (ret) {
			pr_err("Failed to read 'trace_type'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("trace_type=%s\n", component->encoder.trace_type);

		ret = of_property_read_string(node, "insn_mode", &component->encoder.insn_mode);
		if (ret) {
			pr_err("Failed to read 'insn_mode'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("insn_mode=%s\n", component->encoder.insn_mode);

		ret = of_property_read_string(node, "send_context", &str_tmp);
		if (ret) {
			pr_err("Failed to read 'send_context'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.send_context = strcmp(str_tmp, "true") == 0;
		pr_info("send_context=%d\n", component->encoder.send_context);

		ret = of_property_read_string(node, "enable_src", &str_tmp);
		if (ret) {
			pr_err("Failed to read 'enable_src'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.enable_src = strcmp(str_tmp, "true") == 0;
		pr_info("enable_src=%d\n", component->encoder.enable_src);

		ret = of_property_read_u32(node, "src_id", &component->encoder.src_id);
		if (ret) {
			pr_err("Failed to read 'src_id'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("src_id=%d\n", component->encoder.src_id);

		ret = of_property_read_u32(node, "src_bits", &component->encoder.src_bits);
		if (ret) {
			pr_err("Failed to read 'src_bits'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("src_bits=%d\n", component->encoder.src_bits);

		ret = of_property_read_string(node, "inst_sync_mode", &component->encoder.inst_sync_mode);
		if (ret) {
			pr_err("Failed to read 'inst_sync_mode'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("inst_sync_mode=%s\n", component->encoder.inst_sync_mode);

		ret = of_property_read_u32(node, "inst_sync_value", &component->encoder.inst_sync_value);
		if (ret) {
			pr_err("Failed to read 'inst_sync_value'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("inst_sync_value=0x%x\n", component->encoder.inst_sync_value);

		ret = of_property_read_string(node, "enable_cpu_trigger", &str_tmp);
		if (ret) {
			pr_err("Failed to read 'enable_cpu_trigger'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.enable_cpu_trigger = strcmp(str_tmp, "true") == 0;
		pr_info("enable_cpu_trigger=%d\n", component->encoder.enable_cpu_trigger);

		ret = of_property_read_string(node, "enable_timestamp", &str_tmp);
		if (ret) {
			pr_err("Failed to read 'enable_timestamp'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.enable_timestamp = strcmp(str_tmp, "true") == 0;
		pr_info("enable_timestamp=%d\n", component->encoder.enable_timestamp);

		ret = of_property_read_string(node, "timestamp_runindebugmode", &str_tmp);
		if (ret) {
			pr_err("Failed to read 'timestamp_runindebugmode'\n");
			of_node_put(node);
			return ret;
		}
		component->encoder.timestamp_runindebugmode = strcmp(str_tmp, "true") == 0;
		pr_info("timestamp_runindebugmode=%d\n", component->encoder.timestamp_runindebugmode);

		ret = of_property_read_string(node, "timestamp_source", &component->encoder.timestamp_source);
		if (ret) {
			pr_err("Failed to read 'timestamp_source'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("timestamp_source=%s\n", component->encoder.timestamp_source);

		ret = of_property_read_u32(node, "timestamp_prescale", &component->encoder.timestamp_prescale);
		if (ret) {
			pr_err("Failed to read 'timestamp_prescale'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("timestamp_prescale=%d\n", component->encoder.timestamp_prescale);

		ret = of_property_read_u32(node, "timestamp_bits", &component->encoder.timestamp_bits);
		if (ret) {
			pr_err("Failed to read 'timestamp_bits'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("timestamp_bits=%d\n", component->encoder.timestamp_bits);

		child_node = of_get_child_by_name(node, "output_port");
		if (!child_node) {
			pr_err("Failed to find 'output_port'\n");
			of_node_put(node);
			return -ENODEV;
		}
		component->out_num = count_device_node_child(child_node);
		if (component->out_num) {
			component->out = krealloc_array(component->out, component->out_num, sizeof(*component->out), GFP_KERNEL);
			if (!component->out)
				return -ENOMEM;
			port_nr = 0;

			for_each_child_of_node(child_node, port_node) {
				if (!of_device_is_available(port_node)) {
					of_node_put(child_node);
					continue;
				}
				pr_info("Found output_port: %pOF\n", port_node);
				const struct device_node *endpoint_node = of_parse_phandle(port_node, "endpoint", 0);
				pr_info("\t endpoint: %pOF\n", endpoint_node);

				of_property_read_u32_array((struct device_node *)endpoint_node, "reg", &reg[0], 4);

				io_port = kmalloc(sizeof(struct xuantie_io_port), GFP_KERNEL);
				io_port->is_input = false;
				io_port->endpoint_num = port_nr;
				io_port->type = XUANTIE_NTRACE_FUNNEL;
				io_port->base_addr = ((u64)reg[0] << 32) | reg[1];
				component->out[port_nr] = io_port;
				port_nr++;
			}
		}

		INIT_LIST_HEAD(&component->list);
		list_add_tail(&component->list, &xuantie_ntrace_controllers);
	}

	pr_info("xuantie_ntrace_controllers=%d\n", get_list_count(&xuantie_ntrace_controllers));

	return ret;
}
device_initcall(xuantie_ntrace_encoder_init);
