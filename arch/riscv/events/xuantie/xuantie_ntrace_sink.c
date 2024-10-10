// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>

#include "xuantie_ntrace.h"

static const struct of_device_id xuantie_ntrace_sink_of_match[] = {
	{.compatible = "xuantie_ntrace,sink-controller",},
	{},
};

static int __init xuantie_ntrace_sink_init(void)
{
	struct xuantie_ntrace_component *component;
	struct device_node *node, *child_node, *port_node;
	struct xuantie_io_port *io_port;
	struct resource rmem;
	u32 reg[4];
	int port_nr;
	int ret;

	for_each_matching_node(node, xuantie_ntrace_sink_of_match) {
		if (!of_device_is_available(node)) {
			of_node_put(node);
			continue;
		}

		component = kzalloc(sizeof(*component), GFP_KERNEL);
		if (!component)
			return -ENOMEM;
		component->type = XUANTIE_NTRACE_SINK_SMEM;

		ret = of_property_read_u32_array(node, "reg", &reg[0], 4);
		if (ret) {
			pr_err("Failed to read 'reg'\n");
			of_node_put(node);
			return ret;
		}
		component->reg_base = ((resource_size_t)reg[0] << 32) | reg[1];
		component->reg_size = ((resource_size_t)reg[2] << 32) | reg[3];
		pr_info("reg_base=0x%llx reg_size=0x%llx\n", component->reg_base, component->reg_size);

		ret = of_property_read_string(node, "working_mode", &component->sink.working_mode);
		if (ret) {
			pr_err("Failed to read 'working_mode'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("working_mode=%s\n", component->sink.working_mode);

		ret = of_property_read_string(node, "format", &component->sink.format);
		if (ret) {
			pr_err("Failed to read 'format'\n");
			of_node_put(node);
			return ret;
		}
		pr_info("format=%s\n", component->sink.format);

		child_node = of_parse_phandle(node, "memory-region", 0);
		if (!child_node) {
			pr_err("Failed to find 'memory-region'\n");
			of_node_put(node);
			return -ENODEV;
		}
		ret = of_address_to_resource(child_node, 0, &rmem);
		if (ret) {
			pr_err("Failed to find 'reserved-memory'\n");
			of_node_put(child_node);
			of_node_put(node);
			return ret;
		}
		pr_info("reserved-memory {0x%llx-0x%llx}\n", rmem.start, rmem.end);
		component->sink.start_addr = rmem.start;
		component->sink.limit_addr = rmem.end;

		child_node = of_get_child_by_name(node, "input_port");
		if (!child_node) {
			pr_err("Failed to find 'input_port'\n");
			of_node_put(node);
			return -ENODEV;
		}
		component->in_num = count_device_node_child(child_node);
		if (component->in_num) {
			component->in = krealloc_array(component->in, component->in_num, sizeof(*component->in), GFP_KERNEL);
			if (!component->in)
				return -ENOMEM;
			port_nr = 0;

			for_each_child_of_node(child_node, port_node) {
				if (!of_device_is_available(port_node)) {
					of_node_put(child_node);
					continue;
				}
				pr_info("Found input_port: %pOF\n", port_node);
				const struct device_node *endpoint_node = of_parse_phandle(port_node, "endpoint", 0);
				pr_info("\t endpoint: %pOF\n", endpoint_node);

				of_property_read_u32_array((struct device_node *)endpoint_node, "reg", &reg[0], 4);

				io_port = kmalloc(sizeof(struct xuantie_io_port), GFP_KERNEL);
				io_port->is_input = true;
				io_port->endpoint_num = port_nr;
				io_port->type = XUANTIE_NTRACE_FUNNEL;
				io_port->base_addr = ((u64)reg[0] << 32) | reg[1];
				component->in[port_nr] = io_port;
				port_nr++;
			}
		}

		INIT_LIST_HEAD(&component->list);
		list_add_tail(&component->list, &xuantie_ntrace_controllers);
	}

	pr_info("xuantie_ntrace_controllers=%d\n", get_list_count(&xuantie_ntrace_controllers));

	return ret;
}
device_initcall(xuantie_ntrace_sink_init);
