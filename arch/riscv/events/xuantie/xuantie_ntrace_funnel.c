// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>

#include "xuantie_ntrace.h"

static const struct of_device_id xuantie_ntrace_funnel_of_match[] = {
	{.compatible = "xuantie_ntrace,funnel-controller",},
	{},
};

static int __init xuantie_ntrace_funnel_init(void)
{
	struct xuantie_ntrace_component *component;
	struct device_node *node, *child_node, *port_node;
	struct xuantie_io_port *io_port;
	u32 reg[4];
	int port_nr;
	int ret;

	for_each_matching_node(node, xuantie_ntrace_funnel_of_match) {
		if (!of_device_is_available(node)) {
			of_node_put(node);
			continue;
		}

		component = kzalloc(sizeof(*component), GFP_KERNEL);
		if (!component)
			return -ENOMEM;
		component->type = XUANTIE_NTRACE_FUNNEL;

		ret = of_property_read_u32_array(node, "reg", &reg[0], 4);
		if (ret) {
			pr_err("Failed to read 'reg'\n");
			of_node_put(node);
			return ret;
		}
		component->reg_base = ((resource_size_t)reg[0] << 32) | reg[1];
		component->reg_size = ((resource_size_t)reg[2] << 32) | reg[3];
		pr_info("reg_base=0x%llx reg_size=0x%llx\n", component->reg_base, component->reg_size);

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
				io_port->type = XUANTIE_NTRACE_ENCODER;
				io_port->base_addr = ((u64)reg[0] << 32) | reg[1];
				component->in[port_nr] = io_port;
				port_nr++;
			}
		}

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
				io_port->type = XUANTIE_NTRACE_SINK_SMEM;
				io_port->base_addr = ((u64)reg[0] << 32) | reg[1];
				component->out[port_nr] = io_port;
				port_nr++;
			}
		}

		for (int i = 0; i < component->in_num; i++) {
			pr_info("\t in[%d]is_input=%d endpoint_num=%d\n", i, component->in[i]->is_input, component->in[i]->endpoint_num);
		}
		for (int j = 0; j < component->out_num; j++) {
			pr_info("\t out[%d]is_input=%d endpoint_num=%d\n", j, component->out[j]->is_input, component->out[j]->endpoint_num);
		}

		INIT_LIST_HEAD(&component->list);
		list_add_tail(&component->list, &xuantie_ntrace_controllers);
	}

	pr_info("xuantie_ntrace_controllers=%d\n", get_list_count(&xuantie_ntrace_controllers));

	return ret;
}
device_initcall(xuantie_ntrace_funnel_init);
