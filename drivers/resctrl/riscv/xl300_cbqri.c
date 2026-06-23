// SPDX-License-Identifier: GPL-2.0-only
/*
 * Xuantie XL300 CBQRI driver — DT probe for L3 Cache capacity QoS controllers.
 *
 * XL300 exposes CC (capacity) CBQRI register banks
 * within a single MMIO region:
 *   CC registers at base + 0x400
 *   BC registers at base + 0x480
 *
 * The L3 partition feature must be enabled by setting L3CR.PAE (bit 0 at
 * base + 0x000) before the controllers become active.
 */
#define pr_fmt(fmt) "xl300-cbqri: " fmt

#include <linux/device.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/riscv_qos.h>

#define XL300_L3CR_OFF		0x000
#define XL300_L3CR_PAE		BIT(0)

#define XL300_CC_BASE_OFF	0x400
#define XL300_BC_BASE_OFF	0x480
#define XL300_CTRL_SIZE		0x40

static const struct of_device_id xl300_cbqri_ids[] = {
	{ .compatible = "xuantie,xl300-cbqri" },
	{ }
};

static int __init xl300_cbqri_init(void)
{
	struct cbqri_controller_info *cc_info, *bc_info;
	struct device_node *np;
	void __iomem *base;
	u64 l3cr;
	u32 value;
	int err;

	for_each_matching_node(np, xl300_cbqri_ids) {
		if (!of_device_is_available(np)) {
			of_node_put(np);
			continue;
		}

		err = of_property_read_u32_index(np, "reg", 1, &value);
		if (err) {
			pr_err("failed to read reg base address (%d)\n", err);
			goto err_node_put;
		}
		u64 dt_base = value;

		err = of_property_read_u32_index(np, "reg", 3, &value);
		if (err) {
			pr_err("failed to read reg size (%d)\n", err);
			goto err_node_put;
		}
		u32 dt_size = value;

		base = ioremap(dt_base, dt_size);
		if (!base) {
			pr_err("failed to ioremap 0x%llx\n", dt_base);
			err = -ENOMEM;
			goto err_node_put;
		}

		l3cr = readq(base + XL300_L3CR_OFF);
		l3cr |= XL300_L3CR_PAE;
		writeq(l3cr, base + XL300_L3CR_OFF);

		u64 cc_caps = readq(base + XL300_CC_BASE_OFF);
		pr_info("CC_CAPABILITIES = 0x%016llx (NCBLKS=%llu, VER=0x%llx)\n",
			cc_caps,
			(cc_caps >> 8) & 0xFFFF,
			cc_caps & 0xFF);

		u64 bc_caps = readq(base + XL300_BC_BASE_OFF);
		pr_info("BC_CAPABILITIES = 0x%016llx (NBWBLKS=%llu, MRBWB=%llu, VER=0x%llx)\n",
			bc_caps,
			(bc_caps >> 8) & 0xFFFF,
			(bc_caps >> 32) & 0xFFFF,
			bc_caps & 0xFF);
		iounmap(base);

		/* Capacity controller info (CC at base + 0x400) */
		cc_info = kzalloc(sizeof(*cc_info), GFP_KERNEL);
		if (!cc_info) {
			err = -ENOMEM;
			goto err_node_put;
		}
		cc_info->type = CBQRI_CONTROLLER_TYPE_CAPACITY;
		cc_info->addr = dt_base + XL300_CC_BASE_OFF;
		cc_info->size = XL300_CTRL_SIZE;

		err = of_property_read_u32(np, "cache-level", &value);
		if (err) {
			pr_err("failed to read cache-level (%d)\n", err);
			goto err_free_cc;
		}
		cc_info->cache.cache_level = value;

		err = of_property_read_u32(np, "cache-size", &value);
		if (err) {
			pr_err("failed to read cache-size (%d)\n", err);
			goto err_free_cc;
		}
		cc_info->cache.cache_size = value;

		err = of_property_read_u32(np, "riscv,cbqri-rcid", &value);
		if (err) {
			pr_err("failed to read RCID count (%d)\n", err);
			goto err_free_cc;
		}
		cc_info->rcid_count = value;

		err = of_property_read_u32(np, "riscv,cbqri-mcid", &value);
		if (err) {
			pr_err("failed to read MCID count (%d)\n", err);
			goto err_free_cc;
		}
		cc_info->mcid_count = value;

		cpumask_copy(&cc_info->cache.cpu_mask, cpu_possible_mask);

		INIT_LIST_HEAD(&cc_info->list);
		list_add_tail(&cc_info->list, &cbqri_controllers);

		pr_info("CC: addr=0x%lx rcid=%u mcid=%u level=%d size=%u\n",
			cc_info->addr, cc_info->rcid_count, cc_info->mcid_count,
			cc_info->cache.cache_level, cc_info->cache.cache_size);

		/* Bandwidth controller info (BC at base + 0x480) */
		bc_info = kzalloc(sizeof(*bc_info), GFP_KERNEL);
		if (!bc_info) {
			err = -ENOMEM;
			goto err_node_put;
		}
		bc_info->type = CBQRI_CONTROLLER_TYPE_BANDWIDTH;
		bc_info->addr = dt_base + XL300_BC_BASE_OFF;
		bc_info->size = XL300_CTRL_SIZE;
		bc_info->rcid_count = cc_info->rcid_count;
		bc_info->mcid_count = cc_info->mcid_count;

		INIT_LIST_HEAD(&bc_info->list);
		list_add_tail(&bc_info->list, &cbqri_controllers);

		pr_info("BC: addr=0x%lx rcid=%u mcid=%u\n",
			bc_info->addr, bc_info->rcid_count, bc_info->mcid_count);

		of_node_put(np);
	}

	return 0;

err_free_cc:
	kfree(cc_info);
err_node_put:
	of_node_put(np);
	return err;
}
device_initcall(xl300_cbqri_init);
