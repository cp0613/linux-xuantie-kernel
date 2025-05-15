// SPDX-License-Identifier: GPL-2.0-only
/*
 * Resource Director Technology(RDT)
 * - Cache Allocation code.
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * Authors:
 *    Fenghua Yu <fenghua.yu@intel.com>
 *    Tony Luck <tony.luck@intel.com>
 *
 * More information about RDT be found in the Intel (R) x86 Architecture
 * Software Developer Manual June 2016, volume 3, section 17.17.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/cpu.h>
#include <linux/kernfs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include "internal.h"

/*
 * Check whether MBA bandwidth percentage value is correct. The value is
 * checked against the minimum and max bandwidth values specified by the
 * hardware. The allocated bandwidth percentage is rounded to the next
 * control step available on the hardware.
 */
static bool bw_validate(char *buf, unsigned long *data, struct rdt_resource *r)
{
	unsigned long bw;
	int ret;

	/*
	 * Only linear delay values is supported for current Intel SKUs.
	 */
	if (!r->membw.delay_linear && r->membw.arch_needs_linear) {
		rdt_last_cmd_puts("No support for non-linear MB domains\n");
		return false;
	}

	ret = kstrtoul(buf, 10, &bw);
	if (ret) {
		rdt_last_cmd_printf("Non-decimal digit in MB value %s\n", buf);
		return false;
	}

	if ((bw < r->membw.min_bw || bw > r->default_ctrl) &&
	    !is_mba_sc(r)) {
		rdt_last_cmd_printf("MB value %ld out of range [%d,%d]\n", bw,
				    r->membw.min_bw, r->default_ctrl);
		return false;
	}

	*data = roundup(bw, (unsigned long)r->membw.bw_gran);
	return true;
}

int parse_bw(struct rdt_parse_data *data, struct resctrl_schema *s,
	     struct rdt_domain *d)
{
	struct resctrl_staged_config *cfg;
	u32 closid = data->rdtgrp->closid;
	struct rdt_resource *r = s->res;
	unsigned long bw_val;

	cfg = &d->staged_config[s->conf_type];
	if (cfg->have_new_ctrl) {
		rdt_last_cmd_printf("Duplicate domain %d\n", d->id);
		return -EINVAL;
	}

	if (!bw_validate(data->buf, &bw_val, r))
		return -EINVAL;

	if (is_mba_sc(r)) {
		d->mbps_val[closid] = bw_val;
		return 0;
	}

	cfg->new_ctrl = bw_val;
	cfg->have_new_ctrl = true;

	return 0;
}

/*
 * Check whether a cache bit mask is valid.
 * For Intel the SDM says:
 *	Please note that all (and only) contiguous '1' combinations
 *	are allowed (e.g. FFFFH, 0FF0H, 003CH, etc.).
 * Additionally Haswell requires at least two bits set.
 * AMD allows non-contiguous bitmasks.
 */
static bool cbm_validate(char *buf, u32 *data, struct rdt_resource *r)
{
	unsigned long first_bit, zero_bit, val;
	unsigned int cbm_len = r->cache.cbm_len;
	int ret;

	ret = kstrtoul(buf, 16, &val);
	if (ret) {
		rdt_last_cmd_printf("Non-hex character in the mask %s\n", buf);
		return false;
	}

	if ((r->cache.min_cbm_bits > 0 && val == 0) || val > r->default_ctrl) {
		rdt_last_cmd_puts("Mask out of range\n");
		return false;
	}

	first_bit = find_first_bit(&val, cbm_len);
	zero_bit = find_next_zero_bit(&val, cbm_len, first_bit);

	/* Are non-contiguous bitmaps allowed? */
	if (!r->cache.arch_has_sparse_bitmaps &&
	    (find_next_bit(&val, cbm_len, zero_bit) < cbm_len)) {
		rdt_last_cmd_printf("The mask %lx has non-consecutive 1-bits\n", val);
		return false;
	}

	if ((zero_bit - first_bit) < r->cache.min_cbm_bits) {
		rdt_last_cmd_printf("Need at least %d bits in the mask\n",
				    r->cache.min_cbm_bits);
		return false;
	}

	*data = val;
	return true;
}

/*
 * Read one cache bit mask (hex). Check that it is valid for the current
 * resource type.
 */
int parse_cbm(struct rdt_parse_data *data, struct resctrl_schema *s,
	      struct rdt_domain *d)
{
	struct rdtgroup *rdtgrp = data->rdtgrp;
	struct resctrl_staged_config *cfg;
	struct rdt_resource *r = s->res;
	u32 cbm_val;

	cfg = &d->staged_config[s->conf_type];
	if (cfg->have_new_ctrl) {
		rdt_last_cmd_printf("Duplicate domain %d\n", d->id);
		return -EINVAL;
	}

	/*
	 * Cannot set up more than one pseudo-locked region in a cache
	 * hierarchy.
	 */
	if (rdtgrp->mode == RDT_MODE_PSEUDO_LOCKSETUP &&
	    rdtgroup_pseudo_locked_in_hierarchy(d)) {
		rdt_last_cmd_puts("Pseudo-locked region in hierarchy\n");
		return -EINVAL;
	}

	if (!cbm_validate(data->buf, &cbm_val, r))
		return -EINVAL;

	if ((rdtgrp->mode == RDT_MODE_EXCLUSIVE ||
	     rdtgrp->mode == RDT_MODE_SHAREABLE) &&
	    rdtgroup_cbm_overlaps_pseudo_locked(d, cbm_val)) {
		rdt_last_cmd_puts("CBM overlaps with pseudo-locked region\n");
		return -EINVAL;
	}

	/*
	 * The CBM may not overlap with the CBM of another closid if
	 * either is exclusive.
	 */
	if (rdtgroup_cbm_overlaps(s, d, cbm_val, rdtgrp->closid, true)) {
		rdt_last_cmd_puts("Overlaps with exclusive group\n");
		return -EINVAL;
	}

	if (rdtgroup_cbm_overlaps(s, d, cbm_val, rdtgrp->closid, false)) {
		if (rdtgrp->mode == RDT_MODE_EXCLUSIVE ||
		    rdtgrp->mode == RDT_MODE_PSEUDO_LOCKSETUP) {
			rdt_last_cmd_puts("Overlaps with other group\n");
			return -EINVAL;
		}
	}

	cfg->new_ctrl = cbm_val;
	cfg->have_new_ctrl = true;

	return 0;
}

static u32 get_config_index(u32 closid, enum resctrl_conf_type type)
{
	switch (type) {
	default:
	case CDP_NONE:
		return closid;
	case CDP_CODE:
		return closid * 2 + 1;
	case CDP_DATA:
		return closid * 2;
	}
}

static bool apply_config(struct rdt_hw_domain *hw_dom,
			 struct resctrl_staged_config *cfg, u32 idx,
			 cpumask_var_t cpu_mask)
{
	struct rdt_domain *dom = &hw_dom->d_resctrl;

	if (cfg->new_ctrl != hw_dom->ctrl_val[idx]) {
		cpumask_set_cpu(cpumask_any(&dom->cpu_mask), cpu_mask);
		hw_dom->ctrl_val[idx] = cfg->new_ctrl;

		return true;
	}

	return false;
}

int resctrl_arch_update_one(struct rdt_resource *r, struct rdt_domain *d,
			    u32 closid, enum resctrl_conf_type t, u32 cfg_val)
{
	struct rdt_hw_resource *hw_res = resctrl_to_arch_res(r);
	struct rdt_hw_domain *hw_dom = resctrl_to_arch_dom(d);
	u32 idx = get_config_index(closid, t);
	struct msr_param msr_param;

	if (!cpumask_test_cpu(smp_processor_id(), &d->cpu_mask))
		return -EINVAL;

	hw_dom->ctrl_val[idx] = cfg_val;

	msr_param.res = r;
	msr_param.low = idx;
	msr_param.high = idx + 1;
	hw_res->msr_update(d, &msr_param, r);

	return 0;
}

int resctrl_arch_update_domains(struct rdt_resource *r, u32 closid)
{
	struct resctrl_staged_config *cfg;
	struct rdt_hw_domain *hw_dom;
	struct msr_param msr_param;
	enum resctrl_conf_type t;
	cpumask_var_t cpu_mask;
	struct rdt_domain *d;
	u32 idx;

	if (!zalloc_cpumask_var(&cpu_mask, GFP_KERNEL))
		return -ENOMEM;

	msr_param.res = NULL;
	list_for_each_entry(d, &r->domains, list) {
		hw_dom = resctrl_to_arch_dom(d);
		for (t = 0; t < CDP_NUM_TYPES; t++) {
			cfg = &hw_dom->d_resctrl.staged_config[t];
			if (!cfg->have_new_ctrl)
				continue;

			idx = get_config_index(closid, t);
			if (!apply_config(hw_dom, cfg, idx, cpu_mask))
				continue;

			if (!msr_param.res) {
				msr_param.low = idx;
				msr_param.high = msr_param.low + 1;
				msr_param.res = r;
			} else {
				msr_param.low = min(msr_param.low, idx);
				msr_param.high = max(msr_param.high, idx + 1);
			}
		}
	}

	if (cpumask_empty(cpu_mask))
		goto done;

	/* Update resource control msr on all the CPUs. */
	on_each_cpu_mask(cpu_mask, rdt_ctrl_update, &msr_param, 1);

done:
	free_cpumask_var(cpu_mask);

	return 0;
}

u32 resctrl_arch_get_config(struct rdt_resource *r, struct rdt_domain *d,
			    u32 closid, enum resctrl_conf_type type)
{
	struct rdt_hw_domain *hw_dom = resctrl_to_arch_dom(d);
	u32 idx = get_config_index(closid, type);

	return hw_dom->ctrl_val[idx];
}
