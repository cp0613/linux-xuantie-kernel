/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __LINUX_RISCV_QOS_H
#define __LINUX_RISCV_QOS_H

#include <linux/resctrl_types.h>
#include <linux/iommu.h>
#include <linux/types.h>

#include <asm/qos.h>

enum cbqri_controller_type {
	CBQRI_CONTROLLER_TYPE_CAPACITY,
	CBQRI_CONTROLLER_TYPE_BANDWIDTH,
	CBQRI_CONTROLLER_TYPE_UNKNOWN
};

struct cbqri_controller_info {
	unsigned long addr;
	unsigned long size;
	enum cbqri_controller_type type;
	u32 rcid_count;
	u32 mcid_count;
	struct list_head list;

	struct cache_controller {
		u32 cache_level;
		u32 cache_size; /* in bytes */
		struct cpumask cpu_mask;
	} cache;
};

extern struct list_head cbqri_controllers;

bool resctrl_arch_alloc_capable(void);
bool resctrl_arch_mon_capable(void);

struct rdt_resource;
/*
 * Note about terminology between x86 (Intel RDT/AMD QoS) and RISC-V:
 *   CLOSID on x86 is RCID on RISC-V
 *     RMID on x86 is MCID on RISC-V
 *      CDP on x86 is AT (access type) on RISC-V
 */
u32  resctrl_arch_rmid_idx_encode(u32 closid, u32 rmid);
void resctrl_arch_rmid_idx_decode(u32 idx, u32 *closid, u32 *rmid);
void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 pmg);
void resctrl_arch_sched_in(struct task_struct *tsk);
void resctrl_arch_set_closid_rmid(struct task_struct *tsk, u32 closid, u32 rmid);
bool resctrl_arch_match_closid(struct task_struct *tsk, u32 closid);
bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid);
void resctrl_arch_reset_resources(void);
void *resctrl_arch_mon_ctx_alloc(struct rdt_resource *r, enum resctrl_event_id evtid);
void resctrl_arch_mon_ctx_free(struct rdt_resource *r, enum resctrl_event_id evtid,
			       void *arch_mon_ctx);
struct rdt_domain_hdr *resctrl_arch_find_domain(struct list_head *domain_list, int id);

static inline bool resctrl_arch_event_is_free_running(enum resctrl_event_id evt)
{
	/* must be true for resctrl L3 monitoring files to be created */
	return true;
}

#endif /* __LINUX_RISCV_QOS_H */
