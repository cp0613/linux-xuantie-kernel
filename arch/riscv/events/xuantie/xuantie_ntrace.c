// SPDX-License-Identifier: GPL-2.0-only

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/perf_event.h>

#include "xuantie_ntrace.h"

LIST_HEAD(xuantie_ntrace_controllers);
static struct xuantie_ntrace_pmu xuantie_ntrace_pmu;

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
	pr_info("%s:%d\n", __func__, __LINE__);
	return 0;
}

static void xuantie_ntrace_event_del(struct perf_event *event, int mode)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static void xuantie_ntrace_event_start(struct perf_event *event, int mode)
{
	pr_info("%s:%d on_cpu=%d cpu=%d\n", __func__, __LINE__, event->oncpu, event->cpu);
}

static void xuantie_ntrace_event_stop(struct perf_event *event, int mode)
{
	pr_info("%s:%d on_cpu=%d cpu=%d\n", __func__, __LINE__, event->oncpu, event->cpu);
}

static void xuantie_ntrace_event_read(struct perf_event *event)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static void xuantie_ntrace_event_enable(struct pmu *pmu)
{
	pr_info("%s:%d\n", __func__, __LINE__);
}

static void xuantie_ntrace_event_disable(struct pmu *pmu)
{
	pr_info("%s:%d\n", __func__, __LINE__);
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
		pr_info("type=%s in_num=%d out_num=%d\n", xuantie_ntrace_type2str(component->type), component->in_num, component->out_num);
		for (int i = 0; i < component->in_num; i++) {
			pr_info("\t in[%d] type=%s base_addr=0x%llx\n", i, xuantie_ntrace_type2str(component->in[i]->type), component->in[i]->base_addr);
		}
		for (int j = 0; j < component->out_num; j++) {
			pr_info("\t out[%d] type=%s base_addr=0x%llx\n", j, xuantie_ntrace_type2str(component->out[j]->type), component->out[j]->base_addr);
		}
	}

	xuantie_ntrace_pmu.pmu.module = THIS_MODULE,
	xuantie_ntrace_pmu.pmu.name = "xuantie_ntrace",
	xuantie_ntrace_pmu.pmu.capabilities	= PERF_PMU_CAP_EXCLUSIVE | PERF_PMU_CAP_ITRACE;
	xuantie_ntrace_pmu.pmu.attr_groups	= xuantie_ntrace_event_attr_groups;
	xuantie_ntrace_pmu.pmu.task_ctx_nr	= perf_sw_context,
	xuantie_ntrace_pmu.pmu.event_init	= xuantie_ntrace_event_init;
	xuantie_ntrace_pmu.pmu.add			= xuantie_ntrace_event_add; //解析配置
	xuantie_ntrace_pmu.pmu.del			= xuantie_ntrace_event_del; //结束，收集数据
	xuantie_ntrace_pmu.pmu.start		= xuantie_ntrace_event_start; //使能trace
	xuantie_ntrace_pmu.pmu.stop			= xuantie_ntrace_event_stop; //禁止trace
	xuantie_ntrace_pmu.pmu.read			= xuantie_ntrace_event_read;
	xuantie_ntrace_pmu.pmu.pmu_enable	= xuantie_ntrace_event_enable,
	xuantie_ntrace_pmu.pmu.pmu_disable	= xuantie_ntrace_event_disable,
	// xuantie_ntrace_pmu.pmu.setup_aux	= xuantie_ntrace_buffer_setup_aux;
	// xuantie_ntrace_pmu.pmu.free_aux		= xuantie_ntrace_buffer_free_aux;
	xuantie_ntrace_pmu.pmu.addr_filters_sync	= xuantie_ntrace_event_filters_sync,
	xuantie_ntrace_pmu.pmu.addr_filters_validate	= xuantie_ntrace_event_filters_validate,

	ret = perf_pmu_register(&xuantie_ntrace_pmu.pmu, "xuantie_ntrace", -1);
	pr_info("%s:%d ret=%d\n", __func__, __LINE__, ret);
	return ret;
}
late_initcall(xuantie_ntrace_init);
