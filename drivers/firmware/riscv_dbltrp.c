// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Rivos Inc.
 */

#define pr_fmt(fmt) "riscv-dbltrp: " fmt

#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/riscv_dbltrp.h>

#include <asm/sbi.h>

static bool double_trap_enabled;

bool riscv_double_trap_enabled(void)
{
	return double_trap_enabled;
}
EXPORT_SYMBOL(riscv_double_trap_enabled);

static int __init riscv_dbltrp(void)
{
	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SSDBLTRP)) {
		pr_err("Ssdbltrp extension not available\n");
		return 1;
	}

	double_trap_enabled = true;

	pr_info("Double trap handling registered\n");

	return 0;
}
device_initcall(riscv_dbltrp);
