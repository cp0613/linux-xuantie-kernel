/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELFTEST_RISCV_ASM_H
#define SELFTEST_RISCV_ASM_H

#if __riscv_xlen == 64
#define __REG_SEL(a, b)	a

#elif __riscv_xlen == 32
#define __REG_SEL(a, b)	b
#endif

#define REG_L	__REG_SEL(ld, lw)
#define REG_S	__REG_SEL(sd, sw)

#define SZREG	__REG_SEL(8, 4)
#define LGREG	__REG_SEL(3, 2)

#endif
