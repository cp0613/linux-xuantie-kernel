// SPDX-License-Identifier: GPL-2.0-or-later

#include <string.h>
#include <objtool/check.h>
#include <objtool/warn.h>
#include <asm/insn.h>
#include <asm/orc_types.h>
#include <linux/objtool_types.h>

#define RISCV_INSN_SIZE		4
#define RISCV_INSN_NOP		_UL(0x00000013)
#define RISCV_INSN_JARL		_UL(0x00008067)
#define RISCV_INSN_EBREAK	_UL(0x00100073)
#define RISCV_INSN_C_SIZE	2
#define RISCV_INSN_C_NOP	_UL(0x0001)
#define RISCV_INSN_C_JARL	_UL(0x9082)
#define RISCV_INSN_C_EBREAK	_UL(0x9002)

int arch_ftrace_match(char *name)
{
	return !strcmp(name, "_mcount");
}

unsigned long arch_jump_destination(struct instruction *insn)
{
	return insn->offset + insn->immediate;
}

unsigned long arch_dest_reloc_offset(int addend)
{
	return addend;
}

bool arch_pc_relative_reloc(struct reloc *reloc)
{
	return false;
}

bool arch_callee_saved_reg(unsigned char reg)
{
	switch (reg) {
	case CFI_RA:
	case CFI_FP:
	case CFI_S1 ... CFI_S11:
		return true;
	default:
		return false;
	}
}

int arch_decode_hint_reg(u8 sp_reg, int *base)
{
	switch (sp_reg) {
	case ORC_REG_UNDEFINED:
		*base = CFI_UNDEFINED;
		break;
	case ORC_REG_SP:
		*base = CFI_SP;
		break;
	case ORC_REG_FP:
		*base = CFI_FP;
		break;
	default:
		return -1;
	}

	return 0;
}

int arch_decode_instruction(struct objtool_file *file, const struct section *sec,
			    unsigned long offset, unsigned int maxlen,
			    struct instruction *insn)
{
	return -1;
}

const char *arch_nop_insn(int len)
{
	static u32 nop = RISCV_INSN_NOP, nop_c = RISCV_INSN_C_NOP;

	if ((len != RISCV_INSN_SIZE) && (len != RISCV_INSN_C_SIZE)) {
		WARN("invalid NOP size: %d\n", len);
		return NULL;
	}

	return (len == RISCV_INSN_SIZE) ? (const char *)&nop : (const char *)&nop_c;
}

const char *arch_ret_insn(int len)
{
	static u32 ret = RISCV_INSN_JARL, ret_c = RISCV_INSN_C_JARL;

	if ((len != RISCV_INSN_SIZE) && (len != RISCV_INSN_C_SIZE)) {
		WARN("invalid RET size: %d\n", len);
		return NULL;
	}

	return (len == RISCV_INSN_SIZE) ? (const char *)&ret : (const char *)&ret_c;
}

void arch_initial_func_cfi_state(struct cfi_init_state *state)
{
	int i;

	for (i = 0; i < CFI_NUM_REGS; i++) {
		state->regs[i].base = CFI_UNDEFINED;
		state->regs[i].offset = 0;
	}

	/* initial CFA (call frame address) */
	state->cfa.base = CFI_SP;
	state->cfa.offset = 0;
}
