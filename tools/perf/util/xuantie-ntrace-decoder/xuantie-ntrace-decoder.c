// SPDX-License-Identifier: GPL-2.0

#include <stdlib.h>
#include <string.h>
#include <linux/bitops.h>
#include "thread.h"
#include "thread-stack.h"
#include "map.h"
#include "map_symbol.h"
#include "symbol.h"
#include "dso.h"

#include "xuantie-ntrace-decoder.h"
#include "xuantie-mseo-mdo.h"
#include "xuantie-ntrace-message.h"

enum GET_AN_INSN_STATE {
	GET_AN_INSN_FIRST = 0,
	GET_AN_INSN_MIDDLE = 1,
	GET_AN_INSN_END = 2,
};

enum rv_mmu_type {
	MMU_SV39,
	MMU_SV48,
	MMU_SV57,
	MMU_UNKNOWN
};

// used for i-cnt and hist
struct xt_trace_address_range {
	uint64_t start_addr;
	uint64_t end_addr;
	struct xt_trace_address_range *next;
};

struct xt_trace_program_flow_node {
	uint64_t start_addr; // the start addr of this message
	char saddr_dso[PATH_MAX];
	char saddr_sym[PATH_MAX];
	// the start addr of the next message
	// also means the destination address of this message
	uint64_t full_addr;
	char faddr_dso[PATH_MAX];
	char faddr_sym[PATH_MAX];
	struct xt_trace_address_range *addr_range; // need free
	struct xt_riscv_nexus_trace_message msg;
	struct xt_riscv_nexus_trace_message *ownership; // no need to free

	// We need to go through the list from head to end
	// and from end to head.
	struct xt_trace_program_flow_node *next;
	struct xt_trace_program_flow_node *prev;

	//set if can't get full addr or addr_range
	int invalid;
};

/*************************************************************
 * Classify the insns
 *************************************************************/
static inline unsigned int riscv_insn_length(uint8_t insn)
{
	if ((insn & 0x3) != 0x3) /* RVC.  */
		return 2;
	if ((insn & 0x1f) !=
	    0x1f) /* Base ISA and extensions in 32-bit space.  */
		return 4;
	if ((insn & 0x7f) == 0x7f) /* DROPPED. p extensions.  */
		return 4;
	if ((insn & 0x3f) == 0x1f) /* 48-bit extensions.  */
		return 6;
	if ((insn & 0x7f) == 0x3f) /* 64-bit extensions.  */
		return 8;
	/* Longer instructions not supported at the moment.  */
	return 2;
}

static enum rv_mmu_type parse_mmu_mode(void)
{
	FILE *fp;
	char line[256];
	const char *target = "mmu";
	const char *delimiter = ":";
	char *key, *value;
	enum rv_mmu_type mmu_mode = MMU_UNKNOWN;

	fp = fopen("/proc/cpuinfo", "r");
	if (!fp) {
		perror("fopen");
		return mmu_mode;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, target)) {
			key = strtok(line, delimiter);
			value = strtok(NULL, delimiter);
			if (key && value) {
				key = strtok(key, " \t\n");
				value = strtok(value, " \t\n");
				if (strcmp(key, target) == 0) {
					if (strcmp(value, "sv39") == 0)
						mmu_mode = MMU_SV39;
					else if (strcmp(value, "sv48") == 0)
						mmu_mode = MMU_SV48;
					else if (strcmp(value, "sv57") == 0)
						mmu_mode = MMU_SV57;
					else
						mmu_mode = MMU_UNKNOWN;
					break;
				}
			}
		}
	}

	fclose(fp);

	return mmu_mode;
}
/* https://www.kernel.org/doc/html/next/riscv/vm-layout.html */
static u8 riscv_get_cpu_mode(u64 vaddr)
{
	static enum rv_mmu_type mmu_mode = MMU_UNKNOWN;

	if (mmu_mode == MMU_UNKNOWN)
		mmu_mode = parse_mmu_mode();

	switch (mmu_mode) {
	case MMU_SV39:
		if (vaddr > 0x3fffffffff) //SV39:256G
			return PERF_RECORD_MISC_KERNEL;
		break;
	case MMU_SV48:
		if (vaddr > 0x7fffffffffff) //SV48:128T
			return PERF_RECORD_MISC_KERNEL;
		break;
	case MMU_SV57:
		if (vaddr > 0xffffffffffffff) //SV57:64P
			return PERF_RECORD_MISC_KERNEL;
		break;
	case MMU_UNKNOWN:
	default:
		printf("Unknown MMU Mode: %d\n", mmu_mode);
		break;
	}

	return PERF_RECORD_MISC_USER;
}

#define FAILED_TO_GET_AN_INSN 0xabcddeadbeef1234

static uint64_t get_an_insn(struct perf_session *session,
			    struct auxtrace_buffer *buffer, uint64_t addr,
			    uint32_t *len, enum GET_AN_INSN_STATE state, uint64_t addr2)
{
	static struct addr_location al;
	static struct dso *dso;
	static struct thread *thread;
	static u64 start_addr_offset;
	u64 offset;
	uint8_t buf[8] = {0};
	long length;
	u8 cpumode;

	if (state == GET_AN_INSN_FIRST) {
		cpumode = PERF_RECORD_MISC_KERNEL;
		thread = machine__findnew_thread(&session->machines.host, buffer->pid, buffer->tid);

		cpumode = riscv_get_cpu_mode(addr);

		addr_location__init(&al);
		if (!thread__find_map(thread, cpumode, addr, &al))
			goto error_end;
		dso = map__dso(al.map);
		if (!dso)
			goto error_end;
		if (dso->data.status == DSO_DATA_STATUS_ERROR &&
		    dso__data_status_seen(dso, DSO_DATA_STATUS_SEEN_ITRACE))
			goto error_end;
		offset = map__map_ip(al.map, addr);
		if (cpumode == PERF_RECORD_MISC_KERNEL)
			offset -= (0xffffffff80002000 - 0x3000); // readelf -S vmlinux in .text
		map__load(al.map);
		length = dso__data_read_offset(dso, maps__machine(thread__maps(thread)),
			offset, buf, 2);
		if (length <= 0) {
			//printf ("XUANTIE NTrace: Debug data not found for address %#"PRIx64" in %s\n",
			//	addr, dso->long_name ? dso->long_name : "Unknown");
			goto error_end;
		}
		/* insn length */
		*len = riscv_insn_length(buf[0]);
		if (*len > 2) {
			length = dso__data_read_offset(dso, maps__machine(thread__maps(thread)),
					offset + 2, buf + 2, *len - 2);
			if (length <= 0) {
				printf("XUANTIE NTrace: Debug data not found for address %#"PRIx64" in %s\n",
						addr + 2, dso->long_name ? dso->long_name : "Unknown");
				goto error_end;
			}

			if (length != (*len - 2)) {
				printf("XUANTIE NTrace: can't get full insn value for address %#"PRIx64" in %s\n",
					addr, dso->long_name ? dso->long_name : "Unknown");
				goto error_end;
			}
		}

		start_addr_offset = offset;
		return *(uint64_t *)buf;
	} else if (state == GET_AN_INSN_MIDDLE) {
		if (dso == NULL || thread == NULL)
			return FAILED_TO_GET_AN_INSN;
		if (addr2 > addr)
			offset = start_addr_offset + (addr2 - addr);
		else
			offset = start_addr_offset - (addr - addr2);

		length = dso__data_read_offset(dso, maps__machine(thread__maps(thread)), offset, buf, 2);
		if (length <= 0) {
			printf("XUANTIE NTrace: Debug data not found for address %#"PRIx64" in %s\n",
				addr2, dso->long_name ? dso->long_name : "Unknown");
			goto error_end;
		}

		/* insn length */
		*len = riscv_insn_length(buf[0]);
		if (*len > 2) {
			length = dso__data_read_offset(dso, maps__machine(thread__maps(thread)),
				offset + 2, buf + 2, *len - 2);
			if (length <= 0) {
				printf("XUANTIE NTrace: Debug data not found for address %#"PRIx64" in %s\n",
					addr2 + 2, dso->long_name ? dso->long_name : "Unknown");
				goto error_end;
			}

			if (length != (*len - 2)) {
				printf("XUANTIE NTrace: can't get full insn value for address %#"PRIx64" in %s\n",
					addr2, dso->long_name ? dso->long_name : "Unknown");
				goto error_end;
			}
		}
		return *(uint64_t *)buf;
	} else {
		if (dso == NULL || thread == NULL)
			return FAILED_TO_GET_AN_INSN;
	}

error_end:
	//printf("can't read insn for addr %#" PRIx64 "\n", addr);
	addr_location__exit(&al);
	dso = NULL;
	thread = NULL;
	return FAILED_TO_GET_AN_INSN;
}

static bool xt_trace_is_condition_branch_insn(uint32_t insn_length,
					      uint32_t insn_value)
{
	if (insn_length == 2) {
		if (RV_IS_C_BEQZ(insn_value) || RV_IS_C_BNEZ(insn_value))
			return true;
	} else {
		if (RV_IS_BEQ(insn_value) || RV_IS_BGE(insn_value) ||
		    RV_IS_BGEU(insn_value) || RV_IS_BLT(insn_value) ||
		    RV_IS_BLTU(insn_value) || RV_IS_BNE(insn_value))
			return true;
	}

	return false;
}

//..
static bool xt_trace_is_special_jump_insn(uint32_t insn_length,
					  uint32_t insn_value)
{
	if (insn_length == 2) {
		if (RV_IS_C_EBREAK(insn_value))
			return true;
	} else {
		if (RV_IS_EBREAK(insn_value) || RV_IS_ECALL(insn_value))
			return true;
	}

	return false;
}

static bool xt_trace_is_ret_insn(uint32_t insn_length, uint32_t insn_value)
{
	if (insn_length == 4) {
		if (RV_IS_MRET(insn_value) || RV_IS_SRET(insn_value) ||
		    RV_IS_URET(insn_value))
			return true;
	}

	return false;
}

static bool xt_trace_is_indirect_jump_insn(uint32_t insn_length,
					   uint32_t insn_value)
{
	if (insn_length == 2) {
		if (RV_IS_C_JALR(insn_value) || RV_IS_C_JR(insn_value) ||
		    RV_IS_C_J(insn_value))
			return true;
	} else {
		if (RV_IS_JAL(insn_value) || RV_IS_JALR(insn_value))
			return true;
	}

	return false;
}

static bool xt_trace_is_inferable_jump(uint32_t insn_length,
				       uint32_t insn_value)
{
	if (insn_length == 2) {
		if (RV_IS_C_J(insn_value) || RV_IS_C_JAL(insn_value))
			return true;
	} else {
		if (RV_IS_JAL(insn_value))
			return true;
	}

	return false;
}

//static bool
//xt_trace_is_sequential_insn(uint32_t insn_length, uint32_t insn_value)
//{
//    if (xt_trace_is_condition_branch_insn(insn_length, insn_value))
//        return false;
//    if (xt_trace_is_special_jump_insn(insn_length, insn_value))
//        return false;
//    if (xt_trace_is_ret_insn(insn_length, insn_value))
//        return false;
//    if (xt_trace_is_indirect_jump_insn(insn_length, insn_value))
//        return false;
//    return true;
//}

static bool xt_trace_is_indirect_branch_insn(uint32_t insn_length,
					     uint32_t insn_value)
{
	if (xt_trace_is_special_jump_insn(insn_length, insn_value))
		return true;
	if (xt_trace_is_ret_insn(insn_length, insn_value))
		return true;
	if (xt_trace_is_indirect_jump_insn(insn_length, insn_value))
		return true;
	return false;
}

/*************************************************************
 * Proccess I-CNT and HIST
 *************************************************************/
#define INSN_C_CONDITION_BRANCH_GET_IMM(insn)                           \
	(((((insn) >> 2) & 0x1) << 5) + ((((insn) >> 3) & 0x3) << 1) +  \
	 ((((insn) >> 5) & 0x3) << 6) + ((((insn) >> 10) & 0x3) << 3) + \
	 ((((insn) >> 12) & 0x1) << 8))

#define INSN_CONDITION_BRANCH_GET_IMM(insn)                             \
	(((((insn) >> 7) & 0x1) << 11) + ((((insn) >> 8) & 0xf) << 1) + \
	 ((((insn) >> 25) & 0x3f) << 5) + ((((insn) >> 31) & 0x1) << 12))

#define INSN_C_CONTROL_TRANSFER_GET_IMM(insn)                           \
	(((((insn) >> 2) & 0x1) << 5) + ((((insn) >> 3) & 0x7) << 1) +  \
	 ((((insn) >> 6) & 0x1) << 7) + ((((insn) >> 7) & 0x1) << 6) +  \
	 ((((insn) >> 8) & 0x1) << 10) + ((((insn) >> 9) & 0x3) << 8) + \
	 ((((insn) >> 11) & 0x1) << 4) + ((((insn) >> 12) & 0x1) << 11))

#define INSN_CONTROL_TRANSFER_GET_IMM(insn)                                 \
	(((((insn) >> 12) & 0xff) << 12) + ((((insn) >> 20) & 0x1) << 11) + \
	 ((((insn) >> 21) & 0x3ff) << 1) + ((((insn) >> 31) & 0x1) << 20))

#define RESOURCEFULL_MSG_MAX 64
struct resourcefull_message {
	uint32_t rdata0;
	uint32_t hist_count;
	struct resourcefull_message *next;
};

struct hist_resourcefull_message {
	struct resourcefull_message *msg;
	uint32_t total_hist_count;
};

static struct resourcefull_message *icnt_resourcefull_header;
static struct hist_resourcefull_message hist_resourcefull_header;

static void resource_full_clear(void)
{
	if (icnt_resourcefull_header) {
		struct resourcefull_message *tmp = NULL;

		while (icnt_resourcefull_header) {
			tmp = icnt_resourcefull_header->next;
			free(icnt_resourcefull_header);
			icnt_resourcefull_header = tmp;
		}
	}

	if (hist_resourcefull_header.msg) {
		struct resourcefull_message *tmp = NULL;

		while (hist_resourcefull_header.msg) {
			tmp = hist_resourcefull_header.msg->next;
			free(hist_resourcefull_header.msg);
			hist_resourcefull_header.msg = tmp;
		}

		hist_resourcefull_header.total_hist_count = 0;
	}
}

static int32_t add_resource_full_icnt(uint32_t icnt)
{
	struct resourcefull_message *msg =
		(struct resourcefull_message *)malloc(sizeof(struct resourcefull_message));

	if (msg == NULL) {
		printf("malloc failed: add i-cnt\n");
		return -1;
	}
	msg->rdata0 = icnt;
	msg->next = NULL;

	if (icnt_resourcefull_header) {
		struct resourcefull_message *tmp = icnt_resourcefull_header;

		while (tmp->next)
			tmp = tmp->next;
		tmp->next = msg;
	} else
		icnt_resourcefull_header = msg;

	return 0;
}

static uint64_t get_resource_full_icnt(uint32_t icnt)
{
	uint64_t total_icnt = icnt;
	struct resourcefull_message *tmp = icnt_resourcefull_header;

	while (tmp) {
		total_icnt += tmp->rdata0;
		tmp = tmp->next;
	}

	return total_icnt;
}

static int32_t add_resource_full_hist(uint32_t hist)
{
	uint32_t i = 0;
	struct resourcefull_message *msg = NULL;

	if (hist == 0 || hist == 1)
		return 0;

	msg = (struct resourcefull_message *)malloc(sizeof(struct resourcefull_message));
	if (msg == NULL) {
		printf("malloc failed: add hist\n");
		return -1;
	}

	for (i = 31; i > 0; i--) {
		if ((1 << i) & hist)
			break;
	}
	msg->hist_count = i;
	msg->rdata0 = hist;
	msg->next = NULL;

	if (hist_resourcefull_header.msg != NULL) {
		struct resourcefull_message *tmp = hist_resourcefull_header.msg;

		while (tmp->next)
			tmp = tmp->next;
		tmp->next = msg;
	} else
		hist_resourcefull_header.msg = msg;

	hist_resourcefull_header.total_hist_count += i;

	return 0;
}

static int32_t get_one_hist(void)
{
	uint32_t condition = 0;
	struct resourcefull_message *tmp = hist_resourcefull_header.msg;

	if (hist_resourcefull_header.total_hist_count == 0) {
		printf("Error No Hist.\n");
		return -1;
	}

	while (tmp) {
		if (tmp->hist_count != 0) {
			condition = (1 << (tmp->hist_count - 1)) & tmp->rdata0;
			tmp->hist_count--;
			hist_resourcefull_header.total_hist_count--;
			return condition ? 1 : 0;
		} else
			tmp = tmp->next;
	}

	printf("Error No Hist.\n");
	return -1;
}

static uint32_t get_hist_count(void)
{
	return hist_resourcefull_header.total_hist_count;
}

static int32_t
xt_trace_analyze_i_cnt_vs_hist(struct perf_session *session,
			       struct auxtrace_buffer *buffer, uint32_t i_cnt,
			       uint64_t start_addr, uint32_t hist,
			       struct xt_trace_address_range **range)
{
	int32_t ret = -1;
	uint64_t insn_addr = start_addr;
	uint32_t insn_len = 0;
	uint64_t insn_value = 0;
	struct xt_trace_address_range *range_last_p = NULL;
	int64_t insn_cnt = 0;
	bool get_range_end = false;
	enum GET_AN_INSN_STATE state = GET_AN_INSN_FIRST;

	if (add_resource_full_hist(hist))
		return -1;
	insn_cnt = get_resource_full_icnt(i_cnt);

	// If only hist == 0, we can't just set end_addr = start_addr + i_cnt * 2
	// as the i_cnt may contain c.j, c.jal or jal
	// if (hist_count == 0) {
	//	//for i-cnt with
	//	if (xt_trace_analyze_i_cnt(i_cnt, start_addr, true, false, elf_p, handler))
	//		return -1;

	//	*range =(struct xt_trace_address_range *)
	//		malloc(sizeof(struct xt_trace_address_range));
	//	if (*range == NULL)
	//		return -1;
	//	(*range)->start_addr = start_addr;
	//	(*range)->end_addr = start_addr + i_cnt * 2;
	//	(*range)->next = NULL;
	//	return 0;
	//}

	(*range) = (struct xt_trace_address_range *)malloc(
		sizeof(struct xt_trace_address_range));
	if ((*range) == NULL) {
		printf("Fail to malloc space for address range.\n");
		return -1;
	}
	(*range)->start_addr = start_addr;
	(*range)->end_addr = start_addr;
	(*range)->next = NULL;
	range_last_p = *range;

	while (insn_cnt) {
		//
		insn_value = get_an_insn(session, buffer, start_addr, &insn_len, state, insn_addr);
		if (insn_value == FAILED_TO_GET_AN_INSN) {
			ret = 1;
			goto error_end;
		}
		state = GET_AN_INSN_MIDDLE;

		if (xt_trace_is_condition_branch_insn(insn_len, insn_value)) {
			int32_t condition = 0;

			/*
			 * If the last insn is a condition branch in message ProgramCorrection,
			 * HIST may records or not records the condition.
			 */
			if (insn_cnt == (insn_len/2)) {
				if (get_hist_count())
					condition = get_one_hist();
				else
					condition = false;
			} else {
				// get one hist
				condition = get_one_hist();
				if (condition < 0) {
					if (insn_cnt == (insn_len/2))
						condition = false;
					else
						goto error_end;
				}
			}

			// if condition == true, create new address range
			if (condition != 0) {
				uint64_t new_addr = 0;
				struct xt_trace_address_range *range_tmp = NULL;

				if (insn_len == 2 &&
				    (RV_IS_C_BEQZ(insn_value) ||
				     RV_IS_C_BNEZ(insn_value))) {
					if (INSN_C_CONDITION_BRANCH_GET_IMM(
						    insn_value) >>
					    8)
						new_addr =
							insn_addr -
							((((~INSN_C_CONDITION_BRANCH_GET_IMM(
								   insn_value)) &
							   0xff) +
							  1) &
							 0xff);
					else
						new_addr =
							insn_addr +
							(INSN_C_CONDITION_BRANCH_GET_IMM(
								 insn_value) &
							 0xff);
				} else if (insn_len == 4 &&
					   (RV_IS_BEQ(insn_value) ||
					    RV_IS_BGE(insn_value) ||
					    RV_IS_BGEU(insn_value) ||
					    RV_IS_BLT(insn_value) ||
					    RV_IS_BLTU(insn_value) ||
					    RV_IS_BNE(insn_value))) {
					if (INSN_CONDITION_BRANCH_GET_IMM(
						    insn_value) >>
					    12)
						new_addr =
							insn_addr -
							((((~INSN_CONDITION_BRANCH_GET_IMM(
								   insn_value)) &
							   0xfff) +
							  1) &
							 0xfff);
					else
						new_addr =
							insn_addr +
							(INSN_CONDITION_BRANCH_GET_IMM(
								 insn_value) &
							 0xfff);
				} else {
					printf("Error: insn value 0x%lx with addr 0x%lx is not a condition branch insn.\n",
						insn_value, insn_addr);
					goto error_end;
				}

				// set range_last_p->end_addr to insn_addr and add
				// range_tmp to the range_last_p, then set range_last_p
				// to range_tmp
				// set range_last_p->end_addr to insn_addr
				range_last_p->end_addr = insn_addr + insn_len;

				/* If this condition branch insn is the last excuted
				 * no need to add range_tmp any more.
				 */
				if (insn_cnt == (insn_len/2)) {
					range_last_p->next = NULL;
					get_range_end = true;
				} else {
					// get new address range and add range_tmp to the range_last_p
					// then set range_last_p to range_tmp
					range_tmp = (struct xt_trace_address_range *)malloc(sizeof(struct xt_trace_address_range));
					if (range_tmp == NULL) {
						// msg
						goto error_end;
					}
					range_tmp->start_addr = new_addr;
					range_tmp->end_addr = new_addr;
					range_tmp->next = NULL;

					// add range_tmp to last
					range_last_p->next = range_tmp;
					range_last_p = range_tmp;
				}

				// update insn_addr
				insn_addr = new_addr;
			} else
				insn_addr += insn_len;
		} else if (xt_trace_is_indirect_branch_insn(insn_len,
							    insn_value)) {
			if (xt_trace_is_inferable_jump(insn_len, insn_value)) {
				uint64_t new_addr = 0;
				struct xt_trace_address_range *range_tmp = NULL;

				if (insn_len == 2) {
					if (INSN_C_CONTROL_TRANSFER_GET_IMM(
						    insn_value) >>
					    11)
						new_addr =
							insn_addr -
							((((~INSN_C_CONTROL_TRANSFER_GET_IMM(
								   insn_value)) &
							   0x7ff) +
							  1) &
							 0x7ff);
					else
						new_addr =
							insn_addr +
							(INSN_C_CONTROL_TRANSFER_GET_IMM(
								 insn_value) &
							 0x7ff);
				} else {
					if (INSN_CONTROL_TRANSFER_GET_IMM(
						    insn_value) >>
					    20)
						new_addr =
							insn_addr -
							((((~INSN_CONTROL_TRANSFER_GET_IMM(
								   insn_value)) &
							   0xfffff) +
							  1) &
							 0xfffff);
					else
						new_addr =
							insn_addr +
							(INSN_CONTROL_TRANSFER_GET_IMM(
								 insn_value) &
							 0xfffff);
				}

				// set range_last_p->end_addr to insn_addr
				range_last_p->end_addr = insn_addr + insn_len;

				/* If this indirect insn is the last excuted,
				 * no need to add range_tmp any more.
				 */
				if (insn_cnt == (insn_len/2)) {
					range_last_p->next = NULL;
					get_range_end = true;
				} else {
					// get new address range
					range_tmp = (struct xt_trace_address_range *)malloc(sizeof(struct xt_trace_address_range));
					if (range_tmp == NULL) {
						// msg
						printf("Fail to malloc space for address range1.\n");
						goto error_end;
					}
					range_tmp->start_addr = new_addr;
					range_tmp->end_addr = new_addr;
					range_tmp->next = NULL;

					// add range_tmp to the range_last_p, then set range_last_p
					// to range_tmp
					range_last_p->next = range_tmp;
					range_last_p = range_tmp;
				}

				// update insn_addr
				insn_addr = new_addr;
			} else {
				if (insn_cnt != insn_len / 2) {
					printf("I-cnt error.\n");
					goto error_end;
				}

				insn_addr += insn_len;
			}
		} else
			insn_addr += insn_len;

		insn_cnt -= insn_len / 2;
		if (insn_cnt == 0)
			break;
		else if (insn_cnt < 0) {
			// msg
			printf("I-cnt error2.\n");
			goto error_end;
		}
	}

	if (get_hist_count()) {
		// msg
		printf("Hist error.\n");
		goto error_end;
	}

	if (!get_range_end)
		range_last_p->end_addr = insn_addr;

	get_an_insn(NULL, NULL, 0, NULL, GET_AN_INSN_END, 0);

	return 0;

error_end:
	// free range
	while (*range) {
		struct xt_trace_address_range *range_tmp = *range;

		*range = (*range)->next;
		free(range_tmp);
	}

	get_an_insn(NULL, NULL, 0, NULL, GET_AN_INSN_END, 0);

	return ret;
}

/*************************************************************
 * Build struct xt_trace_program_flow_node
 *************************************************************/
static struct xt_trace_program_flow_node *trace_program_header;

static struct xt_trace_program_flow_node *
xt_trace_malloc_program_flow_node(void)
{
	struct xt_trace_program_flow_node *node =
		(struct xt_trace_program_flow_node *)malloc(
			sizeof(struct xt_trace_program_flow_node));

	if (node)
		memset(node, 0, sizeof(struct xt_trace_program_flow_node));

	return node;
}

static void
xt_trace_add_program_flow_node_to_list(struct xt_trace_program_flow_node *node)
{
	if (trace_program_header == NULL)
		trace_program_header = node;
	else {
		struct xt_trace_program_flow_node *node_p =
			trace_program_header;

		while (node_p->next)
			node_p = node_p->next;

		node_p->next = node;
		node->prev = node_p;
	}
}

static struct xt_trace_program_flow_node *xt_trace_get_last_node(void)
{
	struct xt_trace_program_flow_node *node_p = trace_program_header;

	while (node_p->next)
		node_p = node_p->next;

	return node_p;
}

static bool xt_trace_msg_has_full_addr(struct xt_riscv_nexus_trace_message *msg)
{
	if (msg->tcode == TCODE_PROGTRACESYNC ||
	    msg->tcode == TCODE_DIRECTBRANCHSYNC ||
	    msg->tcode == TCODE_INDIRECTBRANCHSYNC ||
	    msg->tcode == TCODE_INDIRECTBRANCHHISTSYNC)
		return true;

	return false;
}

static void xt_trace_free_program_flow_node(void)
{
	struct xt_trace_program_flow_node *node_p = trace_program_header;
	struct xt_trace_address_range *range_p = NULL;

	while (trace_program_header) {
		trace_program_header = trace_program_header->next;

		while (node_p->addr_range) {
			range_p = node_p->addr_range;
			node_p->addr_range = node_p->addr_range->next;
			free(range_p);
		}

		free(node_p);
		node_p = trace_program_header;
	}
}

/*************************************************************
 * Process U-addr and FULL-addr
 *************************************************************/
static void xt_trace_get_dso_and_symbol_for_node(
	struct xt_trace_program_flow_node *node,
	struct perf_session *session, struct auxtrace_buffer *buffer)
{
	u8 cpumode = PERF_RECORD_MISC_KERNEL;
	struct addr_location al;
	struct dso *dso = NULL;
	struct symbol *sym = NULL;
	struct thread *thread;
	uint64_t addr;

	thread = machine__findnew_thread(&session->machines.host, buffer->pid, buffer->tid);

	addr = node->start_addr;
	cpumode = riscv_get_cpu_mode(addr);

	addr_location__init(&al);
	if (!thread__find_map(thread, cpumode, addr, &al))
		goto next;
	dso = map__dso(al.map);
	if (!dso)
		goto next;
	//if (dso->data.status == DSO_DATA_STATUS_ERROR &&
	//	dso__data_status_seen(dso, DSO_DATA_STATUS_SEEN_ITRACE))
	//	goto next;
	sym = dso__find_symbol(dso, al.addr);
	if (sym && sym->name[0] != '\0') {
		strcpy(node->saddr_sym, sym->name);
		goto next;
	}
	map__load(al.map);
	sym = dso__find_symbol(dso, al.addr);
	if (sym && sym->name[0] != '\0')
		strcpy(node->saddr_sym, sym->name);

next:
	if (dso && dso->long_name && dso->long_name[0] != '\0')
		strcpy(node->saddr_dso, dso->name);
	addr_location__exit(&al);
	addr = node->full_addr;
	cpumode = riscv_get_cpu_mode(addr);

	addr_location__init(&al);
	if (!thread__find_map(thread, cpumode, addr, &al))
		goto end;
	dso = map__dso(al.map);
	if (!dso)
		goto end;
	//if (dso->data.status == DSO_DATA_STATUS_ERROR &&
	//	dso__data_status_seen(dso, DSO_DATA_STATUS_SEEN_ITRACE))
	//	goto end;
	map__load(al.map);
	sym = dso__find_symbol(dso, al.addr);
	if (sym && sym->name[0] != '\0')
		strcpy(node->faddr_sym, sym->name);
end:
	if (dso && dso->long_name && dso->long_name[0] != '\0')
		strcpy(node->faddr_dso, dso->name);
	addr_location__exit(&al);
}

static int32_t
xt_trace_get_start_and_full_addr(struct xt_trace_program_flow_node *node,
	struct perf_session *session, struct auxtrace_buffer *buffer)
{
	bool unknown_tcode = false;
	static enum rv_mmu_type mmu_mode = MMU_UNKNOWN;
	static int rv_svmode_int = 39;

	if (mmu_mode == MMU_UNKNOWN) {
		mmu_mode = parse_mmu_mode();
		if (mmu_mode == MMU_SV48)
			rv_svmode_int = 48;
		else if (mmu_mode == MMU_SV57)
			rv_svmode_int = 57;
		else
			rv_svmode_int = 39; //default
	}

	switch (node->msg.tcode) {
	case TCODE_DIRECTBRANCH:
		node->full_addr = node->start_addr +
			get_resource_full_icnt(node->msg.sub_value.directbranch.i_cnt) * 2;
		break;
		// u-addr
	case TCODE_INDIRECTBRANCH:
		node->full_addr =
			node->start_addr ^
			(node->msg.sub_value.indirectbranch.u_addr * 2);
		break;
	case TCODE_INDIRECTBRANCHHIST:
		node->full_addr =
			node->start_addr ^
			(node->msg.sub_value.indirectbranchhist.u_addr * 2);
		break;
		// f-addr
	case TCODE_PROGTRACESYNC:
		node->full_addr = node->msg.sub_value.progtracesync.f_addr * 2;
		break;
	case TCODE_DIRECTBRANCHSYNC:
		node->full_addr =
			node->msg.sub_value.directbranchsync.f_addr * 2;
		break;
	case TCODE_INDIRECTBRANCHSYNC:
		node->full_addr =
			node->msg.sub_value.indirectbranchsync.f_addr * 2;
		break;
	case TCODE_INDIRECTBRANCHHISTSYNC:
		node->full_addr =
			node->msg.sub_value.indirectbranchhistsync.f_addr * 2;
		break;
	case TCODE_RESOURCEFULL:
		printf("Error: should not get full addr for TCODE_RESOURCEFULL.\n");
		return -1;
	case TCODE_PROGTRACECORRELATION: {
		struct xt_trace_address_range *range = node->addr_range;

		if (!node->addr_range) {
			node->full_addr = 0xffffffffffffffff;
			return 0;
		}

		while (range->next)
			range = range->next;
		node->full_addr = range->end_addr;
	} break;
	default:
		unknown_tcode = true;
		break;
	}

	node->full_addr = sign_extend64(node->full_addr, rv_svmode_int - 1);
	if (!unknown_tcode)
		xt_trace_get_dso_and_symbol_for_node(node, session, buffer);

	return 0;
}

int32_t xuantie_ntrace_decoder__process_metedata(
	struct xuantie_saved_config *saved_config, unsigned char *buf,
	size_t len)
{
	int32_t ret = 0;
	// uint64_t pre_full_addr = 0;
	struct xt_riscv_nexus_trace_message msg;
	struct xt_riscv_nexus_trace_message *ownership = NULL;
	struct xt_trace_program_flow_node *node = NULL;
	uint32_t trace_data_wrapped = saved_config->trace_ram_wrap;
	uint32_t wrap_used = 1;
	// If true, we should find a message with full address
	bool error_message_happened = true;
	uint64_t repeat_msg_count = 0;

	// for MESO/MDO
	xt_trace_mseo_mdo_init(buf, len);

	// get next msg, If get CTRL_C, exit
	while (!XT_PERF_GET_CTRL_C()) {
		// If repeat_msg_count !=0, not update msg
		if (repeat_msg_count == 0) {
			// get a new msg
			ret = xt_trace_analyze_message_field(
				&msg, trace_data_wrapped, wrap_used,
				saved_config->src_bits,
				saved_config->timestamp_bits);
			trace_data_wrapped = 0;
			wrap_used = 0;
			if (ret > 0) {
				// msg: get trace date end
				return 0;
			} else if (ret < 0) {
				// msg: any error happens
				printf("Fail to get a new message.\n");
				goto error_end;
			}
		} else
			repeat_msg_count--;

		if (error_message_happened) {
			if (xt_trace_msg_has_full_addr(&msg)) {
				node = xt_trace_malloc_program_flow_node();
				if (node == NULL) {
					printf("Fail to malloc space for flow node1.\n");
					goto error_end;
				}
				memcpy(&node->msg, &msg, sizeof(msg));

				xt_trace_add_program_flow_node_to_list(node);

				error_message_happened = false;
				continue;
			} else {
				// any msg
				continue;
			}
		}

		// malloc space
		node = xt_trace_malloc_program_flow_node();
		if (node == NULL) {
			printf("Fail to malloc space for flow node2.\n");
			goto error_end;
		}
		memcpy(&node->msg, &msg, sizeof(msg));

		// extend i-cnt,hist,u-addr
		switch (msg.tcode) {
		case TCODE_OWNERSHIP:
			ownership = &node->msg;
			break;
		case TCODE_DIRECTBRANCH:
		case TCODE_INDIRECTBRANCH:
		case TCODE_PROGTRACESYNC:
		case TCODE_DIRECTBRANCHSYNC:
		case TCODE_INDIRECTBRANCHSYNC:
		case TCODE_RESOURCEFULL:
		case TCODE_INDIRECTBRANCHHIST:
		case TCODE_INDIRECTBRANCHHISTSYNC:
		case TCODE_PROGTRACECORRELATION:
			node->ownership = ownership;
			break;
		case TCODE_ERROR:
			error_message_happened = true;
			if (msg.sub_value.error.etype == ERROR_MSG_ETYPE_STANDARD &&
				(msg.sub_value.error.etype & ERROR_MSG_ECODE_OWNERSHIP))
				ownership = NULL;
			break;
		case TCODE_REPEATBRANCH:
			// set msg to the prev msg and set repeat_msg_count
			{
				struct xt_trace_program_flow_node *node_p =
					xt_trace_get_last_node();
				memcpy(&msg, &node_p->msg, sizeof(msg));
				repeat_msg_count =
					msg.sub_value.repeatbranch.b_cnt;
			}
			break;
		default:
			// msg
			goto error_end;
		}

		// and node to program_flow_header
		xt_trace_add_program_flow_node_to_list(node);
	}

	return 0;

error_end:
	return -1;
}

/*************************************************************
 * Display NODE(msg)
 *************************************************************/
static int32_t
xt_trace_output_ntrace_message(struct xt_riscv_nexus_trace_message *msg,
			       char *buf)
{
	char *buf_p = buf;
	const char *priv_mode_str[4] = { "U-mode", "S-mode", "Unknown-mode",
					 "M-mode" };
	const char *b_type_str[4] = { "IndirectBranch",
				      "Exception or Interrupt", "Exception",
				      "Interrupt" };
	const char *sync_str[16] = { "External Trace Trigger",
				     "Exit From Reset",
				     "Periodic Synchronization",
				     "Exit from Debug Mode",
				     "Sequential Instruction Counter",
				     "Trace Enable",
				     "Trace Event",
				     "Restart from FIFO",
				     "Reserved8",
				     "Exit from Powerdown",
				     "Reserved10",
				     "Reserved11",
				     "Reserved12",
				     "Reserved13",
				     "Reserved14",
				     "Reserved15" };
	const char *evcode_str[16] = {
		"Entry into Debug Mode",
		"Entry into Low-power Mode",
		"Reserved2",
		"Reserved3",
		"Program Trace Disabled",
		"Reserved5",
		"Reserved6",
		"Reserved7",
		"Reserved8",
		"Reserved9",
		"Reserved10",
		"Reserved11",
		"Reserved12",
		"Reserved13",
		"Reserved14",
		"Reserved15"
	};

	buf_p += sprintf(buf_p, ".  ");

	switch (msg->tcode) {
		case TCODE_OWNERSHIP: {
			buf_p += sprintf(buf_p, "TCODE=2(OwnerShip)");
			buf_p += sprintf(
				buf_p, ", Privilege is %s%s",
				msg->sub_value.ownership.is_virtual ? "V" : "",
				priv_mode_str[msg->sub_value.ownership.privilege & 0x3]);
			if (msg->sub_value.ownership.has_context)
				buf_p += sprintf(buf_p, ", %sContext = 0x%lx",
						msg->sub_value.ownership.is_scontext ?
							"S" :
							"H",
						msg->sub_value.ownership.context);
		} break;
		case TCODE_DIRECTBRANCH: {
			buf_p += sprintf(buf_p, "TCODE=3(DIRECTBRANCH)");
			buf_p += sprintf(buf_p, ", i-cnt=0x%lx",
					msg->sub_value.directbranch.i_cnt);
		} break;
		case TCODE_INDIRECTBRANCH: {
			buf_p += sprintf(buf_p, "TCODE=4(INDIRECTBRANCH)");
			buf_p += sprintf(
				buf_p, ", b_type=%d(%s), i-cnt=0x%lx, u-addr=0x%lx",
				msg->sub_value.indirectbranch.b_type,
				b_type_str[msg->sub_value.indirectbranch.b_type & 0x3],
				msg->sub_value.indirectbranch.i_cnt,
				msg->sub_value.indirectbranch.u_addr);
		} break;
		case TCODE_ERROR: {
			buf_p += sprintf(buf_p, "TCODE=8(ERROR)");
			buf_p += sprintf(buf_p, "etype=%d(%s), ecode=0x%lx",
					msg->sub_value.error.etype,
					msg->sub_value.error.etype == 0 ? "Standard" :
									"Reserved",
					msg->sub_value.error.ecode);
			if (msg->sub_value.error.etype == 0 &&
				msg->sub_value.error.ecode) {
				buf_p += sprintf(buf_p, "(");
				if (msg->sub_value.error.ecode & (1 << 0))
					buf_p += sprintf(buf_p, "[0]:Reserved");
				if (msg->sub_value.error.ecode & (1 << 1))
					buf_p += sprintf(buf_p, ", [1]:Reserved");
				if (msg->sub_value.error.ecode & (1 << 2))
					buf_p += sprintf(
						buf_p,
						", [2]:Program Trace Message(s) lost");
				if (msg->sub_value.error.ecode & (1 << 3))
					buf_p += sprintf(
						buf_p,
						", [3]:Ownership Trace Message(s) lost");
				if (msg->sub_value.error.ecode & (1 << 4))
					buf_p += sprintf(buf_p, ", [4]:Reserved");
				if (msg->sub_value.error.ecode & (1 << 5))
					buf_p += sprintf(buf_p, ", [5]:Reserved");
				if (msg->sub_value.error.ecode & (1 << 6))
					buf_p += sprintf(buf_p, ", [6]:Reserved");
				if (msg->sub_value.error.ecode & (1 << 7))
					buf_p += sprintf(
						buf_p,
						", [7]:Vendor Defined Message(s) lost");
				buf_p += sprintf(buf_p, "),");
			} else if (msg->sub_value.error.etype == 0) {
				buf_p += sprintf(buf_p,
						"(Exact reason unknown/not provided)");
			}
		} break;
		case TCODE_PROGTRACESYNC: {
			buf_p += sprintf(buf_p, "TCODE=9(PROGTRACESYNC)");
			buf_p += sprintf(
				buf_p, ", sync=%d(%s), i-cnt=0x%lx, f_addr=0x%lx",
				msg->sub_value.progtracesync.sync,
				sync_str[msg->sub_value.progtracesync.sync & 0xf],
				msg->sub_value.progtracesync.i_cnt,
				msg->sub_value.progtracesync.f_addr);
		} break;
		case TCODE_DIRECTBRANCHSYNC: {
			buf_p += sprintf(buf_p, "TCODE=11(DIRECTBRANCHSYNC)");
			buf_p += sprintf(
				buf_p, ", sync=%d(%s), i-cnt=0x%lx, f_addr=0x%lx",
				msg->sub_value.directbranchsync.sync,
				sync_str[msg->sub_value.directbranchsync.sync & 0xf],
				msg->sub_value.directbranchsync.i_cnt,
				msg->sub_value.directbranchsync.f_addr);
		} break;
		case TCODE_INDIRECTBRANCHSYNC: {
			buf_p += sprintf(buf_p, "TCODE=12(INDIRECTBRANCHSYNC)");
			buf_p += sprintf(
				buf_p,
				", sync=%d(%s), b-type=%d(%s), i-cnt=0x%lx, f_addr=0x%lx",
				msg->sub_value.indirectbranchsync.sync,
				sync_str[msg->sub_value.indirectbranchsync.sync & 0xf],
				msg->sub_value.indirectbranchsync.b_type,
				b_type_str[msg->sub_value.indirectbranchsync.b_type &
					0x3],
				msg->sub_value.indirectbranchsync.i_cnt,
				msg->sub_value.indirectbranchsync.f_addr);
		} break;
		case TCODE_RESOURCEFULL: {
			buf_p += sprintf(buf_p, "TCODE=27(RESOURCEFULL)");
			buf_p += sprintf(buf_p, ", rcode=%d",
					msg->sub_value.resourcefull.rcode);
			if (msg->sub_value.resourcefull.rcode == 0)
				buf_p += sprintf(buf_p, ", rdata0=0x%lx(i-cnt)",
						msg->sub_value.resourcefull.rdata0);
			else if (msg->sub_value.resourcefull.rcode == 1)
				buf_p += sprintf(buf_p, ", rdata0=0x%lx(hist)",
						msg->sub_value.resourcefull.rdata0);
			else if (msg->sub_value.resourcefull.rcode == 2)
				buf_p += sprintf(
					buf_p,
					", rdata0=0x%lx(hist), rdata1=0x%lx(repeated count)",
					msg->sub_value.resourcefull.rdata0,
					msg->sub_value.resourcefull.rdata1);
			else
				buf_p += sprintf(
					buf_p,
					", rdata0=0x%lx(unknown), rdata1=0x%lx(unknown)",
					msg->sub_value.resourcefull.rdata0,
					msg->sub_value.resourcefull.rdata1);
		} break;
		case TCODE_INDIRECTBRANCHHIST: {
			buf_p += sprintf(buf_p, "TCODE=28(INDIRECTBRANCHHIST)");
			buf_p += sprintf(
				buf_p,
				", b-type=%d(%s), i-cnt=0x%lx, u_addr=0x%lx, hist=0x%lx",
				msg->sub_value.indirectbranchhist.b_type,
				b_type_str[msg->sub_value.indirectbranchhist.b_type &
					0x3],
				msg->sub_value.indirectbranchhist.i_cnt,
				msg->sub_value.indirectbranchhist.u_addr,
				msg->sub_value.indirectbranchhist.hist);
		} break;
		case TCODE_INDIRECTBRANCHHISTSYNC: {
			buf_p += sprintf(buf_p, "TCODE=29(INDIRECTBRANCHHISTSYNC)");
			buf_p += sprintf(
				buf_p,
				", sync=%d(%s), b-type=%d(%s), i-cnt=0x%lx, f_addr=0x%lx, hist=0x%lx",
				msg->sub_value.indirectbranchhistsync.sync,
				sync_str[msg->sub_value.indirectbranchhistsync.sync &
					0xf],
				msg->sub_value.indirectbranchhistsync.b_type,
				b_type_str[msg->sub_value.indirectbranchhistsync.b_type &
					0x3],
				msg->sub_value.indirectbranchhistsync.i_cnt,
				msg->sub_value.indirectbranchhistsync.f_addr,
				msg->sub_value.indirectbranchhistsync.hist);
		} break;
		case TCODE_REPEATBRANCH: {
			buf_p += sprintf(buf_p, "TCODE=30(REPEATBRANCH)");
			buf_p += sprintf(buf_p, ", b-cnt=0x%lx",
					msg->sub_value.repeatbranch.b_cnt);
		} break;
		case TCODE_PROGTRACECORRELATION: {
			buf_p += sprintf(buf_p, "TCODE=33(PROGTRACECORRELATION)");
			buf_p += sprintf(
				buf_p, ", evcode=%d(%s)",
				msg->sub_value.progtracecorrelation.evcode,
				evcode_str[msg->sub_value.progtracecorrelation.evcode &
					0xf]);
			if (msg->sub_value.progtracecorrelation.cdf == 0) {
				buf_p +=
					sprintf(buf_p, ", cdf=0(cdata only has i-cnt)");
				buf_p += sprintf(
					buf_p, ", i-cnt=0x%lx",
					msg->sub_value.progtracecorrelation.i_cnt);
			} else if (msg->sub_value.progtracecorrelation.cdf == 1) {
				buf_p += sprintf(buf_p,
						", cdf=1(cdata has i-cnt and hist)");
				buf_p += sprintf(
					buf_p, ", i-cnt=0x%lx, hist=0x%lx",
					msg->sub_value.progtracecorrelation.i_cnt,
					msg->sub_value.progtracecorrelation.hist);
			} else
				buf_p += sprintf(
					buf_p, ", cdf=%d(unknown)",
					msg->sub_value.progtracecorrelation.cdf);
		} break;
		default: {
			buf_p += sprintf(buf_p, "Unknown TCODE %d", msg->tcode);
		} break;
	}

	if (msg->has_src)
		buf_p += sprintf(buf_p, ", src=%d", msg->src);
	if (msg->has_timestamp)
		buf_p += sprintf(buf_p, ", timestamp=0x%lx",
					msg->timestamp);
	buf_p += sprintf(buf_p, ".\n");

	return 0;
}

static int32_t
xt_trace_output_specified_message(struct xt_riscv_nexus_trace_message *msg, char *buf)
{
	char *buf_p = buf;
	const char *priv_mode_str[4] = {
		"U-mode", "S-mode", "Unknown-mode", "M-mode"};
	const char *sync_str[16] = {
		"External Trace Trigger",
		"Exit From Reset",
		"Periodic Synchronization",
		"Exit from Debug Mode",
		"Sequential Instruction Counter",
		"Trace Enable",
		"Trace Event",
		"Restart from FIFO",
		"Reserved8",
		"Exit from Powerdown",
		"Reserved10",
		"Reserved11",
		"Reserved12",
		"Reserved13",
		"Reserved14",
		"Reserved15"};
	const char *evcode_str[16] = {
		"Entry into Debug Mode",
		"Entry into Low-power Mode",
		"Reserved2",
		"Reserved3",
		"Program Trace Disabled",
		"Reserved5",
		"Reserved6",
		"Reserved7",
		"Reserved8",
		"Reserved9",
		"Reserved10",
		"Reserved11",
		"Reserved12",
		"Reserved13",
		"Reserved14",
		"Reserved15"};
	buf_p += sprintf(buf_p, ".  ");

	switch (msg->tcode) {
		case TCODE_OWNERSHIP: {
			buf_p += sprintf(buf_p, "Messages below are in");
			buf_p += sprintf(buf_p, " %s%s", msg->sub_value.ownership.is_virtual ? "V" : "",
				priv_mode_str[msg->sub_value.ownership.privilege & 0x3]);
		if (msg->sub_value.ownership.has_context)
			buf_p += sprintf(buf_p, " with %sContext=0x%lx", msg->sub_value.ownership.is_scontext ? "S" : "H",
			msg->sub_value.ownership.context);
		} break;
		//case TCODE_DIRECTBRANCH: {
		//	buf_p += sprintf(buf_p, "TCODE=3(DIRECTBRANCH)");
		//    buf_p += sprintf(buf_p, ", i-cnt=0x%lx", msg->sub_value.directbranch.i_cnt);
		//} break;
		//case TCODE_INDIRECTBRANCH: {
		//    buf_p += sprintf(buf_p, "TCODE=4(INDIRECTBRANCH)");
		//    buf_p += sprintf(buf_p, ", b_type=%d(%s), i-cnt=0x%lx, u-addr=0x%lx", msg->sub_value.indirectbranch.b_type,
		//                     b_type_str[msg->sub_value.indirectbranch.b_type & 0x3], msg->sub_value.indirectbranch.i_cnt,
		//                     msg->sub_value.indirectbranch.u_addr);
		//} break;
		case TCODE_ERROR: {
			buf_p += sprintf(buf_p, "Error happened:");
			buf_p += sprintf(buf_p, "error type=%s, error code=0x%lx",
				msg->sub_value.error.etype == 0 ? "Standard" : "Reserved", msg->sub_value.error.ecode);
			if (msg->sub_value.error.etype == 0 && msg->sub_value.error.ecode) {
				buf_p += sprintf(buf_p, "(");
				if (msg->sub_value.error.ecode & (1 << 0))
					buf_p += sprintf(buf_p, "[0]:Reserved");
				if (msg->sub_value.error.ecode & (1 << 1))
					buf_p += sprintf(buf_p, ", [1]:Reserved");
				if (msg->sub_value.error.ecode & (1 << 2))
					buf_p += sprintf(buf_p, ", [2]:Program Trace Message(s) lost");
				if (msg->sub_value.error.ecode & (1 << 3))
					buf_p += sprintf(buf_p, ", [3]:Ownership Trace Message(s) lost");
				if (msg->sub_value.error.ecode & (1 << 4))
					buf_p += sprintf(buf_p, ", [4]:Reserved");
				if (msg->sub_value.error.ecode & (1 << 5))
					buf_p += sprintf(buf_p, ", [5]:Reserved");
				if (msg->sub_value.error.ecode & (1 << 6))
					buf_p += sprintf(buf_p, ", [6]:Reserved");
				if (msg->sub_value.error.ecode & (1 << 7))
					buf_p += sprintf(buf_p, ", [7]:Vendor Defined Message(s) lost");
				buf_p += sprintf(buf_p, "),");
			} else if (msg->sub_value.error.etype == 0)
				buf_p += sprintf(buf_p, "(Exact reason unknown/not provided)");
		} break;
		case TCODE_PROGTRACESYNC: {
			buf_p += sprintf(buf_p, "Synchronization Reason: %s", sync_str[msg->sub_value.progtracesync.sync & 0xf]);
		} break;
		//case TCODE_DIRECTBRANCHSYNC: {
		//    buf_p += sprintf(buf_p, "TCODE=11(DIRECTBRANCHSYNC)");
		//    buf_p += sprintf(buf_p, ", sync=%d(%s), i-cnt=0x%lx, f_addr=0x%lx", msg->sub_value.directbranchsync.sync,
		//                     sync_str[msg->sub_value.directbranchsync.sync & 0xf], msg->sub_value.directbranchsync.i_cnt,
		//                     msg->sub_value.directbranchsync.f_addr);
		//} break;
		//case TCODE_INDIRECTBRANCHSYNC: {
		//    buf_p += sprintf(buf_p, "TCODE=12(INDIRECTBRANCHSYNC)");
		//    buf_p += sprintf(buf_p, ", sync=%d(%s), b-type=%d(%s), i-cnt=0x%lx, f_addr=0x%lx",
		//                     msg->sub_value.indirectbranchsync.sync, sync_str[msg->sub_value.indirectbranchsync.sync & 0xf],
		//                     msg->sub_value.indirectbranchsync.b_type,
		//                     b_type_str[msg->sub_value.indirectbranchsync.b_type & 0x3],
		//                     msg->sub_value.indirectbranchsync.i_cnt, msg->sub_value.indirectbranchsync.f_addr);
		//} break;
		//case TCODE_RESOURCEFULL: {
		//    buf_p += sprintf(buf_p, "TCODE=27(RESOURCEFULL)");
		//    buf_p += sprintf(buf_p, ", rcode=%d", msg->sub_value.resourcefull.rcode);
		//    if (msg->sub_value.resourcefull.rcode == 0)
		//        buf_p += sprintf(buf_p, ", rdata0=0x%lx(i-cnt)", msg->sub_value.resourcefull.rdata0);
		//    else if (msg->sub_value.resourcefull.rcode == 1)
		//        buf_p += sprintf(buf_p, ", rdata0=0x%lx(hist)", msg->sub_value.resourcefull.rdata0);
		//    else if (msg->sub_value.resourcefull.rcode == 2)
		//        buf_p += sprintf(buf_p, ", rdata0=0x%lx(hist), rdata1=0x%lx(repeated count)", msg->sub_value.resourcefull.rdata0,
		//                         msg->sub_value.resourcefull.rdata1);
		//    else
		//        buf_p += sprintf(buf_p, ", rdata0=0x%lx(unknown), rdata1=0x%lx(unknown)",
		//                         msg->sub_value.resourcefull.rdata0, msg->sub_value.resourcefull.rdata1);
		//} break;
		//case TCODE_INDIRECTBRANCHHIST: {
		//    buf_p += sprintf(buf_p, "TCODE=28(INDIRECTBRANCHHIST)");
		//    buf_p +=
		//        sprintf(buf_p, ", b-type=%d(%s), i-cnt=0x%lx, u_addr=0x%lx, hist=0x%lx",
		//                msg->sub_value.indirectbranchhist.b_type,
		//                b_type_str[msg->sub_value.indirectbranchhist.b_type & 0x3], msg->sub_value.indirectbranchhist.i_cnt,
		//                msg->sub_value.indirectbranchhist.u_addr, msg->sub_value.indirectbranchhist.hist);
		//} break;
		//case TCODE_INDIRECTBRANCHHISTSYNC: {
		//    buf_p += sprintf(buf_p, "TCODE=29(INDIRECTBRANCHHISTSYNC)");
		//    buf_p += sprintf(
		//        buf_p, ", sync=%d(%s), b-type=%d(%s), i-cnt=0x%lx, f_addr=0x%lx, hist=0x%lx",
		//        msg->sub_value.indirectbranchhistsync.sync, sync_str[msg->sub_value.indirectbranchhistsync.sync & 0xf],
		//        msg->sub_value.indirectbranchhistsync.b_type,
		//        b_type_str[msg->sub_value.indirectbranchhistsync.b_type & 0x3], msg->sub_value.indirectbranchhistsync.i_cnt,
		//        msg->sub_value.indirectbranchhistsync.f_addr, msg->sub_value.indirectbranchhistsync.hist);
		//} break;
		//case TCODE_REPEATBRANCH: {
		//    buf_p += sprintf(buf_p, "TCODE=30(REPEATBRANCH)");
		//    buf_p += sprintf(buf_p, ", b-cnt=0x%lx", msg->sub_value.repeatbranch.b_cnt);
		//} break;
		case TCODE_PROGTRACECORRELATION: {
			buf_p += sprintf(buf_p, "Correction Event: %s",
				evcode_str[msg->sub_value.progtracecorrelation.evcode & 0xf]);
			//if (msg->sub_value.progtracecorrelation.cdf == 0) {
			//    buf_p += sprintf(buf_p, ", cdf=0(cdata only has i-cnt)");
			//    buf_p += sprintf(buf_p, ", i-cnt=0x%lx", msg->sub_value.progtracecorrelation.i_cnt);
			//}
			//else if (msg->sub_value.progtracecorrelation.cdf == 1) {
			//    buf_p += sprintf(buf_p, ", cdf=1(cdata has i-cnt and hist)");
			//    buf_p += sprintf(buf_p, ", i-cnt=0x%lx, hist=0x%lx", msg->sub_value.progtracecorrelation.i_cnt,
			//                     msg->sub_value.progtracecorrelation.hist);
			//}
			//else
			//    buf_p += sprintf(buf_p, ", cdf=%d(unknown)", msg->sub_value.progtracecorrelation.cdf);
		} break;
		default: {
			buf_p += sprintf(buf_p, "Unknown TCODE %d", msg->tcode);
		} break;
	}

	if (msg->has_src)
		buf_p += sprintf(buf_p, ", CPU Num=%d", msg->src);
	if (msg->has_timestamp)
		buf_p += sprintf(buf_p, ", Timestamp=0x%lx", msg->timestamp);
	buf_p += sprintf(buf_p, ".\n");

	return 0;
}

int32_t xuantie_ntrace_decoder__process_full_message(struct perf_session *session,
	struct auxtrace_buffer *buffer, bool analyze_ranges)
{
	int ret = 0;
	bool error_message_happened = true;
	struct xt_trace_program_flow_node *node = trace_program_header;
	uint64_t pre_full_addr = 0;

	while (node) {
		if (error_message_happened) {
			resource_full_clear();
			if (xt_trace_msg_has_full_addr(&node->msg)) {
				xt_trace_get_start_and_full_addr(node, session, buffer);

				//ignore the i-cnt and hist of the first msg
				node->start_addr = node->full_addr;
				pre_full_addr = node->full_addr;
				if (node->faddr_dso[0] != '\0')
					strcpy(node->saddr_dso, node->faddr_dso);
				if (node->faddr_sym[0] != '\0')
					strcpy(node->saddr_sym, node->faddr_sym);

				//go next
				node = node->next;
				error_message_happened = false;
				continue;
			} else
				node->invalid = 1;

			node = node->next;
			continue;
		}

		switch (node->msg.tcode) {
		case TCODE_OWNERSHIP:
			break;
		case TCODE_DIRECTBRANCH:
			node->start_addr = pre_full_addr;
			xt_trace_get_start_and_full_addr(node, session, buffer);
			resource_full_clear();

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCH:
			node->start_addr = pre_full_addr;
			if (analyze_ranges)
				ret = xt_trace_analyze_i_cnt_vs_hist(
					session, buffer,
					node->msg.sub_value.indirectbranch.i_cnt,
					pre_full_addr, 0, &node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				// error_message_happened = true;
				// break;
			}

			if (xt_trace_get_start_and_full_addr(node, session, buffer)) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_ERROR:
			//error_message_happened = true;
			//if (msg.sub_value.error.etype == ERROR_MSG_ETYPE_STANDARD &&
			//    (msg.sub_value.error.etype & ERROR_MSG_ECODE_OWNERSHIP))
			//    ownership = NULL;
			//FIXME:... reinit pre_full_addr
			error_message_happened = true;
			break;
		case TCODE_PROGTRACESYNC:
			node->start_addr = pre_full_addr;
			if (analyze_ranges)
				ret = xt_trace_analyze_i_cnt_vs_hist(
					session, buffer,
					node->msg.sub_value.progtracesync.i_cnt,
					pre_full_addr, 0, &node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				// error_message_happened = true;
				// break;
			}
			if (xt_trace_get_start_and_full_addr(node, session, buffer)) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_DIRECTBRANCHSYNC:
			node->start_addr = pre_full_addr;
			if (analyze_ranges)
				ret = xt_trace_analyze_i_cnt_vs_hist(
					session, buffer,
					node->msg.sub_value.directbranchsync.i_cnt,
					pre_full_addr, 0, &node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				// error_message_happened = true;
				// break;
			}
			if (xt_trace_get_start_and_full_addr(node, session, buffer)) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCHSYNC:
			node->start_addr = pre_full_addr;
			if (analyze_ranges)
				ret = xt_trace_analyze_i_cnt_vs_hist(
					session, buffer,
					node->msg.sub_value.indirectbranchsync.i_cnt,
					pre_full_addr, 0, &node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				// error_message_happened = true;
				// break;
			}
			if (xt_trace_get_start_and_full_addr(node, session, buffer)) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_RESOURCEFULL:
			node->start_addr = pre_full_addr;
			if (node->msg.sub_value.resourcefull.rcode == 0) {
				add_resource_full_icnt(
					node->msg.sub_value.resourcefull.rdata0);
			} else if (node->msg.sub_value.resourcefull.rcode == 1) {
				add_resource_full_hist(
					node->msg.sub_value.resourcefull.rdata0);
			} else {
				// msg
				node->invalid = 1;
				error_message_happened = true;
				break;
			}
			break;
		case TCODE_INDIRECTBRANCHHIST:
			node->start_addr = pre_full_addr;
			if (analyze_ranges)
				ret = xt_trace_analyze_i_cnt_vs_hist(
					session, buffer,
					node->msg.sub_value.indirectbranchhist.i_cnt,
					pre_full_addr,
					node->msg.sub_value.indirectbranchhist.hist,
					&node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				// error_message_happened = true;
				// break;
			}
			if (xt_trace_get_start_and_full_addr(node, session, buffer)) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCHHISTSYNC:
			node->start_addr = pre_full_addr;
			if (analyze_ranges)
				ret = xt_trace_analyze_i_cnt_vs_hist(
					session, buffer,
					node->msg.sub_value.indirectbranchhistsync.i_cnt,
					pre_full_addr,
					node->msg.sub_value.indirectbranchhistsync.hist,
					&node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				// error_message_happened = true;
				// break;
			}
			if (xt_trace_get_start_and_full_addr(node, session, buffer)) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_REPEATBRANCH:
			printf("REPEATBRANCH  ///\n");
			break;
		case TCODE_PROGTRACECORRELATION:
			node->start_addr = pre_full_addr;
			ret = xt_trace_analyze_i_cnt_vs_hist(
				session, buffer,
				node->msg.sub_value.progtracecorrelation.i_cnt,
				pre_full_addr,
				node->msg.sub_value.progtracecorrelation.hist,
				&node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				// error_message_happened = true;
				// break;
			}
			if (xt_trace_get_start_and_full_addr(node, session, buffer)) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			error_message_happened = true;
			// update pre_full_addr
			//pre_full_addr = node->full_addr;
			break;
		default:
			// msg
			node->invalid = 1;
			error_message_happened = true;
			break;
		}

		// get next node
		node = node->next;
	}

	return 0;
}

#ifdef HAVE_LIBBFD_SUPPORT
#define PACKAGE "perf"
#include <bfd.h>
#include <dis-asm.h>
#include <tools/dis-asm-compat.h>

static int
xt_trace_disassemble_and_display(char *file_name, struct xt_trace_address_range *range_p)
{
	struct disassemble_info info;
	bfd *bfdf;
	disassembler_ftype disassemble;
	int count = 0;
	asection *sect = NULL;
	bfd_byte *data = NULL;
	uint64_t addr = 0;

	if (file_name == NULL)
		return 0;

	bfdf = bfd_openr(file_name, NULL);
	if (bfdf == NULL) {
		//printf ("Can't open file %s\n", dso->name);
		return 0;
	}
	if (!bfd_check_format(bfdf, bfd_object))
		goto end;

	init_disassemble_info_compat(&info, stdout,
				     (fprintf_ftype) fprintf,
				     fprintf_styled);
	info.arch = bfd_get_arch(bfdf);
	info.mach = bfd_get_mach(bfdf);

	while (range_p && !XT_PERF_GET_CTRL_C()) {
		//printf range start and end first
		printf("      {0x%lx, 0x%lx - 1}\n", range_p->start_addr, range_p->end_addr);

		//disassemble and print insns
		//reuse sect and data
		addr = range_p->start_addr;
		if (sect && data) {
			if (bfd_section_vma(sect) <= addr
			    && addr < (bfd_section_vma(sect) + bfd_section_size(sect))) {
				while (1) {
					if (addr > 0xffffffff)
						printf("      %16lx:    ", addr);
					else
						printf("      %8lx:    ", addr);
					count = disassemble(addr, &info);
					if (count < 0)
						goto end;
					printf("\n");
					addr += count;

					if (addr >= range_p->end_addr)
						break;
				}

				range_p = range_p->next;
				continue;
			}
			free(data);
			data = NULL;
		}


		//find sect and disassmbler
		sect = bfdf->sections;
		for (sect = bfdf->sections; sect != NULL; sect = sect->next)
			if (bfd_section_vma(sect) <= addr
			    && addr < (bfd_section_vma(sect) + bfd_section_size(sect)))
				break;
		if (sect == NULL)
			goto end;
		if (!bfd_malloc_and_get_section(bfdf, sect, &data))
			goto end;
		info.buffer = data;
		info.buffer_length = bfd_section_size(sect);
		info.buffer_vma = bfd_section_vma(sect);

		disassemble_init_for_target(&info);
		disassemble = disassembler(info.arch,
					   bfd_big_endian(bfdf),
					   info.mach,
					   bfdf);
		if (disassemble == NULL)
			goto end;

		while (1) {
			if (addr > 0xffffffff)
				printf("      %16lx:    ", addr);
			else
				printf("      %8lx:    ", addr);
			count = disassemble(addr, &info);
			if (count < 0)
				goto end;
			printf("\n");
			addr += count;

			if (addr >= range_p->end_addr)
				break;
		}

		//next range
		range_p = range_p->next;
	}
end:
	if (data)
		free(data);
	bfd_close(bfdf);

	return 0;
}
#endif

#define STR_LEN_MAX (1024 * 8)
int32_t xt_trace_program_trace_display(bool with_msg, bool with_addr,
						bool with_insn)
{
	char str[STR_LEN_MAX] = { '\0' };
	struct xt_trace_program_flow_node *node_p = trace_program_header;

	while (node_p && !XT_PERF_GET_CTRL_C()) {
		// printf n-trace message contents
		memset(str, 0, STR_LEN_MAX);

		if (with_msg) {
			if (xt_trace_output_ntrace_message(&node_p->msg, str)) {
				printf("Can not analysis ntrace message.\n");
				return -1;
			}
		} else if (node_p->msg.tcode == TCODE_OWNERSHIP
			 || node_p->msg.tcode == TCODE_ERROR
			 || node_p->msg.tcode == TCODE_PROGTRACESYNC
			 || node_p->msg.tcode == TCODE_PROGTRACECORRELATION) {
			if (xt_trace_output_specified_message(&node_p->msg, str)) {
				printf("Can not analysis ntrace message mark2.\n");
				return -1;
			}
		}

		if (strlen(str) >= STR_LEN_MAX) {
			printf("str with length 0x%lx is bigger than STR_LEN_MAX 0x%x\n",
				strlen(str), STR_LEN_MAX);
			return -1;
		}

		printf("%s", str);
		if (with_addr || with_insn) {
			switch (node_p->msg.tcode) {
			case TCODE_OWNERSHIP:
			case TCODE_ERROR:
			case TCODE_REPEATBRANCH:
			case TCODE_RESOURCEFULL:
				break;
			case TCODE_DIRECTBRANCH:
			case TCODE_INDIRECTBRANCH:
			case TCODE_PROGTRACESYNC:
			case TCODE_DIRECTBRANCHSYNC:
			case TCODE_INDIRECTBRANCHSYNC:
			case TCODE_INDIRECTBRANCHHIST:
			case TCODE_INDIRECTBRANCHHISTSYNC:
			case TCODE_PROGTRACECORRELATION:
				printf(
				"    Start from 0x%lx %-30s (%s)  ==>  End to 0x%lx %-30s (%s)\n",
					node_p->start_addr,
					node_p->saddr_sym[0] == '\0' ?
						"unknown" : node_p->saddr_sym,
					node_p->saddr_dso[0] == '\0' ?
						"unknown" : node_p->saddr_dso,
					node_p->full_addr,
					node_p->faddr_sym[0] == '\0' ?
						"unknown" : node_p->faddr_sym,
					node_p->faddr_dso[0] == '\0' ?
						"unknown" : node_p->faddr_dso);
				if (node_p->invalid)
					break;
				if (node_p->addr_range) {
					struct xt_trace_address_range *range_p =
						node_p->addr_range;
					printf("    Include pc ranges:\n");
					while (range_p) {
#ifdef HAVE_LIBBFD_SUPPORT
						if (with_insn &&
							(range_p->end_addr > range_p->start_addr)) {
							xt_trace_disassemble_and_display(
								node_p->saddr_dso, range_p);
							range_p = NULL;
						} else {
							printf("    {0x%lx, 0x%lx - 1}\n",
								range_p->start_addr,
								range_p->end_addr);
							range_p = range_p->next;
						}
#else
						printf("    {0x%lx, 0x%lx - 1}\n",
							range_p->start_addr, range_p->end_addr);
						range_p = range_p->next;
#endif
					}
				}
				break;
			default:
				//...
				break;
			}
		}

		node_p = node_p->next;
	}

	xt_trace_free_program_flow_node();
	return 0;
}
