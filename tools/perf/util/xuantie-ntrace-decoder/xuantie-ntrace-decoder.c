// SPDX-License-Identifier: GPL-2.0

#include <stdlib.h>
#include <string.h>
#include "thread.h"
#include "thread-stack.h"
#include "map.h"
#include "map_symbol.h"
#include "symbol.h"
#include "dso.h"

#include "xuantie-ntrace-decoder.h"
#include "xuantie-mseo-mdo.h"
#include "xuantie-ntrace-message.h"

// used for i-cnt and hist
struct xt_trace_address_range {
	uint64_t start_addr;
	uint64_t end_addr;
	struct xt_trace_address_range *next;
};

struct xt_trace_program_flow_node {
	uint64_t start_addr; // the start addr of this message
	// the start addr of the next message
	// also means the destination address of this message
	uint64_t full_addr;
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

static u8 riscv_get_cpu_mode(u64 vaddr)
{
	if (vaddr > 0x3fffffffff) //SV39:256G
		return PERF_RECORD_MISC_KERNEL;

	return PERF_RECORD_MISC_USER;

	//FIXME: other mode ???
}

static uint64_t get_an_insn(struct perf_session *session,
			    struct auxtrace_buffer *buffer, uint64_t addr,
			    uint32_t *len)
{
	uint8_t buf[8] = { 0 };
	u8 cpumode = PERF_RECORD_MISC_KERNEL;
	struct addr_location al;
	struct dso *dso;
	u64 offset;
	u32 length;

	struct thread *thread = machine__findnew_thread(
		&session->machines.host, buffer->pid, buffer->tid);

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
	map__load(al.map);
	length = dso__data_read_offset(dso, maps__machine(thread__maps(thread)),
				       offset, buf, 2);
	if (length <= 0) {
		printf("XUANTIE NTrace: Debug data not found for address %#" PRIx64
		       " in %s\n",
		       addr, dso->long_name ? dso->long_name : "Unknown");
		goto error_end;
	}

	/* insn length */
	*len = riscv_insn_length(buf[0]);
	if (*len > 2) {
		length = dso__data_read_offset(
			dso, maps__machine(thread__maps(thread)), offset + 2,
			buf + 2, *len - 2);
		if (length <= 0) {
			printf("XUANTIE NTrace: Debug data not found for address %#" PRIx64
			       " in %s\n",
			       addr + 2,
			       dso->long_name ? dso->long_name : "Unknown");
			goto error_end;
		}

		if (length != (*len - 2)) {
			printf("XUANTIE NTrace: can't get full insn value for address %#" PRIx64
			       " in %s\n",
			       addr,
			       dso->long_name ? dso->long_name : "Unknown");
			goto error_end;
		}
	}

	return *(uint64_t *)buf;

error_end:
	printf("can't read insn for addr %#" PRIx64 "\n", addr);
	addr_location__exit(&al);
	return 1;
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
	uint32_t rdata0[RESOURCEFULL_MSG_MAX];
	uint32_t rdata0_count;
	uint32_t hist_count[RESOURCEFULL_MSG_MAX];
	uint32_t total_hist_count;
} resource_full_icnt, resource_full_hist;

static void resource_full_clear(void)
{
	memset(&resource_full_icnt, 0, sizeof(resource_full_icnt));
	memset(&resource_full_hist, 0, sizeof(resource_full_hist));
}

static int32_t add_resource_full_icnt(uint32_t icnt)
{
	resource_full_icnt.rdata0[resource_full_icnt.rdata0_count] = icnt;
	resource_full_icnt.rdata0_count++;

	if (resource_full_icnt.rdata0_count >= RESOURCEFULL_MSG_MAX) {
		printf("Get icount count max %d\n", RESOURCEFULL_MSG_MAX);
		return -1;
	} else
		return 0;
}

static uint64_t get_resource_full_icnt(uint32_t icnt)
{
	uint32_t i = 0;
	uint64_t total_icnt = icnt;

	for (i = 0; i < resource_full_icnt.rdata0_count; i++)
		total_icnt += resource_full_icnt.rdata0[i];

	return total_icnt;
}

static int32_t add_resource_full_hist(uint32_t hist)
{
	uint32_t i = 0;

	if (hist == 0 || hist == 1)
		return 0;
	resource_full_hist.rdata0[resource_full_hist.rdata0_count] = hist;
	resource_full_hist.rdata0_count++;

	if (resource_full_hist.rdata0_count >= RESOURCEFULL_MSG_MAX) {
		printf("Get hist count max %d\n", RESOURCEFULL_MSG_MAX);
		return -1;
	}

	for (i = 31; i > 0; i--) {
		if ((1 << i) & hist)
			break;
	}

	if (i == 0) {
		printf("Get error hist value 0x%x\n", hist);
		return -1;
	}
	resource_full_hist.hist_count[resource_full_hist.rdata0_count - 1] = i;
	resource_full_hist.total_hist_count += i;

	return 0;
}

static int32_t get_one_hist(void)
{
	uint32_t i = 0;
	uint32_t condition = 0;

	if (resource_full_hist.total_hist_count == 0) {
		printf("Error No Hist.\n");
		return -1;
	}

	for (i = 0; i < resource_full_hist.rdata0_count; i++) {
		if (resource_full_hist.hist_count[i] != 0) {
			condition =
				(1 << (resource_full_hist.hist_count[i] - 1)) &
				resource_full_hist.rdata0[i];
			resource_full_hist.hist_count[i]--;
			resource_full_hist.total_hist_count--;
			return condition ? 1 : 0;
		}
	}

	printf("Error No Hist.\n");
	return -1;
}

static uint32_t get_hist_count(void)
{
	return resource_full_hist.total_hist_count;
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
	uint32_t insn_value = 0;
	struct xt_trace_address_range *range_last_p = NULL;
	uint64_t insn_cnt = 0;

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
		insn_value = get_an_insn(session, buffer, insn_addr, &insn_len);
		if (insn_value == 1) {
			ret = 1;
			goto error_end;
		}

		if (xt_trace_is_condition_branch_insn(insn_len, insn_value)) {
			int32_t condition = 0;

			// get one hist
			condition = get_one_hist();
			if (condition < 0)
				goto error_end;

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
					printf("Err: insn 0x%x addr 0x%lx isn't condition branch\n",
						insn_value, insn_addr);
					goto error_end;
				}

				// get new address range
				range_tmp = (struct xt_trace_address_range *)
					malloc(sizeof(
						struct xt_trace_address_range));
				if (range_tmp == NULL) {
					// msg
					goto error_end;
				}
				range_tmp->start_addr = new_addr;
				range_tmp->end_addr = new_addr;
				range_tmp->next = NULL;

				// set range_last_p->end_addr to insn_addr and add
				// range_tmp to the range_last_p, then set range_last_p
				// to range_tmp
				range_last_p->end_addr = insn_addr + insn_len;
				range_last_p->next = range_tmp;
				range_last_p = range_tmp;

				// update insn_addr
				insn_addr = new_addr;
			} else {
				insn_addr += insn_len;
			}
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

				// get new address range
				range_tmp = (struct xt_trace_address_range *)
					malloc(sizeof(
						struct xt_trace_address_range));
				if (range_tmp == NULL) {
					// msg
					printf("Fail to malloc space for address range1.\n");
					goto error_end;
				}
				range_tmp->start_addr = new_addr;
				range_tmp->end_addr = new_addr;
				range_tmp->next = NULL;

				// set range_last_p->end_addr to insn_addr and add
				// range_tmp to the range_last_p, then set range_last_p
				// to range_tmp
				range_last_p->end_addr = insn_addr + insn_len;
				range_last_p->next = range_tmp;
				range_last_p = range_tmp;

				// update insn_addr
				insn_addr = new_addr;
			} else {
				if (insn_cnt != insn_len / 2) {
					printf("I-cnt error.\n");
					goto error_end;
				}

				insn_addr += insn_len;
			}
		} else {
			insn_addr += insn_len;
		}

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

	range_last_p->end_addr = insn_addr;
	return 0;

error_end:
	// free range
	while (*range) {
		struct xt_trace_address_range *range_tmp = *range;

		*range = (*range)->next;
		free(range_tmp);
	}
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
static int32_t
xt_trace_get_start_and_full_addr(struct xt_trace_program_flow_node *node)
{
	switch (node->msg.tcode) {
	case TCODE_DIRECTBRANCH:
		node->full_addr = node->start_addr +
				  (node->msg.sub_value.directbranch.i_cnt * 2);
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
	case TCODE_RESOURCEFULL: {
		struct xt_trace_address_range *range = node->addr_range;

		if (!node->addr_range)
			return -1;

		while (range->next)
			range = range->next;
		node->full_addr = range->end_addr;
	} break;
	case TCODE_PROGTRACECORRELATION: {
		struct xt_trace_address_range *range = node->addr_range;

		if (!node->addr_range)
			return -1;

		while (range->next)
			range = range->next;
		node->full_addr = range->end_addr;
	} break;
	default:
		break;
	}

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

	// get next msg
	while (1) {
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

				// if (xt_trace_get_start_and_full_addr(node)) {
				//	free(node);
				//	goto error_end;
				// }
				// // ignore i-cnt and hist
				// node->start_addr = node->full_addr;
				// pre_full_addr = node->full_addr;
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
			node->ownership = ownership;
			// node->start_addr = pre_full_addr;
			// node->full_addr = pre_full_addr +
			//	msg.sub_value.directbranch.i_cnt;

			// // update pre_full_addr
			// pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCH:
			node->ownership = ownership;
			// node->start_addr = pre_full_addr;
			// if (xt_trace_analyze_i_cnt_vs_hist(
			//	msg.sub_value.indirectbranch.i_cnt, pre_full_addr, 0,
			//	&node->addr_range)) {
			//	free(node);
			//	goto error_end;
			// }
			// if (xt_trace_get_start_and_full_addr(node)) {
			//	free(node);
			//	goto error_end;
			// }

			// // update pre_full_addr
			// pre_full_addr = node->full_addr;
			break;
		case TCODE_ERROR:
			error_message_happened = true;
			if (msg.sub_value.error.etype ==
				    ERROR_MSG_ETYPE_STANDARD &&
			    (msg.sub_value.error.etype &
			     ERROR_MSG_ECODE_OWNERSHIP))
				ownership = NULL;
			break;
		case TCODE_PROGTRACESYNC:
			node->ownership = ownership;
			// node->start_addr = pre_full_addr;
			// if (xt_trace_analyze_i_cnt_vs_hist(
			//	msg.sub_value.progtracesync.i_cnt, pre_full_addr, 0,
			//	&node->addr_range)) {
			//	free(node);
			//	goto error_end;
			// }
			// if (xt_trace_get_start_and_full_addr(node)) {
			//	free(node);
			//	goto error_end;
			// }

			// // update pre_full_addr
			// pre_full_addr = node->full_addr;
			break;
		case TCODE_DIRECTBRANCHSYNC:
			node->ownership = ownership;
			// node->start_addr = pre_full_addr;
			// if (xt_trace_analyze_i_cnt_vs_hist(
			//	msg.sub_value.directbranchsync.i_cnt, pre_full_addr, 0,
			//	&node->addr_range)) {
			//	free(node);
			//	goto error_end;
			// }
			// if (xt_trace_get_start_and_full_addr(node)) {
			//	free(node);
			//	goto error_end;
			// }

			// // update pre_full_addr
			// pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCHSYNC:
			node->ownership = ownership;
			// node->start_addr = pre_full_addr;
			// if (xt_trace_analyze_i_cnt_vs_hist(
			//	msg.sub_value.indirectbranchsync.i_cnt, pre_full_addr, 0,
			//	&node->addr_range)) {
			//	free(node);
			//	goto error_end;
			// }
			// if (xt_trace_get_start_and_full_addr(node)) {
			//	free(node);
			//	goto error_end;
			// }

			// // update pre_full_addr
			// pre_full_addr = node->full_addr;
			break;
		case TCODE_RESOURCEFULL:
			node->ownership = ownership;
			// node->start_addr = pre_full_addr;
			// if (msg.sub_value.resourcefull.rcode == 0 ||
			//	msg.sub_value.resourcefull.rcode == 2) {
			//	if (xt_trace_analyze_i_cnt_vs_hist(
			//		msg.sub_value.resourcefull.rdata0, pre_full_addr,
			//		msg.sub_value.resourcefull.rdata1, &node->addr_range)) {
			//		free(node);
			//		goto error_end;
			//	}
			// }
			// else if (msg.sub_value.resourcefull.rcode == 1) {
			//	if (xt_trace_analyze_i_cnt_vs_hist(
			//		0, pre_full_addr, msg.sub_value.resourcefull.rdata0,
			//		&node->addr_range)) {
			//		free(node);
			//		goto error_end;
			//	}
			// }
			// else {
			//	// msg
			//	free(node);
			//	goto error_end;
			// }

			// if (xt_trace_get_start_and_full_addr(node)) {
			//	free(node);
			//	goto error_end;
			// }

			// // update pre_full_addr
			// pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCHHIST:
			node->ownership = ownership;
			// node->start_addr = pre_full_addr;
			// if (xt_trace_analyze_i_cnt_vs_hist(
			//	msg.sub_value.indirectbranchhist.i_cnt, pre_full_addr,
			//	msg.sub_value.indirectbranchhist.hist, &node->addr_range)) {
			//	free(node);
			//	goto error_end;
			// }
			// if (xt_trace_get_start_and_full_addr(node)) {
			//	free(node);
			//	goto error_end;
			// }

			// // update pre_full_addr
			// pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCHHISTSYNC:
			node->ownership = ownership;
			// node->start_addr = pre_full_addr;
			//if (xt_trace_analyze_i_cnt_vs_hist(
			//	msg.sub_value.indirectbranchhistsync.i_cnt, pre_full_addr,
			//	msg.sub_value.indirectbranchhistsync.hist, &node->addr_range)) {
			//	free(node);
			//	goto error_end;
			// }
			// if (xt_trace_get_start_and_full_addr(node)) {
			//	free(node);
			//	goto error_end;
			// }

			// // update pre_full_addr
			// pre_full_addr = node->full_addr;
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
		case TCODE_PROGTRACECORRELATION:
			node->ownership = ownership;
			// node->start_addr = pre_full_addr;
			// if (xt_trace_analyze_i_cnt_vs_hist(
			//	msg.sub_value.progtracecorrelation.i_cnt, pre_full_addr,
			//	msg.sub_value.progtracecorrelation.hist, &node->addr_range)) {
			//	free(node);
			//	goto error_end;
			// }
			// if (xt_trace_get_start_and_full_addr(node)) {
			//	free(node);
			//	goto error_end;
			// }

			// // update pre_full_addr
			// pre_full_addr = node->full_addr;
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
				     "Reserved",
				     "Exit from Powerdonw",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved",
				     "Reserved" };
	const char *evcode_str[16] = {
		"Entry into Debug Mode",
		"Entry into Low-power Mode",
		"Reserved",
		"Reserved",
		"Program Trace Disabled (hart is still running)",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved",
		"Reserved"
	};

	buf_p += sprintf(buf_p, ".  ");

	switch (msg->tcode) {
		case TCODE_OWNERSHIP: {
			buf_p += sprintf(buf_p, "TCODE=2(OwnerShip)");
			buf_p += sprintf(
				buf_p, ", Privilege change to %s%s",
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

int32_t xuantie_ntrace_decoder__process_full_message(
	struct perf_session *session, struct auxtrace_buffer *buffer)
{
	int ret = 0;
	bool error_message_happened = true;
	uint64_t pre_full_addr = 0;
	struct xt_trace_program_flow_node *node = trace_program_header;

	while (node) {
		if (error_message_happened) {
			resource_full_clear();
			if (xt_trace_msg_has_full_addr(&node->msg)) {
				xt_trace_get_start_and_full_addr(node);

				//ignore the i-cnt and hist of the first msg
				node->start_addr = node->full_addr;
				pre_full_addr = node->full_addr;

				//go next
				node = node->next;
				error_message_happened = false;
				continue;
			} else {
				node->invalid = 1;
			}

			node = node->next;
			continue;
		}

		switch (node->msg.tcode) {
		case TCODE_OWNERSHIP:
			break;
		case TCODE_DIRECTBRANCH:
			node->start_addr = pre_full_addr;
			node->full_addr =
				pre_full_addr +
				get_resource_full_icnt(
					node->msg.sub_value.directbranch
						.i_cnt) *
					2;
			resource_full_clear();

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCH:
			node->start_addr = pre_full_addr;
			ret = xt_trace_analyze_i_cnt_vs_hist(
				session, buffer,
				node->msg.sub_value.indirectbranch.i_cnt,
				pre_full_addr, 0, &node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			if (xt_trace_get_start_and_full_addr(node)) {
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
			ret = xt_trace_analyze_i_cnt_vs_hist(
				session, buffer,
				node->msg.sub_value.progtracesync.i_cnt,
				pre_full_addr, 0, &node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}
			if (xt_trace_get_start_and_full_addr(node)) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_DIRECTBRANCHSYNC:
			node->start_addr = pre_full_addr;
			ret = xt_trace_analyze_i_cnt_vs_hist(
				session, buffer,
				node->msg.sub_value.directbranchsync
					.i_cnt,
				pre_full_addr, 0, &node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}
			if (xt_trace_get_start_and_full_addr(node)) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCHSYNC:
			node->start_addr = pre_full_addr;
			ret = xt_trace_analyze_i_cnt_vs_hist(
				session, buffer,
				node->msg.sub_value.indirectbranchsync
					.i_cnt,
				pre_full_addr, 0, &node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}
			if (xt_trace_get_start_and_full_addr(node)) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_RESOURCEFULL:
			node->start_addr = pre_full_addr;
			if (node->msg.sub_value.resourcefull.rcode ==
				0) {
				add_resource_full_icnt(
					node->msg.sub_value.resourcefull
						.rdata0);
			} else if (node->msg.sub_value.resourcefull
						.rcode == 1) {
				add_resource_full_hist(
					node->msg.sub_value.resourcefull
						.rdata0);
			} else {
				// msg
				node->invalid = 1;
				error_message_happened = true;
				break;
			}
			break;
		case TCODE_INDIRECTBRANCHHIST:
			node->start_addr = pre_full_addr;
			ret = xt_trace_analyze_i_cnt_vs_hist(
				session, buffer,
				node->msg.sub_value.indirectbranchhist
					.i_cnt,
				pre_full_addr,
				node->msg.sub_value.indirectbranchhist
					.hist,
				&node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}
			if (xt_trace_get_start_and_full_addr(node)) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCHHISTSYNC:
			node->start_addr = pre_full_addr;
			ret = xt_trace_analyze_i_cnt_vs_hist(
				session, buffer,
				node->msg.sub_value
					.indirectbranchhistsync.i_cnt,
				pre_full_addr,
				node->msg.sub_value
					.indirectbranchhistsync.hist,
				&node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}
			if (xt_trace_get_start_and_full_addr(node)) {
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
				node->msg.sub_value.progtracecorrelation
					.i_cnt,
				pre_full_addr,
				node->msg.sub_value.progtracecorrelation
					.hist,
				&node->addr_range);
			resource_full_clear();
			if (ret < 0) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}
			if (xt_trace_get_start_and_full_addr(node)) {
				node->invalid = 1;
				error_message_happened = true;
				break;
			}

			// update pre_full_addr
			pre_full_addr = node->full_addr;
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

#define STR_LEN_MAX (1024 * 8)
int32_t xt_trace_program_trace_display(bool with_addr, bool with_symbol,
						bool with_insn)
{
	char str[STR_LEN_MAX] = { '\0' };
	struct xt_trace_program_flow_node *node_p =
		trace_program_header;

	while (node_p) {
		// printf n-trace message contents
		memset(str, 0, STR_LEN_MAX);
		if (xt_trace_output_ntrace_message(&node_p->msg, str)) {
			printf("Can not analysis ntrace message.\n");
			return -1;
		}

		if (strlen(str) >= STR_LEN_MAX) {
			printf("str with length 0x%lx is bigger than STR_LEN_MAX 0x%x\n",
					strlen(str), STR_LEN_MAX);
			return -1;
		}

		printf("%s", str);
		if (with_addr || with_symbol || with_insn) {
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
				if (node_p->invalid)
					break;
				printf("    Start from 0x%lx, End to 0x%lx",
						node_p->start_addr,
						node_p->full_addr);
				if (node_p->addr_range) {
					struct xt_trace_address_range
						*range_p =
							node_p->addr_range;
					printf(", include pc ranges:\n");
					while (range_p) {
						printf("    {0x%lx, 0x%lx}\n",
								range_p->start_addr,
								range_p->end_addr);
						range_p = range_p->next;
					}
				} else
					printf(".\n");
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
