// SPDX-License-Identifier: GPL-2.0

#include <stdlib.h>
#include <string.h>
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
};

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

	while (trace_program_header) {
		trace_program_header = trace_program_header->next;

		free(node_p);
		node_p = trace_program_header;
	}
}

/*************************************************************
 * Process U-addr and FULL-addr
 *************************************************************/
static int32_t
xt_trace_get_directbranch_full_addr(struct xt_trace_program_flow_node *node)
{
	(void)node;
	return 0;
}

static int32_t
xt_trace_get_start_and_full_addr(struct xt_trace_program_flow_node *node)
{
	switch (node->msg.tcode) {
	case TCODE_DIRECTBRANCH:
		if (xt_trace_get_directbranch_full_addr(node)) {
			printf("Fail to get full addr for direct branch message.\n");
			return -1;
		}
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

		while (range->next)
			range = range->next;
		node->full_addr = range->end_addr;
	} break;
	case TCODE_PROGTRACECORRELATION: {
		struct xt_trace_address_range *range = node->addr_range;

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
	uint64_t pre_full_addr = 0;
	struct xt_riscv_nexus_trace_message msg;
	struct xt_riscv_nexus_trace_message *ownership = NULL;
	struct xt_trace_program_flow_node *node = NULL;
	uint32_t trace_data_wrapped = saved_config->trace_ram_wrap;
	uint32_t wrap_used = 1;
	// If true, we should find a message with full address
	bool error_message_happened = false;
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

				if (xt_trace_get_start_and_full_addr(node)) {
					free(node);
					goto error_end;
				}
				// ignore i-cnt and hist
				node->start_addr = node->full_addr;
				pre_full_addr = node->full_addr;
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
			node->start_addr = pre_full_addr;
			node->full_addr = pre_full_addr +
					  msg.sub_value.directbranch.i_cnt;
			node->ownership = ownership;

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCH:
			node->start_addr = pre_full_addr;
			if (xt_trace_get_start_and_full_addr(node)) {
				free(node);
				goto error_end;
			}
			node->ownership = ownership;

			// update pre_full_addr
			pre_full_addr = node->full_addr;
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
			node->start_addr = pre_full_addr;
			if (xt_trace_get_start_and_full_addr(node)) {
				free(node);
				goto error_end;
			}
			node->ownership = ownership;

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_DIRECTBRANCHSYNC:
			node->start_addr = pre_full_addr;
			if (xt_trace_get_start_and_full_addr(node)) {
				free(node);
				goto error_end;
			}
			node->ownership = ownership;

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCHSYNC:
			node->start_addr = pre_full_addr;
			if (xt_trace_get_start_and_full_addr(node)) {
				free(node);
				goto error_end;
			}
			node->ownership = ownership;

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_RESOURCEFULL:
			node->start_addr = pre_full_addr;
			break;
		case TCODE_INDIRECTBRANCHHIST:
			node->start_addr = pre_full_addr;
			if (xt_trace_get_start_and_full_addr(node)) {
				free(node);
				goto error_end;
			}
			node->ownership = ownership;

			// update pre_full_addr
			pre_full_addr = node->full_addr;
			break;
		case TCODE_INDIRECTBRANCHHISTSYNC:
			node->start_addr = pre_full_addr;
			if (xt_trace_get_start_and_full_addr(node)) {
				free(node);
				goto error_end;
			}
			node->ownership = ownership;

			// update pre_full_addr
			pre_full_addr = node->full_addr;
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
			node->start_addr = pre_full_addr;
			//if (xt_trace_get_start_and_full_addr(node)) {
			//    free(node);
			//    goto error_end;
			//}
			node->ownership = ownership;

			// update pre_full_addr
			pre_full_addr = node->full_addr;
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
	return 0;
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
			msg->sub_value.ownership.is_virtual ? "V" : " ",
			priv_mode_str[msg->sub_value.ownership.privilege & 0x3]);
		if (msg->sub_value.ownership.has_context)
			buf_p += sprintf(buf_p, ", %sContext = 0x%lx",
					 msg->sub_value.ownership.is_scontext ?
						 "S" :
						 "H",
					 msg->sub_value.ownership.context);
		buf_p += sprintf(buf_p, ".");
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
		if (msg->sub_value.error.etype == 0) {
			buf_p += sprintf(buf_p, ", (");
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
				", rdata0=0x%lx(i-cnt), rdata1=0x%lx(hist)",
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
		buf_p += sprintf(buf_p, ", timestamp=0x%lx", msg->timestamp);
	buf_p += sprintf(buf_p, ".\n");

	return 0;
}

#define STR_LEN_MAX (1024 * 8)
int32_t xt_trace_program_trace_display_node(void)
{
	char str[STR_LEN_MAX] = { '\0' };
	struct xt_trace_program_flow_node *node_p = trace_program_header;

	while (node_p) {
		// printf n-trace message contents
		memset(str, 0, STR_LEN_MAX);
		if (xt_trace_output_ntrace_message(&node_p->msg, str)) {
			printf("Can not analysis ntrace message.\n");
			xt_trace_free_program_flow_node();
			return -1;
		}

		if (strlen(str) >= STR_LEN_MAX) {
			printf("str with length 0x%lx is bigger than STR_LEN_MAX 0x%x\n",
				strlen(str), STR_LEN_MAX);
			xt_trace_free_program_flow_node();
			return -1;
		}

		printf("%s", str);

		node_p = node_p->next;
	}

	xt_trace_free_program_flow_node();
	return 0;
}
