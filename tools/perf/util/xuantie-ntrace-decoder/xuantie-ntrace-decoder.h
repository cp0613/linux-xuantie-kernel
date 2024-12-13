/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/types.h>

struct xuantie_saved_config {
	u32 _size;
	u32 inst_mode;
	u32 src_bits;
	u32 timestamp_bits;
	u32 trace_ram_wrap;
	u32 _align;
};

int32_t xuantie_ntrace_decoder__process_metedata(struct xuantie_saved_config *saved_config,
		unsigned char *buf, size_t len);
int32_t xt_trace_program_trace_display_node(void);
