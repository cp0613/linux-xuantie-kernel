// SPDX-License-Identifier: GPL-2.0
#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/types.h>
#include <linux/zalloc.h>
#include <stdlib.h>
#include <unistd.h>

#include "auxtrace.h"
#include "color.h"
#include "debug.h"
#include "evsel.h"
#include "machine.h"
#include "session.h"
#include "tool.h"
#include <internal/lib.h>
#include "xuantie-ntrace.h"
#include "xuantie-ntrace-decoder/xuantie-ntrace-decoder.h"

struct xuantie_ntrace {
	struct auxtrace auxtrace;
	u32 auxtrace_type;
	struct perf_session *session;
	struct machine *machine;
	u32 pmu_type;
};

static void xuantie_ntrace_dump(struct xuantie_ntrace *ntrace __maybe_unused,
			  unsigned char *buf, size_t len)
{
	struct xuantie_saved_config *saved_config;
	const char *color = PERF_COLOR_BLUE;

	color_fprintf(stdout, color, ". ... %s: buf=%p len=%zubytes\n", __func__, buf, len);
	for (size_t i = 0; i < len; i++) {
		printf("  [%4d]: %02x", i, buf[i]);
		if ((i+1)%4 == 0)
			printf("\n");
	}

	/* Display xuantie_saved_conifg. */
	if (len < sizeof(struct xuantie_saved_config)) {
		printf("Error size of struct auxtrace_event->size 0x%lx, should bigger then 0x%lx",
			len, sizeof(struct xuantie_saved_config));
		return;
	}

	saved_config = (struct xuantie_saved_config *)buf;
	color_fprintf(stdout, color, ". ... xuantie saved configs are:\n");
	printf("saved_config->_size is 0x%x\n", saved_config->_size);
	printf("saved_config->inst_mode is 0x%x\n", saved_config->inst_mode);
	printf("saved_config->src_bits is 0x%x\n", saved_config->src_bits);
	printf("saved_config->timestamp_bits is 0x%x\n", saved_config->timestamp_bits);
	printf("saved_config->trace_ram_wrap is 0x%x\n", saved_config->trace_ram_wrap);

	/* Display XuanTie NTrace Data. */
	if (xuantie_ntrace_decoder__process_metedata(saved_config,
			buf + sizeof(struct xuantie_saved_config),
			len - sizeof(struct xuantie_saved_config)) == 0)
		xt_trace_program_trace_display_node();
}

static void xuantie_ntrace_dump_event(struct xuantie_ntrace *ntrace, unsigned char *buf,
				size_t len)
{
	printf(".\n");

	xuantie_ntrace_dump(ntrace, buf, len);
}

static int xuantie_ntrace_process_event(struct perf_session *session __maybe_unused,
				  union perf_event *event __maybe_unused,
				  struct perf_sample *sample __maybe_unused,
				  struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static int xuantie_ntrace_process_auxtrace_event(struct perf_session *session,
					   union perf_event *event,
					   struct perf_tool *tool __maybe_unused)
{
	struct xuantie_ntrace *ntrace = container_of(session->auxtrace, struct xuantie_ntrace,
					    auxtrace);
	int fd = perf_data__fd(session->data);
	int size = event->auxtrace.size;
	void *data = malloc(size);
	off_t data_offset;
	int err;

	if (!data)
		return -errno;

	if (perf_data__is_pipe(session->data)) {
		data_offset = 0;
	} else {
		data_offset = lseek(fd, 0, SEEK_CUR);
		if (data_offset == -1) {
			free(data);
			return -errno;
		}
	}

	err = readn(fd, data, size);
	if (err != (ssize_t)size) {
		free(data);
		return -errno;
	}

	if (dump_trace)
		xuantie_ntrace_dump_event(ntrace, data, size);

	free(data);
	return 0;
}

static int xuantie_ntrace_flush(struct perf_session *session __maybe_unused,
			  struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static void xuantie_ntrace_free_events(struct perf_session *session __maybe_unused)
{
}

static void xuantie_ntrace_free(struct perf_session *session)
{
	struct xuantie_ntrace *ntrace = container_of(session->auxtrace, struct xuantie_ntrace,
					    auxtrace);

	session->auxtrace = NULL;
	free(ntrace);
}

static bool xuantie_ntrace_evsel_is_auxtrace(struct perf_session *session,
				       struct evsel *evsel)
{
	struct xuantie_ntrace *ntrace = container_of(session->auxtrace, struct xuantie_ntrace,
					    auxtrace);

	return evsel->core.attr.type == ntrace->pmu_type;
}

static void xuantie_ntrace_print_info(__u64 type)
{
	if (!dump_trace)
		return;

	fprintf(stdout, "  PMU Type           %" PRId64 "\n", (s64) type);
}

int xuantie_ntrace_process_auxtrace_info(union perf_event *event,
				   struct perf_session *session)
{
	struct perf_record_auxtrace_info *auxtrace_info = &event->auxtrace_info;
	struct xuantie_ntrace *ntrace;

	if (auxtrace_info->header.size < XUANTIE_NTRACE_AUXTRACE_PRIV_SIZE +
				sizeof(struct perf_record_auxtrace_info))
		return -EINVAL;

	ntrace = zalloc(sizeof(*ntrace));
	if (!ntrace)
		return -ENOMEM;

	ntrace->session = session;
	ntrace->machine = &session->machines.host; /* No kvm support */
	ntrace->auxtrace_type = auxtrace_info->type;
	ntrace->pmu_type = auxtrace_info->priv[0];

	ntrace->auxtrace.process_event = xuantie_ntrace_process_event;
	ntrace->auxtrace.process_auxtrace_event = xuantie_ntrace_process_auxtrace_event;
	ntrace->auxtrace.flush_events = xuantie_ntrace_flush;
	ntrace->auxtrace.free_events = xuantie_ntrace_free_events;
	ntrace->auxtrace.free = xuantie_ntrace_free;
	ntrace->auxtrace.evsel_is_auxtrace = xuantie_ntrace_evsel_is_auxtrace;
	session->auxtrace = &ntrace->auxtrace;

	xuantie_ntrace_print_info(auxtrace_info->priv[0]);

	return 0;
}
