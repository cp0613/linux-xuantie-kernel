// SPDX-License-Identifier: GPL-2.0-only

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>

void print_usage(const char *prog_name)
{
	fprintf(stderr, "Usage: %s <cfi_type>\n", prog_name);
	fprintf(stderr, "  lp  - Only enable LANDING_PAD\n");
	fprintf(stderr, "  ss  - Only enable SHADOW_STACK\n");
}

int main(int argc, char *argv[])
{
	int ret;
	int cfi_type = -1;
	unsigned long status = 0;

	if (argc != 2) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (strcmp(argv[1], "lp") == 0) {
		cfi_type = PR_SET_INDIR_BR_LP_STATUS;
	} else if (strcmp(argv[1], "ss") == 0) {
		cfi_type = PR_SET_SHADOW_STACK_STATUS;
	} else {
		fprintf(stderr, "Error: Invalid argument '%s' (enable all)\n", argv[1]);
		print_usage(argv[0]);
	}

	if (cfi_type == PR_SET_INDIR_BR_LP_STATUS) {
		prctl(PR_SET_INDIR_BR_LP_STATUS, PR_INDIR_BR_LP_ENABLE, 0, 0, 0);
		prctl(PR_SET_SHADOW_STACK_STATUS, 0, 0, 0, 0);
	} else if (cfi_type == PR_SET_SHADOW_STACK_STATUS) {
		prctl(PR_SET_INDIR_BR_LP_STATUS, 0, 0, 0, 0);
		prctl(PR_SET_SHADOW_STACK_STATUS, PR_SHADOW_STACK_ENABLE, 0, 0, 0);
	} else {
		prctl(PR_SET_INDIR_BR_LP_STATUS, PR_INDIR_BR_LP_ENABLE, 0, 0, 0);
		prctl(PR_SET_SHADOW_STACK_STATUS, PR_SHADOW_STACK_ENABLE, 0, 0, 0);
	}

	for (int i = 0; i < 10; i++) {
		ret = prctl(PR_GET_INDIR_BR_LP_STATUS, &status, 0, 0, 0);
		printf("PR_GET_INDIR_BR_LP_STATUS: %s\n",
			status&PR_INDIR_BR_LP_ENABLE ? "enable" : "disable");
		ret = prctl(PR_GET_SHADOW_STACK_STATUS, &status, 0, 0, 0);
		printf("PR_GET_SHADOW_STACK_STATUS: %s\n",
			status&PR_SHADOW_STACK_ENABLE ? "enable" : "disable");

		sleep(1);
	}

	return EXIT_SUCCESS;
}
