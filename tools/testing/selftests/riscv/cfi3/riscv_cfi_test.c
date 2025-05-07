// SPDX-License-Identifier: GPL-2.0-only

#include "../../kselftest.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/prctl.h>
#include <errno.h>
#include <signal.h>
#include <asm/ucontext.h>

/* do not optimize cfi related test functions */
#pragma GCC push_options
#pragma GCC optimize("O0")                           // disable optmize
#pragma GCC diagnostic ignored "-Wstringop-overflow" // disable overflow warning

#define TEST_TYPE_LP_DISABLE 0
#define TEST_TYPE_LP_ENABLE  1
#define TEST_TYPE_SS_DISABLE 2
#define TEST_TYPE_SS_ENABLE  3

#ifndef SEGV_CPERR
#define SEGV_CPERR	10	/* Control protection fault */
#endif

void print_usage(const char *prog_name)
{
	printf("Usage: %s <cfi_type>\n", prog_name);
	printf("  lp [0] - test LANDING_PAD\n");
	printf("  ss [0] - test SHADOW_STACK\n");
}

struct test_ctx {
	int test_mode;
	int test_type;
};
static struct test_ctx g_ctx = {0};

static int parse_args(int argc, char **argv)
{
	if (argc < 2 || argc > 3 ||
	    (strcmp(argv[1], "lp") != 0 && strcmp(argv[1], "ss") != 0) ||
	    ((argc == 3) && (strcmp(argv[2], "0") != 0 && strcmp(argv[2], "1") != 0))) {
		return -1;
	}

	if (strcmp(argv[1], "lp") == 0) {
		if (argc == 3 && strcmp(argv[2], "0") == 0) {
			g_ctx.test_type = TEST_TYPE_LP_DISABLE;
			printf("test_type = TEST_TYPE_LP_DISABLE(%d)\n", TEST_TYPE_LP_DISABLE);
		} else {
			g_ctx.test_type = TEST_TYPE_LP_ENABLE;
			printf("test_type = TEST_TYPE_LP_ENABLE(%d)\n", TEST_TYPE_LP_ENABLE);
		}
	} else {
		if (argc == 3 && strcmp(argv[2], "0") == 0) {
			g_ctx.test_type = TEST_TYPE_SS_DISABLE;
			printf("test_type = TEST_TYPE_SS_DISABLE(%d)\n", TEST_TYPE_SS_DISABLE);
		} else {
			g_ctx.test_type = TEST_TYPE_SS_ENABLE;
			printf("test_type = TEST_TYPE_SS_ENABLE(%d)\n", TEST_TYPE_SS_ENABLE);
		}
	}

	return 0;
}

typedef int (*TestFuncPtr)(void);
static int test_func0(void)
{
	return 0;
}

static int test_func1(void)
{
	return 1;
}

static TestFuncPtr g_func_array[] = {
	test_func0,
	test_func1,
};

static int test_lp_disable(void)
{
	int func_id = 1;
	int ret;

	prctl(PR_SET_INDIR_BR_LP_STATUS, 0, 0, 0, 0);
	if (func_id == 0)
		ret = g_func_array[0]();
	else
		ret = g_func_array[1]();

	return ret;
}

static int test_lp_enable(void)
{
	int func_id = 0;
	int ret;

	prctl(PR_SET_INDIR_BR_LP_STATUS, PR_INDIR_BR_LP_ENABLE, 0, 0, 0);

	if (func_id == 0)
		ret = g_func_array[0]();
	else
		ret = g_func_array[1]();

	prctl(PR_SET_INDIR_BR_LP_STATUS, 0, 0, 0, 0);
	return ret;
}

static int test_protect_return(void)
{
	char local_buf[32];

	memset(local_buf, 0, 64);	// stack overflow attach
	return 0;
}

static void sigsegv_handler(int signum, siginfo_t *si, void *uc)
{
	int exit_code = 128 + SIGSEGV;

	prctl(PR_SET_INDIR_BR_LP_STATUS, 0, 0, 0, 0);
	prctl(PR_SET_SHADOW_STACK_STATUS, 0, 0, 0, 0);

	if (si->si_code == SEGV_CPERR) {
		printf("Control flow violation happened somewhere\n");
		printf("pc where violation happened %lx\n", si->si_addr);

		if (g_ctx.test_type == TEST_TYPE_LP_ENABLE ||
		    g_ctx.test_type == TEST_TYPE_SS_ENABLE) {
			printf("Test(%d) pass, attack detected\n", g_ctx.test_type);
			ksft_cnt.ksft_pass += 1;
			exit_code = 0;
		}
	}

	if (g_ctx.test_type == TEST_TYPE_SS_DISABLE) {
		printf("Test(%d) pass, crash detected\n", g_ctx.test_type);
		ksft_cnt.ksft_pass += 1;
		exit_code = 0;
	}

	ksft_print_msg("%s: %u / %u tests passed.\n",
		ksft_cnt.ksft_pass == ksft_plan ? "PASSED" : "FAILED",
		ksft_cnt.ksft_pass, ksft_plan);
	ksft_finished();

	exit(exit_code);
}

static bool register_signal_handler(void)
{
	struct sigaction sa = {};

	sa.sa_sigaction = sigsegv_handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSEGV, &sa, NULL))
		return false;

	return true;
}

int main(int argc, char *argv[])
{
	int ret;

	ksft_print_header();
	ksft_set_plan(1);
	ksft_print_msg("starting risc-v cfi tests\n");

	ret = parse_args(argc, argv);
	if (ret != 0) {
		print_usage(argv[0]);
		return EXIT_FAILURE;	// TODO: ksft_finished()
	}

	if (!register_signal_handler()) {
		printf("registering signal handler for SIGSEGV failed\n");
		return -1;
	}

	if (g_ctx.test_type == TEST_TYPE_LP_DISABLE) {
		printf("Test(%d) indirect jump without landing pad protect\n",
			g_ctx.test_type);
		test_lp_disable();	// return back here normally
		printf("Test(%d) pass, return normallly\n",
			g_ctx.test_type);
		ksft_cnt.ksft_pass += 1;
	}
	if (g_ctx.test_type == TEST_TYPE_LP_ENABLE) {
		printf("Test(%d) indirect jump with landing pad protect\n",
			g_ctx.test_type);
		test_lp_enable();	// get SIGSEGV and handle in sigsegv_handler()
	}

	if (g_ctx.test_type == TEST_TYPE_SS_DISABLE) {
		printf("Test(%d) return stack without shadow stack protect\n",
			g_ctx.test_type);
		prctl(PR_SET_SHADOW_STACK_STATUS, 0, 0, 0, 0);
		test_protect_return();	// get SIGSEGV and handle in sigsegv_handler()
	}
	if (g_ctx.test_type == TEST_TYPE_SS_ENABLE) {
		printf("Test(%d) return stack with shadow stack protect\n",
			g_ctx.test_type);
		prctl(PR_SET_SHADOW_STACK_STATUS, PR_SHADOW_STACK_ENABLE, 0, 0, 0);
		test_protect_return();	// get SIGSEGV and handle in sigsegv_handler()
		prctl(PR_SET_SHADOW_STACK_STATUS, 0, 0, 0, 0);
	}

	ksft_print_msg("%s: %u / %u tests passed.\n",
			ksft_cnt.ksft_pass == ksft_plan ? "PASSED" : "FAILED",
			ksft_cnt.ksft_pass, ksft_plan);
	ksft_finished();
}

#pragma GCC pop_options
