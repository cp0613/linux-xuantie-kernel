# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 ARM Limited
# Originally tools/testing/arm64/abi/Makefile

CFLAGS += -I$(top_srcdir)/tools/include
CFLAGS += -I$(top_srcdir)/arch/riscv/include

TEST_GEN_PROGS := string_zbb_bench

include ../../lib.mk

$(OUTPUT)/string_zbb_bench: string_zbb_bench.c strlen_comm.S strlen_zbb.S
	$(CC) -static -o$@ $(CFLAGS) $(LDFLAGS) $^
