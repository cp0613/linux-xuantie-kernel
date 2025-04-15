CFLAGS += -I$(top_srcdir)/tools/include
CFLAGS += -I$(top_srcdir)/include/uapi

TEST_GEN_PROGS := riscv_cfi_test

include ../../lib.mk

$(OUTPUT)/riscv_cfi_test: riscv_cfi_test.c
	$(CC) -static -o$@ $(CFLAGS) $(LDFLAGS) $^
