CFLAGS += -I$(top_srcdir)/tools/include
CFLAGS += -I$(top_srcdir)/include/uapi

TEST_GEN_PROGS := riscv_cfi_test
TEST_PROGS := run_cfi.sh

include ../../lib.mk

CFI_CC=$(CC)
CFI_CC := $(filter-out -march=%,$(CFI_CC))
CFI_CC := $(filter-out -mabi=%,$(CFI_CC))
CFI_CC += -march=rva23u64_zicfilp_zicfiss -fcf-protection=return -fcf-protection=branch
$(info =========CFI_CC:$(CFI_CC)================)

$(OUTPUT)/riscv_cfi_test: riscv_cfi_test.c
	$(CFI_CC) -static -o$@ $(CFLAGS) $(LDFLAGS) $^
	./modify_lp_func_label_hash.sh $(OUTPUT)/riscv_cfi_test "test_func0"
	./modify_ss_sspush.sh $(OUTPUT)/riscv_cfi_test "sigsegv_handler"
