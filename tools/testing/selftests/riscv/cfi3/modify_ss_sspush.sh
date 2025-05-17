#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

# input params
default_prog_name="riscv_cfi_test"
default_func_name="sigsegv_handler"

prog_name="${1:-$default_prog_name}"
func_name="${2:-$default_func_name}"

func_lp_patch='\x01\x00'

func_addr_hex=$(/usr/bin/env readelf -s $prog_name | grep $func_name | awk '{print $2}')
text_addr_hex=$(/usr/bin/env readelf -S $prog_name | grep text| awk '{print $5}')
text_offs_hex=$(/usr/bin/env readelf -S $prog_name | grep text| awk '{print $6}')
printf "func_addr_hex=0x%s, text_addr_hex=0x%s, text_offs_hex=0x%s\n" $func_addr_hex $text_addr_hex $text_offs_hex

func_addr_dec=$((16#$func_addr_hex))
text_addr_dec=$((16#$text_addr_hex))
text_offs_dec=$((16#$text_offs_hex))
printf "func_addr_hex=%d, text_addr_hex=%d, text_offs_hex=%d\n" $func_addr_dec $text_addr_dec $text_offs_dec

func_file_offset=$((func_addr_dec + 4 - text_addr_dec + text_offs_dec))
printf "func_file_offset=0x%X (%d)\n" $func_file_offset $func_file_offset

echo -ne $func_lp_patch > lp_patch.bin

echo "dd if=lp_patch.bin of=$prog_name bs=1 seek=$(($func_file_offset)) conv=notrunc"
/usr/bin/env dd if=lp_patch.bin of=$prog_name bs=1 seek=$(($func_file_offset)) conv=notrunc
rm -f lp_patch.bin
