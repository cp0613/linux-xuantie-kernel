/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef SELFTEST_RISCV_STRLEN_H
#define SELFTEST_RISCV_STRLEN_H

#include <stddef.h>

size_t strlen_comm(const char *s);
size_t strlen_zbb(const char *s);

#endif
