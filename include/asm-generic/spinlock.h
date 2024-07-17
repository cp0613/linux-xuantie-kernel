/* SPDX-License-Identifier: GPL-2.0 */

/*
 * 'Generic' ticket-lock implementation.
 *
 * It relies on atomic_fetch_add() having well defined forward progress
 * guarantees under contention. If your architecture cannot provide this, stick
 * to a test-and-set lock.
 *
 * It also relies on atomic_fetch_add() being safe vs smp_store_release() on a
 * sub-word of the value. This is generally true for anything LL/SC although
 * you'd be hard pressed to find anything useful in architecture specifications
 * about this. If your architecture cannot do this you might be better off with
 * a test-and-set.
 *
 * It further assumes atomic_*_release() + atomic_*_acquire() is RCpc and hence
 * uses atomic_fetch_add() which is RCsc to create an RCsc hot path, along with
 * a full fence after the spin to upgrade the otherwise-RCpc
 * atomic_cond_read_acquire().
 *
 * The implementation uses smp_cond_load_acquire() to spin, so if the
 * architecture has WFE like instructions to sleep instead of poll for word
 * modifications be sure to implement that (see ARM64 for example).
 *
 */

#ifndef __ASM_GENERIC_SPINLOCK_H
#define __ASM_GENERIC_SPINLOCK_H

#include <asm-generic/ticket_spinlock.h>
#include <asm/qrwlock.h>

#endif /* __ASM_GENERIC_SPINLOCK_H */
