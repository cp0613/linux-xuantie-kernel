// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <linux/uaccess.h>
#include <asm/cpufeature.h>
#include <asm/vector.h>

void kvm_riscv_vcpu_m_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *cntx = &vcpu->arch.guest_context;

	cntx->sstatus &= ~SR_MS;

	if (has_matrix())
		cntx->sstatus |= SR_MS_INITIAL;
	else
		cntx->sstatus |= SR_MS_OFF;
}

static void kvm_riscv_vcpu_m_clean(struct kvm_cpu_context *cntx)
{
	cntx->sstatus &= ~SR_MS;
	cntx->sstatus |= SR_MS_CLEAN;
}

void kvm_riscv_vcpu_guest_m_save(struct kvm_cpu_context *cntx,
				 const unsigned long *isa)
{
	if (!has_matrix())
		return;

	if ((cntx->sstatus & SR_MS) == SR_MS_DIRTY) {
		__riscv_m_mstate_save(&cntx->mstate, cntx->mstate.datap);
		kvm_riscv_vcpu_m_clean(cntx);
	}
}

void kvm_riscv_vcpu_guest_m_restore(struct kvm_cpu_context *cntx,
				    const unsigned long *isa)
{
	if (!has_matrix())
		return;

	if ((cntx->sstatus & SR_MS) != SR_MS_OFF) {
		__riscv_m_mstate_restore(&cntx->mstate, cntx->mstate.datap);
		kvm_riscv_vcpu_m_clean(cntx);
	}
}

void kvm_riscv_vcpu_host_m_save(struct kvm_cpu_context *cntx)
{
	if (!has_matrix())
		return;

	__riscv_m_mstate_save(&cntx->mstate, cntx->mstate.datap);
}

void kvm_riscv_vcpu_host_m_restore(struct kvm_cpu_context *cntx)
{
	if (!has_matrix())
		return;

	__riscv_m_mstate_restore(&cntx->mstate, cntx->mstate.datap);
}

int kvm_riscv_vcpu_alloc_m_context(struct kvm_vcpu *vcpu,
					struct kvm_cpu_context *cntx)
{
	size_t alloc_size;

	if (!has_matrix())
		return 0;

	riscv_m_enable();
	alloc_size = csr_read(CSR_XMLENB) * 8;
	riscv_m_disable();

	cntx->mstate.datap = kmalloc(alloc_size, GFP_KERNEL);
	if (!cntx->mstate.datap)
		return -ENOMEM;

	vcpu->arch.host_context.mstate.datap = kzalloc(alloc_size, GFP_KERNEL);
	if (!vcpu->arch.host_context.mstate.datap)
		return -ENOMEM;

	return 0;
}

void kvm_riscv_vcpu_free_m_context(struct kvm_vcpu *vcpu)
{
	if (!has_matrix())
		return;

	kfree(vcpu->arch.guest_reset_context.mstate.datap);
	kfree(vcpu->arch.host_context.mstate.datap);
}
