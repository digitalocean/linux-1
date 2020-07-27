// SPDX-License-Identifier: GPL-2.0

#include <linux/entry-kvm.h>
#include <linux/kvm_host.h>

static int xfer_to_guest_mode_work(struct kvm_vcpu *vcpu, unsigned long ti_work)
{
	do {
		int ret;

		if (ti_work & _TIF_SIGPENDING) {
			kvm_handle_signal_exit(vcpu);
			return -EINTR;
		}

		if (ti_work & _TIF_NEED_RESCHED)
			schedule();

		if (ti_work & _TIF_NOTIFY_RESUME)
			tracehook_notify_resume(NULL);

		ret = arch_xfer_to_guest_mode_handle_work(vcpu, ti_work);
		if (ret)
			return ret;

		ti_work = READ_ONCE(current_thread_info()->flags);
	} while (ti_work & XFER_TO_GUEST_MODE_WORK || need_resched());
	return 0;
}

int xfer_to_guest_mode_handle_work(struct kvm_vcpu *vcpu)
{
	unsigned long ti_work;

	/*
	 * This is invoked from the outer guest loop with interrupts and
	 * preemption enabled.
	 *
	 * KVM invokes xfer_to_guest_mode_work_pending() with interrupts
	 * disabled in the inner loop before going into guest mode. No need
	 * to disable interrupts here.
	 */
	ti_work = READ_ONCE(current_thread_info()->flags);
	if (!(ti_work & XFER_TO_GUEST_MODE_WORK))
		return 0;

	return xfer_to_guest_mode_work(vcpu, ti_work);
}
EXPORT_SYMBOL_GPL(xfer_to_guest_mode_handle_work);

/**
 * kvm_enter_from_guest_mode - Hook called just after entering kernel from guest.
 * Caller should ensure interrupts are off.
 */
void kvm_enter_from_guest_mode(void)
{
	if (!entry_kernel_protected(HT_PROTECT_KVM))
		return;

	sched_core_unsafe_enter(HT_PROTECT_KVM);
}
EXPORT_SYMBOL_GPL(kvm_enter_from_guest_mode);

/**
 * kvm_exit_to_guest_mode - Hook called just before entering guest from kernel.
 * Caller should ensure interrupts are off.
 */
void kvm_exit_to_guest_mode(void)
{
	if (!entry_kernel_protected(HT_PROTECT_KVM))
		return;

	sched_core_unsafe_exit(HT_PROTECT_KVM);

	/*
	 * Wait here instead of in xfer_to_guest_mode_handle_work(). The reason
	 * is because in vcpu_run(), xfer_to_guest_mode_handle_work() is called
	 * when a vCPU was either runnable or blocked. However, we only care
	 * about the runnable case (VM entry/exit) which is handled by
	 * vcpu_enter_guest().
	 */
	sched_core_wait_till_safe(XFER_TO_GUEST_MODE_WORK);
}
EXPORT_SYMBOL_GPL(kvm_exit_to_guest_mode);
