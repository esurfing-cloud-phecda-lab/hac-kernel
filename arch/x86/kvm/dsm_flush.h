#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include "dsm-util.h"
#include "ivy.h"
#include "mmu.h"

#include <linux/kthread.h>

// #define DSM_WRITE_GUEST_PAGE

#define FLUSH_GFN_METHOD_3

#ifdef FLUSH_GFN_METHOD_3
int flush_gfn_3(struct kvm *kvm, struct kvm_memory_slot *slot, gfn_t gfn, bool is_local)
{
	if(!is_local)
		kthread_use_mm(kvm->mm);
	unsigned long addr;

	addr = gfn_to_hva_memslot_prot(slot, gfn, NULL);
	if (kvm_is_error_hva(addr)){
		if(!is_local)
			kthread_unuse_mm(kvm->mm);
		pr_alert("%s: gfn to hva failed: gfn=%llu addr=%lu local=%d\n", __func__, gfn, addr, is_local);
		return -EFAULT;
	}
	stac();
	clflush_cache_range((void*)addr, FLUSH_PAGE_SIZE);
	clac();
	if(!is_local)
		kthread_unuse_mm(kvm->mm);

	return 0;
}
#endif

int flush_gfn(struct kvm *kvm, struct kvm_memory_slot *slot, gfn_t gfn, bool is_local)
{
	#ifdef IVY_PAGE_FAULT_FLUSH_TIME
	ktime_t start, diff;
	start = ktime_get();
	#endif
	int ret = 0;
#ifdef FLUSH_GFN_METHOD_3
	ret |= flush_gfn_3(kvm, slot, gfn, is_local);
#endif

	#ifdef IVY_PAGE_FAULT_FLUSH_TIME
	diff = ktime_sub(ktime_get(), start);
	save_pf_time_to_db(kvm, diff, is_local?DSM_TIME_TYPE_FLUSH_LOCAL:DSM_TIME_TYPE_FLUSH_REMOTE, is_local);
	#endif
	return ret;
}