#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include "mmu.h"
#include "dsm.h" /* KVM_DSM_DEBUG */
#include "dsm-util.h"

#include <linux/kthread.h>
#include <linux/mmu_context.h>

struct kvm_network_ops network_ops;

int get_dsm_address(struct kvm *kvm, int dsm_id, struct dsm_address *addr)
{
	if (addr == NULL) {
		return -EINVAL;
	}

	sprintf(addr->port, "%d", 37710 + dsm_id);
	addr->host = kvm->arch.cluster_iplist[dsm_id];

	return 0;
}

int dsm_create_memslot(struct kvm_dsm_memory_slot *slot,
		unsigned long npages)
{
	unsigned long i;
	int ret = 0;
	// 分配vfn_dsm_state等字段，前16位代表vfn的owner，后16位代表vfn的状态
	slot->vfn_dsm_state = kvm_kvzalloc(npages * sizeof(*slot->vfn_dsm_state));
	if (!slot->vfn_dsm_state)
		return -ENOMEM;

	slot->rmap = kvm_kvzalloc(npages * sizeof(*slot->rmap));
	if (!slot->rmap) {
		ret = -ENOMEM;
		goto out_free_dsm_state;
	}

	slot->backup_rmap = kvm_kvzalloc(npages * sizeof(*slot->backup_rmap));
	if (!slot->backup_rmap) {
		ret = -ENOMEM;
		goto out_free_rmap;
	}

	slot->rmap_lock = kmalloc(sizeof(*slot->rmap_lock), GFP_KERNEL);
	if (!slot->rmap_lock) {
		ret = -ENOMEM;
		goto out_free_backup_rmap;
	}
	mutex_init(slot->rmap_lock);

	for (i = 0; i < npages; i++) {
		mutex_init(&slot->vfn_dsm_state[i].fast_path_lock);
		mutex_init(&slot->vfn_dsm_state[i].lock);
	}

	return ret;

out_free_backup_rmap:
	kvfree(slot->backup_rmap);
out_free_rmap:
	kvfree(slot->rmap);
out_free_dsm_state:
	kvfree(slot->vfn_dsm_state);
	return ret;
}

int insert_hvaslot(struct kvm_dsm_memslots *slots, int pos, hfn_t start,
		unsigned long npages)
{
	int ret, i;

	if (slots->used_slots == KVM_MEM_SLOTS_NUM) {
		printk(KERN_ERR "kvm-dsm: all slots are used, no more space for new hvaslot[%llu,%lu]\n",
				start, npages);
		return -EINVAL;
	}

	for (i = slots->used_slots++; i > pos; i--) {
		slots->memslots[i] = slots->memslots[i - 1];
	}

	slots->memslots[i].base_vfn = start;
	slots->memslots[i].npages = npages;
	ret = dsm_create_memslot(&slots->memslots[i], npages);
	if (ret < 0)
		return ret;

	return 0;
}

void dsm_lock(struct kvm *kvm, struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
#ifdef KVM_DSM_DEBUG
	char cur_comm[TASK_COMM_LEN];
#ifdef CONFIG_DEBUG_MUTEXES
	char lock_owner_comm[TASK_COMM_LEN];
#endif
	int retry_cnt = 0;

	retry_cnt = 0;
	while (!mutex_trylock(&slot->vfn_dsm_state[vfn -
				slot->base_vfn].lock)) {
		// usleep_range(10, 10);
		udelay(10);
		retry_cnt++;
		/* ~10s */
		if (retry_cnt > 1000000) {
			gfn_t gfn = __kvm_dsm_vfn_to_gfn(slot, false, vfn, NULL, NULL);
			get_task_comm(cur_comm, current);
#ifdef CONFIG_DEBUG_MUTEXES
			get_task_comm(lock_owner_comm, slot->vfn_dsm_state[vfn -
				slot->base_vfn].lock.owner);
			printk(KERN_ERR "%s: task %s DEADLOCK (held by %s) on gfn[%llu] "
					"vfn[%llu] caller %pf\n",
					__func__, cur_comm, lock_owner_comm, gfn, vfn,
					__builtin_return_address(0));
#else
			printk(KERN_ERR "%s: task %s DEADLOCK on gfn[%llu] "
					"vfn[%llu] caller %pf\n",
					__func__, cur_comm, gfn, vfn,
					__builtin_return_address(0));
			dump_stack();
#endif
			retry_cnt = 0;
		}
	}

#else
	return mutex_lock(&slot->vfn_dsm_state[vfn - slot->base_vfn].lock);
#endif
}

void dsm_unlock(struct kvm *kvm, struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	return mutex_unlock(&slot->vfn_dsm_state[vfn - slot->base_vfn].lock);
}

int kvm_dsm_connect(struct kvm *kvm, int dest_id, kconnection_t **conn_sock)
{
	int ret;
	struct dsm_address addr;
	// 确定socket连接的host
	ret = get_dsm_address(kvm, dest_id, &addr);
	if (ret < 0) {
		printk(KERN_ERR "kvm-dsm: address not configured properly for node-%d\n", dest_id);
		return ret;
	}

	ret = network_ops.connect(addr.host, addr.port, conn_sock);
	if (ret < 0) {
		printk(KERN_ERR "kvm-dsm: node-%d failed to connect to node-%d\n",
				kvm->arch.dsm_id, dest_id);
		return ret;
	}
	printk(KERN_INFO "kvm-dsm: node-%d established connection with node-%d [%s:%s]\n",
			kvm->arch.dsm_id, dest_id, addr.host, addr.port);
	return 0;
}

int kvm_read_guest_page_nonlocal(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn,
		void *data, int offset, int len)
{
	int ret = 0;

	kthread_use_mm(kvm->mm);
	ret = __kvm_read_guest_page(slot, gfn, data, offset, len);
	kthread_unuse_mm(kvm->mm);
	return ret;
}

int kvm_write_guest_page_nonlocal(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn,
		const void *data, int offset, int len)
{
	int ret = 0;

	kthread_use_mm(kvm->mm);
	ret = __kvm_write_guest_page(kvm, slot, gfn, data, offset, len);
	kthread_unuse_mm(kvm->mm);
	return ret;
}

#ifdef KVM_KTCP_DEBUG
unsigned kvm_hash_guest_page_nonlocal(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn, bool use_mm, struct PageDebugDSM *pdd)
{
	int ret;
	char *data;
	unsigned hash=0;
	data = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(data==NULL){
		dsm_debug_v("kmalloc failed");
		return 0;
	}
	if(use_mm)
		kthread_use_mm(kvm->mm);
	pdd->pfn = gfn_to_pfn(kvm, gfn);
	ret = __kvm_read_guest_page(slot, gfn, data, 0, PAGE_SIZE);
	if(use_mm)
		kthread_unuse_mm(kvm->mm);
	if(ret<0){
		dsm_debug_v("kvm_hash_guest_page_nonlocal failed");
		kfree(data);
		return 0;
	}
	hash = jhash(data, PAGE_SIZE, JHASH_INITVAL);
	kfree(data);
	pdd->hash = hash;
	pdd->gfn=gfn;
	return hash;
}
#endif
