#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include "dsm.h"
#include "mmu.h"

#include <linux/kthread.h>
#include <linux/mmu_context.h>

#ifdef KVM_DSM_DEBUG
bool kvm_dsm_dbg_verbose = 1;
#endif

struct kvm_dsm_debug_buffer dsm_db_list[2];

static int kvm_dsm_page_fault(struct kvm *kvm, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write);
/*
 * The old dsm_memslots are free here rather than kvm_dsm_remove_memslot.
 */
int kvm_dsm_register_memslot_hva(struct kvm *kvm, struct kvm_memory_slot *slot,
		unsigned long npages)
{
	int ret, i;
	hfn_t base_vfn, start, end;

	struct kvm_dsm_memslots *slots = NULL, *old_slots = __kvm_hvaslots(kvm);
	struct kvm_dsm_memory_slot *old_slot;

	if (!kvm->arch.dsm_enabled || slot->id >= KVM_USER_MEM_SLOTS)
		return 0;

	slots = kvm_kvzalloc(sizeof(struct kvm_dsm_memslots));
	if (!slots)
		return -ENOMEM;
	memcpy(slots, old_slots, sizeof(struct kvm_dsm_memslots));

	base_vfn = slot->userspace_addr >> PAGE_SHIFT;
	for (i = 0; i < old_slots->used_slots; i++) {
		if (base_vfn >= old_slots->memslots[i].base_vfn)
			continue;
		if (i == 0) {
			start = base_vfn;
			end = min(base_vfn + npages, old_slots->memslots[i].base_vfn);
		} else {
			old_slot = &old_slots->memslots[i - 1];
			if (base_vfn + npages <= old_slot->base_vfn + old_slot->npages)
				continue;
			start = max(base_vfn, old_slot->base_vfn + old_slot->npages);
			end = min(base_vfn + npages, old_slots->memslots[i].base_vfn);
			if (start == end)
				continue;
		}

		ret = insert_hvaslot(slots, i, start, end - start);
		if (ret < 0)
			goto out_free;
	}

	if (old_slots->used_slots == 0) {
		start = base_vfn;
		end = base_vfn + npages;
	} else {
		old_slot = &old_slots->memslots[old_slots->used_slots - 1];
		start = max(base_vfn, old_slot->base_vfn + old_slot->npages);
		end = base_vfn + npages;
	}
	if (end > start) {
		ret = insert_hvaslot(slots, old_slots->used_slots, start, end - start);
		if (ret < 0)
			goto out_free;
	}

	rcu_assign_pointer(kvm->arch.dsm_hvaslots, slots);
	synchronize_srcu_expedited(&kvm->srcu);
	kvfree(old_slots);
	return 0;

out_free:
	kvfree(slots);
	return ret;
}

/* This should happen before the new memslot is added to kvm_memslots */
int kvm_dsm_add_memslot(struct kvm *kvm, struct kvm_memory_slot *slot,
		int as_id)
{
	struct kvm_dsm_memslots *slots;
	struct kvm_dsm_memory_slot *hvaslot, *new_hvaslot;
	unsigned long npages;
	gfn_t gfn, gfn_end, gfn_iter;
	hfn_t vfn;
	int ret = 0, i, iter_idx;
	bool flag;

	gfn_end = slot->base_gfn + slot->npages;
	slots = __kvm_hvaslots(kvm);
	for (gfn = slot->base_gfn; gfn < gfn_end; gfn += npages) {
		flag = false;
		npages = 1;
		for (i = 0; i < slots->used_slots; i++) {
			hvaslot = &slots->memslots[i];
			iter_idx = 0;
			while (iter_idx >= 0) {
				bool is_smm;
				// 找到base_vfn对应的gfn（别名gfn_iter）
				gfn_iter = __kvm_dsm_vfn_to_gfn(hvaslot, true, hvaslot->base_vfn,
						&is_smm, &iter_idx);
				// 找到了这个gfn对应的hvaslot
				if (!!is_smm == !!as_id && gfn_iter <= gfn && gfn_iter +
						hvaslot->npages > gfn) {
					flag = true;
					break;
				}
			}
			if (flag)
				break;
		}

		if (!flag)
			continue;

		vfn = __gfn_to_vfn_memslot(slot, gfn);
		
		new_hvaslot = gfn_to_hvaslot(kvm, slot, gfn);
		if (new_hvaslot == hvaslot)
			continue;
		npages = min(gfn_end - gfn, min(hvaslot->npages - (gfn - gfn_iter),
					new_hvaslot->npages - (vfn - new_hvaslot->base_vfn)));
		/* Retreive dsm state from backup in case of gfn->vfn mapping changes. */
		for (i = 0; i < npages; i++) {
			new_hvaslot->vfn_dsm_state[i + (vfn - new_hvaslot->base_vfn)].state
				= hvaslot->vfn_dsm_state[i + (gfn - gfn_iter)].state;
#ifdef IVY_KVM_DSM
			memcpy(new_hvaslot->vfn_dsm_state[i + (vfn -
					new_hvaslot->base_vfn)].copyset,
					hvaslot->vfn_dsm_state[i + (gfn - gfn_iter)].copyset,
					sizeof(copyset_t));
#endif
		}
		kvm_dsm_rmap_remove(kvm, hvaslot, true, (gfn << 1) | GFN_PRESENT_MASK |
				(as_id ? GFN_SMM_MASK : 0), hvaslot->base_vfn + (gfn -
				gfn_iter), npages);
	}

	for (gfn = slot->base_gfn; gfn < gfn_end; gfn += npages) {
		vfn = __gfn_to_vfn_memslot(slot, gfn);
		hvaslot = gfn_to_hvaslot(kvm, slot, gfn);
		/* ignore private memslots, they have no corresponding hvaslots */
		if (!hvaslot)
			return 0;
		npages = min(gfn_end - gfn, hvaslot->base_vfn + hvaslot->npages - vfn);
		ret = kvm_dsm_rmap_add(kvm, hvaslot, false, (gfn << 1) | GFN_PRESENT_MASK |
				(as_id ? GFN_SMM_MASK : 0), vfn, npages);
		if (ret < 0)
			goto out_free;
	}
	return ret;

out_free:
	gfn_end = gfn;
	for (gfn = slot->base_gfn; gfn < gfn_end; gfn += npages) {
		vfn = __gfn_to_vfn_memslot(slot, gfn);
		hvaslot = gfn_to_hvaslot(kvm, slot, gfn);
		npages = min(gfn_end - gfn, hvaslot->base_vfn + hvaslot->npages - vfn);
		kvm_dsm_rmap_remove(kvm, hvaslot, false, (gfn << 1) | GFN_PRESENT_MASK |
				(as_id ? GFN_SMM_MASK : 0), vfn, npages);
	}
	return ret;
}

/* This should happen after the old memslot is marked invalid in kvm_memslots */
void kvm_dsm_remove_memslot(struct kvm *kvm, struct kvm_memory_slot *slot)
{
	struct kvm_memslots *memslots;
	struct kvm_memory_slot *memslot;
	struct kvm_dsm_memory_slot *hvaslot;
	unsigned long npages;
	gfn_t gfn, gfn_end;
	hfn_t vfn;
	int i;

	/*
	 * The slot passed in is exactly the memory slot marked invalid in the
	 * current kvm_memslots, so we can find if the slot is in smm space.
	 *
	 * XXX: Or maybe we can use KVM_MEMSLOT_INVALID as the indicator of the
	 * matching memslot, as there should be only one slot that is invalid at a
	 * given time.
	 */
	for (i = 0; i < KVM_ADDRESS_SPACE_NUM; i++) {
		int bkt;
		memslots = __kvm_memslots(kvm, i);
		kvm_for_each_memslot(memslot, bkt, memslots) {
			if (memslot == slot)
				goto out;
		}
	}
out:
	if (i == KVM_ADDRESS_SPACE_NUM) {
		return;
	}

	gfn_end = slot->base_gfn + slot->npages;
	for (gfn = slot->base_gfn; gfn < gfn_end; gfn += npages) {
		vfn = __gfn_to_vfn_memslot(slot, gfn);
		hvaslot = gfn_to_hvaslot(kvm, slot, gfn);
		/* ignore private memslots, they have no corresponding hvaslots */
		if (!hvaslot)
			return;
		npages = min(gfn_end - gfn, hvaslot->base_vfn + hvaslot->npages - vfn);
		kvm_dsm_rmap_remove(kvm, hvaslot, false, (gfn << 1) | GFN_PRESENT_MASK |
				(i ? GFN_SMM_MASK : 0), vfn, npages);
		/* Backup dsm state. */
		kvm_dsm_rmap_add(kvm, hvaslot, true, (gfn << 1) | GFN_PRESENT_MASK |
				(i ? GFN_SMM_MASK : 0), vfn, npages);
	}
}

/*
 * Should be called inside kvm->srcu or kvm->slots_lock, and paired with
 * kvm_dsm_release_page.
 */
static int __kvm_dsm_acquire_page(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn, bool is_smm, bool write)
{
	struct kvm_dsm_memory_slot *hvaslot;
	hfn_t vfn;
	int dsm_access;

	if (WARN_ON(kvm->mm != current->mm))
		return -EINVAL;
	if (!kvm->arch.dsm_enabled)
		return ACC_ALL;

	/*
	 * We should ignore private memslots since they are not really visible
	 * to guest and thus are not part of guest state that should be
	 * distributedly shared.
	 */
	if (!slot || slot->id >= KVM_USER_MEM_SLOTS ||
			slot->flags & KVM_MEMSLOT_INVALID)
		return ACC_ALL;

	vfn = __gfn_to_vfn_memslot(slot, gfn);

	hvaslot = gfn_to_hvaslot(kvm, slot, gfn);
	if (!hvaslot)
		return ACC_ALL;

	dsm_lock(kvm, hvaslot, vfn);
	dsm_access = kvm_dsm_page_fault(kvm, slot, gfn, is_smm, write);
	if (dsm_access < 0) {
		dsm_debug_v("dsm_access < 0\n");
		dsm_unlock(kvm, hvaslot, vfn);
	}
	return dsm_access;
}

int kvm_dsm_vcpu_acquire_page(struct kvm_vcpu *vcpu,
		struct kvm_memory_slot **slot, gfn_t gfn, bool write)
{
	struct kvm_memory_slot *memslot;
	memslot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);
	if (slot)
		*slot = memslot;

	int ret =  __kvm_dsm_acquire_page(vcpu->kvm, memslot,
			gfn, is_smm(vcpu), write);

	return ret;
}

/*
 * Should be called inside kvm->srcu or kvm->slots_lock, and paired with
 * kvm_dsm_acquire_page.
 */
void kvm_dsm_release_page(struct kvm *kvm, struct kvm_memory_slot *slot,
		gfn_t gfn)
{
	struct kvm_dsm_memory_slot *hvaslot;
	hfn_t vfn;

	if(WARN_ON(kvm->mm != current->mm))
	{
		return;
	}

	if (!kvm->arch.dsm_enabled || !slot || slot->id >= KVM_USER_MEM_SLOTS ||
					slot->flags & KVM_MEMSLOT_INVALID)
	{
		return;
	}

	vfn = __gfn_to_vfn_memslot(slot, gfn);

	hvaslot = gfn_to_hvaslot(kvm, slot, gfn);
	if (!hvaslot){
		return;
	}

	dsm_unlock_fast_path(hvaslot, vfn, false);
	dsm_unlock(kvm, hvaslot, vfn);
}

void kvm_dsm_vcpu_release_page(struct kvm_vcpu *vcpu,
		struct kvm_memory_slot *slot, gfn_t gfn)
{
	kvm_dsm_release_page(vcpu->kvm, slot, gfn);
}

int kvm_dsm_acquire(struct kvm *kvm, struct kvm_memslots **slots, gpa_t gpa,
		unsigned long len, bool write)
{
	struct kvm_memslots *memslots;
	struct kvm_memory_slot *slot;
	gfn_t gfn, gfn_end = (gpa + len - 1) >> PAGE_SHIFT;
	int ret = ACC_ALL;

	memslots = __kvm_memslots(kvm, 0);
	if (slots)
		*slots = memslots;

	for (gfn = gpa >> PAGE_SHIFT; gfn <= gfn_end; gfn++) {
		slot = __gfn_to_memslot(memslots, gfn);
		ret = __kvm_dsm_acquire_page(kvm, slot, gfn, 0, write);
		if (ret < 0)
			goto out_release;
	}

	return ret;

out_release:
	pr_err("%s failed\n", __func__);

	while (--gfn >= (gpa >> PAGE_SHIFT)) {
		slot = __gfn_to_memslot(memslots, gfn);
		kvm_dsm_release_page(kvm, slot, gfn);
	}
	return ret;
}

int kvm_dsm_vcpu_acquire(struct kvm_vcpu *vcpu, struct kvm_memslots **slots,
		gpa_t gpa, unsigned long len, bool write)
{
	struct kvm_memslots *memslots;
	struct kvm_memory_slot *slot;
	gfn_t gfn, gfn_end = (gpa + len - 1) >> PAGE_SHIFT;
	int ret = ACC_ALL;

	memslots = kvm_vcpu_memslots(vcpu);
	if (slots)
		*slots = memslots;
	for (gfn = gpa >> PAGE_SHIFT; gfn <= gfn_end; gfn++) {
		slot = __gfn_to_memslot(memslots, gfn);
		ret = __kvm_dsm_acquire_page(vcpu->kvm, slot,
				gfn, is_smm(vcpu), write);
		if (ret < 0)
			goto out_release;
	}
	return ret;

out_release:
	pr_err("%s failed\n", __func__);
	while (--gfn >= (gpa >> PAGE_SHIFT)) {
		slot = __gfn_to_memslot(memslots, gfn);
		kvm_dsm_vcpu_release_page(vcpu, slot, gfn);
	}
	return ret;
}

void kvm_dsm_release(struct kvm *kvm, struct kvm_memslots *slots, gpa_t gpa,
		unsigned long len)
{
	struct kvm_memory_slot *slot;
	gfn_t gfn, gfn_end = (gpa + len - 1) >> PAGE_SHIFT;

	BUG_ON(!slots);
	for (gfn = gpa >> PAGE_SHIFT; gfn <= gfn_end; gfn++) {
		slot = __gfn_to_memslot(slots, gfn);
		kvm_dsm_release_page(kvm, slot, gfn);
	}
}

void kvm_dsm_vcpu_release(struct kvm_vcpu *vcpu, struct kvm_memslots *slots,
		gpa_t gpa, unsigned long len)
{
	struct kvm_memory_slot *slot;
	gfn_t gfn, gfn_end = (gpa + len - 1) >> PAGE_SHIFT;

	BUG_ON(!slots);
	for (gfn = gpa >> PAGE_SHIFT; gfn <= gfn_end; gfn++) {
		slot = __gfn_to_memslot(slots, gfn);
		kvm_dsm_vcpu_release_page(vcpu, slot, gfn);
	}
}

/* DSM server functions entry. */
static int kvm_dsm_handle_req(void *data)
{
#ifdef IVY_KVM_DSM
	return ivy_kvm_dsm_handle_req(data);
#endif
}

static int kvm_dsm_threadfn(void *data)
{
	dsm_debug_v("enter kvm_dsm_threadfn\n");
	int ret;

	kconnection_t *listen_sock = NULL;
	kconnection_t *accept_sock = NULL;
	struct dsm_address addr;
	struct dsm_conn *conn;
	struct list_head conn_list;
	struct task_struct *thread;
	int i, count;
	char comm[TASK_COMM_LEN];

	struct kvm *kvm = (struct kvm *)data;
	dsm_debug_v("kvm[%d] enter kvm_dsm_threadfn\n", kvm->arch.dsm_id);

	allow_signal(SIGKILL);
	INIT_LIST_HEAD(&conn_list);
	dsm_debug_v("kvm[%d] after INIT_LIST_HEAD\n", kvm->arch.dsm_id);

	// 根据dsm_id和cluster_iplist设置addr的host ip
	ret = get_dsm_address(kvm, kvm->arch.dsm_id, &addr);
	if (ret < 0) {
		return ret;
	}
	dsm_debug_v("kvm[%d] before listen on %s:%s\n",  kvm->arch.dsm_id, addr.host, addr.port);
	// 监听等待连接
	ret = network_ops.listen(addr.host, addr.port, &listen_sock);
	if (ret < 0) {
		return ret;
	}

	dsm_debug_v("kvm[%d] started dsm server on %s:%s\n", kvm->arch.dsm_id,
			addr.host, addr.port);

	count = 0;
	while (1) {
		if (kthread_should_stop()) {
			ret = 0;
			goto out_listen_sock;
		}

		ret = network_ops.accept(listen_sock, &accept_sock, 0);
		if (ret < 0) {
			/* We only exit with -ERESTARTSYS when the kthread should stop. */
			if (ret == -ERESTARTSYS)
				ret = 0;
			goto out_listen_sock;
		}

		conn = kmalloc(sizeof(struct dsm_conn), GFP_KERNEL);
		if (conn == NULL) {
			ret = -ENOMEM;
			goto out_accept_sock;
		}
		printk(KERN_INFO "kvm-dsm: node-%d accepted connection\n", kvm->arch.dsm_id);
		conn->kvm = kvm;
		conn->sock = accept_sock;

		// 开启NDSM_CONN_THREADS个线程处理kvm_dsm_handle,执行write、read、invalid等操作
		for (i = 0; i < 1; i++) {
			/*
			 * The count is somewhat meaningless since it doesn't contain
			 * information about which remote node it connects to.
			 */
			thread = kthread_run(kvm_dsm_handle_req, (void*)conn, "dsm-conn/%d:%d",
					kvm->arch.dsm_id, count++);
			if (IS_ERR(thread)) {
				printk(KERN_ERR "kvm-dsm: failed to start kernel thread for dsm connection\n");
				ret = PTR_ERR(thread);
				goto out_accept_sock;
			}
			conn->threads[i] = thread;
		}
		list_add_tail(&conn->link, &conn_list);
	}

out_accept_sock:
	network_ops.release(accept_sock);
out_listen_sock:

	for (i = 0; i < DSM_MAX_INSTANCES*SOCKS_PER_INSTANCE; i++) {
		if (kvm->arch.dsm_conn_socks[i]) {
			network_ops.release(kvm->arch.dsm_conn_socks[i]);
		}
		if (kvm->arch.dsm_conn_socks[DSM_MAX_INSTANCES*SOCKS_PER_INSTANCE + i]) {
			network_ops.release(kvm->arch.dsm_conn_socks[DSM_MAX_INSTANCES*SOCKS_PER_INSTANCE + i]);
		}
	}
	kfree(kvm->arch.dsm_conn_socks);

	while (!list_empty(&conn_list)) {
		conn = list_first_entry(&conn_list, struct dsm_conn, link);
		list_del(&conn->link);
		for (i = 0; i < NDSM_CONN_THREADS; i++) {
			get_task_comm(comm, conn->threads[i]);
			send_sig(SIGKILL, conn->threads[i], 1);
			ret = kthread_stop(conn->threads[i]);
			dsm_debug("kvm[%d] dsm connection thread %s exited with %d",
					kvm->arch.dsm_id, comm, ret);
		}
		network_ops.release(conn->sock);
		kfree(conn);
	}

	network_ops.release(listen_sock);

	return ret;
}

static int kvm_dsm_init(struct kvm *kvm, struct kvm_dsm_params *params)
{
	int ret = 0;
	struct task_struct *thread;
	int i;
	char **user_cluster_iplist;

	if (params->dsm_id >= DSM_MAX_INSTANCES)
		return -EINVAL;

	// 代表是否已经进行初始化
	if (kvm->arch.dsm_enabled)
		return ret;

	dsm_debug("Enable kvm dsm mode, this kvm instance will be node-%u\n",
			params->dsm_id);

	/* Deep copy cluster_iplist from user space. */
	kvm->arch.cluster_iplist_len = params->cluster_iplist_len;
	kvm->arch.cluster_iplist = (char **)kzalloc(sizeof(void *) *
			params->cluster_iplist_len, GFP_KERNEL);
	if (!kvm->arch.cluster_iplist)
		return -ENOMEM;
	user_cluster_iplist = (char **)kzalloc(sizeof(void *) *
			params->cluster_iplist_len, GFP_KERNEL);
	if (!user_cluster_iplist) {
		ret = -ENOMEM;
		goto out_free_cluster_iplist;
	}
	int failed_cnt = copy_from_user(user_cluster_iplist, params->cluster_iplist, sizeof(void *) *
			params->cluster_iplist_len);
	if(failed_cnt)
		printk(KERN_ERR "%s: copy_from_user failed.\n",__func__);
	for (i = 0; i < params->cluster_iplist_len; i++) {
		kvm->arch.cluster_iplist[i] = (char *)kmalloc(20, GFP_KERNEL);
		if (!kvm->arch.cluster_iplist[i]) {
			ret = -ENOMEM;
			goto out_free_cluster_iplist;
		}
		int copyed_cnt = strncpy_from_user(kvm->arch.cluster_iplist[i], user_cluster_iplist[i], 20);
		if(copyed_cnt<0){
			printk(KERN_ERR "%s: strncpy_from_user failed.\n",__func__);
		}
	}

	mutex_init(&kvm->arch.conn_init_lock);

#ifdef USE_KTCP_NETWORK
	network_ops.send = ktcp_send;
	network_ops.receive = ktcp_receive;
	network_ops.connect = ktcp_connect;
	network_ops.listen = ktcp_listen;
	network_ops.accept = ktcp_accept;
	network_ops.release = ktcp_release;
	dsm_debug("%s: kvm %d use TCP connection\n", __func__, params->dsm_id);
#endif

#ifdef USE_KRDMA_NETWORK
	// network_ops.send = krdma_send;
	// network_ops.receive = krdma_receive;
	// network_ops.connect = krdma_connect;
	// network_ops.listen = krdma_listen;
	// network_ops.accept = krdma_accept;
	// network_ops.release = krdma_release;
	dsm_debug("ERROR: %s: kvm %d use RDMA connection\n", __func__, params->dsm_id);
#endif

	kvm->arch.dsm_conn_socks = kzalloc(DSM_MAX_INSTANCES * SOCKS_PER_INSTANCE * 2 *
			sizeof(kconnection_t *), GFP_KERNEL);
	if (kvm->arch.dsm_conn_socks == NULL) {
		return -ENOMEM;
	}

	kvm->arch.dsm_enabled = true;
	kvm->arch.dsm_id = params->dsm_id;
	dsm_debug("%s: kvm %d before kthread_run\n", __func__, params->dsm_id);
	dsm_debug_v("before enter kvm_dsm_threadfn\n");
	thread = kthread_run(kvm_dsm_threadfn, (void*)kvm, "kvm-dsm/%d",
			kvm->arch.dsm_id);
	if (IS_ERR(thread)) {
		printk(KERN_ERR "kvm-dsm: failed to start kernel thread for dsm server\n");
		ret = PTR_ERR(thread);
		goto out;
	}
	kvm->arch.dsm_thread = thread;
	return ret;

out:
	kfree(kvm->arch.dsm_conn_socks);
	kvm->arch.dsm_enabled = false;
	return ret;
out_free_cluster_iplist:
	for (i = 0; i < params->cluster_iplist_len; i++)
		kfree(kvm->arch.cluster_iplist[i]);
	kfree(kvm->arch.cluster_iplist);
	kfree(user_cluster_iplist);
	return ret;
}

int kvm_dsm_alloc(struct kvm *kvm)
{
	mutex_init(&kvm->arch.dsm_lock);
	/* TODO: number of nodes is not set in this moment. */
	kvm->arch.dsm_hvaslots = kvm_kvzalloc(sizeof(struct kvm_dsm_memslots));
	if (!kvm->arch.dsm_hvaslots)
		return -ENOMEM;

	return 0;
}

void kvm_dsm_free(struct kvm *kvm)
{
	int ret, i;
	struct kvm_dsm_memslots *slots;

	if (kvm->arch.dsm_enabled && kvm->arch.dsm_thread != NULL) {
		printk(KERN_INFO "kvm-dsm: node-%d stopping dsm server\n", kvm->arch.dsm_id);
		kvm->arch.dsm_stopped = true;
		smp_mb();
		send_sig(SIGKILL, kvm->arch.dsm_thread, 1);
		ret = kthread_stop(kvm->arch.dsm_thread);
		if (ret < 0) {
			printk(KERN_ERR "%s: node-%d dsm root server exited with %d\n",
					__func__, kvm->arch.dsm_id, ret);
		}
		for (i = 0; i < kvm->arch.cluster_iplist_len; i ++)
			kfree(kvm->arch.cluster_iplist[i]);
		kfree(kvm->arch.cluster_iplist);
	}

	slots = kvm->arch.dsm_hvaslots;
	if (!slots)
		return;

	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++) {
#ifdef KVM_DSM_DIFF
		unsigned long j;
		for (j = 0; j < slots->memslots[i].npages; j++) {
			kfree(slots->memslots[i].vfn_dsm_state[j].diff.twin);
		}
#endif
		kvfree(slots->memslots[i].vfn_dsm_state);
		kvm_dsm_free_rmap(kvm, &slots->memslots[i]);
		kvfree(slots->memslots[i].rmap);
		kvfree(slots->memslots[i].backup_rmap);
		kvfree(slots->memslots[i].rmap_lock);
	}
	kvfree(slots);
}


// #define IVY_PAGE_FAULT_TIME

#ifdef IVY_PAGE_FAULT_TIME
static inline void save_pf_time_to_db(struct kvm *kvm, ktime_t diff)
{
	static atomic_t pf_cnt = ATOMIC_INIT(0);
	int r =  (int)atomic_add_return(1, &pf_cnt);
	struct kvm_dsm_debug_buffer dsm_db = dsm_db_list[kvm->arch.dsm_id];
	if(r*sizeof(ktime_t)<dsm_db.length){
		int ret = copy_to_user((ktime_t*)dsm_db.host_virt_addr+r, &diff, sizeof(ktime_t));
		if(ret){
			printk(KERN_ERR "kvm-dsm: copy_to_user %d bytes not copied\n", ret);
		}
	}else{
		printk(KERN_ERR "kvm-dsm: pf_cnt %u is larger than dsm_db.length %lld\n", r, dsm_db.length);
	}
}
#endif

static int kvm_dsm_page_fault(struct kvm *kvm, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write)
{
	int ret;

#ifdef IVY_PAGE_FAULT_TIME
	ktime_t start, diff;
	start = ktime_get();
#endif

#ifdef IVY_KVM_DSM
	ret = ivy_kvm_dsm_page_fault(kvm, memslot, gfn, is_smm, write);
#endif

#ifdef IVY_PAGE_FAULT_TIME
	diff = ktime_sub(ktime_get(), start);
	save_pf_time_to_db(kvm, diff);
#endif
	return ret;
}

int kvm_dsm_memcpy(struct kvm *kvm, unsigned long host_virt_addr,
		unsigned long userspace_addr, unsigned long length, bool write)
{
	struct kvm_dsm_memory_slot *slot;
	struct kvm_memory_slot *memslot;
	hfn_t vfn, vfn_end;
	gfn_t gfn;
	bool is_smm;
	unsigned long npages, gfn_npages, i, j;
	unsigned long hva_start, hva_end, l;
	void *user_buf;
	int idx, ret = 0;

	if (current->mm != kvm->mm)
		return -EFAULT;
	if (!kvm->arch.dsm_enabled)
		return -EINVAL;

	dsm_debug_v("hva %lx, length %lu, write %d\n", host_virt_addr, length, write);
	idx = srcu_read_lock(&kvm->srcu);

	vfn_end = ((host_virt_addr + length - 1) >> PAGE_SHIFT) + 1;
	for (vfn = host_virt_addr >> PAGE_SHIFT; vfn < vfn_end; vfn += npages) {
		slot = vfn_to_hvaslot(kvm, vfn);
		/* for private memslots, do memcpy directly without DSM fetching */
		dsm_debug_v("hva %lx, vfn: %llx, slot: %p\n", host_virt_addr, vfn, slot);
		if (!slot) {
			npages = 1;
			goto do_memcpy;
		}
		npages = min(vfn_end - vfn, slot->base_vfn + slot->npages - vfn);

		mutex_lock(&kvm->arch.dsm_lock);
		for (i = 0; i < npages; i++) {
			dsm_lock(kvm, slot, vfn + i);
		}

		for (i = 0; i < npages; i += gfn_npages) {
			gfn = __kvm_dsm_vfn_to_gfn(slot, false, vfn + i, &is_smm, NULL);
			memslot = __gfn_to_memslot(__kvm_memslots(kvm, is_smm), gfn);
			gfn_npages = min(npages - i, (unsigned long)(memslot->base_gfn +
						memslot->npages - gfn));
			for (j = 0; j < gfn_npages; j++) {
				ret = kvm_dsm_page_fault(kvm, memslot, gfn + j, is_smm, write);
				if (ret < 0){
					pr_err("kvm_dsm_page_fault failed\n");
					goto out_unlock;
				}
			}
		}

do_memcpy:
		hva_start = max(host_virt_addr, (unsigned long)(vfn << PAGE_SHIFT));
		user_buf = (void *)(userspace_addr + hva_start - host_virt_addr);
		if (slot) {
			hva_end = min(host_virt_addr + length, (unsigned long)
					(slot->base_vfn + slot->npages) << PAGE_SHIFT);
		} else {
			hva_end = min(host_virt_addr + length, (unsigned long)
					(vfn + 1) << PAGE_SHIFT);
		}
		/* This is actually an user-to-user memcpy, but as we are sure that
		 * hva is valid, we can treat it as kernel memory. */
		l = hva_end - hva_start;
		if (write)
			ret = __copy_from_user((void *)hva_start, user_buf, l);
		else
			ret = __copy_to_user(user_buf, (void *)hva_start, l);
		dsm_debug_v("hva_start %lx, user_buf %p, l %lx\n", hva_start, user_buf, l);
		if (!slot)
			continue;

out_unlock:
		for (i = 0; i < npages; i++) {
			dsm_unlock_fast_path(slot, vfn + i, false);
			dsm_unlock(kvm, slot, vfn + i);
		}
		mutex_unlock(&kvm->arch.dsm_lock);
		if (ret < 0)
			goto out;
	}
out:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}


int kvm_dsm_mempin(struct kvm *kvm, unsigned long host_virt_addr,
		unsigned long length, bool write, bool unpin)
{
	struct kvm_dsm_memory_slot *slot;
	struct kvm_memory_slot *memslot;
	hfn_t vfn, vfn_end;
	gfn_t gfn;
	bool is_smm;
	unsigned long npages, gfn_npages, i, j;
	int idx, ret = 0;

	if (current->mm != kvm->mm)
		return -EFAULT;
	if (!kvm->arch.dsm_enabled)
		return -EINVAL;

	dsm_debug_v("hva %lx, length %lu, write %d unpin %d\n", host_virt_addr, length, write, unpin);
	idx = srcu_read_lock(&kvm->srcu);

	vfn_end = ((host_virt_addr + length - 1) >> PAGE_SHIFT) + 1;
	for (vfn = host_virt_addr >> PAGE_SHIFT; vfn < vfn_end; vfn += npages) {
		slot = vfn_to_hvaslot(kvm, vfn);
		/* ignore private memslots, they have no corresponding hvaslots */
		if (!slot) {
			npages = 1;
			continue;
		}
		npages = min(vfn_end - vfn, slot->base_vfn + slot->npages - vfn);

		mutex_lock(&kvm->arch.dsm_lock);
		for (i = 0; i < npages; i++) {
			dsm_lock(kvm, slot, vfn + i);
		}

		if (unpin) {
			for (i = 0; i < npages; i++) {
				dsm_unpin(slot, vfn + i, write);
			}
			goto out_unlock;
		}

		for (i = 0; i < npages; i += gfn_npages) {
			gfn = __kvm_dsm_vfn_to_gfn(slot, false, vfn + i, &is_smm, NULL);
			memslot = __gfn_to_memslot(__kvm_memslots(kvm, is_smm), gfn);
			gfn_npages = min(npages - i, (unsigned long)(memslot->base_gfn +
						memslot->npages - gfn));
			for (j = 0; j < gfn_npages; j++) {
				ret = kvm_dsm_page_fault(kvm, memslot, gfn + j, is_smm, write);
				if (ret < 0){
					pr_err("kvm_dsm_page_fault failed\n");
					goto out_unlock;
				}
			}
		}

		for (i = 0; i < npages; i++) {
			dsm_pin(slot, vfn + i, write);
		}

out_unlock:
		for (i = 0; i < npages; i++) {
			dsm_unlock_fast_path(slot, vfn + i, false);
			dsm_unlock(kvm, slot, vfn + i);
		}
		mutex_unlock(&kvm->arch.dsm_lock);
		if (ret < 0)
			goto out;
	}
out:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}


long kvm_vm_ioctl_dsm(struct kvm *kvm, unsigned ioctl,
				  unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int r;

	switch (ioctl) {
	case KVM_DSM_ENABLE: {
		struct kvm_dsm_params params;
		r = -EFAULT;
		if (copy_from_user(&params, argp, sizeof(params)))
			goto out;

		/* TODO: It would be better to ensure DSM mode is enabled before the VM
		 * is started, not sure how this can be done properly, maybe using the
		 * following code?
		 *
		 * r = -EINVAL;
		 * if (kvm->created_vcpus)
		 *     goto out;
		 */
		r = kvm_dsm_init(kvm, &params);
		if (r)
			goto out;
		break;
	}
	case KVM_DSM_MEMCPY: {
		struct kvm_dsm_memcpy cpy;
		r = -EFAULT;
		if (copy_from_user(&cpy, argp, sizeof(cpy)))
			goto out;
		r = kvm_dsm_memcpy(kvm, cpy.host_virt_addr, cpy.userspace_addr,
				cpy.length, cpy.write);
		if (r)
			goto out;
		break;
	}
	case KVM_DSM_MEMPIN: {
		r=0;
		struct kvm_dsm_mempin pin;
		r = -EFAULT;
		if (copy_from_user(&pin, argp, sizeof(pin)))
			goto out;
		r = kvm_dsm_mempin(kvm, pin.host_virt_addr, pin.length, pin.write,
				pin.unpin);
		if (r)
			goto out;
		break;
	}
	case KVM_DSM_DEBUG_BUFFER: {
		pr_info("KVM_DSM_DEBUG_BUFFER 1\n");
		if (copy_from_user(&dsm_db_list[kvm->arch.dsm_id], argp, sizeof(dsm_db_list[kvm->arch.dsm_id])))
			goto out;
		// dsm_db.host_virt_addr = addr_to_kaddr(current->mm, dsm_db.host_virt_addr, dsm_db.length);
		pr_info("KVM_DSM_DEBUG_BUFFER 2\n");
		break;
	}
	default:
		r = -ENOTTY;
		break;
	}
out:
	return r;
}
