#ifndef ARCH_X86_KVM_DSM_UTIL_H
#define ARCH_X86_KVM_DSM_UTIL_H

#include <linux/kvm_host.h>
#include <linux/jhash.h>
#include <linux/kvm_types.h>

#define DSM_INITIAL     0
#define DSM_INVALID     1
#define DSM_SHARED      2
#define DSM_MODIFIED    3

#define DSM_OWNER       (1 << 2)

#define DSM_STATE_SHIFT     16
#define DSM_STATE_MASK      ((1 << DSM_STATE_SHIFT) - 1)
#define DSM_MSI_STATE_MASK  3

#define GFN_PRESENT_MASK    (1ULL << 63)
#define GFN_SMM_MASK        (1ULL << 62)

#ifdef KVM_DSM_DEBUG
extern bool kvm_dsm_dbg_verbose;
#define dsm_debug(fmt, ...) printk(KERN_DEBUG "%s: " fmt,		\
		__func__, ##__VA_ARGS__)
#define dsm_debug_v(fmt, ...) do {					\
		if (kvm_dsm_dbg_verbose) printk(KERN_DEBUG "%s: " fmt,	\
		__func__, ##__VA_ARGS__); } while (0)
#else
#define dsm_debug(fmt, ...) no_printk(KERN_DEBUG "%s: " fmt,		\
		__func__, ##__VA_ARGS__)
#define dsm_debug_v(fmt, ...) no_printk(KERN_DEBUG "%s: " fmt,		\
		__func__, ##__VA_ARGS__)
#endif

#define dsm_debug_tidy(fmt, ...) printk(KERN_DEBUG "%s[%d]:%d " fmt,           \
               __func__, kvm->arch.dsm_id, __LINE__, ##__VA_ARGS__)

#ifdef KVM_KTCP_DEBUG
#define dsm_debug_ktcp(fmt, ...) printk(KERN_DEBUG "%s: " fmt,		\
		__func__, ##__VA_ARGS__)
#else
#define dsm_debug_ktcp(fmt, ...) no_printk(KERN_DEBUG "%s: " fmt,		\
		__func__, ##__VA_ARGS__)
#endif

#define ACC_EXEC_MASK    1
#define ACC_WRITE_MASK   PT_WRITABLE_MASK
#define ACC_USER_MASK    PT_USER_MASK
#define ACC_ALL          (ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)

// #define DSM_TRANSFER_PAGE

#define FLUSH_PAGE_SIZE (4 * 1024)
#ifdef DSM_TRANSFER_PAGE
#define PAGE_SIZE_TRANSFER (4*1024)
#else
#define PAGE_SIZE_TRANSFER (1)
#endif
struct kvm_network_ops {
	int (*send)(kconnection_t *, const char *, size_t, unsigned long,
			const tx_add_t*);
	int (*receive)(kconnection_t *, char *, unsigned long, tx_add_t*);
	int (*connect)(const char *, const char *, kconnection_t **);
	int (*listen)(const char *, const char *, kconnection_t **);
	int (*accept)(kconnection_t *, kconnection_t **, unsigned long);
	int (*release)(kconnection_t *);
};

extern struct kvm_network_ops network_ops;

struct dsm_address {
	const char *host;
	char port[8];
};

#define NDSM_CONN_THREADS 8
struct dsm_conn {
	struct list_head link;
	struct kvm *kvm;
	kconnection_t *sock;
	struct task_struct *threads[NDSM_CONN_THREADS];
};

struct PageDebugDSM{
	unsigned hash;
	gfn_t gfn;
	kvm_pfn_t pfn;
	uint16_t txid;
};

/* mmu.c */
extern int kvm_dsm_rmap_add(struct kvm *kvm, struct kvm_dsm_memory_slot *slot, bool backup,
		gfn_t gfn, hfn_t vfn, unsigned long npages);
extern void kvm_dsm_rmap_remove(struct kvm *kvm, struct kvm_dsm_memory_slot *slot, bool backup,
		gfn_t gfn, hfn_t vfn, unsigned long npages);
extern void kvm_dsm_free_rmap(struct kvm *kvm, struct kvm_dsm_memory_slot *slot);
extern gfn_t __kvm_dsm_vfn_to_gfn(struct kvm_dsm_memory_slot *slot, bool backup,
		hfn_t vfn, bool *is_smm, int *iter_idx);
extern void kvm_dsm_apply_access_right(struct kvm *kvm,
		struct kvm_dsm_memory_slot *slot, hfn_t vfn, unsigned long dsm_access, gfn_t gfn_to_flush);

static inline uint16_t generate_txid(struct kvm *kvm, uint16_t dest_id)
{
	/* TODO: currently only 4 nodes are supported here. */
	static atomic_t id[44] = { ATOMIC_INIT(0) };

	uint16_t r = 0;
	do {
		r =  (uint16_t)atomic_add_return(1, &id[kvm->arch.dsm_id * 10 + dest_id]);
	} while (r == 0xFF);

	return r;
}

static inline struct kvm_dsm_memslots *__kvm_hvaslots(struct kvm *kvm)
{
	return rcu_dereference_check(kvm->arch.dsm_hvaslots,
			srcu_read_lock_held(&kvm->srcu)
			|| lockdep_is_held(&kvm->slots_lock));
}

static inline hfn_t __gfn_to_vfn_memslot(struct kvm_memory_slot *slot, gfn_t gfn)
{
	// TODO 这里不能直接PAGE_SHIFT，没有考虑大页
	// 需要像page fault中一样，根据level得到PAGE_SHIFT的大小
	return (slot->userspace_addr >> PAGE_SHIFT) + (gfn - slot->base_gfn);
}
static inline struct kvm_dsm_memory_slot *
search_hvaslots(struct kvm_dsm_memslots *slots, hfn_t vfn)
{
	int start = 0, end = slots->used_slots - 1;
	int slot = atomic_read(&slots->lru_slot);
	struct kvm_dsm_memory_slot *memslots = slots->memslots;

	if (slots->used_slots == 0)
		return NULL;

	if (vfn >= memslots[slot].base_vfn &&
	    vfn < memslots[slot].base_vfn + memslots[slot].npages)
		return &memslots[slot];

	while (start < end) {
		slot = start + (end - start + 1) / 2;

		if (vfn >= memslots[slot].base_vfn)
			start = slot;
		else
			end = slot - 1;
	}

	if (vfn >= memslots[start].base_vfn &&
	    vfn < memslots[start].base_vfn + memslots[start].npages) {
		atomic_set(&slots->lru_slot, start);
		return &memslots[start];
	}

	return NULL;
}

static inline struct kvm_dsm_memory_slot *
gfn_to_hvaslot(struct kvm *kvm, struct kvm_memory_slot *slot, gfn_t gfn)
{
	return search_hvaslots(__kvm_hvaslots(kvm), __gfn_to_vfn_memslot(slot, gfn));
}

static inline struct kvm_dsm_memory_slot *
vfn_to_hvaslot(struct kvm *kvm, hfn_t vfn)
{
	return search_hvaslots(__kvm_hvaslots(kvm), vfn);
}

int get_dsm_address(struct kvm *kvm, int dsm_id, struct dsm_address *addr);
int dsm_create_memslot(struct kvm_dsm_memory_slot *slot,
		unsigned long npages);
int insert_hvaslot(struct kvm_dsm_memslots *slots, int pos, hfn_t start,
		unsigned long npages);

void dsm_lock(struct kvm *kvm, struct kvm_dsm_memory_slot *slot, hfn_t vfn);
void dsm_unlock(struct kvm *kvm, struct kvm_dsm_memory_slot *slot, hfn_t vfn);


static inline bool dsm_is_pinned(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	return slot->vfn_dsm_state[vfn - slot->base_vfn].pinned_read ||
		slot->vfn_dsm_state[vfn - slot->base_vfn].pinned_write;
}

static inline bool dsm_is_pinned_read(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	return slot->vfn_dsm_state[vfn - slot->base_vfn].pinned_read &&
		(slot->vfn_dsm_state[vfn - slot->base_vfn].pinned_write == 0);
}

static inline void dsm_pin(struct kvm_dsm_memory_slot *slot, hfn_t vfn, bool write)
{
	unsigned long index;

	index = vfn - slot->base_vfn;
	if (write) {
		slot->vfn_dsm_state[index].pinned_write++;
		WARN_ON(slot->vfn_dsm_state[index].pinned_write == 0);
	} else {
		slot->vfn_dsm_state[index].pinned_read++;
		WARN_ON(slot->vfn_dsm_state[index].pinned_read == 0);
	}
}

static inline void dsm_unpin(struct kvm_dsm_memory_slot *slot, hfn_t vfn, bool write)
{
	unsigned long index;

	index = vfn - slot->base_vfn;
	if (write)
		slot->vfn_dsm_state[index].pinned_write--;
	else
		slot->vfn_dsm_state[index].pinned_read--;
}

static inline bool dsm_is_initial(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	// 用state的前两位代表vfn的状态
	return (slot->vfn_dsm_state[vfn - slot->base_vfn].state &
			DSM_MSI_STATE_MASK) == DSM_INITIAL;
}

static inline bool dsm_is_readable(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	unsigned long val;

	val = slot->vfn_dsm_state[vfn - slot->base_vfn].state & DSM_MSI_STATE_MASK;
	return (val == DSM_SHARED) || (val == DSM_MODIFIED);
}

static inline bool dsm_is_modified(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	return (slot->vfn_dsm_state[vfn - slot->base_vfn].state &
			DSM_MSI_STATE_MASK) == DSM_MODIFIED;
}

static inline void dsm_change_state(struct kvm_dsm_memory_slot *slot, hfn_t vfn,
		unsigned state)
{
	dsm_debug("dsm_change_state(vfn=%lld state=%d)\n", vfn, state);
	unsigned owner = slot->vfn_dsm_state[vfn - slot->base_vfn].state >> DSM_STATE_SHIFT;
	slot->vfn_dsm_state[vfn - slot->base_vfn].state = (owner << DSM_STATE_SHIFT) | state;
}

static inline int dsm_get_prob_owner(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	return slot->vfn_dsm_state[vfn - slot->base_vfn].state >> DSM_STATE_SHIFT;
}

static inline void dsm_set_prob_owner(struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, int owner)
{
	unsigned state = slot->vfn_dsm_state[vfn - slot->base_vfn].state &
		DSM_STATE_MASK;
	slot->vfn_dsm_state[vfn - slot->base_vfn].state =
		(owner << DSM_STATE_SHIFT) | state;

}

static inline bool dsm_is_owner(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	return slot->vfn_dsm_state[vfn - slot->base_vfn].state & DSM_OWNER;
}

static inline version_t dsm_get_version(struct kvm_dsm_memory_slot *slot,
		hfn_t vfn)
{
#ifdef IVY_KVM_DSM
	return slot->vfn_dsm_state[vfn - slot->base_vfn].version;
#endif
}

static inline void dsm_incr_version(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
	/* dsm_lock should be held. */
#ifdef IVY_KVM_DSM
	slot->vfn_dsm_state[vfn - slot->base_vfn].version++;
#endif
}

static inline void dsm_set_version(struct kvm_dsm_memory_slot *slot, hfn_t vfn,
		version_t version)
{
#ifdef IVY_KVM_DSM
	/* dsm_lock should be held. */
	slot->vfn_dsm_state[vfn - slot->base_vfn].version = version;
#endif
}

int kvm_dsm_connect(struct kvm *kvm, int dest_id, kconnection_t **conn_sock);
int kvm_read_guest_page_nonlocal(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn,
		void *data, int offset, int len);
int kvm_write_guest_page_nonlocal(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn,
		const void *data, int offset, int len);

#ifdef KVM_KTCP_DEBUG
unsigned kvm_hash_guest_page_nonlocal(struct kvm *kvm,
		struct kvm_memory_slot *slot, gfn_t gfn, bool use_mm, struct PageDebugDSM *pdd);
#endif
/*
 * kvm_dsm_release_page must know whether a kvm_dsm_acquire_* is coped with fast
 * path. An alternative is to change the interfaces of these routines, which
 * pass a boolean value to kvm_dsm_release_page to indicate whether it should
 * release the fast_path lock.
 */
static inline void dsm_lock_fast_path(struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, bool is_server)
{
	mutex_lock(&slot->vfn_dsm_state[vfn - slot->base_vfn].fast_path_lock);
	if (!is_server) {
		/*
		 * Only one vCPU can modify this value hence here is no data race.
		 */
		slot->vfn_dsm_state[vfn - slot->base_vfn].fast_path_locked = true;
	}
}

static inline void dsm_unlock_fast_path(struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, bool is_server)
{
	if (!is_server && !slot->vfn_dsm_state[vfn -
			slot->base_vfn].fast_path_locked) {
		return;
	}
	mutex_unlock(&slot->vfn_dsm_state[vfn - slot->base_vfn].fast_path_lock);
	if (!is_server) {
		slot->vfn_dsm_state[vfn - slot->base_vfn].fast_path_locked = false;
	}
}

// #define IVY_PAGE_FAULT_TIME_NOTFAST
// #define IVY_PAGE_FAULT_TIME_INVD
// #define IVY_PAGE_FAULT_TIME_DSM_FETCH
// #define IVY_PAGE_FAULT_TIME_HANDLE_SEND
// #define IVY_PAGE_FAULT_TIME_HANDLE_REQ
// #define IVY_PAGE_FAULT_GFN_COUNT_TIME
// #define IVY_PAGE_FAULT_FLUSH_TIME
// #define IVY_PAGE_FAULT_PAGE_STATE_FLOW_TIME
// #define IVY_PAGE_FAULT_SEND_RECV_REQ_TIME

#if defined(IVY_PAGE_FAULT_TIME_NOTFAST)||defined(IVY_PAGE_FAULT_TIME_INVD)||defined(IVY_PAGE_FAULT_TIME_DSM_FETCH)||defined(IVY_PAGE_FAULT_TIME_HANDLE_SEND)||defined(IVY_PAGE_FAULT_TIME_HANDLE_REQ)||defined(IVY_PAGE_FAULT_GFN_COUNT_TIME) \
|| defined(IVY_PAGE_FAULT_FLUSH_TIME) || defined(IVY_PAGE_FAULT_PAGE_STATE_FLOW_TIME) \
|| defined(IVY_PAGE_FAULT_SEND_RECV_REQ_TIME)

extern struct kvm_dsm_debug_buffer dsm_db_list[2];

enum dsm_time_type {
	DSM_TIME_TYPE_NOTFAST_PF_READ,
	DSM_TIME_TYPE_NOTFAST_PF_WRITE,
	DSM_TIME_TYPE_INVD,
	DSM_TIME_TYPE_DSM_FETCH_INVD_SEND,
	DSM_TIME_TYPE_DSM_FETCH_READ_SEND,
	DSM_TIME_TYPE_DSM_FETCH_WRITE_SEND,
	DSM_TIME_TYPE_DSM_FETCH_INVD_RECV,
	DSM_TIME_TYPE_DSM_FETCH_READ_RECV,
	DSM_TIME_TYPE_DSM_FETCH_WRITE_RECV,
	DSM_TIME_TYPE_HANDLE_INVD_SEND,
	DSM_TIME_TYPE_HANDLE_READ_SEND,
	DSM_TIME_TYPE_HANDLE_WRITE_SEND,
	DSM_TIME_TYPE_HANDLE_REQ,
	DSM_TIME_TYPE_FLUSH_LOCAL,
	DSM_TIME_TYPE_FLUSH_REMOTE,
	DSM_TIME_TYPE_PAGE_STATE_FLOW,
	DSM_TIME_TYPE_SEND_RECV_REQ,
};


static inline void save_pf_time_to_db(struct kvm *kvm, ktime_t diff, enum dsm_time_type dtt, bool is_local)
{
	static atomic_t pf_cnt_list[] = {ATOMIC_INIT(0), ATOMIC_INIT(0)};
	int r =  (int)atomic_add_return(1, &pf_cnt_list[kvm->arch.dsm_id]);
	struct kvm_dsm_debug_buffer dsm_db = dsm_db_list[kvm->arch.dsm_id];
	diff |= (((unsigned long)dtt)<<50);
	if(r*sizeof(ktime_t)<dsm_db.length){
		if(!is_local)
			kthread_use_mm(kvm->mm);
		stac();
		*((ktime_t*)dsm_db.host_virt_addr+ r) = diff;
		clac();
		if(!is_local)
			kthread_unuse_mm(kvm->mm);
	}else{
		printk(KERN_ERR "kvm-dsm: pf_cnt %u is larger than dsm_db.length %lld\n", r, dsm_db.length);
	}
}

struct gfn_count_time{
	u64 gfn;
	u64 ts;
};

static inline void save_pf_gfn_count_time_to_db(struct kvm *kvm, gfn_t gfn)
{
	struct gfn_count_time gct={gfn, ktime_get()};

	static atomic_t pf_cnt_list[] = {ATOMIC_INIT(0), ATOMIC_INIT(0)};
	int r =  (int)atomic_add_return(1, &pf_cnt_list[kvm->arch.dsm_id]);
	struct kvm_dsm_debug_buffer dsm_db = dsm_db_list[kvm->arch.dsm_id];

	if(r*sizeof(ktime_t)<dsm_db.length){
		int ret = copy_to_user((struct gfn_count_time*)dsm_db.host_virt_addr+r, &gct, sizeof(struct gfn_count_time));
		if(ret){
			printk(KERN_ERR "kvm-dsm: copy_to_user %d bytes not copied\n", ret);
		}
	}else{
		printk(KERN_ERR "kvm-dsm: pf_cnt %u is larger than dsm_db.length %lld\n", r, dsm_db.length);
	}
}

#endif

#endif /* ARCH_X86_KVM_DSM_UTIL_H */
