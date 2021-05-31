// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019-2020 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#define pr_fmt(fmt) "simple_lmk: " fmt

#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/oom.h>
#include <linux/sort.h>
#include <linux/vmpressure.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/android_tweaks.h>

/* The minimum number of pages to free per reclaim */
#define MIN_FREE_PAGES (CONFIG_ANDROID_SIMPLE_LMK_MINFREE * SZ_1M / PAGE_SIZE)

#define MAX_FREE_PAGES (64 * SZ_1M / PAGE_SIZE)

#define MIN_MEM_FREE (CONFIG_ANDROID_SIMPLE_LMK_MINMEM * SZ_1K)

#define MAX_FREE_KL MAX_FREE_PAGES/MIN_FREE_PAGES

#define K(x) ((x) << (PAGE_SHIFT - 10))

/* Kill up to this many victims per reclaim */
#define MAX_VICTIMS 512

/* Timeout in jiffies for each reclaim */
#define RECLAIM_EXPIRES msecs_to_jiffies(CONFIG_ANDROID_SIMPLE_LMK_TIMEOUT_MSEC)

#define DEFAULT_NKPS "kcompactd,kswapd,init,ecryptfs,msm_watchdog,rvicemanager,vold,magiskd,zygote,ashmemd,lmkd,gpuservice,oid.systemui,ndroid.phone,automagic"

struct victim_info {
	struct task_struct *tsk;
	struct mm_struct *mm;
	unsigned long size;
};

typedef struct NKPSll NKPSLL;

struct NKPSll {
        char *el;
        NKPSLL *next;
};

static NKPSLL *nkpl = NULL;

static struct mutex slmk_lock;

/* Pulled from the Android framework. Lower adj means higher priority. */
#ifdef CONFIG_ANDROID_SIMPLE_LMK_PIE
static const short adj_prio[] = {
       906, /* CACHED_APP_MAX_ADJ */
       905, /* Cached app */
       904, /* Cached app */
       903, /* Cached app */
       902, /* Cached app */
       901, /* Cached app */
       900, /* CACHED_APP_MIN_ADJ */
       800, /* SERVICE_B_ADJ */
       700, /* PREVIOUS_APP_ADJ */
       600, /* HOME_APP_ADJ */
       500, /* SERVICE_ADJ */
       400, /* HEAVY_WEIGHT_APP_ADJ */
       300, /* BACKUP_APP_ADJ */
       200, /* PERCEPTIBLE_APP_ADJ */
       100, /* VISIBLE_APP_ADJ */
       0    /* FOREGROUND_APP_ADJ */
#else
static const unsigned short adjs[] = {
	SHRT_MAX + 1, /* Include all positive adjs in the final range */
	950, /* CACHED_APP_LMK_FIRST_ADJ */
	900, /* CACHED_APP_MIN_ADJ */
	800, /* SERVICE_B_ADJ */
	700, /* PREVIOUS_APP_ADJ */
	600, /* HOME_APP_ADJ */
	500, /* SERVICE_ADJ */
	400, /* HEAVY_WEIGHT_APP_ADJ */
	300, /* BACKUP_APP_ADJ */
	250, /* PERCEPTIBLE_LOW_APP_ADJ */
	200, /* PERCEPTIBLE_APP_ADJ */
	100, /* VISIBLE_APP_ADJ */
	50, /* PERCEPTIBLE_RECENT_FOREGROUND_APP_ADJ */
	0 /* FOREGROUND_APP_ADJ */
#endif
};

static struct victim_info victims[MAX_VICTIMS];
static DECLARE_WAIT_QUEUE_HEAD(oom_waitq);
static DECLARE_COMPLETION(reclaim_done);
static DEFINE_RWLOCK(mm_free_lock);
static int nr_victims;
static atomic_t needs_reclaim = ATOMIC_INIT(0);
static atomic_t nr_killed = ATOMIC_INIT(0);

static int victim_size_cmp(const void *lhs_ptr, const void *rhs_ptr)
{
	const struct victim_info *lhs = (typeof(lhs))lhs_ptr;
	const struct victim_info *rhs = (typeof(rhs))rhs_ptr;

	return rhs->size - lhs->size;
}

static bool vtsk_is_duplicate(int vlen, struct task_struct *vtsk)
{
	int i;

	for (i = 0; i < vlen; i++) {
		if (same_thread_group(victims[i].tsk, vtsk))
			return true;
	}

	return false;
}

static unsigned long get_total_mm_pages(struct mm_struct *mm)
{
	unsigned long pages = 0;
	int i;

	for (i = 0; i < NR_MM_COUNTERS; i++)
		pages += get_mm_counter(mm, i);

	return pages;
}

static int is_tsk_killable(unsigned short adj, char *tsk_name)
{
	NKPSLL *nkpsl = nkpl;

        if ((adj == 0) && (tsk_name != NULL)) {
		mutex_lock(&slmk_lock);
		while (nkpsl != NULL) {
			if (strstr(tsk_name, nkpsl->el) != NULL) {
				mutex_unlock(&slmk_lock);
				return 0;
			}
			nkpsl = nkpsl->next;
		}
		mutex_unlock(&slmk_lock);
        }
        return 1;
}

#ifdef CONFIG_ANDROID_SIMPLE_LMK_PIE
static unsigned long find_victims(int *vindex, short target_adj)
#else
static unsigned long find_victims(int *vindex, unsigned short target_adj_min,
				  unsigned short target_adj_max)
#endif
{
	unsigned long pages_found = 0;
	int old_vindex = *vindex;
	struct task_struct *tsk;
#ifndef CONFIG_ANDROID_SIMPLE_LMK_PIE
	short adj;
#endif

	for_each_process(tsk) {
		struct signal_struct *sig;
		struct task_struct *vtsk;

		/*
		 * Search for suitable tasks with the targeted importance (adj).
		 * Since only tasks with a positive adj can be targeted, that
		 * naturally excludes tasks which shouldn't be killed, like init
		 * and kthreads. Although oom_score_adj can still be changed
		 * while this code runs, it doesn't really matter. We just need
		 * to make sure that if the adj changes, we won't deadlock
		 * trying to lock a task that we locked earlier.
		 */
		sig = tsk->signal;
#ifdef CONFIG_ANDROID_SIMPLE_LMK_PIE
		if (READ_ONCE(sig->oom_score_adj) != target_adj ||
#else
		    adj = READ_ONCE(sig->oom_score_adj);
		    if (adj < target_adj_min || adj > target_adj_max - 1 ||
#endif
		    sig->flags & (SIGNAL_GROUP_EXIT | SIGNAL_GROUP_COREDUMP) ||
		    (thread_group_empty(tsk) && tsk->flags & PF_EXITING) ||
		    vtsk_is_duplicate(*vindex, tsk))
			continue;

		vtsk = find_lock_task_mm(tsk);
		if (!vtsk || !is_tsk_killable(target_adj_min, vtsk->comm))
			continue;

		/* Store this potential victim away for later */
		victims[*vindex].tsk = vtsk;
		victims[*vindex].mm = vtsk->mm;
		victims[*vindex].size = get_total_mm_pages(vtsk->mm);

		/* Keep track of the number of pages that have been found */
		pages_found += victims[*vindex].size;

		/* Make sure there's space left in the victim array */
		if (++*vindex == MAX_VICTIMS)
			break;
	}

	/*
	 * Sort the victims in descending order of size to prioritize killing
	 * the larger ones first.
	 */
	if (pages_found)
		sort(&victims[old_vindex], *vindex - old_vindex,
		     sizeof(*victims), victim_size_cmp, NULL);

	return pages_found;
}

static int process_victims(int vlen, unsigned long pages_needed)
{
	unsigned long pages_found = 0;
	int i, nr_to_kill = 0;

	/*
	 * Calculate the number of tasks that need to be killed and quickly
	 * release the references to those that'll live.
	 */
	for (i = 0; i < vlen; i++) {
		struct victim_info *victim = &victims[i];
		struct task_struct *vtsk = victim->tsk;

		/* The victim's mm lock is taken in find_victims; release it */
		if (pages_found >= pages_needed) {
			task_unlock(vtsk);
		} else {
			pages_found += victim->size;
			nr_to_kill++;
		}
	}

	return nr_to_kill;
}

static long get_available_memory()
{
	struct sysinfo m;
	long available;
	unsigned long pages[NR_LRU_LISTS];
	struct zone *zone;
	unsigned long pagecache;
	unsigned long wmark_low = 0;
	int lru;

	si_meminfo(&m);

	for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
                pages[lru] = global_page_state(NR_LRU_BASE + lru);

	for_each_zone(zone)
                wmark_low += zone->watermark[WMARK_LOW];

	available = m.freeram - totalreserve_pages;

	if (available < 0)
		available = 0;

	pagecache = pages[LRU_ACTIVE_FILE] + pages[LRU_INACTIVE_FILE];

	pagecache -= min(pagecache / 2, wmark_low);

	available += pagecache;

	available += global_page_state(NR_SLAB_RECLAIMABLE) -
                     min(global_page_state(NR_SLAB_RECLAIMABLE) / 2, wmark_low);

	available += global_page_state(NR_INDIRECTLY_RECLAIMABLE_BYTES) >>
                PAGE_SHIFT;

	if (available < 0)
                available = 0;

	return K(available);
}

static void scan_and_kill(unsigned long pages_needed)
{
	int i, nr_to_kill = 0, nr_found = 0;
	unsigned long pages_found = 0;
	int kl = 0;
	long available_memory = 0;

	available_memory = get_available_memory();

	for (i = 1; MIN_MEM_FREE * i < available_memory; i++)
		kl++;

	if (kl < MAX_FREE_KL)
		pages_needed *= (MAX_FREE_KL - kl);

	/* Hold an RCU read lock while traversing the global process list */
	rcu_read_lock();
#ifdef CONFIG_ANDROID_SIMPLE_LMK_PIE
	for (i = 0; i < ARRAY_SIZE(adj_prio) - kl; i++) {
		pages_found += find_victims(&nr_found, adj_prio[i]);
#else
	for (i = 1; i < ARRAY_SIZE(adjs) - kl; i++) {
		pages_found += find_victims(&nr_found, adjs[i], adjs[i - 1]);
#endif
		if (pages_found >= pages_needed || nr_found == MAX_VICTIMS)
			break;
	}
	rcu_read_unlock();

	/* Pretty unlikely but it can happen */
	if (unlikely(!nr_found)) {
		printk_once("No processes available to kill!\n");
		return;
	}

	/* First round of victim processing to weed out unneeded victims */
	nr_to_kill = process_victims(nr_found, pages_needed);

	/*
	 * Try to kill as few of the chosen victims as possible by sorting the
	 * chosen victims by size, which means larger victims that have a lower
	 * adj can be killed in place of smaller victims with a high adj.
	 */
	sort(victims, nr_to_kill, sizeof(*victims), victim_size_cmp, NULL);

	/* Second round of victim processing to finally select the victims */
	nr_to_kill = process_victims(nr_to_kill, pages_needed);

	/* Store the final number of victims for simple_lmk_mm_freed() */
	write_lock(&mm_free_lock);
	nr_victims = nr_to_kill;
	write_unlock(&mm_free_lock);

	/* Kill the victims */
	for (i = 0; i < nr_to_kill; i++) {
		static const struct sched_param sched_zero_prio;
		struct victim_info *victim = &victims[i];
		struct task_struct *t, *vtsk = victim->tsk;

		pr_info("Killing %s with adj %d to free %lu KiB\n", vtsk->comm,
			vtsk->signal->oom_score_adj,
			victim->size << (PAGE_SHIFT - 10));

		/* Accelerate the victim's death by forcing the kill signal */
		do_send_sig_info(SIGKILL, SEND_SIG_FORCED, vtsk, true);

		/* Mark the thread group dead so that other kernel code knows */
		rcu_read_lock();
		for_each_thread(vtsk, t)
			set_tsk_thread_flag(t, TIF_MEMDIE);
		rcu_read_unlock();

		/* Elevate the victim to SCHED_RR with zero RT priority */
		sched_setscheduler_nocheck(vtsk, SCHED_RR, &sched_zero_prio);

		/* Allow the victim to run on any CPU. This won't schedule. */
		set_cpus_allowed_ptr(vtsk, cpu_all_mask);

		/* Finally release the victim's task lock acquired earlier */
		task_unlock(vtsk);
	}

	/* Wait until all the victims die or until the timeout is reached */
	if (!wait_for_completion_timeout(&reclaim_done, RECLAIM_EXPIRES))
		pr_info("Timeout hit waiting for victims to die, proceeding\n");

	/* Clean up for future reclaim invocations */
	write_lock(&mm_free_lock);
	reinit_completion(&reclaim_done);
	nr_victims = 0;
	nr_killed = (atomic_t)ATOMIC_INIT(0);
	write_unlock(&mm_free_lock);
}

static int simple_lmk_reclaim_thread(void *data)
{
	static const struct sched_param sched_max_rt_prio = {
		.sched_priority = MAX_RT_PRIO - 1
	};

	sched_setscheduler_nocheck(current, SCHED_FIFO, &sched_max_rt_prio);

	while (1) {
		wait_event(oom_waitq, atomic_read(&needs_reclaim));
		scan_and_kill(MIN_FREE_PAGES);
		atomic_set_release(&needs_reclaim, 0);
	}

	return 0;
}

void simple_lmk_mm_freed(struct mm_struct *mm)
{
	int i;

	read_lock(&mm_free_lock);
	for (i = 0; i < nr_victims; i++) {
		if (victims[i].mm == mm) {
			victims[i].mm = NULL;
			if (atomic_inc_return_relaxed(&nr_killed) == nr_victims)
				complete(&reclaim_done);
			break;
		}
	}
	read_unlock(&mm_free_lock);
}

static int simple_lmk_vmpressure_cb(struct notifier_block *nb,
				    unsigned long pressure, void *data)
{
	if (pressure == 100 && !atomic_cmpxchg_acquire(&needs_reclaim, 0, 1))
		wake_up(&oom_waitq);

	return NOTIFY_OK;
}

static struct notifier_block vmpressure_notif = {
	.notifier_call = simple_lmk_vmpressure_cb,
	.priority = INT_MAX
};

/* Initialize Simple LMK when lmkd in Android writes to the minfree parameter */
static int simple_lmk_init_set(const char *val, const struct kernel_param *kp)
{
	static atomic_t init_done = ATOMIC_INIT(0);
	struct task_struct *thread;

	if (!atomic_cmpxchg(&init_done, 0, 1)) {
		thread = kthread_run_perf_critical(simple_lmk_reclaim_thread,
						   NULL, "simple_lmkd");
		BUG_ON(IS_ERR(thread));
		BUG_ON(vmpressure_notifier_register(&vmpressure_notif));
	}

	return 0;
}

static const struct kernel_param_ops simple_lmk_init_ops = {
	.set = simple_lmk_init_set
};

static ssize_t fs_slmknonkillable_show(struct device *dev, struct device_attribute *attr, char *buf)
{
        size_t count = 0;
        NKPSLL *nkpsl = nkpl;
        char tbuf[1024];

        memset(tbuf, 0, sizeof(tbuf));

        mutex_lock(&slmk_lock);
        while ((nkpsl != NULL) && ((count + strlen(nkpsl->el)) < sizeof(tbuf))) {
                if (nkpsl->next != NULL) {
                        count += sprintf(&tbuf[count], "%s,", nkpsl->el);
                }
                else {
                        count += sprintf(&tbuf[count], "%s", nkpsl->el);
                }
                nkpsl = nkpsl->next;
        }
        sprintf(buf, "%s\n", tbuf);
        count++;
        mutex_unlock(&slmk_lock);

        return count;
}

static ssize_t fs_slmknonkillable_dump(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        char *pend = NULL, *ptok = NULL;
        NKPSLL *ckpsl = nkpl;
        NKPSLL *nkpsl = NULL;
        char *pr = kstrdup(buf, GFP_KERNEL);

        mutex_lock(&slmk_lock);
        while (ckpsl != NULL) {
                nkpsl = ckpsl->next;
                kfree(ckpsl->el);
                kfree(ckpsl);
                ckpsl = nkpsl;
        }
        nkpl = NULL;
        ptok = pr;
        pend = pr;

        ptok = strsep(&pend, ",");
        if (ptok != NULL) {
                ckpsl = kmalloc(sizeof(struct NKPSll), GFP_KERNEL);
                ckpsl->el = kmalloc(sizeof(strlen(ptok)) + 1, GFP_KERNEL);
                memcpy(ckpsl->el, ptok, strlen(ptok));
                if (ckpsl->el[strlen(ptok)-1] == '\n')
                        ckpsl->el[strlen(ptok)-1] = 0;
                else
                        ckpsl->el[strlen(ptok)] = 0;
                ckpsl->next = NULL;
                nkpl = ckpsl;
                while ((ptok = strsep(&pend, ",")) != NULL) {
                        nkpsl = kmalloc(sizeof(struct NKPSll), GFP_KERNEL);
                        nkpsl->el = kmalloc(sizeof(strlen(ptok)) + 1, GFP_KERNEL);
                        memcpy(nkpsl->el, ptok, strlen(ptok));
                        if (nkpsl->el[strlen(ptok)-1] == '\n')
                                nkpsl->el[strlen(ptok)-1] = 0;
                        else
                                nkpsl->el[strlen(ptok)] = 0;
                        nkpsl->next = NULL;
                        ckpsl->next = nkpsl;
			ckpsl = nkpsl;
                }
        }
        mutex_unlock(&slmk_lock);
        kfree(pr);

        return count;
}
static DEVICE_ATTR(slmknonkillable, 0644, fs_slmknonkillable_show, fs_slmknonkillable_dump);

static int __init simplelmk_init(void)
{
	int ret = 0;
	char dnkpl[] = DEFAULT_NKPS;
        char *pr = NULL, *pend = NULL, *ptok = NULL;
        NKPSLL *nkpsl = NULL, *ckpsl = NULL;

	if (android_tweaks_kfpobj == NULL) {
                android_tweaks_kfpobj = kobject_create_and_add("android_tweaks", NULL) ;
        }
        if (android_tweaks_kfpobj == NULL) {
                pr_warn("%s: android_tweaks_kobj create_and_add failed\n", __func__);
                ret = -ENODEV;
        }
        else {
                ret = sysfs_create_file(android_tweaks_kfpobj, &dev_attr_slmknonkillable.attr);
                if (ret) {
                        pr_warn("%s: sysfs_create_file failed for slmknonkillable\n", __func__);
                }
        }
 
	mutex_init(&slmk_lock);
	if (ret == 0) {
		pr = kstrdup(dnkpl, GFP_KERNEL);
                pend = pr;
                ptok = pr;
                ptok = strsep(&pend, ",");
		if (ptok != NULL) {
                        ckpsl = kmalloc(sizeof(struct NKPSll), GFP_KERNEL);
                        ckpsl->el = kmalloc(sizeof(strlen(ptok)) + 1, GFP_KERNEL);
                        memcpy(ckpsl->el, ptok, strlen(ptok));
                        ckpsl->el[strlen(ptok)] = 0;
                        ckpsl->next = NULL;
                        nkpl = ckpsl;
                        while ((ptok = strsep(&pend, ",")) != NULL) {
                                nkpsl = kmalloc(sizeof(struct NKPSll), GFP_KERNEL);
                                nkpsl->el = kmalloc(sizeof(strlen(ptok)) + 1, GFP_KERNEL);
                                memcpy(nkpsl->el, ptok, strlen(ptok));
                                nkpsl->el[strlen(ptok)] = 0;
                                nkpsl->next = NULL;
                                ckpsl->next = nkpsl;
                                ckpsl = nkpsl;
                        }
                }
                kfree(pr);
	}
	return 0;
}

static void __exit simplelmk_exit(void)
{
	NKPSLL *ckpsl = nkpl;
	NKPSLL *nkpsl = NULL;

	mutex_lock(&slmk_lock);
	while (ckpsl != NULL) {
                nkpsl = ckpsl->next;
                kfree(ckpsl->el);
                kfree(ckpsl);
                ckpsl = nkpsl;
        }
	mutex_unlock(&slmk_lock);
	mutex_destroy(&slmk_lock);
}

/* Needed to prevent Android from thinking there's no LMK and thus rebooting */
#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "lowmemorykiller."
module_param_cb(minfree, &simple_lmk_init_ops, NULL, 0200);
module_init(simplelmk_init);
module_exit(simplelmk_exit);

