// SPDX-License-Identifier: GPL-2.0-only

#include <linux/prctl.h>
#include <linux/rbtree.h>
#include <linux/cgroup.h>
#include "sched.h"

/*
 * A simple wrapper around refcount. An allocated sched_core_cookie's
 * address is used to compute the cookie of the task.
 */
struct sched_core_cookie {
	refcount_t	refcnt;
	unsigned int	type;
};

static inline void *cookie_ptr(unsigned long cookie)
{
	return (void *)(cookie & ~3UL);
}

static inline int cookie_type(unsigned long cookie)
{
	return cookie & 3;
}

static inline void sched_core_init_cookie(struct sched_core_cookie *ck, unsigned int type)
{
	refcount_set(&ck->refcnt, 1);
	ck->type = type;
}

#ifdef CONFIG_CGROUP_SCHED

#define FAT_COOKIE	0x03

struct sched_core_fat_cookie {
	struct sched_core_cookie	cookie;
	unsigned long			task_cookie;
	unsigned long			group_cookie;
	struct rb_node			node;
};

static DEFINE_RAW_SPINLOCK(fat_lock);
static struct rb_root fat_root;

static void fat_mutex_lock(void)
{
	/*
	 * { ss->can_attach(), ss->attach() } vs prctl() for p->core_spare_fat
	 */
	mutex_lock(&cgroup_mutex);
}

static void fat_mutex_unlock(void)
{
	mutex_unlock(&cgroup_mutex);
}

static void sched_core_put_fat(struct sched_core_fat_cookie *fat)
{
	unsigned long flags;

	if (fat->cookie.type != FAT_COOKIE)
		return;

	sched_core_put_cookie(fat->task_cookie);
	sched_core_put_cookie(fat->group_cookie);

	if (!RB_EMPTY_NODE(&fat->node)) {
		raw_spin_lock_irqsave(&fat_lock, flags);
		rb_erase(&fat->node, &fat_root);
		raw_spin_unlock_irqrestore(&fat_lock, flags);
	}
}

static void *node_2_fat(struct rb_node *n)
{
	return rb_entry(n, struct sched_core_fat_cookie, node);
}

static int fat_cmp(struct rb_node *a, struct rb_node *b)
{
	struct sched_core_fat_cookie *ca = node_2_fat(a);
	struct sched_core_fat_cookie *cb = node_2_fat(b);

	if (ca->group_cookie < cb->group_cookie)
		return -1;
	if (ca->group_cookie > cb->group_cookie)
		return 1;

	if (ca->task_cookie < cb->task_cookie)
		return -1;
	if (ca->task_cookie > cb->task_cookie)
		return 1;

	if (refcount_inc_not_zero(&cb->cookie.refcnt))
		return 0;

	return 1;
}

static unsigned long __sched_core_fat_cookie(struct task_struct *p,
					     void **spare_fat,
					     unsigned long cookie)
{
	unsigned long task_cookie, group_cookie;
	unsigned int p_type = cookie_type(p->core_cookie);
	unsigned int c_type = cookie_type(cookie);
	struct sched_core_fat_cookie *fat;
	unsigned long flags;
	struct rb_node *n;

	if (WARN_ON_ONCE(c_type == FAT_COOKIE))
		return cookie;

	if (!p_type || p_type == c_type)
		return cookie;

	if (p_type == FAT_COOKIE) {
		fat = cookie_ptr(p->core_cookie);

		/* loose fat */
		if (!cookie_ptr(cookie)) {
			if (c_type == TASK_COOKIE)
				cookie = fat->group_cookie;
			else
				cookie = fat->task_cookie;

			WARN_ON_ONCE(!cookie_ptr(cookie));
			return sched_core_get_cookie(cookie);
		}

		/* other fat */
		if (c_type == TASK_COOKIE)
			group_cookie = fat->group_cookie;
		else
			task_cookie = fat->task_cookie;

	} else {

		/* new fat */
		if (p_type == TASK_COOKIE)
			task_cookie = p->core_cookie;
		else
			group_cookie = p->core_cookie;
	}

	if (c_type == TASK_COOKIE)
		task_cookie = cookie;
	else
		group_cookie = cookie;

	fat = *spare_fat;
	if (WARN_ON_ONCE(!fat))
		return cookie;

	sched_core_init_cookie(&fat->cookie, FAT_COOKIE);
	fat->task_cookie = sched_core_get_cookie(task_cookie);
	fat->group_cookie = sched_core_get_cookie(group_cookie);
	RB_CLEAR_NODE(&fat->node);

	raw_spin_lock_irqsave(&fat_lock, flags);
	n = rb_find_add(&fat->node, &fat_root, fat_cmp);
	raw_spin_unlock_irqrestore(&fat_lock, flags);

	if (n) {
		sched_core_put_fat(fat);
		fat = node_2_fat(n);
	} else {
		*spare_fat = NULL;
	}

	return (unsigned long)fat | FAT_COOKIE;
}

static int __sched_core_alloc_fat(void **spare_fat)
{
	if (*spare_fat)
		return 0;

	*spare_fat = kmalloc(sizeof(struct sched_core_fat_cookie), GFP_KERNEL);
	if (!*spare_fat)
		return -ENOMEM;

	return 0;
}

int sched_core_prealloc_fat(struct task_struct *p)
{
	lockdep_assert_held(&cgroup_mutex);
	return __sched_core_alloc_fat(&p->core_spare_fat);
}

static inline unsigned long __sched_core_task_cookie(struct task_struct *p)
{
	unsigned long cookie = p->core_cookie;
	unsigned int c_type = cookie_type(cookie);

	if (!(c_type & TASK_COOKIE))
		return 0;

	if (c_type == FAT_COOKIE)
		cookie = ((struct sched_core_fat_cookie *)cookie_ptr(cookie))->task_cookie;

	return cookie;
}

#else

static inline void fat_mutex_lock(void) { }
static inline void fat_mutex_unlock(void) { }

static inline void sched_core_put_fat(void *ptr) { }
static inline int __sched_core_alloc_fat(void **spare_fat) { return 0; }

static inline unsigned long __sched_core_fat_cookie(struct task_struct *p,
						    void **spare_fat,
						    unsigned long cookie)
{
	return cookie;
}

static inline unsigned long __sched_core_task_cookie(struct task_struct *p)
{
	return p->core_cookie;
}

#endif /* CGROUP_SCHED */

unsigned long sched_core_alloc_cookie(unsigned int type)
{
	struct sched_core_cookie *ck = kmalloc(sizeof(*ck), GFP_KERNEL);
	if (!ck)
		return 0;

	WARN_ON_ONCE(type > GROUP_COOKIE);
	sched_core_init_cookie(ck, type);
	sched_core_get();

	return (unsigned long)ck | type;
}

void sched_core_put_cookie(unsigned long cookie)
{
	struct sched_core_cookie *ptr = cookie_ptr(cookie);

	if (ptr && refcount_dec_and_test(&ptr->refcnt)) {
		sched_core_put_fat((void *)ptr);
		kfree(ptr);
		sched_core_put();
	}
}

unsigned long sched_core_get_cookie(unsigned long cookie)
{
	struct sched_core_cookie *ptr = cookie_ptr(cookie);

	if (ptr)
		refcount_inc(&ptr->refcnt);

	return cookie;
}

/*
 * sched_core_update_cookie - Common helper to update a task's core cookie. This
 * updates the selected cookie field.
 * @p: The task whose cookie should be updated.
 * @cookie: The new cookie.
 * @cookie_type: The cookie field to which the cookie corresponds.
 */
static unsigned long __sched_core_update_cookie(struct task_struct *p,
						void **spare_fat,
						unsigned long cookie)
{
	unsigned long old_cookie;
	struct rq_flags rf;
	struct rq *rq;
	bool enqueued;

	raw_spin_lock_irqsave(&p->pi_lock, rf.flags);

	cookie = __sched_core_fat_cookie(p, spare_fat, cookie);
	if (!cookie_ptr(cookie))
		cookie = 0UL;

	rq = __task_rq_lock(p, &rf);

	/*
	 * Since creating a cookie implies sched_core_get(), and we cannot set
	 * a cookie until after we've created it, similarly, we cannot destroy
	 * a cookie until after we've removed it, we must have core scheduling
	 * enabled here.
	 */
	SCHED_WARN_ON((p->core_cookie || cookie) && !sched_core_enabled(rq));

	enqueued = sched_core_enqueued(p);
	if (enqueued)
		sched_core_dequeue(rq, p);

	old_cookie = p->core_cookie;
	p->core_cookie = cookie;

	if (enqueued)
		sched_core_enqueue(rq, p);

	/*
	 * If task is currently running , it may not be compatible anymore after
	 * the cookie change, so enter the scheduler on its CPU to schedule it
	 * away.
	 */
	if (task_running(rq, p))
		resched_curr(rq);

	task_rq_unlock(rq, p, &rf);

	return old_cookie;
}

unsigned long sched_core_update_cookie(struct task_struct *p, unsigned long cookie)
{
	cookie =  __sched_core_update_cookie(p, &p->core_spare_fat, cookie);
	if (p->core_spare_fat) {
		kfree(p->core_spare_fat);
		p->core_spare_fat = NULL;
	}
	return cookie;
}

static unsigned long sched_core_clone_cookie(struct task_struct *p)
{
	unsigned long flags, cookie;

	raw_spin_lock_irqsave(&p->pi_lock, flags);
	cookie = sched_core_get_cookie(p->core_cookie);
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);

	return cookie;
}

static unsigned long sched_core_clone_task_cookie(struct task_struct *p)
{
	unsigned long flags, cookie;

	raw_spin_lock_irqsave(&p->pi_lock, flags);
	cookie = sched_core_get_cookie(__sched_core_task_cookie(p));
	raw_spin_unlock_irqrestore(&p->pi_lock, flags);

	return cookie;
}

void sched_core_fork(struct task_struct *p)
{
	RB_CLEAR_NODE(&p->core_node);
	p->core_cookie = sched_core_clone_cookie(current);
	p->core_spare_fat = NULL;
}

void sched_core_free(struct task_struct *p)
{
	sched_core_put_cookie(p->core_cookie);
	kfree(p->core_spare_fat);
}

int sched_core_exec(void)
{
	/* absent a policy mech, if task had a cookie, give it a new one */
	if (current->core_cookie & TASK_COOKIE) {
		void *spare_fat = NULL;
		unsigned long cookie;

		if (__sched_core_alloc_fat(&spare_fat))
			return -ENOMEM;

		cookie = sched_core_alloc_cookie(TASK_COOKIE);
		if (!cookie)
			return -ENOMEM;

		cookie = __sched_core_update_cookie(current, &spare_fat, cookie);
		sched_core_put_cookie(cookie);
		kfree(spare_fat);
	}

	return 0;
}

static void __sched_core_set(struct task_struct *p, unsigned long cookie)
{
	cookie = sched_core_get_cookie(cookie);
	cookie = sched_core_update_cookie(p, cookie | TASK_COOKIE);
	sched_core_put_cookie(cookie);
}

/* Called from prctl interface: PR_SCHED_CORE */
int sched_core_share_pid(unsigned int cmd, pid_t pid, enum pid_type type,
			 unsigned long uaddr)
{
	unsigned long cookie = 0, id = 0;
	struct task_struct *task, *p;
	struct pid *grp;
	int err = 0;

	if (!static_branch_likely(&sched_smt_present))
		return -ENODEV;

	if (type > PIDTYPE_PGID || cmd >= PR_SCHED_CORE_MAX || pid < 0 ||
	    (cmd != PR_SCHED_CORE_GET && uaddr))
		return -EINVAL;

	rcu_read_lock();
	if (pid == 0) {
		task = current;
	} else {
		task = find_task_by_vpid(pid);
		if (!task) {
			rcu_read_unlock();
			return -ESRCH;
		}
	}
	get_task_struct(task);
	rcu_read_unlock();

	/*
	 * Check if this process has the right to modify the specified
	 * process. Use the regular "ptrace_may_access()" checks.
	 */
	if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {
		err = -EPERM;
		goto out;
	}

	fat_mutex_lock();

	err = sched_core_prealloc_fat(task);
	if (err)
		goto out_unlock;

	switch (cmd) {
	case PR_SCHED_CORE_GET:
		if (type != PIDTYPE_PID || uaddr & 7) {
			err = -EINVAL;
			goto out_unlock;
		}
		cookie = sched_core_clone_task_cookie(task);
		if (cookie_ptr(cookie)) {
			/* XXX improve ? */
			ptr_to_hashval((void *)cookie, &id);
		}
		err = put_user(id, (u64 __user *)uaddr);
		goto out_unlock;

	case PR_SCHED_CORE_CLEAR:
		cookie = 0;
		break;

	case PR_SCHED_CORE_CREATE:
		cookie = sched_core_alloc_cookie(TASK_COOKIE);
		if (!cookie) {
			err = -ENOMEM;
			goto out_unlock;
		}
		break;

	case PR_SCHED_CORE_SHARE_TO:
		cookie = sched_core_clone_task_cookie(current);
		break;

	case PR_SCHED_CORE_SHARE_FROM:
		if (type != PIDTYPE_PID) {
			err = -EINVAL;
			goto out_unlock;
		}
		cookie = sched_core_clone_task_cookie(task);
		__sched_core_set(current, cookie);
		goto out_unlock;

	default:
		err = -EINVAL;
		goto out_unlock;
	};

	if (type == PIDTYPE_PID) {
		__sched_core_set(task, cookie);
		goto out_unlock;
	}

again:
	read_lock(&tasklist_lock);
	grp = task_pid_type(task, type);

	do_each_pid_thread(grp, type, p) {
		if (!ptrace_may_access(p, PTRACE_MODE_READ_REALCREDS)) {
			err = -EPERM;
			goto out_tasklist;
		}

		if (IS_ENABLED(CONFIG_CGROUP_SCHED) && !p->core_spare_fat) {
			get_task_struct(p);
			read_unlock(&tasklist_lock);

			err = sched_core_prealloc_fat(p);
			put_task_struct(p);
			if (err)
				goto out_unlock;

			goto again;
		}
	} while_each_pid_thread(grp, type, p);

	do_each_pid_thread(grp, type, p) {
		__sched_core_set(p, cookie);
	} while_each_pid_thread(grp, type, p);
out_tasklist:
	read_unlock(&tasklist_lock);

out_unlock:
	fat_mutex_unlock();
out:
	sched_core_put_cookie(cookie);
	put_task_struct(task);
	return err;
}

