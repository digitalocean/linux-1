// SPDX-License-Identifier: GPL-2.0-only
/*
 * kernel/sched/core-tag.c
 *
 * Core-scheduling tagging interface support.
 *
 * Copyright(C) 2020, Joel Fernandes.
 * Initial interfacing code  by Peter Ziljstra.
 */

#include <linux/prctl.h>
#include "sched.h"

/*
 * Wrapper representing a complete cookie. The address of the cookie is used as
 * a unique identifier. Each cookie has a unique permutation of the internal
 * cookie fields.
 */
struct sched_core_cookie {
	unsigned long task_cookie;
	unsigned long group_cookie;

	struct rb_node node;
	refcount_t refcnt;
};

/*
 * A simple wrapper around refcount. An allocated sched_core_task_cookie's
 * address is used to compute the cookie of the task.
 */
struct sched_core_task_cookie {
	refcount_t refcnt;
	struct work_struct work; /* to free in WQ context. */;
};

/* All active sched_core_cookies */
static struct rb_root sched_core_cookies = RB_ROOT;
static DEFINE_RAW_SPINLOCK(sched_core_cookies_lock);

static void sched_core_cookie_init_from_task(struct sched_core_cookie *cookie,
					     struct task_struct *p)
{
	cookie->task_cookie = p->core_task_cookie;
	cookie->group_cookie = p->core_group_cookie;
}

/*
 * Returns the following:
 * a < b  => -1
 * a == b => 0
 * a > b  => 1
 */
static int sched_core_cookie_cmp(const struct sched_core_cookie *a,
				 const struct sched_core_cookie *b)
{
#define COOKIE_CMP_RETURN(field) do {		\
	if (a->field < b->field)		\
		return -1;			\
	else if (a->field > b->field)		\
		return 1;			\
} while (0)					\

	COOKIE_CMP_RETURN(task_cookie);
	COOKIE_CMP_RETURN(group_cookie);

	/* all cookie fields match */
	return 0;

#undef COOKIE_CMP_RETURN
}

static inline void __sched_core_erase_cookie(struct sched_core_cookie *cookie)
{
	lockdep_assert_held(&sched_core_cookies_lock);

	/* Already removed */
	if (RB_EMPTY_NODE(&cookie->node))
		return;

	rb_erase(&cookie->node, &sched_core_cookies);
	RB_CLEAR_NODE(&cookie->node);
}

/* Called when a task no longer points to the cookie in question */
static void sched_core_put_cookie(struct sched_core_cookie *cookie)
{
	unsigned long flags;

	if (!cookie)
		return;

	if (refcount_dec_and_test(&cookie->refcnt)) {
		raw_spin_lock_irqsave(&sched_core_cookies_lock, flags);
		__sched_core_erase_cookie(cookie);
		raw_spin_unlock_irqrestore(&sched_core_cookies_lock, flags);
		kfree(cookie);
	}
}

/*
 * A task's core cookie is a compound structure composed of various cookie
 * fields (task_cookie, group_cookie). The overall core_cookie is
 * a pointer to a struct containing those values. This function either finds
 * an existing core_cookie or creates a new one, and then updates the task's
 * core_cookie to point to it. Additionally, it handles the necessary reference
 * counting.
 */
static void __sched_core_update_cookie(struct task_struct *p)
{
	struct rb_node *parent, **node;
	struct sched_core_cookie *node_core_cookie, *match;
	static const struct sched_core_cookie zero_cookie;
	struct sched_core_cookie requested_cookie;
	bool is_zero_cookie;
	struct sched_core_cookie *const curr_cookie =
		(struct sched_core_cookie *)p->core_cookie;

	/*
	 * Ensures that we do not cause races/corruption by modifying/reading
	 * task cookie fields. Also ensures task cannot get migrated.
	 */
	lockdep_assert_held(rq_lockp(task_rq(p)));

	sched_core_cookie_init_from_task(&requested_cookie, p);

	is_zero_cookie = !sched_core_cookie_cmp(&requested_cookie, &zero_cookie);

	/*
	 * Already have a cookie matching the requested settings? Nothing to
	 * do.
	 */
	if ((curr_cookie && !sched_core_cookie_cmp(curr_cookie, &requested_cookie)) ||
	    (!curr_cookie && is_zero_cookie))
		return;

	raw_spin_lock(&sched_core_cookies_lock);

	if (is_zero_cookie) {
		match = NULL;
		goto finish;
	}

retry:
	match = NULL;

	node = &sched_core_cookies.rb_node;
	parent = *node;
	while (*node) {
		int cmp;

		node_core_cookie =
			container_of(*node, struct sched_core_cookie, node);
		parent = *node;

		cmp = sched_core_cookie_cmp(&requested_cookie, node_core_cookie);
		if (cmp < 0) {
			node = &parent->rb_left;
		} else if (cmp > 0) {
			node = &parent->rb_right;
		} else {
			match = node_core_cookie;
			break;
		}
	}

	if (!match) {
		/* No existing cookie; create and insert one */
		match = kmalloc(sizeof(struct sched_core_cookie), GFP_ATOMIC);

		/* Fall back to zero cookie */
		if (WARN_ON_ONCE(!match))
			goto finish;

		*match = requested_cookie;
		refcount_set(&match->refcnt, 1);

		rb_link_node(&match->node, parent, node);
		rb_insert_color(&match->node, &sched_core_cookies);
	} else {
		/*
		 * Cookie exists, increment refcnt. If refcnt is currently 0,
		 * we're racing with a put() (refcnt decremented but cookie not
		 * yet removed from the tree). In this case, we can simply
		 * perform the removal ourselves and retry.
		 * sched_core_put_cookie() will still function correctly.
		 */
		if (unlikely(!refcount_inc_not_zero(&match->refcnt))) {
			__sched_core_erase_cookie(match);
			goto retry;
		}
	}

finish:
	p->core_cookie = (unsigned long)match;

	raw_spin_unlock(&sched_core_cookies_lock);

	sched_core_put_cookie(curr_cookie);
}

/*
 * sched_core_update_cookie - Common helper to update a task's core cookie. This
 * updates the selected cookie field and then updates the overall cookie.
 * @p: The task whose cookie should be updated.
 * @cookie: The new cookie.
 * @cookie_type: The cookie field to which the cookie corresponds.
 */
static void sched_core_update_cookie(struct task_struct *p, unsigned long cookie,
				     enum sched_core_cookie_type cookie_type)
{
	struct rq_flags rf;
	struct rq *rq;

	if (!p)
		return;

	rq = task_rq_lock(p, &rf);

	switch (cookie_type) {
	case sched_core_task_cookie_type:
		p->core_task_cookie = cookie;
		break;
	case sched_core_group_cookie_type:
		p->core_group_cookie = cookie;
		break;
	default:
		WARN_ON_ONCE(1);
	}

	/* Set p->core_cookie, which is the overall cookie */
	__sched_core_update_cookie(p);

	if (sched_core_enqueued(p)) {
		sched_core_dequeue(rq, p);
		if (!p->core_cookie) {
			task_rq_unlock(rq, p, &rf);
			return;
		}
	}

	if (sched_core_enabled(rq) &&
	    p->core_cookie && task_on_rq_queued(p))
		sched_core_enqueue(task_rq(p), p);

	/*
	 * If task is currently running or waking, it may not be compatible
	 * anymore after the cookie change, so enter the scheduler on its CPU
	 * to schedule it away.
	 */
	if (task_running(rq, p) || p->state == TASK_WAKING)
		resched_curr(rq);

	task_rq_unlock(rq, p, &rf);
}

#ifdef CONFIG_CGROUP_SCHED
static unsigned long cpu_core_get_group_cookie(struct task_group *tg);

void sched_core_change_group(struct task_struct *p, struct task_group *new_tg)
{
	lockdep_assert_held(rq_lockp(task_rq(p)));

	/*
	 * It is ok if this races with an update to new_tg->core_tagged. Any
	 * update that occurs after we read the group_cookie here will have to
	 * perform a cookie update on this task _after_ the update below, due
	 * to the dependence on task_rq lock.
	 */
	p->core_group_cookie = cpu_core_get_group_cookie(new_tg);

	__sched_core_update_cookie(p);
}
#endif

/* Per-task interface: Used by fork(2) and prctl(2). */
static void sched_core_put_cookie_work(struct work_struct *ws);

/* Caller has to call sched_core_get() if non-zero value is returned. */
static unsigned long sched_core_alloc_task_cookie(void)
{
	struct sched_core_task_cookie *ck =
		kmalloc(sizeof(struct sched_core_task_cookie), GFP_KERNEL);

	if (!ck)
		return 0;
	refcount_set(&ck->refcnt, 1);
	INIT_WORK(&ck->work, sched_core_put_cookie_work);

	return (unsigned long)ck;
}

static void sched_core_get_task_cookie(unsigned long cookie)
{
	struct sched_core_task_cookie *ptr =
		(struct sched_core_task_cookie *)cookie;

	refcount_inc(&ptr->refcnt);
}

static void sched_core_put_task_cookie(unsigned long cookie)
{
	struct sched_core_task_cookie *ptr =
		(struct sched_core_task_cookie *)cookie;

	if (refcount_dec_and_test(&ptr->refcnt))
		kfree(ptr);
}

static void sched_core_put_cookie_work(struct work_struct *ws)
{
	struct sched_core_task_cookie *ck =
		container_of(ws, struct sched_core_task_cookie, work);

	sched_core_put_task_cookie((unsigned long)ck);
	sched_core_put();
}

static inline void sched_core_update_task_cookie(struct task_struct *t,
						 unsigned long c)
{
	sched_core_update_cookie(t, c, sched_core_task_cookie_type);
}

int sched_core_share_tasks(struct task_struct *t1, struct task_struct *t2)
{
	static DEFINE_MUTEX(sched_core_tasks_mutex);
	unsigned long cookie;
	int ret = -ENOMEM;

	mutex_lock(&sched_core_tasks_mutex);

	if (!t2) {
		if (t1->core_task_cookie) {
			sched_core_put_task_cookie(t1->core_task_cookie);
			sched_core_update_task_cookie(t1, 0);
			sched_core_put();
		}
	} else if (t1 == t2) {
		/* Assign a unique per-task cookie solely for t1. */
		cookie = sched_core_alloc_task_cookie();
		if (!cookie)
			goto out_unlock;
		sched_core_get();

		if (t1->core_task_cookie) {
			sched_core_put_task_cookie(t1->core_task_cookie);
			sched_core_put();
		}
		sched_core_update_task_cookie(t1, cookie);
	} else if (!t1->core_task_cookie && !t2->core_task_cookie) {
		/*
		 * 		t1		joining		t2
		 * CASE 1:
		 * before	0				0
		 * after	new cookie			new cookie
		 *
		 * CASE 2:
		 * before	X (non-zero)			0
		 * after	0				0
		 *
		 * CASE 3:
		 * before	0				X (non-zero)
		 * after	X				X
		 *
		 * CASE 4:
		 * before	Y (non-zero)			X (non-zero)
		 * after	X				X
		 */

		/* CASE 1. */
		cookie = sched_core_alloc_task_cookie();
		if (!cookie)
			goto out_unlock;
		sched_core_get(); /* For the alloc. */

		/* Add another reference for the other task. */
		sched_core_get_task_cookie(cookie);
		sched_core_get(); /* For the other task. */

		sched_core_update_task_cookie(t1, cookie);
		sched_core_update_task_cookie(t2, cookie);
	} else if (t1->core_task_cookie && !t2->core_task_cookie) {
		/* CASE 2. */
		sched_core_put_task_cookie(t1->core_task_cookie);
		sched_core_update_task_cookie(t1, 0);
		sched_core_put();
	} else if (!t1->core_task_cookie && t2->core_task_cookie) {
		/* CASE 3. */
		sched_core_get_task_cookie(t2->core_task_cookie);
		sched_core_get();
		sched_core_update_task_cookie(t1, t2->core_task_cookie);

	} else {
		/* CASE 4. */
		sched_core_get_task_cookie(t2->core_task_cookie);
		sched_core_get();

		sched_core_put_task_cookie(t1->core_task_cookie);
		sched_core_update_task_cookie(t1, t2->core_task_cookie);
		sched_core_put();
	}

	ret = 0;
out_unlock:
	mutex_unlock(&sched_core_tasks_mutex);
	return ret;
}

/* Called from prctl interface: PR_SCHED_CORE_SHARE */
int sched_core_share_pid(unsigned long flags, pid_t pid)
{
	struct task_struct *to;
	struct task_struct *from;
	struct task_struct *task;
	int err;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}

	get_task_struct(task);

	/*
	 * Check if this process has the right to modify the specified
	 * process. Use the regular "ptrace_may_access()" checks.
	 */
	if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {
		rcu_read_unlock();
		err = -EPERM;
		goto out;
	}
	rcu_read_unlock();

	if (flags == PR_SCHED_CORE_CLEAR) {
		to = task;
		from = NULL;
	} else if (flags == PR_SCHED_CORE_SHARE_TO) {
		to = task;
		from = current;
	} else if (flags == PR_SCHED_CORE_SHARE_FROM) {
		to = current;
		from = task;
	} else {
		err = -EINVAL;
		goto out;
	}

	err = sched_core_share_tasks(to, from);
out:
	put_task_struct(task);
	return err;
}

/* CGroup core-scheduling interface support. */
#ifdef CONFIG_CGROUP_SCHED
/*
 * Helper to get the group cookie in a hierarchy. Any ancestor can have a
 * cookie.
 *
 * Can race with an update to tg->core_tagged if sched_core_group_mutex is
 * not held.
 */
static unsigned long cpu_core_get_group_cookie(struct task_group *tg)
{
	for (; tg; tg = tg->parent) {
		if (READ_ONCE(tg->core_tagged))
			return (unsigned long)tg;
	}

	return 0;
}

/* Determine if any group in @tg's children are tagged. */
static bool cpu_core_check_descendants(struct task_group *tg, bool check_tag)
{
	struct task_group *child;

	rcu_read_lock();
	list_for_each_entry_rcu(child, &tg->children, siblings) {
		if ((child->core_tagged && check_tag)) {
			rcu_read_unlock();
			return true;
		}

		rcu_read_unlock();
		return cpu_core_check_descendants(child, check_tag);
	}

	rcu_read_unlock();
	return false;
}

u64 cpu_core_tag_read_u64(struct cgroup_subsys_state *css,
			  struct cftype *cft)
{
	return !!css_tg(css)->core_tagged;
}

#ifdef CONFIG_SCHED_DEBUG
u64 cpu_core_group_cookie_read_u64(struct cgroup_subsys_state *css,
				   struct cftype *cft)
{
	return cpu_core_get_group_cookie(css_tg(css));
}
#endif

int cpu_core_tag_write_u64(struct cgroup_subsys_state *css, struct cftype *cft,
			   u64 val)
{
	static DEFINE_MUTEX(sched_core_group_mutex);
	struct task_group *tg = css_tg(css);
	struct cgroup_subsys_state *css_tmp;
	struct task_struct *p;
	unsigned long cookie;
	int ret = 0;

	if (val > 1)
		return -ERANGE;

	if (!static_branch_likely(&sched_smt_present))
		return -EINVAL;

	mutex_lock(&sched_core_group_mutex);

	if (!tg->core_tagged && val) {
		/* Tag is being set. Check ancestors and descendants. */
		if (cpu_core_get_group_cookie(tg) ||
		    cpu_core_check_descendants(tg, true /* tag */)) {
			ret = -EBUSY;
			goto out_unlock;
		}
	} else if (tg->core_tagged && !val) {
		/* Tag is being reset. Check descendants. */
		if (cpu_core_check_descendants(tg, true /* tag */)) {
			ret = -EBUSY;
			goto out_unlock;
		}
	} else {
		goto out_unlock;
	}

	if (!!val)
		sched_core_get();

	tg->core_tagged = val;
	cookie = cpu_core_get_group_cookie(tg);

	rcu_read_lock();
	css_for_each_descendant_pre(css_tmp, css) {
		struct css_task_iter it;

		css_task_iter_start(css_tmp, 0, &it);
		/*
		 * Note: css_task_iter_next will skip dying tasks.
		 * There could still be dying tasks left in the core queue
		 * when we set cgroup tag to 0 when the loop is done below.
		 */
		while ((p = css_task_iter_next(&it)))
			sched_core_update_cookie(p, cookie, sched_core_group_cookie_type);

		css_task_iter_end(&it);
	}
	rcu_read_unlock();

	if (!val)
		sched_core_put();

out_unlock:
	mutex_unlock(&sched_core_group_mutex);
	return ret;
}
#endif

/* Called from sched_fork() */
int sched_core_fork(struct task_struct *p, unsigned long clone_flags)
{
	/*
	 * These are ref counted; avoid an uncounted reference.
	 * If p should have a cookie, it will be set below.
	 */
	p->core_task_cookie = 0;
	p->core_cookie = 0;

	/*
	 * First, update the new task's per-task cookie.
	 * If parent is tagged via per-task cookie, tag the child (either with
	 * the parent's cookie, or a new one).
	 */
	if (READ_ONCE(current->core_task_cookie)) {
		int ret;

		if (clone_flags & CLONE_THREAD) {
			/* For CLONE_THREAD, share parent's per-task tag. */
			ret = sched_core_share_tasks(p, p);
		} else {
			/* Otherwise, assign a new per-task tag. */
			ret = sched_core_share_tasks(p, current);
		}

		if (ret)
			return ret;

		/* sched_core_share_tasks() should always update p's core_cookie. */
		WARN_ON_ONCE(!p->core_cookie);

		return 0;
	}

	/*
	 * NOTE: This might race with a concurrent cgroup cookie update. That's
	 * ok; sched_core_change_group() will handle this post-fork, once the
	 * task is visible.
	 */
	if (p->core_group_cookie) {
		struct sched_core_cookie *parent_cookie;
		struct sched_core_cookie child_requested_cookie;
		bool needs_update = false;
		struct rq_flags rf;
		struct rq *rq;
		unsigned long flags;

		/* No locking needed; child is not yet visible */
		sched_core_cookie_init_from_task(&child_requested_cookie, p);

		/*
		 * Optimization: try to grab the parent's cookie and increment
		 * the refcount directly, rather than traverse the RB tree.
		 *
		 * Note: sched_core_cookies_lock is less contended than
		 * rq_lock(current), and is sufficient to protect
		 * current->core_cookie.
		 */
		raw_spin_lock_irqsave(&sched_core_cookies_lock, flags);
		parent_cookie = (struct sched_core_cookie *)current->core_cookie;
		if (likely(parent_cookie &&
			   !sched_core_cookie_cmp(&child_requested_cookie, parent_cookie) &&
			   refcount_inc_not_zero(&parent_cookie->refcnt))) {
			p->core_cookie = (unsigned long)parent_cookie;
		} else {
			needs_update = true; /* raced */
		}
		raw_spin_unlock_irqrestore(&sched_core_cookies_lock, flags);

		if (needs_update) {
			rq = task_rq_lock(p, &rf);
			__sched_core_update_cookie(p);
			task_rq_unlock(rq, p, &rf);
			WARN_ON_ONCE(!p->core_cookie);
		}
	}

	return 0;
}

void sched_tsk_free(struct task_struct *tsk)
{
	struct sched_core_task_cookie *ck;

	sched_core_put_cookie((struct sched_core_cookie *)tsk->core_cookie);

	if (!tsk->core_task_cookie)
		return;

	ck = (struct sched_core_task_cookie *)tsk->core_task_cookie;
	queue_work(system_wq, &ck->work);
}
