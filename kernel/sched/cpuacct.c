#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/cpumask.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <linux/res_counter.h>
#include <linux/kernel_stat.h>
#include <linux/err.h>

#include "sched.h"

/*
 * CPU accounting code for task groups.
 *
 * Based on the work by Paul Menage (menage@google.com) and Balbir Singh
 * (balbir@in.ibm.com).
 */

/* Time spent by the tasks of the cpu accounting group executing in ... */
enum cpuacct_stat_index {
	CPUACCT_STAT_USER,	/* ... user mode */
	CPUACCT_STAT_SYSTEM,	/* ... kernel mode */

	CPUACCT_STAT_NSTATS,
};

/* track cpu usage of a group of tasks and its child groups */
struct cpuacct {
	struct cgroup_subsys_state css;
	/* cpuusage holds pointer to a u64-type object on every cpu */
	u64 __percpu *cpuusage;
	struct kernel_cpustat __percpu *cpustat;

	/* counter for allowed tasks */
	struct res_counter task_limit;
	/* counter for allowed forks */
	struct res_counter fork_limit;
};

static inline struct cpuacct *css_ca(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct cpuacct, css) : NULL;
}

/* return cpu accounting group to which this task belongs */
static inline struct cpuacct *task_ca(struct task_struct *tsk)
{
	return css_ca(task_css(tsk, cpuacct_subsys_id));
}

static inline struct cpuacct *parent_ca(struct cpuacct *ca)
{
	return css_ca(css_parent(&ca->css));
}

static DEFINE_PER_CPU(u64, root_cpuacct_cpuusage);
static struct cpuacct root_cpuacct = {
	.cpustat	= &kernel_cpustat,
	.cpuusage	= &root_cpuacct_cpuusage,
};

/* create a new cpu accounting group */
static struct cgroup_subsys_state *
cpuacct_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct cpuacct *ca;

	if (!parent_css) {
		res_counter_init(&root_cpuacct.task_limit, NULL);
		res_counter_init(&root_cpuacct.fork_limit, NULL);
		return &root_cpuacct.css;
	}

	ca = kzalloc(sizeof(*ca), GFP_KERNEL);
	if (!ca)
		goto out;

	ca->cpuusage = alloc_percpu(u64);
	if (!ca->cpuusage)
		goto out_free_ca;

	ca->cpustat = alloc_percpu(struct kernel_cpustat);
	if (!ca->cpustat)
		goto out_free_cpuusage;

	res_counter_init(&ca->task_limit, &css_ca(parent_css)->task_limit);
	res_counter_inherit(&ca->task_limit, RES_LIMIT);

	res_counter_init(&ca->fork_limit, &css_ca(parent_css)->fork_limit);
	res_counter_inherit(&ca->fork_limit, RES_LIMIT);

	return &ca->css;

out_free_cpuusage:
	free_percpu(ca->cpuusage);
out_free_ca:
	kfree(ca);
out:
	return ERR_PTR(-ENOMEM);
}

/* destroy an existing cpu accounting group */
static void cpuacct_css_free(struct cgroup_subsys_state *css)
{
	struct cpuacct *ca = css_ca(css);

	free_percpu(ca->cpustat);
	free_percpu(ca->cpuusage);
	kfree(ca);
}

static u64 cpuacct_cpuusage_read(struct cpuacct *ca, int cpu)
{
	u64 *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);
	u64 data;

#ifndef CONFIG_64BIT
	/*
	 * Take rq->lock to make 64-bit read safe on 32-bit platforms.
	 */
	raw_spin_lock_irq(&cpu_rq(cpu)->lock);
	data = *cpuusage;
	raw_spin_unlock_irq(&cpu_rq(cpu)->lock);
#else
	data = *cpuusage;
#endif

	return data;
}

static void cpuacct_cpuusage_write(struct cpuacct *ca, int cpu, u64 val)
{
	u64 *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);

#ifndef CONFIG_64BIT
	/*
	 * Take rq->lock to make 64-bit write safe on 32-bit platforms.
	 */
	raw_spin_lock_irq(&cpu_rq(cpu)->lock);
	*cpuusage = val;
	raw_spin_unlock_irq(&cpu_rq(cpu)->lock);
#else
	*cpuusage = val;
#endif
}

/* return total cpu usage (in nanoseconds) of a group */
static u64 cpuusage_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct cpuacct *ca = css_ca(css);
	u64 totalcpuusage = 0;
	int i;

	for_each_present_cpu(i)
		totalcpuusage += cpuacct_cpuusage_read(ca, i);

	return totalcpuusage;
}

static int cpuusage_write(struct cgroup_subsys_state *css, struct cftype *cft,
			  u64 reset)
{
	struct cpuacct *ca = css_ca(css);
	int err = 0;
	int i;

	if (reset) {
		err = -EINVAL;
		goto out;
	}

	for_each_present_cpu(i)
		cpuacct_cpuusage_write(ca, i, 0);

out:
	return err;
}

static int cpuacct_percpu_seq_show(struct seq_file *m, void *V)
{
	struct cpuacct *ca = css_ca(seq_css(m));
	u64 percpu;
	int i;

	for_each_present_cpu(i) {
		percpu = cpuacct_cpuusage_read(ca, i);
		seq_printf(m, "%llu ", (unsigned long long) percpu);
	}
	seq_printf(m, "\n");
	return 0;
}

static const char * const cpuacct_stat_desc[] = {
	[CPUACCT_STAT_USER] = "user",
	[CPUACCT_STAT_SYSTEM] = "system",
};

static int cpuacct_stats_show(struct seq_file *sf, void *v)
{
	struct cpuacct *ca = css_ca(seq_css(sf));
	int cpu;
	s64 val = 0;

	for_each_online_cpu(cpu) {
		struct kernel_cpustat *kcpustat = per_cpu_ptr(ca->cpustat, cpu);
		val += kcpustat->cpustat[CPUTIME_USER];
		val += kcpustat->cpustat[CPUTIME_NICE];
	}
	val = cputime64_to_clock_t(val);
	seq_printf(sf, "%s %lld\n", cpuacct_stat_desc[CPUACCT_STAT_USER], val);

	val = 0;
	for_each_online_cpu(cpu) {
		struct kernel_cpustat *kcpustat = per_cpu_ptr(ca->cpustat, cpu);
		val += kcpustat->cpustat[CPUTIME_SYSTEM];
		val += kcpustat->cpustat[CPUTIME_IRQ];
		val += kcpustat->cpustat[CPUTIME_SOFTIRQ];
	}

	val = cputime64_to_clock_t(val);
	seq_printf(sf, "%s %lld\n", cpuacct_stat_desc[CPUACCT_STAT_SYSTEM], val);

	return 0;
}

static u64 cpuacct_task_limit_read_u64(struct cgroup_subsys_state *css,
				       struct cftype *cft)
{
	struct cpuacct *ca = css_ca(css);
	int type = cft->private;

	return res_counter_read_u64(&ca->task_limit, type);
}

static int cpuacct_task_limit_write_u64(struct cgroup_subsys_state *css,
					struct cftype *cft, u64 val)
{
	struct cpuacct *ca = css_ca(css);

	if (ca == &root_cpuacct)
		return -EINVAL;

	return res_counter_set_limit(&ca->task_limit, val);
}

static u64 cpuacct_fork_limit_read_u64(struct cgroup_subsys_state *css,
				       struct cftype *cft)
{
	struct cpuacct *ca = css_ca(css);
	int type = cft->private;

	return res_counter_read_u64(&ca->fork_limit, type);
}

static int cpuacct_fork_limit_write_u64(struct cgroup_subsys_state *css,
					struct cftype *cft, u64 val)
{
	struct cpuacct *ca = css_ca(css);
	int type = cft->private;

	if (ca == &root_cpuacct)
		return -EINVAL;

	/* always allow 0 to stop an ongoing fork bomb */
	if (val != 0)
		return res_counter_set_limit(&ca->fork_limit, val);
	res_counter_write_u64(&ca->fork_limit, type, val);

	return 0;
}

static int cpuacct_can_fork(void)
{
	int err = 0;
	bool fork_charged = 0;
	struct cpuacct *ca = task_ca(current);

	if (ca == &root_cpuacct)
		return 0;

	if (res_counter_charge_until(&ca->fork_limit, &root_cpuacct.fork_limit, 1, NULL))
		return -EPERM;
	fork_charged = 1;

	if (res_counter_charge_until(&ca->task_limit, &root_cpuacct.task_limit, 1, NULL)) {
		err = -EAGAIN;
		goto err_task_limit;
	}

	return 0;

err_task_limit:
	if (fork_charged)
		res_counter_uncharge_until(&ca->fork_limit, &root_cpuacct.fork_limit, 1);
	return err;
}

static void cpuacct_cancel_can_fork(void)
{
	struct cpuacct *ca = task_ca(current);

	if (ca == &root_cpuacct)
		return;

	res_counter_uncharge_until(&ca->fork_limit, &root_cpuacct.fork_limit, 1);
	res_counter_uncharge_until(&ca->task_limit, &root_cpuacct.task_limit, 1);
}


static void cpuacct_exit(struct cgroup_subsys_state *css,
			 struct cgroup_subsys_state *old_css,
			 struct task_struct *task)
{
	struct cpuacct *ca = css_ca(old_css);

	if (ca == &root_cpuacct)
		return;

	res_counter_uncharge_until(&ca->task_limit, &root_cpuacct.task_limit, 1);
}

/*
 * Complete the attach by uncharging the old cgroups. We can do that now that
 * we are sure the attachment can't be cancelled anymore, because this uncharge
 * operation couldn't be reverted later: a task in the old cgroup could fork
 * after we uncharge and reach the task counter limit, making our return there
 * not possible.
 */
static void cpuacct_attach(struct cgroup_subsys_state *css,
			   struct cgroup_taskset *tset)
{
	struct task_struct *task;
	struct cpuacct *new = css_ca(css);
	struct cpuacct *old;
	struct res_counter *until;

	cgroup_taskset_for_each(task, NULL, tset) {
		old = css_ca(cgroup_taskset_cur_css(tset, cpuacct_subsys_id));
		until = res_counter_common_ancestor(&new->task_limit,
						    &old->task_limit);
		res_counter_uncharge_until(&old->task_limit, until, 1);
	}
}

static void cpuacct_cancel_attach_until(struct cgroup_subsys_state *css,
					struct cgroup_taskset *tset,
					struct task_struct *until_task)
{
	struct task_struct *task;
	struct cpuacct *new = css_ca(css);
	struct cpuacct *old;
	struct res_counter *until;

	cgroup_taskset_for_each(task, NULL, tset) {
		if (task == until_task)
			break;
		old = css_ca(cgroup_taskset_cur_css(tset, cpuacct_subsys_id));
		until = res_counter_common_ancestor(&new->task_limit,
						    &old->task_limit);
		res_counter_uncharge_until(&new->task_limit, until, 1);
	}
}

/*
 * This does more than just probing the ability to attach to the dest cgroup.
 * We can not just _check_ if we can attach to the destination and do the real
 * attachment later in cpuacct_attach() because a task in the dest cgroup can
 * fork before we get there and steal the last remaining count, thus we must
 * charge the dest cgroup right now.
 */
static int cpuacct_can_attach(struct cgroup_subsys_state *css,
			      struct cgroup_taskset *tset)
{
	struct task_struct *task;
	struct cpuacct *new = css_ca(css);
	struct cpuacct *old;
	struct res_counter *until;
	int err;

	cgroup_taskset_for_each(task, NULL, tset) {
		old = css_ca(cgroup_taskset_cur_css(tset, cpuacct_subsys_id));

		/*
		 * When moving a task from a cgroup to another, we don't want
		 * to charge the common ancestors, even though they would be
		 * uncharged later in cpuacct_attach(), because during that
		 * short window between charge and uncharge, a task could fork
		 * in the ancestor and spuriously fail due to the temporary
		 * charge.
		 */
		until = res_counter_common_ancestor(&new->task_limit,
						    &old->task_limit);

		err = res_counter_charge_until(&new->task_limit, until, 1, NULL);
		if (err) {
			cpuacct_cancel_attach_until(css, tset, task);
			return -EINVAL;
		}
	}

	return 0;
}

/* Uncharge the cgroup that we charged in cpuacct_can_attach() */
static void cpuacct_cancel_attach(struct cgroup_subsys_state *css,
				  struct cgroup_taskset *tset)
{
	cpuacct_cancel_attach_until(css, tset, NULL);
}


static struct cftype files[] = {
	{
		.name = "usage",
		.read_u64 = cpuusage_read,
		.write_u64 = cpuusage_write,
	},
	{
		.name = "usage_percpu",
		.seq_show = cpuacct_percpu_seq_show,
	},
	{
		.name = "stat",
		.seq_show = cpuacct_stats_show,
	},
	{
		.name = "task_limit",
		.read_u64 = cpuacct_task_limit_read_u64,
		.write_u64 = cpuacct_task_limit_write_u64,
		.private = RES_LIMIT,
	},
	{
		.name = "task_usage",
		.read_u64 = cpuacct_task_limit_read_u64,
		.private = RES_USAGE,
	},
	{
		.name = "fork_limit",
		.read_u64 = cpuacct_fork_limit_read_u64,
		.write_u64 = cpuacct_fork_limit_write_u64,
		.private = RES_LIMIT,
	},
	{
		.name = "fork_usage",
		.read_u64 = cpuacct_fork_limit_read_u64,
		.private = RES_USAGE,
	},
	{ }	/* terminate */
};

/*
 * charge this task's execution time to its accounting group.
 *
 * called with rq->lock held.
 */
void cpuacct_charge(struct task_struct *tsk, u64 cputime)
{
	struct cpuacct *ca;
	int cpu;

	cpu = task_cpu(tsk);

	rcu_read_lock();

	ca = task_ca(tsk);

	while (true) {
		u64 *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);
		*cpuusage += cputime;

		ca = parent_ca(ca);
		if (!ca)
			break;
	}

	rcu_read_unlock();
}

/*
 * Add user/system time to cpuacct.
 *
 * Note: it's the caller that updates the account of the root cgroup.
 */
void cpuacct_account_field(struct task_struct *p, int index, u64 val)
{
	struct kernel_cpustat *kcpustat;
	struct cpuacct *ca;

	rcu_read_lock();
	ca = task_ca(p);
	while (ca != &root_cpuacct) {
		kcpustat = this_cpu_ptr(ca->cpustat);
		kcpustat->cpustat[index] += val;
		ca = parent_ca(ca);
	}
	rcu_read_unlock();
}

struct cgroup_subsys cpuacct_subsys = {
	.name			= "cpuacct",
	.css_alloc		= cpuacct_css_alloc,
	.css_free		= cpuacct_css_free,
	.subsys_id		= cpuacct_subsys_id,
	.base_cftypes		= files,
	.early_init		= 1,
	.can_fork		= cpuacct_can_fork,
	.cancel_can_fork	= cpuacct_cancel_can_fork,
	.exit			= cpuacct_exit,
	.attach			= cpuacct_attach,
	.can_attach		= cpuacct_can_attach,
	.cancel_attach		= cpuacct_cancel_attach,
};
