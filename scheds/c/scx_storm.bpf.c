// SPDX-License-Identifier: GPL-2.0
/*
 * A storm scheduler.
 *
 * Causes a lot of storm (DSQ migrations)
 *
 * Copyright (c) 2025 Arm Limited
 * Copyright (c) 2025 Christian Loehle <christian.loehle@arm.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define NR_DSQS 5
#define MAX_DSQS 5

#define STORM_FACTOR 10

const volatile u32 nr_cpu_ids = 1;
const volatile unsigned long nr_dsqs_user;
unsigned long nr_dsqs;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, MAX_DSQS+2);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 4096);
	__type(value, s32);
} storm_q SEC(".maps");

struct task_ctx {
	bool runnable;
	bool in_qmap;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static inline unsigned int random(unsigned int n)
{
	static unsigned int i = 0;
	i++;
	return i % n;
}

static inline unsigned int random_dsq(void)
{
	return random(nr_dsqs);
}

static inline bool coinflip(unsigned int n)
{
	return random(n) % n == 0;
}

static inline void do_storm(void)
{
	struct task_struct *p;
	unsigned int dsq_src = random_dsq();
	unsigned int i = 0;

	bpf_for_each(scx_dsq, p, dsq_src, 0) {
		unsigned int dsq_dst = random_dsq();

		i++;
		if (dsq_src != dsq_dst) {
			scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, dsq_dst, 0);
			stat_inc(MAX_DSQS);
		}
		if (coinflip(STORM_FACTOR) || i >= STORM_FACTOR)
			break;
	}
}

s32 BPF_STRUCT_OPS(storm_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	return prev_cpu;
}

void BPF_STRUCT_OPS(storm_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 pid = p->pid;
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);

	if (!tctx) {
		scx_bpf_error("Unable to find task ctx");
		return;
	}
	/* tctx->runnable = 1; Not necessary? doesn't change behaviour anyway. */
	if (tctx->in_qmap)
		return;

	if (coinflip(2) && !bpf_map_push_elem(&storm_q, &pid, 0)) {
		tctx->in_qmap = 1;
		return;
	}
	scx_bpf_dsq_insert(p, random_dsq(), SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(storm_dispatch, s32 cpu, struct task_struct *prev)
{
	int i;

	do_storm();
	bpf_for(i, 0, MAX_DSQS) {
		int random = random_dsq() % nr_dsqs;
		s32 pid;

		if (i >= nr_dsqs)
			break;
		if (!bpf_map_pop_elem(&storm_q, &pid)) {
			struct task_struct *p = bpf_task_from_pid(pid);

			if (!p) {
				scx_bpf_error("Lost task_struct with pid %d", pid);
				return;
			}
			struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
			if (!tctx) {
				bpf_task_release(p);
				scx_bpf_error("Unable to find task ctx");
				return;
			}
			tctx->in_qmap = 0;
			stat_inc(MAX_DSQS+1);
			if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr) || is_migration_disabled(p) || !tctx->runnable) {
				scx_bpf_dsq_insert(p, random_dsq(), SCX_SLICE_DFL, 0);
			} else {
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, 0);
				bpf_task_release(p);
				break;
			}
			bpf_task_release(p);
		}
		if (scx_bpf_dsq_move_to_local(random)) {
			stat_inc(random);
			break;
		}
	}
}


void BPF_STRUCT_OPS(storm_running, struct task_struct *p)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);

	if (!tctx) {
		scx_bpf_error("Unable to find task ctx");
		return;
	}

	if (!tctx->runnable)
		scx_bpf_error("Running not runnable");
	else if (tctx->in_qmap)
		scx_bpf_error("Running qmap task?");
}

void BPF_STRUCT_OPS(storm_stopping, struct task_struct *p, bool runnable)
{
	if (coinflip(3))
		p->scx.slice = 0;
}


void BPF_STRUCT_OPS(storm_tick, struct task_struct *p)
{
	if (coinflip(3))
		p->scx.slice = 0;
}

void BPF_STRUCT_OPS(storm_runnable, struct task_struct *p)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);

	if (!tctx) {
		scx_bpf_error("Unable to find task ctx");
		return;
	}
	tctx->runnable = 1;
}

void BPF_STRUCT_OPS(storm_dequeue, struct task_struct *p)
{
	struct task_ctx *tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);

	if (!tctx) {
		scx_bpf_error("Unable to find task ctx");
		return;
	}

	if (tctx->runnable == 0)
		scx_bpf_error("Spurious dequeue for %d", p->pid);
	tctx->runnable = 0;
}


s32 BPF_STRUCT_OPS(storm_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	/*
	 * @p is new. Let's ensure that its task_ctx is available. We can sleep
	 * in this function and the following will automatically use GFP_KERNEL.
	 */
	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	return 0;
}

void BPF_STRUCT_OPS(storm_enable, struct task_struct *p)
{
}

s32 BPF_STRUCT_OPS_SLEEPABLE(storm_init)
{
	s32 ret = 0;
	int i;

	if (nr_dsqs_user > MAX_DSQS)
		nr_dsqs = MAX_DSQS;
	else
		nr_dsqs = nr_dsqs_user;

	bpf_for(i, 0, MAX_DSQS) {
		if (i >= nr_dsqs)
			break;
		ret |= scx_bpf_create_dsq(i, -1);
		if (ret)
			return ret;
	}
	return ret;
}

void BPF_STRUCT_OPS(storm_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(storm_ops,
	       .select_cpu		= (void *)storm_select_cpu,
	       .enqueue			= (void *)storm_enqueue,
	       .dispatch		= (void *)storm_dispatch,
	       .running			= (void *)storm_running,
	       .stopping		= (void *)storm_stopping,
	       .tick			= (void *)storm_tick,
	       .dequeue			= (void *)storm_dequeue,
	       .runnable		= (void *)storm_runnable,
	       .init_task		= (void *)storm_init_task,
	       .enable			= (void *)storm_enable,
	       .init			= (void *)storm_init,
	       .exit			= (void *)storm_exit,
	       .name			= "storm");
