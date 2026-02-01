// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Arm Limited.
 * Copyright (c) 2022 Christian Loehle <christian.loehle>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_storm.bpf.skel.h"

const char help_fmt[] =
"A sched_ext scheduler that stresses DSQ moves.\n"
"\n"
"Usage: %s [-j] [-v]\n"
"\n"
"  -j            The number of custom DSQs\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;
unsigned long nr_dsqs;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple)
{
	exit_req = 1;
}

#define NR_STATS 8

static void read_stats(struct scx_storm *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	assert(nr_cpus > 0);
	__u64 cnts[NR_STATS][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * NR_STATS);

	for (idx = 0; idx < NR_STATS; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;

		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

int main(int argc, char **argv)
{
	struct scx_storm *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(storm_ops, scx_storm);

	while ((opt = getopt(argc, argv, "j:vh")) != -1) {
		switch (opt) {
		case 'j':
			char *end = NULL;
			nr_dsqs = strtoul(optarg, &end, 0);
			if (nr_dsqs < 2 || nr_dsqs > 5) {
				fprintf(stderr, "nr_dsqs must be between 2 and 5, got %lu\n", nr_dsqs);
				return -EINVAL;
			}
			skel->rodata->nr_dsqs_user = nr_dsqs;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	if (!nr_dsqs)
		skel->rodata->nr_dsqs_user = 2;
	skel->rodata->nr_cpu_ids = libbpf_num_possible_cpus();

	SCX_OPS_LOAD(skel, storm_ops, scx_storm, uei);
	link = SCX_OPS_ATTACH(skel, storm_ops, scx_storm);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[2];

		read_stats(skel, stats);
		printf("0=%llu 1=%llu 2=%llu 3=%llu 4=%llu dsq_moves=%llu qmap_to_dsq=%llu qmap_to_local=%llu\n", stats[0], stats[1], stats[2], stats[3], stats[4], stats[5], stats[6], stats[7]);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_storm__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
