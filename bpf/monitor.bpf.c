#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;

// Memory Metrics Structure
struct mem_metrics {
  u64 rss_bytes;
  u64 vm_size;
  u64 last_update_ns;
  u32 cgroup_id;
  char comm[16];
};

// CPU Metrics Structure
struct cpu_metrics {
  u32 tgid;
  u64 cpu_ns;
  u64 last_sched_ns;
  char comm[16];
};

/***********************
 *      MAPS SETUP     *
 ***********************/
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, u32);
  __type(value, struct mem_metrics);
} mem_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 32768);
  __type(key, u32);
  __type(value, struct cpu_metrics);
} cpu_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

/***********************
 *   MEMORY TRACKING   *
 ***********************/
SEC("tracepoint/vm/rss_stat")
int handle_rss_stat(struct trace_event_raw_rss_stat *ctx) {
  // Process ID extraction
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = pid_tgid >> 32;

  // Skip kernel threads
  if (tgid == 0)
    return 0;

  long delta = ctx->size;

  bpf_printk("RSS event: tgid=%u, member=%d, delta=%ld\n", tgid, ctx->member,
             delta);

  struct mem_metrics *mem = bpf_map_lookup_elem(&mem_map, &tgid);

  if (!mem) {
    struct mem_metrics new_mem = {0};
    new_mem.cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&new_mem.comm, sizeof(new_mem.comm));

    new_mem.rss_bytes = 0;

    bpf_map_update_elem(&mem_map, &tgid, &new_mem, BPF_ANY);
    mem = bpf_map_lookup_elem(&mem_map, &tgid);
    if (!mem)
      return 0;
  }

  switch (ctx->member) {
  case MM_FILEPAGES:
  case MM_ANONPAGES:
  case MM_SHMEMPAGES:
    if (delta < 0) {
      u64 absolute_delta = (u64)(-delta);

      // Guard against underflow
      if (absolute_delta > mem->rss_bytes) {
        mem->rss_bytes = 0;
        bpf_trace_printk("RSS underflow protection: tgid=%u\n", tgid);
      } else {
        mem->rss_bytes -= absolute_delta;
      }
    } else {
      // Positive delta - add to RSS
      // Limit to a reasonable maximum (1TB) to prevent overflow issues
      u64 bytes_to_add = (u64)delta;
      if ((mem->rss_bytes + bytes_to_add) > 1099511627776ULL) { // 1TB limit
        mem->rss_bytes = 1099511627776ULL;
        bpf_trace_printk("RSS overflow protection: tgid=%u\n", tgid);
      } else {
        mem->rss_bytes += bytes_to_add;
      }
    }

    bpf_trace_printk("RSS updated: tgid=%u, new_rss=%llu\n", tgid,
                     mem->rss_bytes);
    break;
  }

  mem->last_update_ns = bpf_ktime_get_ns();
  return 0;
}

/***********************
 *    CPU TRACKING     *
 ***********************/
struct sched_switch_args {
  char prev_comm[16];
  int prev_pid;
  int prev_prio;
  long prev_state;
  char next_comm[16];
  int next_pid;
  int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx) {
  u64 now = bpf_ktime_get_ns();

  // Handle previous task
  if (ctx->prev_pid > 0) {
    volatile u32 prev_pid = (u32)ctx->prev_pid; // Force stack allocation
    struct cpu_metrics *prev = bpf_map_lookup_elem(&cpu_map, (u32 *)&prev_pid);
    if (prev) {
      prev->cpu_ns += now - prev->last_sched_ns;
    }
  }

  // Handle next task
  u64 next_pid_tgid = bpf_get_current_pid_tgid();
  volatile u32 next_pid = (u32)ctx->next_pid; // Force stack allocation
  struct cpu_metrics new_cpu = {
      .tgid = next_pid_tgid >> 32,
      .last_sched_ns = now,
  };
  bpf_get_current_comm(&new_cpu.comm, sizeof(new_cpu.comm));
  bpf_map_update_elem(&cpu_map, (u32 *)&next_pid, &new_cpu, BPF_ANY);

  return 0;
}

/***********************
 *  ACCURACY FEATURES  *
 ***********************/
SEC("perf_event")
int sync_mm_struct(struct bpf_perf_event_data *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tgid = pid_tgid >> 32;
  struct mem_metrics *mem = bpf_map_lookup_elem(&mem_map, &tgid);
  if (!mem)
    return 0;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct mm_struct *mm;
  BPF_CORE_READ_INTO(&mm, task, mm);
  if (!mm)
    return 0;

  s64 file_pages = 0, anon_pages = 0, shmem_pages = 0;

  file_pages = BPF_CORE_READ(mm, rss_stat[MM_FILEPAGES].count);
  anon_pages = BPF_CORE_READ(mm, rss_stat[MM_ANONPAGES].count);
  shmem_pages = BPF_CORE_READ(mm, rss_stat[MM_SHMEMPAGES].count);

  mem->rss_bytes = (file_pages + anon_pages + shmem_pages);
  mem->vm_size = BPF_CORE_READ(mm, total_vm);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
