#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long long u64;

// Constants for mm_rss_stat indexing
#define MM_FILEPAGES 0
#define MM_ANONPAGES 1
#define MM_SHMEMPAGES 2

// Process Metrics holds the high level structure to track
// resource usage per process
struct process_metrics {
  u32 pid;
  u32 tgid;           // Thread group ID (process ID for main thread)
  u64 cpu_ns;         // CPU time in nanoseconds
  u64 rss_bytes;      // Resident set size in bytes
  u64 vm_size;        // Virtual memory size
  u64 stack_size;     // Stack size
  u32 thread_count;   // Number of threads
  u64 start_time_ns;  // Process start time
  u64 last_update_ns; // Last update time
  u32 cgroup_id;      // cgroup ID (for systemd service mapping)
  char comm[16];      // Process name
};

// Process start times
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u32);   // PID
  __type(value, u64); // Start timestamp
} process_start_times SEC(".maps");

// Process runtime state
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u32);                      // PID
  __type(value, struct process_metrics); // Process metrics
} process_metrics_map SEC(".maps");

// Track thread count per process
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u32);   // TGID (Process ID)
  __type(value, u32); // Thread count
} thread_count_map SEC(".maps");

// Ring buffer for streaming events to user space
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); // 256KB
} events SEC(".maps");

// Tracking process execution
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
  u64 now = bpf_ktime_get_ns();
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

  // Get task struct for accessing cgroup and other info
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  struct process_metrics metrics = {0};
  metrics.pid = pid;
  metrics.tgid = tgid;
  metrics.start_time_ns = now;
  metrics.last_update_ns = now;

  // cgroup ID (useful for mapping to systemd service)
  u64 cgroup_id = bpf_get_current_cgroup_id();
  metrics.cgroup_id = (u32)cgroup_id;

  // Get the command name
  bpf_get_current_comm(&metrics.comm, sizeof(metrics.comm));

  // Initialize memory metrics if we can read them
  struct mm_struct *mm;
  BPF_CORE_READ_INTO(&mm, task, mm);
  if (mm) {
    unsigned long rss = 0;

    s64 file_pages = 0, anon_pages = 0, shmem_pages = 0;

    file_pages = BPF_CORE_READ(mm, rss_stat[MM_FILEPAGES].count);
    anon_pages = BPF_CORE_READ(mm, rss_stat[MM_ANONPAGES].count);
    shmem_pages = BPF_CORE_READ(mm, rss_stat[MM_SHMEMPAGES].count);

    rss = (unsigned long)(file_pages + anon_pages + shmem_pages);

    metrics.rss_bytes = rss * 4096;
    metrics.vm_size = BPF_CORE_READ(mm, total_vm) * 4096;
    metrics.stack_size = BPF_CORE_READ(mm, stack_vm) * 4096;
  }

  metrics.thread_count = 1;

  bpf_map_update_elem(&process_start_times, &pid, &now, BPF_ANY);
  bpf_map_update_elem(&process_metrics_map, &pid, &metrics, BPF_ANY);
  u32 count = 1;
  bpf_map_update_elem(&thread_count_map, &tgid, &count, BPF_ANY);

  struct process_metrics *event =
      bpf_ringbuf_reserve(&events, sizeof(struct process_metrics), 0);
  if (event) {
    __builtin_memcpy(event, &metrics, sizeof(struct process_metrics));
    bpf_ringbuf_submit(event, 0);
  }

  return 0;
}

// Track process exit to clean up maps
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

  // Check if this is a thread or the main process
  if (pid != tgid) {
    // This is a thread exit, decrement thread count for the process
    u32 *count = bpf_map_lookup_elem(&thread_count_map, &tgid);
    if (count && *count > 0) {
      (*count)--;
      bpf_map_update_elem(&thread_count_map, &tgid, count, BPF_ANY);
    }
  } else {
    // This is the main process exiting
    // Send a final update to userspace
    struct process_metrics *metrics =
        bpf_map_lookup_elem(&process_metrics_map, &pid);
    if (metrics) {
      metrics->last_update_ns = bpf_ktime_get_ns();

      struct process_metrics *event =
          bpf_ringbuf_reserve(&events, sizeof(struct process_metrics), 0);
      if (event) {
        __builtin_memcpy(event, metrics, sizeof(struct process_metrics));
        bpf_ringbuf_submit(event, 0);
      }

      // Clean up maps
      bpf_map_delete_elem(&process_metrics_map, &pid);
      bpf_map_delete_elem(&process_start_times, &pid);
      bpf_map_delete_elem(&thread_count_map, &pid);
    }
  }

  return 0;
}

// Track thread creation
SEC("tracepoint/sched/sched_process_fork")
int trace_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
  u32 parent_pid = ctx->parent_pid;
  u32 child_pid = ctx->child_pid;
  u32 child_tgid = 0;

  // Possible bug, assuming that child_tgid = child_pid (new process)
  child_tgid = child_pid;

  // Handle in userspace: can do additional detection in userspace or use
  // /proc to determine thread vs process relationships

  if (child_tgid == parent_pid) {
    // This is a new thread for an existing process
    // Increment thread count for the process
    u32 *count = bpf_map_lookup_elem(&thread_count_map, &parent_pid);
    if (count) {
      (*count)++;
      bpf_map_update_elem(&thread_count_map, &parent_pid, count, BPF_ANY);

      // Update the thread_count in the process metrics
      struct process_metrics *metrics =
          bpf_map_lookup_elem(&process_metrics_map, &parent_pid);
      if (metrics) {
        metrics->thread_count = *count;
        metrics->last_update_ns = bpf_ktime_get_ns();

        // Send update to userspace
        struct process_metrics *event =
            bpf_ringbuf_reserve(&events, sizeof(struct process_metrics), 0);
        if (event) {
          __builtin_memcpy(event, metrics, sizeof(struct process_metrics));
          bpf_ringbuf_submit(event, 0);
        }
      }
    }
  } else {
    // This is a new process (clone with CLONE_THREAD not set)
    // Initialize thread count for this new process
    u32 count = 1;
    bpf_map_update_elem(&thread_count_map, &child_tgid, &count, BPF_ANY);
  }

  return 0;
}

// Track CPU usage when a process is scheduled
SEC("tp/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx) {
  u32 prev_pid = ctx->prev_pid;
  u32 next_pid = ctx->next_pid;
  u64 now = bpf_ktime_get_ns();

  // Handle the process being switched out
  if (prev_pid > 0) {
    // Look up the last time this process was scheduled in
    u64 *last_start = bpf_map_lookup_elem(&process_start_times, &prev_pid);
    if (last_start && *last_start > 0) {
      u64 delta = now - *last_start;

      // Update CPU time in the process metrics
      struct process_metrics *metrics =
          bpf_map_lookup_elem(&process_metrics_map, &prev_pid);
      if (metrics) {
        metrics->cpu_ns += delta;
        metrics->last_update_ns = now;
      }

      // Reset the start time to 0 since the process is not running
      u64 zero = 0;
      bpf_map_update_elem(&process_start_times, &prev_pid, &zero, BPF_ANY);
    }
  }

  // Handle the process being scheduled in
  if (next_pid > 0) {
    // Set the start time for the next process
    bpf_map_update_elem(&process_start_times, &next_pid, &now, BPF_ANY);
  }

  return 0;
}

// Periodically send CPU usage updates to userspace
SEC("perf_event")
int collect_cpu_metrics(struct bpf_perf_event_data *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct process_metrics *metrics =
      bpf_map_lookup_elem(&process_metrics_map, &pid);
  if (metrics) {
    // Update last_update timestamp
    metrics->last_update_ns = bpf_ktime_get_ns();

    // Update thread count from thread count map
    u32 tgid = metrics->tgid;
    u32 *thread_count = bpf_map_lookup_elem(&thread_count_map, &tgid);
    if (thread_count) {
      metrics->thread_count = *thread_count;
    }

    // Send to userspace
    struct process_metrics *event =
        bpf_ringbuf_reserve(&events, sizeof(struct process_metrics), 0);
    if (event) {
      __builtin_memcpy(event, metrics, sizeof(struct process_metrics));
      bpf_ringbuf_submit(event, 0);
    }
  }

  return 0;
}

// Track memory allocations
SEC("tp/mm/mm_page_alloc")
int trace_mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct process_metrics *metrics =
      bpf_map_lookup_elem(&process_metrics_map, &pid);
  if (metrics) {
    // Update memory metrics
    metrics->rss_bytes += 4096; // 4KB page size
    metrics->last_update_ns = bpf_ktime_get_ns();
  }

  return 0;
}

// Track memory deallocations
SEC("tp/mm/mm_page_free")
int trace_mm_page_free(struct trace_event_raw_mm_page_free *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct process_metrics *metrics =
      bpf_map_lookup_elem(&process_metrics_map, &pid);
  if (metrics && metrics->rss_bytes >= 4096) {
    // Update memory metrics (avoid underflow)
    metrics->rss_bytes -= 4096; // Assuming 4KB page size
    metrics->last_update_ns = bpf_ktime_get_ns();
  }

  return 0;
}

// For more accurate memory usage, we can track rss_stat events
SEC("tracepoint/vm/rss_stat")
int trace_rss_stat(struct trace_event_raw_rss_stat *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // Only proceed if this is a process-level RSS event
  if (ctx->member != 0) { // MM_FILEPAGES, MM_ANONPAGES, etc.
    return 0;
  }

  struct process_metrics *metrics =
      bpf_map_lookup_elem(&process_metrics_map, &pid);
  if (metrics) {
    // This provides a more accurate total RSS
    // We get absolute values rather than deltas
    u64 rss = (u64)ctx->size * 4096; // Convert pages to bytes

    // Only update if it makes sense (non-zero and not obviously wrong)
    if (rss > 0 && rss < (1ULL << 40)) { // Sanity check: < 1TB
      metrics->rss_bytes = rss;
      metrics->last_update_ns = bpf_ktime_get_ns();

      // Send an update to userspace on significant changes
      struct process_metrics *event =
          bpf_ringbuf_reserve(&events, sizeof(struct process_metrics), 0);
      if (event) {
        __builtin_memcpy(event, metrics, sizeof(struct process_metrics));
        bpf_ringbuf_submit(event, 0);
      }
    }
  }

  return 0;
}

// Get accurate VM statistics through task_struct when available
SEC("kprobe/account_page_dirtied")
int kprobe_account_page_dirtied(struct pt_regs *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct process_metrics *metrics =
      bpf_map_lookup_elem(&process_metrics_map, &pid);
  if (metrics) {
    // Get task struct for accessing mm info
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm;
    BPF_CORE_READ_INTO(&mm, task, mm);

    if (mm) {
      // Update VM size from mm struct (more accurate)
      metrics->vm_size = BPF_CORE_READ(mm, total_vm) * 4096;

      // Also update stack size while we're here
      metrics->stack_size = BPF_CORE_READ(mm, stack_vm) * 4096;

      metrics->last_update_ns = bpf_ktime_get_ns();
    }
  }

  return 0;
}

// Periodically fetch accurate metrics from the task struct
SEC("perf_event")
int collect_memory_metrics(struct bpf_perf_event_data *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct process_metrics *metrics =
      bpf_map_lookup_elem(&process_metrics_map, &pid);
  if (metrics) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm;
    BPF_CORE_READ_INTO(&mm, task, mm);

    if (mm) {
      unsigned long rss = 0;
      s64 file_pages = 0, anon_pages = 0, shmem_pages = 0;

      file_pages = BPF_CORE_READ(mm, rss_stat[MM_FILEPAGES].count);
      anon_pages = BPF_CORE_READ(mm, rss_stat[MM_ANONPAGES].count);
      shmem_pages = BPF_CORE_READ(mm, rss_stat[MM_SHMEMPAGES].count);

      rss = (unsigned long)(file_pages + anon_pages + shmem_pages);

      metrics->rss_bytes = rss * 4096;
      metrics->vm_size = BPF_CORE_READ(mm, total_vm) * 4096;
      metrics->stack_size = BPF_CORE_READ(mm, stack_vm) * 4096;

      metrics->last_update_ns = bpf_ktime_get_ns();

      // Send metrics to userspace
      struct process_metrics *event =
          bpf_ringbuf_reserve(&events, sizeof(struct process_metrics), 0);
      if (event) {
        __builtin_memcpy(event, metrics, sizeof(struct process_metrics));
        bpf_ringbuf_submit(event, 0);
      }
    }
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
