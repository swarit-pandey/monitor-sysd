package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// MetricsEvent represents the data structure for process metrics events
type MetricsEvent struct {
	Pid          uint32
	Tgid         uint32
	CpuNs        uint64
	RssBytes     uint64
	VmSize       uint64
	StackSize    uint64
	ThreadCount  uint32
	StartTimeNs  uint64
	LastUpdateNs uint64
	CgroupID     uint32
	ProcessName  string
}

// EventReader to interact with eBPF's ring buffer
type EventReader struct {
	ringbufReader *ringbuf.Reader
	objects       *monitorObjects
	link          []link.Link
}

// NewEventReader returns new EventReader instance
func NewEventReader() (*EventReader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	var objs monitorObjects
	if err := loadMonitorObjects(&objs, nil); err != nil {
		return nil, err
	}

	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		objs.Close()
		return nil, err
	}

	links := make([]link.Link, 0)

	attachments := []struct {
		name     string
		typ      string
		category string
		event    string
		prog     *ebpf.Program
	}{
		{"sched_switch", "tracepoint", "sched", "sched_switch", objs.TraceSchedSwitch},
		{"sched_process_exec", "tracepoint", "sched", "sched_process_exec", objs.TraceProcessExec},
		{"sched_process_fork", "tracepoint", "sched", "sched_process_fork", objs.TraceProcessFork},
		{"sched_process_exit", "tracepoint", "sched", "sched_process_exit", objs.TraceProcessExit},
		{"rss_stat", "tracepoint", "kmem", "rss_stat", objs.TraceRssStat},
		{"mm_page_alloc", "tracepoint", "kmem", "mm_page_alloc", objs.TraceMmPageAlloc},
		{"mm_page_free", "tracepoint", "kmem", "mm_page_free", objs.TraceMmPageFree},
	}

	// Attach tracepoints
	for _, att := range attachments {
		if att.typ == "tracepoint" {
			l, err := link.Tracepoint(att.category, att.event, att.prog, nil)
			if err != nil {
				log.Printf("Warning: Failed to attach %s: %v", att.name, err)
				continue
			}
			links = append(links, l)
			log.Printf("Successfully attached %s", att.name)
		}
	}

	// Try attaching the kprobe
	if kprobeLink, err := link.Kprobe("account_page_dirtied", objs.KprobeAccountPageDirtied, nil); err != nil {
		log.Printf("Warning: Could not attach kprobe for account_page_dirtied: %v", err)
	} else {
		links = append(links, kprobeLink)
		log.Printf("Successfully attached kprobe account_page_dirtied")
	}

	// Not going to attach perf events for now - focus on getting basic data first

	if len(links) == 0 {
		rb.Close()
		objs.Close()
		return nil, fmt.Errorf("failed to attach any probes")
	}

	return &EventReader{
		objects:       &objs,
		ringbufReader: rb,
		link:          links,
	}, nil
}

// Read from eBPF ring buffer
func (r *EventReader) Read() (*MetricsEvent, error) {
	record, err := r.ringbufReader.Read()
	if err != nil {
		return nil, err
	}

	var internalMetrics monitorProcessMetrics
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &internalMetrics); err != nil {
		return nil, err
	}

	processNameBytes := make([]byte, len(internalMetrics.Comm))
	for i, v := range internalMetrics.Comm {
		processNameBytes[i] = byte(v)
	}
	processName := string(bytes.Trim(processNameBytes, "\x00"))

	return &MetricsEvent{
		Pid:          internalMetrics.Pid,
		Tgid:         internalMetrics.Tgid,
		CpuNs:        internalMetrics.CpuNs,
		RssBytes:     internalMetrics.RssBytes,
		VmSize:       internalMetrics.VmSize,
		StackSize:    internalMetrics.StackSize,
		ThreadCount:  internalMetrics.ThreadCount,
		StartTimeNs:  internalMetrics.StartTimeNs,
		LastUpdateNs: internalMetrics.LastUpdateNs,
		CgroupID:     internalMetrics.CgroupId,
		ProcessName:  processName,
	}, nil
}

// Close releases all resources
func (e *EventReader) Close() error {
	for _, l := range e.link {
		if l != nil {
			l.Close()
		}
	}

	if e.ringbufReader != nil {
		e.ringbufReader.Close()
	}

	if e.objects != nil {
		return e.objects.Close()
	}
	return nil
}
