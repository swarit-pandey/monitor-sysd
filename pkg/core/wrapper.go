package core

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
)

// Monitor represents the eBPF monitoring system
type Monitor struct {
	objects    monitorObjects
	cpuLink    link.Link
	memLink    link.Link
	stopChan   chan struct{}
	cpuMetrics map[uint32]*monitorCpuMetrics
	memMetrics map[uint32]*monitorMemMetrics
	lock       sync.Mutex // Protects access to metrics maps
}

// checkTracepointExists checks if a tracepoint exists
func checkTracepointExists(category, name string) bool {
	// Check in both possible locations
	paths := []string{
		fmt.Sprintf("/sys/kernel/tracing/events/%s/%s", category, name),
		fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s", category, name),
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// findMemoryTracepoint tries to find a suitable memory tracepoint
func findMemoryTracepoint() (string, string, bool) {
	// Check common memory tracepoint locations
	tracepointOptions := []struct {
		category string
		name     string
	}{
		{"vm", "rss_stat"},
		{"kmem", "rss_stat"},
		{"mm", "rss_stat"},
	}

	for _, tp := range tracepointOptions {
		if checkTracepointExists(tp.category, tp.name) {
			return tp.category, tp.name, true
		}
	}

	return "", "", false
}

// NewMonitor creates a new Monitor instance
func NewMonitor() (*Monitor, error) {
	var objects monitorObjects

	// Load the eBPF objects
	if err := loadMonitorObjects(&objects, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	m := &Monitor{
		objects:    objects,
		stopChan:   make(chan struct{}),
		cpuMetrics: make(map[uint32]*monitorCpuMetrics),
		memMetrics: make(map[uint32]*monitorMemMetrics),
	}

	return m, nil
}

// Start attaches the eBPF programs and begins monitoring
func (m *Monitor) Start() error {
	// Attach tracepoints for CPU monitoring
	tpSched, err := link.Tracepoint("sched", "sched_switch", m.objects.HandleSchedSwitch, nil)
	if err != nil {
		m.Close()
		return fmt.Errorf("attaching sched_switch tracepoint: %w", err)
	}
	m.cpuLink = tpSched

	// Try to find and attach the memory tracepoint
	memCategory, memName, found := findMemoryTracepoint()
	if !found {
		fmt.Println("Warning: Could not find memory tracepoint. Memory metrics will not be available.")
	} else {
		tpMem, err := link.Tracepoint(memCategory, memName, m.objects.HandleRssStat, nil)
		if err != nil {
			fmt.Printf("Warning: Failed to attach %s/%s tracepoint: %v\n", memCategory, memName, err)
			fmt.Println("Memory metrics will not be available.")
		} else {
			m.memLink = tpMem
		}
	}

	// Set up map polling with panic recovery
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Recovered from panic in pollMaps: %v\n", r)
				fmt.Fprintf(os.Stderr, "Stack trace:\n%s\n", debug.Stack())
			}
		}()
		m.pollMaps()
	}()

	// Start a goroutine to periodically print metrics with panic recovery
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Recovered from panic in periodicPrint: %v\n", r)
				fmt.Fprintf(os.Stderr, "Stack trace:\n%s\n", debug.Stack())
			}
		}()
		m.periodicPrint()
	}()

	return nil
}

// pollMaps periodically reads from the eBPF maps
func (m *Monitor) pollMaps() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			// Wrap each operation in its own recovery block
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "Panic in ReadCpuMap: %v\n", r)
					}
				}()
				if err := m.ReadCpuMap(); err != nil {
					fmt.Fprintf(os.Stderr, "Error reading CPU map: %v\n", err)
				}
			}()

			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "Panic in ReadMemMap: %v\n", r)
					}
				}()
				if err := m.ReadMemMap(); err != nil {
					fmt.Fprintf(os.Stderr, "Error reading Memory map: %v\n", err)
				}
			}()

			// Print raw events from maps as sanity check
			m.PrintRawEvents()
		}
	}
}

// PrintRawEvents prints raw events from eBPF maps as a sanity check
func (m *Monitor) PrintRawEvents() {
	m.lock.Lock()
	defer m.lock.Unlock()

	fmt.Println("======= RAW EVENTS FROM eBPF MAPS =======")

	// Print raw CPU map data
	fmt.Println("CPU Map contents:")
	var cpuKey uint32
	var cpuValue monitorCpuMetrics
	cpuIter := m.objects.CpuMap.Iterate()
	count := 0
	for cpuIter.Next(&cpuKey, &cpuValue) {
		fmt.Printf("  Key: %d, TGID: %d, CPU_ns: %d, Last_sched_ns: %d, Comm: %s\n",
			cpuKey, cpuValue.Tgid, cpuValue.CpuNs, cpuValue.LastSchedNs,
			bytesToString(cpuValue.Comm[:]))
		count++
		if count >= 5 {
			fmt.Println("  ... (more entries omitted)")
			break
		}
	}
	if count == 0 {
		fmt.Println("  No entries")
	}

	// Print raw Memory map data
	fmt.Println("Memory Map contents:")
	var memKey uint32
	var memValue monitorMemMetrics
	memIter := m.objects.MemMap.Iterate()
	count = 0
	for memIter.Next(&memKey, &memValue) {
		fmt.Printf("  Key: %d, RSS: %d, VM: %d, LastUpdate: %d, CgroupID: %d, Comm: %s\n",
			memKey, memValue.RssBytes, memValue.VmSize, memValue.LastUpdateNs,
			memValue.CgroupId, bytesToString(memValue.Comm[:]))
		count++
		if count >= 5 {
			fmt.Println("  ... (more entries omitted)")
			break
		}
	}
	if count == 0 {
		fmt.Println("  No entries")
	}

	fmt.Println("==========================================")
}

// periodicPrint prints metrics at regular intervals
func (m *Monitor) periodicPrint() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "Panic in PrintMetrics: %v\n", r)
					}
				}()
				m.PrintMetrics()
			}()
		}
	}
}

// PrintMetrics prints the current CPU and memory metrics
func (m *Monitor) PrintMetrics() {
	m.lock.Lock()
	defer m.lock.Unlock()

	fmt.Println("============ CPU Metrics ============")
	if len(m.cpuMetrics) == 0 {
		fmt.Println("No CPU metrics collected yet")
	} else {
		count := 0
		for pid, metric := range m.cpuMetrics {
			if metric == nil {
				continue // Skip nil metrics to avoid panic
			}
			commStr := bytesToString(metric.Comm[:])
			cpuTime := time.Duration(metric.CpuNs) * time.Nanosecond
			fmt.Printf("PID: %d, Command: %s, CPU Time: %v\n", pid, commStr, cpuTime)
			count++
			if count >= 10 {
				fmt.Printf("... and %d more entries\n", len(m.cpuMetrics)-10)
				break
			}
		}
	}

	fmt.Println("\n============ Memory Metrics ============")
	if len(m.memMetrics) == 0 {
		fmt.Println("No memory metrics collected yet")
	} else {
		count := 0
		for cgroupId, metric := range m.memMetrics {
			if metric == nil {
				continue // Skip nil metrics to avoid panic
			}
			commStr := bytesToString(metric.Comm[:])
			rssBytes := metric.RssBytes / 1024 / 1024 // Convert to MB
			vmSize := metric.VmSize / 1024 / 1024     // Convert to MB
			fmt.Printf("CgroupID: %d, Command: %s, RSS: %d MB, VM Size: %d MB\n",
				cgroupId, commStr, rssBytes, vmSize)
			count++
			if count >= 10 {
				fmt.Printf("... and %d more entries\n", len(m.memMetrics)-10)
				break
			}
		}
	}
	fmt.Println("======================================")
}

// bytesToString converts a byte array to a Go string
func bytesToString(bytes []int8) string {
	var result []byte
	for _, b := range bytes {
		if b == 0 {
			break
		}
		result = append(result, byte(b))
	}
	return string(result)
}

// ReadCpuMap reads data directly from the CPU map
func (m *Monitor) ReadCpuMap() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	// Clear existing metrics to avoid stale data
	m.cpuMetrics = make(map[uint32]*monitorCpuMetrics)

	var key uint32
	var value monitorCpuMetrics

	iter := m.objects.CpuMap.Iterate()
	for iter.Next(&key, &value) {
		// Make a copy of the value to store in the map
		valueCopy := value
		m.cpuMetrics[key] = &valueCopy
	}
	return iter.Err()
}

// ReadMemMap reads data directly from the Memory map
func (m *Monitor) ReadMemMap() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	// Clear existing metrics to avoid stale data
	m.memMetrics = make(map[uint32]*monitorMemMetrics)

	var key uint32
	var value monitorMemMetrics

	iter := m.objects.MemMap.Iterate()
	for iter.Next(&key, &value) {
		// Make a copy of the value to store in the map
		valueCopy := value
		m.memMetrics[key] = &valueCopy
	}
	return iter.Err()
}

// ListTracepoints lists all available tracepoints in the system
func ListTracepoints() ([]string, error) {
	var tracepoints []string

	// Check both possible paths for tracepoints
	tracePaths := []string{
		"/sys/kernel/tracing/events",
		"/sys/kernel/debug/tracing/events",
	}

	for _, tracePath := range tracePaths {
		if _, err := os.Stat(tracePath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(tracePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Look for id files which indicate an actual tracepoint
			if !info.IsDir() && info.Name() == "id" {
				// Extract the category and name from the path
				relPath, err := filepath.Rel(tracePath, filepath.Dir(path))
				if err != nil {
					return nil
				}
				tracepoints = append(tracepoints, relPath)
			}
			return nil
		})

		if err != nil {
			return nil, err
		}
	}

	return tracepoints, nil
}

// DebugTracepoints prints all available tracepoints for debugging
func DebugTracepoints() {
	tracepoints, err := ListTracepoints()
	if err != nil {
		fmt.Printf("Error listing tracepoints: %v\n", err)
		return
	}

	fmt.Println("Available tracepoints:")

	// Group tracepoints by category
	categories := make(map[string][]string)
	for _, tp := range tracepoints {
		parts := strings.Split(tp, "/")
		if len(parts) > 0 {
			category := parts[0]
			categories[category] = append(categories[category], tp)
		}
	}

	// Print grouped tracepoints
	for category, tps := range categories {
		fmt.Printf("Category %s:\n", category)
		for _, tp := range tps {
			fmt.Printf("  %s\n", tp)
		}
	}
}

// RunMonitorWithSignalHandling starts the monitor and handles termination signals
func (m *Monitor) RunMonitorWithSignalHandling(ctx context.Context) error {
	// Debug: List available tracepoints to help diagnose issues
	fmt.Println("Listing available tracepoints...")
	DebugTracepoints()

	if err := m.Start(); err != nil {
		return err
	}

	fmt.Println("Monitor started successfully. Press Ctrl+C to exit.")

	// Set up signal handling
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// Wait for termination signal or context cancellation
	select {
	case <-signals:
		fmt.Println("Received termination signal")
	case <-ctx.Done():
		fmt.Println("Context cancelled")
	}

	// Clean up
	m.Close()
	return nil
}

// Close cleans up resources
func (m *Monitor) Close() error {
	// Signal goroutines to stop
	close(m.stopChan)

	// Close links
	if m.cpuLink != nil {
		m.cpuLink.Close()
	}
	if m.memLink != nil {
		m.memLink.Close()
	}

	// Close eBPF objects
	return m.objects.Close()
}

