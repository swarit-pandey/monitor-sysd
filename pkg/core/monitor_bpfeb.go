// Code generated by bpf2go; DO NOT EDIT.
//go:build (mips || mips64 || ppc64 || s390x) && linux

package core

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type monitorCpuMetrics struct {
	Tgid        uint32
	_           [4]byte
	CpuNs       uint64
	LastSchedNs uint64
	Comm        [16]int8
}

type monitorMemMetrics struct {
	RssBytes     uint64
	VmSize       uint64
	LastUpdateNs uint64
	CgroupId     uint32
	Comm         [16]int8
	_            [4]byte
}

// loadMonitor returns the embedded CollectionSpec for monitor.
func loadMonitor() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_MonitorBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load monitor: %w", err)
	}

	return spec, err
}

// loadMonitorObjects loads monitor and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*monitorObjects
//	*monitorPrograms
//	*monitorMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadMonitorObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadMonitor()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// monitorSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type monitorSpecs struct {
	monitorProgramSpecs
	monitorMapSpecs
	monitorVariableSpecs
}

// monitorProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type monitorProgramSpecs struct {
	HandleRssStat     *ebpf.ProgramSpec `ebpf:"handle_rss_stat"`
	HandleSchedSwitch *ebpf.ProgramSpec `ebpf:"handle_sched_switch"`
	SyncMmStruct      *ebpf.ProgramSpec `ebpf:"sync_mm_struct"`
}

// monitorMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type monitorMapSpecs struct {
	CpuMap *ebpf.MapSpec `ebpf:"cpu_map"`
	Events *ebpf.MapSpec `ebpf:"events"`
	MemMap *ebpf.MapSpec `ebpf:"mem_map"`
}

// monitorVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type monitorVariableSpecs struct {
}

// monitorObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadMonitorObjects or ebpf.CollectionSpec.LoadAndAssign.
type monitorObjects struct {
	monitorPrograms
	monitorMaps
	monitorVariables
}

func (o *monitorObjects) Close() error {
	return _MonitorClose(
		&o.monitorPrograms,
		&o.monitorMaps,
	)
}

// monitorMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadMonitorObjects or ebpf.CollectionSpec.LoadAndAssign.
type monitorMaps struct {
	CpuMap *ebpf.Map `ebpf:"cpu_map"`
	Events *ebpf.Map `ebpf:"events"`
	MemMap *ebpf.Map `ebpf:"mem_map"`
}

func (m *monitorMaps) Close() error {
	return _MonitorClose(
		m.CpuMap,
		m.Events,
		m.MemMap,
	)
}

// monitorVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadMonitorObjects or ebpf.CollectionSpec.LoadAndAssign.
type monitorVariables struct {
}

// monitorPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadMonitorObjects or ebpf.CollectionSpec.LoadAndAssign.
type monitorPrograms struct {
	HandleRssStat     *ebpf.Program `ebpf:"handle_rss_stat"`
	HandleSchedSwitch *ebpf.Program `ebpf:"handle_sched_switch"`
	SyncMmStruct      *ebpf.Program `ebpf:"sync_mm_struct"`
}

func (p *monitorPrograms) Close() error {
	return _MonitorClose(
		p.HandleRssStat,
		p.HandleSchedSwitch,
		p.SyncMmStruct,
	)
}

func _MonitorClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed monitor_bpfeb.o
var _MonitorBytes []byte
