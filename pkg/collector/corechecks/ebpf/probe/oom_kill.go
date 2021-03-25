// +build linux_bpf

//go:generate go run ../../../../ebpf/include_headers.go ../c/runtime/oom-kill-kern.c ../../../../ebpf/bytecode/build/runtime/oom-kill.c ../../../../ebpf/c
//go:generate go run ../../../../ebpf/bytecode/runtime/integrity.go ../../../../ebpf/bytecode/build/runtime/oom-kill.c ../../../../ebpf/bytecode/runtime/oom-kill.go runtime

package probe

import (
	"fmt"
	"math"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	bpflib "github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode/runtime"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

/*
#include <string.h>
#include "../c/runtime/oom-kill-kern-user.h"
*/
import "C"

const oomMapName = "oom_stats"

type OOMKillProbe struct {
	m      *manager.Manager
	oomMap *bpflib.Map
}

func NewOOMKillProbe(cfg *ebpf.Config) (*OOMKillProbe, error) {
	compiledOutput, err := runtime.OomKill.Compile(cfg, nil)
	if err != nil {
		return nil, err
	}
	defer compiledOutput.Close()

	probes := []*manager.Probe{
		&manager.Probe{
			Section: "kprobe/oom_kill_process",
		},
	}

	maps := []*manager.Map{
		{Name: "oom_stats"},
	}

	m := &manager.Manager{
		Probes: probes,
		Maps:   maps,
	}

	managerOptions := manager.Options{
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	if err := m.InitWithOptions(compiledOutput, managerOptions); err != nil {
		return nil, errors.Wrap(err, "failed to init manager")
	}

	if err := m.Start(); err != nil {
		return nil, errors.Wrap(err, "failed to start manager")
	}

	oomMap, ok, err := m.GetMap(oomMapName)
	if err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("failed to get map '%s'", statsMapName)
	}

	return &OOMKillProbe{
		m:      m,
		oomMap: oomMap,
	}, nil
}

func (k *OOMKillProbe) Close() {
	k.m.Stop(manager.CleanAll)
}

func (k *OOMKillProbe) GetAndFlush() []OOMKillStats {
	results := k.Get()
	var pid uint32
	var stat C.struct_oom_stats
	it := k.oomMap.Iterate()
	for it.Next(&pid, unsafe.Pointer(&stat)) {
		if err := k.oomMap.Delete(&pid); err != nil {
			log.Warnf("failed to delete stat: %s", err)
		}
	}

	if err := it.Err(); err != nil {
		log.Warnf("failed to iterate on OOM stats while flushing: %s", err)
	}

	return results
}

func (k *OOMKillProbe) Get() (results []OOMKillStats) {
	if k == nil {
		return nil
	}

	var pid uint32
	var stat C.struct_oom_stats
	it := k.oomMap.Iterate()
	for it.Next(&pid, unsafe.Pointer(&stat)) {
		results = append(results, convertStats(stat))
	}

	if err := it.Err(); err != nil {
		log.Warnf("failed to iterate on OOM stats: %s", err)
	}

	log.Debugf("OOM Kill stats gathered from kernel probe: %v", results)
	return
}

func convertStats(in C.struct_oom_stats) (out OOMKillStats) {
	out.ContainerID = C.GoString(&in.cgroup_name[0])
	out.Pid = uint32(in.pid)
	out.TPid = uint32(in.tpid)
	out.FComm = C.GoString(&in.fcomm[0])
	out.TComm = C.GoString(&in.tcomm[0])
	out.Pages = uint64(in.pages)
	out.MemCgOOM = uint32(in.memcg_oom)
	return
}
