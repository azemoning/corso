package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"k8s.io/klog/v2"
)

// LoadedProgram represents an eBPF program loaded in the kernel
type LoadedProgram struct {
	ID            uint32         `json:"id"`
	Name          string         `json:"name"`
	Type          string         `json:"type"`
	Tag           string         `json:"tag"`
	VerifiedInsns uint32         `json:"verified_insns"`
	MapIDs        []uint32       `json:"map_ids"`
}

// EnumeratePrograms iterates over all loaded eBPF programs in the kernel
// using BPF_PROG_GET_NEXT_ID syscall (via cilium/ebpf)
func EnumeratePrograms() ([]LoadedProgram, error) {
	var programs []LoadedProgram
	var nextID ebpf.ProgramID

	for {
		id, err := ebpf.ProgramGetNextID(nextID)
		if err != nil {
			// ENOENT or no more programs
			break
		}

		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			klog.V(4).Infof("Failed to get program %d: %v (may have been unloaded)", id, err)
			nextID = id
			continue
		}

		info, err := prog.Info()
		if err != nil {
			klog.V(4).Infof("Failed to get info for program %d: %v", id, err)
			prog.Close()
			nextID = id
			continue
		}

		loaded := LoadedProgram{
			ID:   uint32(id),
			Name: info.Name,
			Type: info.Type.String(),
			Tag:  info.Tag,
		}

		// Call getter methods for optional fields
		if v, ok := info.VerifiedInstructions(); ok {
			loaded.VerifiedInsns = v
		}
		if v, ok := info.MapIDs(); ok {
			for _, mapID := range v {
				loaded.MapIDs = append(loaded.MapIDs, uint32(mapID))
			}
		}

		programs = append(programs, loaded)
		prog.Close()
		nextID = id
	}

	return programs, nil
}

// GetProgramCount returns the total number of loaded eBPF programs
func GetProgramCount() (int, error) {
	count := 0
	var nextID ebpf.ProgramID

	for {
		id, err := ebpf.ProgramGetNextID(nextID)
		if err != nil {
			break
		}
		count++
		nextID = id
	}

	return count, nil
}

// ProgramTypeStats returns a count of programs by type
func ProgramTypeStats() (map[string]int, error) {
	stats := make(map[string]int)
	var nextID ebpf.ProgramID

	for {
		id, err := ebpf.ProgramGetNextID(nextID)
		if err != nil {
			break
		}

		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			nextID = id
			continue
		}

		info, err := prog.Info()
		if err != nil {
			prog.Close()
			nextID = id
			continue
		}

		stats[info.Type.String()]++
		prog.Close()
		nextID = id
	}

	return stats, nil
}

// FormatProgramSummary returns a human-readable summary
func FormatProgramSummary(programs []LoadedProgram) string {
	summary := fmt.Sprintf("Total eBPF programs: %d\n", len(programs))

	typeCounts := make(map[string]int)
	for _, p := range programs {
		typeCounts[p.Type]++
	}

	for ptype, count := range typeCounts {
		summary += fmt.Sprintf("  %s: %d\n", ptype, count)
	}

	return summary
}
