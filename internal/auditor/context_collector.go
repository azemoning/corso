package auditor

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

// ProcessInfo holds metadata about a process from /proc
type ProcessInfo struct {
	Comm    string `json:"comm"`
	PPid    int32  `json:"ppid"`
	UID     int32  `json:"uid"`
	GID     int32  `json:"gid"`
	CmdLine string `json:"cmdline"`
}

// Connection represents a TCP connection from /proc/<pid>/net/tcp
type Connection struct {
	LocalAddress  string `json:"local_address"`
	RemoteAddress string `json:"remote_address"`
	State         string `json:"state"`
}

// CollectProcessInfo reads process metadata from /proc/<pid>/
func CollectProcessInfo(pid int32) ProcessInfo {
	info := ProcessInfo{}

	// Read comm
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		info.Comm = strings.TrimSpace(string(data))
	} else {
		klog.V(4).Infof("Failed to read /proc/%d/comm: %v", pid, err)
	}

	// Read ppid and uid/gid from status
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if ppid, err := strconv.ParseInt(fields[1], 10, 32); err == nil {
						info.PPid = int32(ppid)
					}
				}
			} else if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if uid, err := strconv.ParseInt(fields[1], 10, 32); err == nil {
						info.UID = int32(uid)
					}
				}
			} else if strings.HasPrefix(line, "Gid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if gid, err := strconv.ParseInt(fields[1], 10, 32); err == nil {
						info.GID = int32(gid)
					}
				}
			}
		}
	} else {
		klog.V(4).Infof("Failed to read /proc/%d/status: %v", pid, err)
	}

	// Read cmdline
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		// cmdline is null-separated, convert to spaces
		info.CmdLine = strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
	} else {
		klog.V(4).Infof("Failed to read /proc/%d/cmdline: %v", pid, err)
	}

	return info
}

// CollectNetworkConnections reads TCP connections from /proc/<pid>/net/tcp
func CollectNetworkConnections(pid int32) []Connection {
	var conns []Connection

	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/tcp", pid))
	if err != nil {
		klog.V(4).Infof("Failed to read /proc/%d/net/tcp: %v", pid, err)
		return conns
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // skip header and empty lines
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		local := parseAddr(fields[1])
		remote := parseAddr(fields[2])
		state := tcpState(fields[3])

		conns = append(conns, Connection{
			LocalAddress:  local,
			RemoteAddress: remote,
			State:         state,
		})
	}

	return conns
}

// CollectOpenFiles lists symlinks in /proc/<pid>/fd/
func CollectOpenFiles(pid int32) []string {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		klog.V(4).Infof("Failed to read /proc/%d/fd: %v", pid, err)
		return nil
	}

	var files []string
	for _, entry := range entries {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if err != nil {
			continue
		}
		files = append(files, link)
	}
	return files
}

// FormatContextString returns a compact context string for alert messages
func FormatContextString(info *ProcessInfo) string {
	if info == nil {
		return ""
	}
	return fmt.Sprintf("process=%s uid=%d cmdline=%s", info.Comm, info.UID, info.CmdLine)
}

// parseAddr parses a hex IP:port pair from /proc/net/tcp format (e.g., "0100007F:0050")
func parseAddr(hex string) string {
	parts := strings.SplitN(hex, ":", 2)
	if len(parts) != 2 {
		return hex
	}

	ipHex := parts[0]
	portHex := parts[1]

	// Parse IPv4 (little-endian hex)
	if len(ipHex) == 8 {
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, _ := strconv.ParseUint(ipHex[i*2:(i+1)*2], 16, 8)
			b[i] = byte(v)
		}
		port, _ := strconv.ParseUint(portHex, 16, 16)
		return fmt.Sprintf("%d.%d.%d.%d:%d", b[0], b[1], b[2], b[3], port)
	}

	return hex
}

// tcpState converts a hex TCP state code to a human-readable string
func tcpState(hex string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	if s, ok := states[hex]; ok {
		return s
	}
	return hex
}
