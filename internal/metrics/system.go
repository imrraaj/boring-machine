package metrics

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SystemStats struct {
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	MemoryUsedMB    uint64  `json:"memory_used_mb"`
	MemoryTotalMB   uint64  `json:"memory_total_mb"`
	MemoryPercent   float64 `json:"memory_percent"`
	NumGoroutines   int     `json:"num_goroutines"`
	NumCPU          int     `json:"num_cpu"`
}

type cpuSample struct {
	user, nice, system, idle, iowait, irq, softirq uint64
}

const (
	KB = 1024
	MB = KB * 1024
	GB = MB * 1024
)

var (
	lastSample cpuSample
	lastTime   time.Time
	cpuMutex   sync.Mutex
)

func (s cpuSample) total() uint64 {
	return s.user + s.nice + s.system + s.idle + s.iowait + s.irq + s.softirq
}

func GetSystemStats() SystemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	memUsedMB := m.Alloc / MB
	memTotalMB := m.Sys / MB
	memPercent := 0.0
	if memTotalMB > 0 {
		memPercent = float64(memUsedMB) / float64(memTotalMB) * 100.0
	}

	return SystemStats{
		CPUUsagePercent: getCPUUsage(),
		MemoryUsedMB:    memUsedMB,
		MemoryTotalMB:   memTotalMB,
		MemoryPercent:   memPercent,
		NumGoroutines:   runtime.NumGoroutine(),
		NumCPU:          runtime.NumCPU(),
	}
}

func getCPUUsage() float64 {
	cpuMutex.Lock()
	defer cpuMutex.Unlock()

	sample1, err := readCPUSample()
	if err != nil {
		return 0.0
	}

	time.Sleep(100 * time.Millisecond)
	sample2, err := readCPUSample()
	if err != nil {
		return 0.0
	}

	lastSample = sample2
	lastTime = time.Now()

	totalDelta := sample2.total() - sample1.total()
	idleDelta := sample2.idle - sample1.idle

	if totalDelta == 0 {
		return 0.0
	}

	return float64(totalDelta-idleDelta) / float64(totalDelta) * 100.0
}

func readCPUSample() (cpuSample, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}

	lines := strings.SplitSeq(string(data), "\n")
	for line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) >= 8 {
				return cpuSample{
					user:    parseUint(fields[1]),
					nice:    parseUint(fields[2]),
					system:  parseUint(fields[3]),
					idle:    parseUint(fields[4]),
					iowait:  parseUint(fields[5]),
					irq:     parseUint(fields[6]),
					softirq: parseUint(fields[7]),
				}, nil
			}
		}
	}
	return cpuSample{}, fmt.Errorf("cpu line not found in /proc/stat")
}

func parseUint(s string) uint64 {
	val, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return val
}
