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

// SystemStats contains system resource usage information
type SystemStats struct {
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	MemoryUsedMB    uint64  `json:"memory_used_mb"`
	MemoryTotalMB   uint64  `json:"memory_total_mb"`
	MemoryPercent   float64 `json:"memory_percent"`
	NumGoroutines   int     `json:"num_goroutines"`
	NumCPU          int     `json:"num_cpu"`
}

// cpuSample represents a snapshot of CPU statistics from /proc/stat
type cpuSample struct {
	user, nice, system, idle, iowait, irq, softirq uint64
}

var (
	lastSample cpuSample
	lastTime   time.Time
	cpuMutex   sync.Mutex
)

// total returns the sum of all CPU time fields
func (s cpuSample) total() uint64 {
	return s.user + s.nice + s.system + s.idle + s.iowait + s.irq + s.softirq
}

// GetSystemStats returns current system resource usage
func GetSystemStats() SystemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	memUsedMB := m.Alloc / 1024 / 1024
	memTotalMB := m.Sys / 1024 / 1024
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

// getCPUUsage calculates CPU usage percentage
func getCPUUsage() float64 {
	cpuMutex.Lock()
	defer cpuMutex.Unlock()

	sample1, err := readCPUSample()
	if err != nil {
		// Fallback: return 0 on error (non-Linux systems)
		return 0.0
	}

	// Use cached sample if less than 1 second old to avoid excessive /proc reads
	if time.Since(lastTime) < time.Second && lastTime.Unix() > 0 {
		total1 := sample1.total()
		total0 := lastSample.total()
		idle1 := sample1.idle
		idle0 := lastSample.idle

		totalDelta := total1 - total0
		idleDelta := idle1 - idle0

		if totalDelta == 0 {
			return 0.0
		}

		return float64(totalDelta-idleDelta) / float64(totalDelta) * 100.0
	}

	// Wait 100ms for delta measurement
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

// readCPUSample reads CPU statistics from /proc/stat (Linux only)
func readCPUSample() (cpuSample, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
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

// parseUint safely parses a string to uint64
func parseUint(s string) uint64 {
	val, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return val
}
