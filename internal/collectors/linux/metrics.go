//go:build linux

package linux

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/LaLegende971/mirador-agent/internal/inventory"
)

func loadAverage1m() (float64, bool) {
	f, err := os.Open("/proc/loadavg")
	if err != nil {
		return 0, false
	}
	defer f.Close()

	var line string
	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		line = scanner.Text()
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	return v, err == nil
}

func memoryUsedPercent() (float64, bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	defer f.Close()

	values := map[string]float64{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		v, err := strconv.ParseFloat(fields[1], 64)
		if err == nil {
			values[key] = v
		}
	}
	total, ok1 := values["MemTotal"]
	avail, ok2 := values["MemAvailable"]
	if !ok1 || !ok2 || total == 0 {
		return 0, false
	}
	return (total - avail) / total * 100, true
}

func diskUsedPercent(mount string) (float64, bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mount, &stat); err != nil {
		return 0, false
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	if total == 0 {
		return 0, false
	}
	return float64(total-free) / float64(total) * 100, true
}

// failedUnitsCount : nombre d'unités systemd en échec. Un indicateur agrégé plutôt qu'un
// état par service — le filtrage par service surveillé viendra avec la configuration
// résolue (étape 3, GET /api/v1/agent/config), pas encore disponible à ce stade.
func failedUnitsCount() (float64, bool) {
	out, err := exec.Command("systemctl", "list-units", "--failed", "--no-legend", "--plain").Output()
	if err != nil {
		return 0, false
	}
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return float64(count), true
}

func CollectMetrics() []inventory.MetricPoint {
	now := time.Now().UTC()
	var points []inventory.MetricPoint

	add := func(key string, value float64, ok bool) {
		if ok {
			points = append(points, inventory.MetricPoint{Time: now, MetricKey: key, Value: value})
		}
	}

	if v, ok := loadAndDivideByCPUs(); ok {
		add("cpu.load", v, ok)
	}
	if v, ok := memoryUsedPercent(); ok {
		add("memory.used_pct", v, ok)
	}
	if v, ok := diskUsedPercent("/"); ok {
		add("disk.root.used_pct", v, ok)
	}
	if v, ok := failedUnitsCount(); ok {
		add("services.failed_count", v, ok)
	}

	return points
}

// loadAndDivideByCPUs ramène la charge 1 min au nombre de coeurs, en pourcentage (0-100+) :
// le catalogue d'intégrations déclare "cpu.load.threshold" avec unit=percent (voir
// be3c109dfcfa_seed_catalogue_intégrations.py), et le collecteur Windows envoie déjà un vrai
// pourcentage (\Processor(_Total)\% Processor Time). Sans le ×100, un ratio brut (0-1) ne
// franchit quasiment jamais un seuil à 90 — l'alerte CPU serait de fait inopérante sur Linux.
func loadAndDivideByCPUs() (float64, bool) {
	load, ok := loadAverage1m()
	if !ok {
		return 0, false
	}
	cpus := numCPU()
	if cpus <= 0 {
		return load * 100, true
	}
	return load / float64(cpus) * 100, true
}

func numCPU() int {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "processor") {
			count++
		}
	}
	return count
}
