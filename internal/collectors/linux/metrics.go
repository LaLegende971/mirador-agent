//go:build linux

package linux

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
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

// readMemInfo lit /proc/meminfo une seule fois par cycle ; memoryUsedPercent et
// swapUsedPercent en partagent le résultat plutôt que de rouvrir le fichier chacune.
func readMemInfo() (map[string]float64, bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, false
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
	return values, true
}

func memoryUsedPercent(meminfo map[string]float64) (float64, bool) {
	total, ok1 := meminfo["MemTotal"]
	avail, ok2 := meminfo["MemAvailable"]
	if !ok1 || !ok2 || total == 0 {
		return 0, false
	}
	return (total - avail) / total * 100, true
}

// swapUsedPercent : comme le check_swap de Centreon — pourcentage utilisé, jamais remonté
// si aucun swap n'est configuré (SwapTotal=0) plutôt que d'envoyer un 0 % trompeur qui
// laisserait croire à un swap présent et vide.
func swapUsedPercent(meminfo map[string]float64) (float64, bool) {
	total, ok1 := meminfo["SwapTotal"]
	free, ok2 := meminfo["SwapFree"]
	if !ok1 || !ok2 || total == 0 {
		return 0, false
	}
	return (total - free) / total * 100, true
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

// agentMemoryBytes : RSS du processus mirador-agent lui-même, pas de l'hôte — empreinte
// affichée sur État pour vérifier que l'agent reste léger, jamais alertée (pas de seuil).
func agentMemoryBytes() (float64, bool) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "VmRSS:" {
			kb, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				return 0, false
			}
			return kb * 1024, true
		}
	}
	return 0, false
}

const clkTck = 100 // USER_HZ : fixe à 100 sur toutes les architectures Linux courantes

var (
	selfCPUMu      sync.Mutex
	selfLastTicks  float64
	selfLastSample time.Time
)

// agentCPUPercent : delta de temps CPU (utime+stime, /proc/self/stat) entre deux cycles de
// collecte, ramené au pourcentage du temps total écoulé sur l'ensemble des coeurs — même
// convention que loadAndDivideByCPUs pour cpu.load. Rien à envoyer au premier cycle (pas
// encore d'échantillon de référence pour calculer un delta).
func agentCPUPercent() (float64, bool) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, false
	}
	// Les champs après la parenthèse fermante du nom de commande (qui peut contenir des
	// espaces) sont à position fixe : utime est le 14e champ, stime le 15e.
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return 0, false
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 13 {
		return 0, false
	}
	utime, err1 := strconv.ParseFloat(fields[11], 64)
	stime, err2 := strconv.ParseFloat(fields[12], 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	ticks := utime + stime
	now := time.Now()

	selfCPUMu.Lock()
	lastTicks, lastSample := selfLastTicks, selfLastSample
	selfLastTicks, selfLastSample = ticks, now
	selfCPUMu.Unlock()

	if lastSample.IsZero() {
		return 0, false
	}
	elapsed := now.Sub(lastSample).Seconds()
	if elapsed <= 0 {
		return 0, false
	}
	cpus := numCPU()
	if cpus <= 0 {
		cpus = 1
	}
	return (ticks - lastTicks) / clkTck / elapsed / float64(cpus) * 100, true
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
	meminfo, _ := readMemInfo()
	if v, ok := memoryUsedPercent(meminfo); ok {
		add("memory.used_pct", v, ok)
	}
	if v, ok := swapUsedPercent(meminfo); ok {
		add("swap.used_pct", v, ok)
	}
	if v, ok := diskUsedPercent("/"); ok {
		add("disk.root.used_pct", v, ok)
	}
	if v, ok := failedUnitsCount(); ok {
		add("services.failed_count", v, ok)
	}
	if v, ok := agentCPUPercent(); ok {
		add("agent.cpu_pct", v, ok)
	}
	if v, ok := agentMemoryBytes(); ok {
		add("agent.memory_bytes", v, ok)
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
