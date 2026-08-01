//go:build windows

package windows

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LaLegende971/mirador-agent/internal/inventory"
)

// Get-Counter s'appuie sur l'API PDH sous le capot : on l'utilise plutôt que d'appeler
// pdh.dll directement en cgo/syscall, pour rester dans un unique mécanisme de collecte
// (PowerShell) cohérent avec le reste des collecteurs Windows de ce fichier.
func queryCounter(path string) (float64, bool) {
	script := `(Get-Counter '` + path + `').CounterSamples[0].CookedValue`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return 0, false
	}
	var v float64
	if err := json.Unmarshal(out, &v); err != nil {
		return 0, false
	}
	return v, true
}

// queryCounterSum additionne CookedValue sur toutes les instances d'un compteur PDH — pour
// le réseau, une instance par carte, jamais de détail par carte souhaité ici (comme le
// collecteur Linux, un seul débit agrégé).
func queryCounterSum(path string) (float64, bool) {
	script := `(Get-Counter '` + path + `').CounterSamples | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return 0, false
	}
	var v float64
	if err := json.Unmarshal(out, &v); err != nil {
		return 0, false
	}
	return v, true
}

type logicalDisk struct {
	DeviceID string
	Size     float64
	Free     float64
}

// allPartitions : DriveType=3 (fixe) exclut les lecteurs amovibles/réseau/CD — même esprit
// que le filtre "/dev/*" côté Linux, ne remonter que des disques locaux réels.
func allPartitions() ([]logicalDisk, bool) {
	script := `
Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" |
  Select-Object DeviceID, Size, @{Name='Free';Expression={$_.FreeSpace}} | ConvertTo-Json
`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return nil, false
	}
	var disks []logicalDisk
	// Un seul disque désérialise en objet, pas en tableau : ConvertTo-Json ne l'enveloppe
	// dans [] que s'il y a plusieurs éléments.
	if err := json.Unmarshal(out, &disks); err != nil {
		var single logicalDisk
		if err := json.Unmarshal(out, &single); err != nil {
			return nil, false
		}
		disks = []logicalDisk{single}
	}
	return disks, true
}

// sanitizeDrive : "C:" -> "root" (préserve la clé "disk.root.used_pct" attendue telle
// quelle par alert_engine.py, déjà le comportement historique de ce collecteur), "D:" -> "d".
func sanitizeDrive(deviceID string) string {
	letter := strings.ToLower(strings.TrimSuffix(deviceID, ":"))
	if letter == "c" {
		return "root"
	}
	return letter
}

type selfProcessSample struct {
	Mem        float64 `json:"Mem"`
	CPUSeconds float64 `json:"CpuSeconds"`
}

// querySelfProcess : working set (RSS) et temps CPU cumulé du processus mirador-agent
// lui-même, via Get-Process -Id — même mécanisme PowerShell que queryCounter plutôt qu'un
// appel Win32 direct, pour rester cohérent avec le reste des collecteurs Windows.
func querySelfProcess() (selfProcessSample, bool) {
	script := `$p = Get-Process -Id ` + strconv.Itoa(os.Getpid()) + `
[PSCustomObject]@{ Mem = $p.WorkingSet64; CpuSeconds = $p.TotalProcessorTime.TotalSeconds } | ConvertTo-Json`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return selfProcessSample{}, false
	}
	var s selfProcessSample
	if err := json.Unmarshal(out, &s); err != nil {
		return selfProcessSample{}, false
	}
	return s, true
}

var (
	selfCPUMu      sync.Mutex
	selfLastCPUSec float64
	selfLastSample time.Time
)

// agentCPUPercent : delta du temps CPU cumulé (TotalProcessorTime) entre deux cycles de
// collecte, ramené au pourcentage du temps total écoulé sur l'ensemble des coeurs logiques
// — même convention que le collecteur Linux. Rien à envoyer au premier cycle (pas encore
// d'échantillon de référence).
func agentCPUPercent(cpuSeconds float64) (float64, bool) {
	now := time.Now()

	selfCPUMu.Lock()
	lastCPUSec, lastSample := selfLastCPUSec, selfLastSample
	selfLastCPUSec, selfLastSample = cpuSeconds, now
	selfCPUMu.Unlock()

	if lastSample.IsZero() {
		return 0, false
	}
	elapsed := now.Sub(lastSample).Seconds()
	if elapsed <= 0 {
		return 0, false
	}
	cpus := runtime.NumCPU()
	if cpus <= 0 {
		cpus = 1
	}
	return (cpuSeconds - lastCPUSec) / elapsed / float64(cpus) * 100, true
}

func CollectMetrics() []inventory.MetricPoint {
	now := time.Now().UTC()
	var points []inventory.MetricPoint

	add := func(key string, value float64, ok bool) {
		if ok {
			points = append(points, inventory.MetricPoint{Time: now, MetricKey: key, Value: value})
		}
	}

	if v, ok := queryCounter(`\Processor(_Total)\% Processor Time`); ok {
		add("cpu.load", v, ok)
	}
	if v, ok := queryCounter(`\Memory\% Committed Bytes In Use`); ok {
		add("memory.used_pct", v, ok)
	}
	// \Paging File(_Total)\% Usage : équivalent Windows du swap (fichier d'échange). Même
	// compteur PDH que les autres métriques, pas de requête CIM séparée à ajouter.
	if v, ok := queryCounter(`\Paging File(_Total)\% Usage`); ok {
		add("swap.used_pct", v, ok)
	}
	if disks, ok := allPartitions(); ok {
		for _, d := range disks {
			if d.Size <= 0 {
				continue
			}
			key := sanitizeDrive(d.DeviceID)
			add("disk."+key+".used_pct", (d.Size-d.Free)/d.Size*100, true)
			add("disk."+key+".total_bytes", d.Size, true)
		}
	}
	if sample, ok := querySelfProcess(); ok {
		add("agent.memory_bytes", sample.Mem, ok)
		if pct, ok := agentCPUPercent(sample.CPUSeconds); ok {
			add("agent.cpu_pct", pct, ok)
		}
	}
	if rx, ok := queryCounterSum(`\Network Interface(*)\Bytes Received/sec`); ok {
		add("network.rx_bytes_per_sec", rx, true)
	}
	if tx, ok := queryCounterSum(`\Network Interface(*)\Bytes Sent/sec`); ok {
		add("network.tx_bytes_per_sec", tx, true)
	}

	return points
}
