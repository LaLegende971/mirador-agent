//go:build windows

package windows

import (
	"encoding/json"
	"os/exec"
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

func diskUsedPercent() (float64, bool) {
	script := `
$d = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
if ($d.Size -gt 0) { [math]::Round((($d.Size - $d.FreeSpace) / $d.Size) * 100, 2) }
`
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
	if v, ok := diskUsedPercent(); ok {
		add("disk.root.used_pct", v, ok)
	}

	return points
}
