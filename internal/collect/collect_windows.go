//go:build windows

package collect

import (
	"github.com/LaLegende971/mirador-agent/internal/collectors/windows"
	"github.com/LaLegende971/mirador-agent/internal/inventory"
)

// OSFamily identifie, côté agent, la clé d'intégration à chercher dans le document
// résolu par /agent/config (section 3.3) — même valeur que hardware.go y écrit côté
// inventaire.
const OSFamily = "windows"

func Hardware(agentVersion string) inventory.HardwareInfo {
	return windows.CollectHardware(agentVersion)
}

func Software() ([]inventory.SoftwareItem, error) { return windows.CollectSoftware() }

func Patches() ([]inventory.PatchItem, error) { return windows.CollectPatches() }

func Metrics() []inventory.MetricPoint { return windows.CollectMetrics() }
