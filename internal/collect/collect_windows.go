//go:build windows

package collect

import (
	"github.com/LaLegende971/mirador-agent/internal/collectors/windows"
	"github.com/LaLegende971/mirador-agent/internal/inventory"
)

func Hardware(agentVersion string) inventory.HardwareInfo {
	return windows.CollectHardware(agentVersion)
}

func Software() ([]inventory.SoftwareItem, error) { return windows.CollectSoftware() }

func Patches() ([]inventory.PatchItem, error) { return windows.CollectPatches() }

func Metrics() []inventory.MetricPoint { return windows.CollectMetrics() }
