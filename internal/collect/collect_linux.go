//go:build linux

// Package collect choisit le jeu de collecteurs à utiliser selon l'OS de compilation :
// un seul fichier par plateforme (suffixe _linux.go / _windows.go) est inclus à la
// compilation, sans branchement au runtime.
package collect

import (
	"github.com/LaLegende971/mirador-agent/internal/collectors/linux"
	"github.com/LaLegende971/mirador-agent/internal/inventory"
)

func Hardware(agentVersion string) inventory.HardwareInfo { return linux.CollectHardware(agentVersion) }

func Software() ([]inventory.SoftwareItem, error) { return linux.CollectSoftware() }

func Patches() ([]inventory.PatchItem, error) { return linux.CollectPatches() }

func Metrics() []inventory.MetricPoint { return linux.CollectMetrics() }
