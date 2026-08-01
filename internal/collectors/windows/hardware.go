//go:build windows

// Package windows implémente les collecteurs Windows : clés de registre Uninstall pour
// les logiciels (jamais Win32_Product, cf. section 6), CIM/WMI pour le matériel, l'API COM
// Windows Update Agent (IUpdateSearcher) pour les correctifs système, winget pour les
// correctifs applicatifs (section 5.1 — seul mécanisme d'applicatif couvert, volontairement).
//
// Ces collecteurs shell vers PowerShell (Get-CimInstance, COM Microsoft.Update.Session)
// plutôt que d'utiliser des liaisons COM Go, pour rester sans dépendance lourde. Ils n'ont
// jamais pu être testés sur une machine Windows réelle pendant le développement initial —
// à valider avant mise en production.
package windows

import (
	"encoding/json"
	"os"
	"os/exec"

	"golang.org/x/sys/windows/registry"

	"github.com/LaLegende971/mirador-agent/internal/inventory"
)

type cimComputerSystem struct {
	Manufacturer        string
	Model               string
	TotalPhysicalMemory uint64
}

type cimBIOS struct {
	SerialNumber string
}

type cimProcessor struct {
	Name string
}

type cimLogicalDisk struct {
	DeviceID string
	Size     uint64
}

// queryCIMArray force un résultat tableau même à instance unique (`@(...)`), sinon
// ConvertTo-Json émet un objet nu pour une seule instance et casse le décodage JSON.
func queryCIMArray(class string) ([]byte, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"@(Get-CimInstance -ClassName "+class+") | ConvertTo-Json -Compress")
	return cmd.Output()
}

// diskTotalBytesC : capacité totale du disque système — filtré sur C: comme
// diskUsedPercent (metrics.go), pas de queryCIMArray générique ici (pas de filtre WQL).
func diskTotalBytesC() int64 {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`@(Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'") | ConvertTo-Json -Compress`)
	b, err := cmd.Output()
	if err != nil {
		return 0
	}
	var disks []cimLogicalDisk
	if err := json.Unmarshal(b, &disks); err != nil || len(disks) == 0 {
		return 0
	}
	return int64(disks[0].Size)
}

func osVersionFromRegistry() (name, version string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "", ""
	}
	defer k.Close()
	productName, _, _ := k.GetStringValue("ProductName")
	displayVersion, _, _ := k.GetStringValue("DisplayVersion")
	return productName, displayVersion
}

func CollectHardware(agentVersion string) inventory.HardwareInfo {
	hostname, _ := os.Hostname()
	osName, osVersion := osVersionFromRegistry()

	var csList []cimComputerSystem
	if b, err := queryCIMArray("Win32_ComputerSystem"); err == nil {
		_ = json.Unmarshal(b, &csList)
	}
	var biosList []cimBIOS
	if b, err := queryCIMArray("Win32_BIOS"); err == nil {
		_ = json.Unmarshal(b, &biosList)
	}
	var cpuList []cimProcessor
	if b, err := queryCIMArray("Win32_Processor"); err == nil {
		_ = json.Unmarshal(b, &cpuList)
	}

	var cs cimComputerSystem
	if len(csList) > 0 {
		cs = csList[0]
	}
	var bios cimBIOS
	if len(biosList) > 0 {
		bios = biosList[0]
	}
	cpuDesc := ""
	if len(cpuList) > 0 {
		cpuDesc = cpuList[0].Name
	}

	return inventory.HardwareInfo{
		FQDN:         hostname,
		OSFamily:     "windows",
		OSName:       osName,
		OSVersion:    osVersion,
		Vendor:       cs.Manufacturer,
		Model:        cs.Model,
		Serial:       bios.SerialNumber,
		CPUDesc:      cpuDesc,
		MemoryBytes:  int64(cs.TotalPhysicalMemory),
		DiskBytes:    diskTotalBytesC(),
		AgentVersion: agentVersion,
	}
}
