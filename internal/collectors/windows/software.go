//go:build windows

package windows

import (
	"golang.org/x/sys/windows/registry"

	"github.com/LaLegende971/mirador-agent/internal/inventory"
)

const uninstallPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

// uninstallHive : les trois vues de registre où les logiciels installent leurs clés
// Uninstall. Jamais Win32_Product (section 6) — cette classe WMI déclenche une réparation
// MSI pour chaque instance interrogée, un effet de bord inacceptable sur un parc en
// production.
var uninstallHives = []struct {
	root  registry.Key
	flags uint32
}{
	{registry.LOCAL_MACHINE, registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS | registry.WOW64_64KEY},
	{registry.LOCAL_MACHINE, registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS | registry.WOW64_32KEY},
	{registry.CURRENT_USER, registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS},
}

func readUninstallEntries(root registry.Key, access uint32) []inventory.SoftwareItem {
	base, err := registry.OpenKey(root, uninstallPath, access)
	if err != nil {
		return nil
	}
	defer base.Close()

	subkeys, err := base.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	var items []inventory.SoftwareItem
	for _, name := range subkeys {
		k, err := registry.OpenKey(root, uninstallPath+`\`+name, access)
		if err != nil {
			continue
		}

		displayName, _, err := k.GetStringValue("DisplayName")
		if err != nil || displayName == "" {
			// Pas de nom d'affichage : composant interne (correctif, patch KB...), pas une
			// application au sens de l'inventaire logiciel.
			k.Close()
			continue
		}
		displayVersion, _, _ := k.GetStringValue("DisplayVersion")
		publisher, _, _ := k.GetStringValue("Publisher")
		installDateRaw, _, _ := k.GetStringValue("InstallDate") // format YYYYMMDD
		systemComponent, _, _ := k.GetIntegerValue("SystemComponent")
		k.Close()

		items = append(items, inventory.SoftwareItem{
			Name:              displayName,
			Version:           displayVersion,
			Publisher:         publisher,
			InstallDate:       formatWindowsInstallDate(installDateRaw),
			IsSystemComponent: systemComponent == 1,
		})
	}
	return items
}

func formatWindowsInstallDate(raw string) string {
	if len(raw) != 8 {
		return ""
	}
	return raw[0:4] + "-" + raw[4:6] + "-" + raw[6:8]
}

// CollectSoftware lit les clés Uninstall des trois vues de registre (64 bits, 32 bits via
// redirection WOW64, et par utilisateur). Un même logiciel peut apparaître dans plusieurs
// vues : le diff serveur (D4) dédoublonne par (nom, version), donc les entrées identiques
// n'y produisent aucun événement superflu.
func CollectSoftware() ([]inventory.SoftwareItem, error) {
	var all []inventory.SoftwareItem
	for _, hive := range uninstallHives {
		all = append(all, readUninstallEntries(hive.root, hive.flags)...)
	}
	return all, nil
}
