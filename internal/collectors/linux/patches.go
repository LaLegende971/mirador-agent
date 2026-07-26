//go:build linux

package linux

import (
	"bufio"
	"os/exec"
	"regexp"
	"strings"

	"github.com/LaLegende971/mirador-agent/internal/inventory"
)

// aptUpgradableRE parse une ligne de `apt list --upgradable`, par ex :
// nginx/jammy-security 1.24.0-2ubuntu7.5 amd64 [upgradable from: 1.24.0-2ubuntu7.4]
var aptUpgradableRE = regexp.MustCompile(`^(\S+)/(\S+)\s+(\S+)\s`)

func collectAptPatches() ([]inventory.PatchItem, error) {
	out, err := exec.Command("apt", "list", "--upgradable").Output()
	if err != nil {
		return nil, err
	}

	var items []inventory.PatchItem
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		m := aptUpgradableRE.FindStringSubmatch(line)
		if m == nil {
			continue // ex: la ligne d'en-tête "Listing... Done"
		}
		name, pocket, version := m[1], m[2], m[3]

		severity := "moderate"
		if strings.Contains(pocket, "security") {
			severity = "critical"
		}

		items = append(items, inventory.PatchItem{
			KB:       name, // apt n'a pas de numérotation KB : le nom de paquet en tient lieu
			Title:    name + " " + version,
			Severity: severity,
			Kind:     "os",
			State:    "pending",
		})
	}
	return items, nil
}

func collectDnfPatches() ([]inventory.PatchItem, error) {
	// dnf check-update sort avec le code 100 quand des mises à jour existent : ce n'est pas
	// une erreur, donc on ignore l'erreur de exec et on parse la sortie disponible.
	out, _ := exec.Command("dnf", "check-update").Output()

	var items []inventory.PatchItem
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		name := fields[0]
		version := fields[1]
		severity := "moderate"
		if strings.Contains(strings.ToLower(fields[2]), "security") {
			severity = "critical"
		}
		items = append(items, inventory.PatchItem{
			KB:       name,
			Title:    name + " " + version,
			Severity: severity,
			Kind:     "os",
			State:    "pending",
		})
	}
	return items, nil
}

// CollectPatches essaie apt (Debian/Ubuntu) puis dnf (RHEL/Fedora). Couvre uniquement les
// correctifs système : le patch management applicatif Linux est hors périmètre (section 6),
// seul winget en tient lieu côté Windows.
func CollectPatches() ([]inventory.PatchItem, error) {
	if _, err := exec.LookPath("apt"); err == nil {
		return collectAptPatches()
	}
	return collectDnfPatches()
}
