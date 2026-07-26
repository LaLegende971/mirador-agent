//go:build linux

package linux

import (
	"bufio"
	"os/exec"
	"strings"

	"github.com/LaLegende971/mirador-agent/internal/inventory"
)

// systemPackagePrefixes : composants de base du système, jamais mis en avant dans la
// chronologie des logiciels d'un asset (bruit sans valeur métier). Liste volontairement
// courte et conservatrice plutôt qu'une classification exhaustive.
var systemPackagePrefixes = []string{
	"linux-", "libc6", "base-files", "systemd", "dpkg", "apt", "coreutils", "gcc-",
}

func isSystemComponent(name string) bool {
	for _, p := range systemPackagePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func collectDpkg() ([]inventory.SoftwareItem, error) {
	// -f fait de chaque paquet une ligne stable et facile à parser, sans dépendre du format
	// d'affichage par défaut de dpkg -l.
	out, err := exec.Command("dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Maintainer}\n").Output()
	if err != nil {
		return nil, err
	}

	var items []inventory.SoftwareItem
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), "\t", 3)
		if len(fields) < 2 || fields[0] == "" {
			continue
		}
		item := inventory.SoftwareItem{
			Name:              fields[0],
			Version:           fields[1],
			IsSystemComponent: isSystemComponent(fields[0]),
		}
		if len(fields) == 3 {
			item.Publisher = fields[2]
		}
		items = append(items, item)
	}
	return items, nil
}

func collectRpm() ([]inventory.SoftwareItem, error) {
	out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n").Output()
	if err != nil {
		return nil, err
	}

	var items []inventory.SoftwareItem
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), "\t", 3)
		if len(fields) < 2 || fields[0] == "" {
			continue
		}
		item := inventory.SoftwareItem{
			Name:              fields[0],
			Version:           fields[1],
			IsSystemComponent: isSystemComponent(fields[0]),
		}
		if len(fields) == 3 {
			item.Publisher = fields[2]
		}
		items = append(items, item)
	}
	return items, nil
}

// CollectSoftware essaie dpkg-query (Debian/Ubuntu) puis se rabat sur rpm -qa
// (RHEL/Fedora/openSUSE). Jamais Win32_Product — sans objet ici, mais le principe est le
// même : ne jamais invoquer un mécanisme de requête coûteux ou à effets de bord.
func CollectSoftware() ([]inventory.SoftwareItem, error) {
	if items, err := collectDpkg(); err == nil {
		return items, nil
	}
	return collectRpm()
}
