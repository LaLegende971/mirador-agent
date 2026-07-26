//go:build windows

package windows

import (
	"encoding/json"
	"os/exec"
	"strings"

	"github.com/LaLegende971/mirador-agent/internal/inventory"
)

type wuUpdate struct {
	KB          string
	Title       string
	Severity    string
	IsInstalled bool
}

// collectWindowsUpdatePatches interroge Windows Update via son API COM (IUpdateSearcher),
// jamais via un mécanisme de scan tiers : c'est la source de vérité de l'éditeur.
func collectWindowsUpdatePatches() ([]inventory.PatchItem, error) {
	script := `
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 or IsInstalled=1")
@($result.Updates) | ForEach-Object {
    [PSCustomObject]@{
        KB = @($_.KBArticleIDs)[0]
        Title = $_.Title
        Severity = $_.MsrcSeverity
        IsInstalled = [bool]$_.IsInstalled
    }
} | ConvertTo-Json -Compress
`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return nil, err
	}

	var updates []wuUpdate
	if err := json.Unmarshal(out, &updates); err != nil {
		return nil, err
	}

	items := make([]inventory.PatchItem, 0, len(updates))
	for _, u := range updates {
		if u.KB == "" {
			continue
		}
		state := "pending"
		if u.IsInstalled {
			state = "installed"
		}
		severity := strings.ToLower(u.Severity)
		if severity == "" {
			severity = "moderate"
		}
		items = append(items, inventory.PatchItem{
			KB:       "KB" + u.KB,
			Title:    u.Title,
			Severity: severity,
			Kind:     "os",
			State:    state,
		})
	}
	return items, nil
}

type wingetUpgrade struct {
	name, id, version, available string
}

// collectWingetPatches liste les mises à jour applicatives disponibles via winget — le
// seul mécanisme couvert pour l'applicatif Windows (section 5.1). Le tableau de winget
// n'a pas de sortie JSON stable sur toutes les versions ; on découpe sur les runs d'au
// moins deux espaces, qui séparent fiablement les colonnes de winget.
func collectWingetPatches() ([]inventory.PatchItem, error) {
	out, err := exec.Command("winget", "upgrade", "--include-unknown", "--disable-interactivity").Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(out), "\n")
	var items []inventory.PatchItem
	headerSeen := false
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.TrimSpace(line), "----") {
			headerSeen = true
			continue
		}
		if !headerSeen || strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Contains(line, "upgrades available") || strings.HasPrefix(strings.TrimSpace(line), "No applicable") {
			continue
		}

		fields := splitOnMultiSpace(line)
		if len(fields) < 4 {
			continue
		}
		name, id, version, available := fields[0], fields[1], fields[2], fields[3]

		items = append(items, inventory.PatchItem{
			KB:       id,
			Title:    name + " " + available,
			Severity: "moderate", // winget ne fournit pas de sévérité éditeur
			Kind:     "application",
			State:    "pending",
		})
		_ = version
	}
	return items, nil
}

func splitOnMultiSpace(line string) []string {
	var fields []string
	var current strings.Builder
	spaceRun := 0
	for _, r := range line {
		if r == ' ' {
			spaceRun++
			if spaceRun == 2 && current.Len() > 0 {
				fields = append(fields, strings.TrimSpace(current.String()))
				current.Reset()
			}
			continue
		}
		if spaceRun >= 2 {
			// entre deux colonnes : espace déjà consommé par la coupure ci-dessus
		}
		spaceRun = 0
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		fields = append(fields, strings.TrimSpace(current.String()))
	}
	return fields
}

// CollectPatches combine les correctifs OS (Windows Update) et applicatifs (winget). Kind
// distingue les deux dans le même flux, cohérent avec le schéma serveur (PatchItem.kind).
func CollectPatches() ([]inventory.PatchItem, error) {
	var all []inventory.PatchItem

	osPatches, err := collectWindowsUpdatePatches()
	if err == nil {
		all = append(all, osPatches...)
	}

	appPatches, err := collectWingetPatches()
	if err == nil {
		all = append(all, appPatches...)
	}

	return all, nil
}
