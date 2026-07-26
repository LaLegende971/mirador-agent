package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// ComputeFingerprint résume l'état d'inventaire courant (matériel, logiciels, correctifs)
// en un hash stable : un tri préalable garantit que l'ordre de collecte ne fait pas croire
// à un changement là où il n'y en a pas.
func ComputeFingerprint(hw HardwareInfo, software []SoftwareItem, patches []PatchItem) (string, error) {
	sw := append([]SoftwareItem(nil), software...)
	sort.Slice(sw, func(i, j int) bool {
		if sw[i].Name != sw[j].Name {
			return sw[i].Name < sw[j].Name
		}
		return sw[i].Version < sw[j].Version
	})

	p := append([]PatchItem(nil), patches...)
	sort.Slice(p, func(i, j int) bool { return p[i].KB < p[j].KB })

	h := sha256.New()
	for _, v := range []any{hw, sw, p} {
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
