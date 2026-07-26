// Package inventory contient les structures échangées avec le serveur (miroir des
// schémas Pydantic de app/schemas/ingestion.py) et le calcul de l'empreinte d'inventaire.
package inventory

import "time"

type HardwareInfo struct {
	FQDN         string `json:"fqdn,omitempty"`
	OSFamily     string `json:"os_family,omitempty"` // windows | linux
	OSName       string `json:"os_name,omitempty"`
	OSVersion    string `json:"os_version,omitempty"`
	Vendor       string `json:"vendor,omitempty"`
	Model        string `json:"model,omitempty"`
	Serial       string `json:"serial,omitempty"`
	CPUDesc      string `json:"cpu_desc,omitempty"`
	MemoryBytes  int64  `json:"memory_bytes,omitempty"`
	PrimaryIP    string `json:"primary_ip,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
}

type SoftwareItem struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	Publisher         string `json:"publisher,omitempty"`
	InstallDate       string `json:"install_date,omitempty"` // YYYY-MM-DD
	IsSystemComponent bool   `json:"is_system_component"`
}

// PatchItem : kind vaut "os" ou "application" ; jamais de catalogue applicatif construit à
// la main (section 6, hors périmètre) — côté Windows, seul winget alimente "application".
type PatchItem struct {
	KB            string `json:"kb"`
	Title         string `json:"title,omitempty"`
	Severity      string `json:"severity,omitempty"` // critical | important | moderate | low
	Kind          string `json:"kind"`
	PublishedAt   string `json:"published_at,omitempty"`
	State         string `json:"state"` // pending | scheduled | installed | failed | excluded
	Attempts      int    `json:"attempts"`
	LastErrorCode string `json:"last_error_code,omitempty"`
	LastErrorText string `json:"last_error_text,omitempty"`
	InstalledAt   string `json:"installed_at,omitempty"`
}

type Snapshot struct {
	AssetID     string         `json:"asset_id"`
	Hostname    string         `json:"hostname"`
	Fingerprint string         `json:"fingerprint"`
	Hardware    HardwareInfo   `json:"hardware"`
	Software    []SoftwareItem `json:"software"`
	Patches     []PatchItem    `json:"patches"`
}

type MetricPoint struct {
	Time      time.Time `json:"time"`
	MetricKey string    `json:"metric_key"`
	Value     float64   `json:"value"`
}
