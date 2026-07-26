// Package config lit la configuration locale de l'agent : où joindre le serveur, où
// persister son état (certificats, identité), et le jeton d'enrôlement à usage unique.
package config

import "os"

type Config struct {
	ServerURL       string // ex: https://mirador.example.org
	StateDir        string // ex: /var/lib/mirador-agent
	EnrollmentToken string // requis uniquement au premier enrôlement
}

func Load() Config {
	return Config{
		ServerURL:       getenv("MIRADOR_SERVER_URL", "https://127.0.0.1"),
		StateDir:        getenv("MIRADOR_STATE_DIR", "/var/lib/mirador-agent"),
		EnrollmentToken: os.Getenv("MIRADOR_ENROLLMENT_TOKEN"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
