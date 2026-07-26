// Package state gère la persistance locale de l'agent : identité (asset_id), certificat
// client mTLS et certificat de la CA serveur. Tout réside sous StateDir, jamais dans le
// dépôt ni dans un emplacement partagé entre agents.
package state

import (
	"os"
	"path/filepath"
	"strings"
)

type State struct {
	dir string
}

func New(dir string) *State {
	return &State{dir: dir}
}

func (s *State) caCertPath() string     { return filepath.Join(s.dir, "ca.cert.pem") }
func (s *State) clientKeyPath() string  { return filepath.Join(s.dir, "client.key.pem") }
func (s *State) clientCertPath() string { return filepath.Join(s.dir, "client.cert.pem") }
func (s *State) assetIDPath() string    { return filepath.Join(s.dir, "asset_id") }

// IsEnrolled indique si l'agent possède déjà un certificat client émis par le serveur.
func (s *State) IsEnrolled() bool {
	_, err1 := os.Stat(s.clientCertPath())
	_, err2 := os.Stat(s.clientKeyPath())
	return err1 == nil && err2 == nil
}

func (s *State) EnsureDir() error {
	return os.MkdirAll(s.dir, 0o750)
}

func (s *State) SaveCACert(pem string) error {
	return os.WriteFile(s.caCertPath(), []byte(pem), 0o644)
}

func (s *State) SaveEnrollment(assetID, clientKeyPEM, clientCertPEM string) error {
	if err := os.WriteFile(s.clientKeyPath(), []byte(clientKeyPEM), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(s.clientCertPath(), []byte(clientCertPEM), 0o644); err != nil {
		return err
	}
	return os.WriteFile(s.assetIDPath(), []byte(strings.TrimSpace(assetID)), 0o644)
}

func (s *State) CACertPath() string     { return s.caCertPath() }
func (s *State) ClientKeyPath() string  { return s.clientKeyPath() }
func (s *State) ClientCertPath() string { return s.clientCertPath() }

func (s *State) AssetID() (string, error) {
	b, err := os.ReadFile(s.assetIDPath())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
