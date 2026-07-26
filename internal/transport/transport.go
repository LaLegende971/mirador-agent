// Package transport construit les clients HTTP mTLS utilisés par l'agent pour parler au
// serveur Mirador : un client "de confiance" (CA seule) pour l'enrôlement, et un client
// mTLS complet (certificat client + CA) pour toutes les routes d'ingestion.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

func loadCAPool(caCertPath string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("lecture du certificat de CA : %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("certificat de CA invalide : %s", caCertPath)
	}
	return pool, nil
}

// NewTrustingClient fait confiance à la CA serveur mais ne présente aucun certificat
// client. Utilisé uniquement pour /agent/enroll, avant que l'agent n'ait un certificat.
func NewTrustingClient(caCertPath string) (*http.Client, error) {
	pool, err := loadCAPool(caCertPath)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

// NewMTLSClient présente le certificat client émis à l'enrôlement, en plus de vérifier
// le certificat serveur contre la CA. C'est le client utilisé pour toutes les routes
// /api/v1/ingest et /api/v1/agent (hors enrôlement).
func NewMTLSClient(caCertPath, clientCertPath, clientKeyPath string) (*http.Client, error) {
	pool, err := loadCAPool(caCertPath)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("chargement du certificat client : %w", err)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}, nil
}
