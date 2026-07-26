// Package enroll réalise l'enrôlement d'un agent : récupération de la CA (amorçage de
// confiance), génération de la paire de clés et de la CSR, puis échange du jeton
// d'enrôlement contre un certificat client mTLS.
package enroll

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/LaLegende971/mirador-agent/internal/state"
	"github.com/LaLegende971/mirador-agent/internal/transport"
)

type caCertificateResponse struct {
	CACertificatePEM string `json:"ca_certificate_pem"`
}

type enrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	CSRPem          string `json:"csr_pem"`
}

type enrollResponse struct {
	AssetID           string `json:"asset_id"`
	CertificatePEM    string `json:"certificate_pem"`
	CACertificatePEM  string `json:"ca_certificate_pem"`
}

// bootstrapURL dérive l'URL HTTP en clair du certificat de CA à partir de l'URL HTTPS du
// serveur : avant l'enrôlement, l'agent ne peut pas encore vérifier le certificat serveur.
func bootstrapCACertURL(serverURL string) string {
	url := strings.Replace(serverURL, "https://", "http://", 1)
	return strings.TrimRight(url, "/") + "/api/v1/agent/ca-certificate"
}

func fetchCACertificate(serverURL string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(bootstrapCACertURL(serverURL))
	if err != nil {
		return "", fmt.Errorf("récupération du certificat de CA : %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("récupération du certificat de CA : HTTP %d : %s", resp.StatusCode, body)
	}
	var out caCertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("réponse invalide du serveur : %w", err)
	}
	return out.CACertificatePEM, nil
}

func generateKeyAndCSR(hostname string) (keyPEM, csrPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("génération de la clé : %w", err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "pending"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return "", "", fmt.Errorf("génération de la CSR : %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("encodage de la clé : %w", err)
	}

	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	_ = hostname
	return keyPEM, csrPEM, nil
}

// Enroll effectue l'enrôlement complet et persiste le résultat dans st. Idempotent au sens
// où il ne fait rien si l'agent est déjà enrôlé (voir state.IsEnrolled).
func Enroll(serverURL, token, hostname string, st *state.State) error {
	if st.IsEnrolled() {
		return nil
	}
	if token == "" {
		return fmt.Errorf("aucun jeton d'enrôlement fourni (MIRADOR_ENROLLMENT_TOKEN) et l'agent n'est pas encore enrôlé")
	}

	caCertPEM, err := fetchCACertificate(serverURL)
	if err != nil {
		return err
	}
	if err := st.EnsureDir(); err != nil {
		return fmt.Errorf("création du répertoire d'état : %w", err)
	}
	if err := st.SaveCACert(caCertPEM); err != nil {
		return fmt.Errorf("sauvegarde du certificat de CA : %w", err)
	}

	keyPEM, csrPEM, err := generateKeyAndCSR(hostname)
	if err != nil {
		return err
	}

	body, err := json.Marshal(enrollRequest{EnrollmentToken: token, Hostname: hostname, CSRPem: csrPEM})
	if err != nil {
		return err
	}

	client, err := transport.NewTrustingClient(st.CACertPath())
	if err != nil {
		return err
	}

	resp, err := client.Post(strings.TrimRight(serverURL, "/")+"/api/v1/agent/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("appel à /agent/enroll : %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enrôlement refusé : HTTP %d : %s", resp.StatusCode, respBody)
	}

	var out enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("réponse d'enrôlement invalide : %w", err)
	}

	return st.SaveEnrollment(out.AssetID, keyPEM, out.CertificatePEM)
}
