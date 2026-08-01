// Package api appelle les routes d'ingestion du serveur Mirador (POST /ingest/*).
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/LaLegende971/mirador-agent/internal/inventory"
)

type Client struct {
	baseURL string
	http    *http.Client
	assetID string
}

func New(baseURL string, httpClient *http.Client, assetID string) *Client {
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient, assetID: assetID}
}

func (c *Client) postJSON(ctx context.Context, path string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("appel à %s : %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s a répondu HTTP %d : %s", path, resp.StatusCode, respBody)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("appel à %s : %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s a répondu HTTP %d : %s", path, resp.StatusCode, respBody)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Task est la vue minimale qu'un agent reçoit d'une tâche (Étape 8) : ni auteur, ni
// historique, ni résultat d'une exécution précédente — le serveur ne lui expose que ce
// qu'il doit exécuter et jusqu'à quand (même principe que /agent/config, section 3.3).
type Task struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	ExpiresAt time.Time       `json:"expires_at"`
}

func (c *Client) FetchTasks(ctx context.Context) ([]Task, error) {
	var out struct {
		Items []Task `json:"items"`
	}
	err := c.getJSON(ctx, "/api/v1/agent/tasks", &out)
	return out.Items, err
}

// SubmitTaskResult remonte un état intermédiaire (`running`) ou terminal (`succeeded`,
// `failed`) — jamais `queued`/`sent`/`expired`, qui n'appartiennent qu'au serveur (D7).
func (c *Client) SubmitTaskResult(ctx context.Context, taskID, state string, result map[string]any) error {
	path := fmt.Sprintf("/api/v1/agent/tasks/%s/result", taskID)
	return c.postJSON(ctx, path, map[string]any{"state": state, "result": result}, nil)
}

func (c *Client) CheckFingerprint(ctx context.Context, fingerprint string) (snapshotRequired bool, err error) {
	var out struct {
		SnapshotRequired bool `json:"snapshot_required"`
	}
	err = c.postJSON(ctx, "/api/v1/ingest/fingerprint", map[string]string{
		"asset_id":    c.assetID,
		"fingerprint": fingerprint,
	}, &out)
	return out.SnapshotRequired, err
}

func (c *Client) SendSnapshot(ctx context.Context, snap inventory.Snapshot) (eventsCreated int, err error) {
	snap.AssetID = c.assetID
	// Un slice Go nil sérialise en JSON `null`, que le schéma serveur rejette (il attend
	// une liste, éventuellement vide, jamais une absence de valeur).
	if snap.Software == nil {
		snap.Software = []inventory.SoftwareItem{}
	}
	if snap.Patches == nil {
		snap.Patches = []inventory.PatchItem{}
	}
	var out struct {
		EventsCreated int `json:"events_created"`
	}
	err = c.postJSON(ctx, "/api/v1/ingest/snapshot", snap, &out)
	return out.EventsCreated, err
}

func (c *Client) SendMetrics(ctx context.Context, points []inventory.MetricPoint) (ingested int, err error) {
	var out struct {
		Ingested int `json:"ingested"`
	}
	err = c.postJSON(ctx, "/api/v1/ingest/metrics", map[string]any{
		"asset_id": c.assetID,
		"points":   points,
	}, &out)
	return out.Ingested, err
}
