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
