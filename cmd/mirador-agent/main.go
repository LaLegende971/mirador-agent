// mirador-agent collecte l'inventaire et les métriques d'un asset et les envoie au serveur
// Mirador via mTLS, selon le pipeline déclaratif décrit section 2.2 du cahier des charges
// (D4) : l'agent n'envoie que des instantanés d'état, jamais d'événements — c'est le
// serveur qui calcule le diff.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LaLegende971/mirador-agent/internal/api"
	"github.com/LaLegende971/mirador-agent/internal/collect"
	"github.com/LaLegende971/mirador-agent/internal/config"
	"github.com/LaLegende971/mirador-agent/internal/enroll"
	"github.com/LaLegende971/mirador-agent/internal/inventory"
	"github.com/LaLegende971/mirador-agent/internal/state"
	"github.com/LaLegende971/mirador-agent/internal/tasks"
	"github.com/LaLegende971/mirador-agent/internal/transport"
)

const agentVersion = "0.4.0"

const (
	metricsInterval   = 60 * time.Second
	inventoryInterval = time.Hour
	tasksInterval     = 5 * time.Second
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := config.Load()
	st := state.New(cfg.StateDir)

	hostname, err := os.Hostname()
	if err != nil {
		logger.Error("impossible de lire le nom d'hôte", "err", err)
		os.Exit(1)
	}

	if !st.IsEnrolled() {
		logger.Info("agent non enrôlé, enrôlement en cours", "server", cfg.ServerURL)
		if err := enroll.Enroll(cfg.ServerURL, cfg.EnrollmentToken, hostname, st); err != nil {
			logger.Error("échec de l'enrôlement", "err", err)
			os.Exit(1)
		}
		logger.Info("enrôlement réussi")
	}

	assetID, err := st.AssetID()
	if err != nil {
		logger.Error("identité de l'asset introuvable après enrôlement", "err", err)
		os.Exit(1)
	}

	httpClient, err := transport.NewMTLSClient(st.CACertPath(), st.ClientCertPath(), st.ClientKeyPath())
	if err != nil {
		logger.Error("impossible de construire le client mTLS", "err", err)
		os.Exit(1)
	}
	client := api.New(cfg.ServerURL, httpClient, assetID)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runInventoryCycle(ctx, logger, client, hostname)

	metricsTicker := time.NewTicker(metricsInterval)
	defer metricsTicker.Stop()
	inventoryTicker := time.NewTicker(inventoryInterval)
	defer inventoryTicker.Stop()
	tasksTicker := time.NewTicker(tasksInterval)
	defer tasksTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("arrêt demandé")
			return
		case <-metricsTicker.C:
			runMetricsCycle(ctx, logger, client)
		case <-inventoryTicker.C:
			runInventoryCycle(ctx, logger, client, hostname)
		case <-tasksTicker.C:
			tasks.Run(ctx, logger, client, func() { runInventoryCycle(ctx, logger, client, hostname) })
		}
	}
}

// runMetricsCycle ne collecte rien tant qu'aucune politique n'est appliquée à cet asset :
// pas un simple filtre à l'envoi, la collecte elle-même (lecture /proc, compteurs
// Windows…) n'a pas lieu. Le document résolu (/agent/config, section 3.3) fait foi : une
// entrée pour la clé d'intégration de cet OS signifie qu'au moins un groupe configure la
// supervision pour cet asset. Tant que ce n'est pas le cas, seuls l'inventaire (Parc) et
// le battement de tâches continuent — la Supervision, elle, reste muette.
func runMetricsCycle(ctx context.Context, logger *slog.Logger, client *api.Client) {
	cfg, err := client.FetchConfig(ctx)
	if err != nil {
		logger.Warn("récupération de la configuration échouée", "err", err)
		return
	}
	if len(cfg[collect.OSFamily]) == 0 {
		logger.Info("aucune politique de supervision appliquée à cet asset, collecte suspendue")
		return
	}

	points := collect.Metrics()
	if len(points) == 0 {
		return
	}
	ingested, err := client.SendMetrics(ctx, points)
	if err != nil {
		logger.Warn("envoi des métriques échoué", "err", err)
		return
	}
	logger.Info("métriques envoyées", "count", ingested)
}

func runInventoryCycle(ctx context.Context, logger *slog.Logger, client *api.Client, hostname string) {
	hw := collect.Hardware(agentVersion)

	software, err := collect.Software()
	if err != nil {
		logger.Warn("collecte logicielle échouée", "err", err)
	}
	patches, err := collect.Patches()
	if err != nil {
		logger.Warn("collecte des correctifs échouée", "err", err)
	}

	fingerprint, err := inventory.ComputeFingerprint(hw, software, patches)
	if err != nil {
		logger.Error("calcul de l'empreinte échoué", "err", err)
		return
	}

	snapshotRequired, err := client.CheckFingerprint(ctx, fingerprint)
	if err != nil {
		logger.Warn("vérification de l'empreinte échouée", "err", err)
		return
	}
	if !snapshotRequired {
		logger.Info("empreinte inchangée, rien à envoyer")
		return
	}

	snap := inventory.Snapshot{
		Hostname:    hostname,
		Fingerprint: fingerprint,
		Hardware:    hw,
		Software:    software,
		Patches:     patches,
	}
	eventsCreated, err := client.SendSnapshot(ctx, snap)
	if err != nil {
		logger.Warn("envoi de l'instantané échoué", "err", err)
		return
	}
	logger.Info("instantané envoyé", "events_created", eventsCreated)
}
