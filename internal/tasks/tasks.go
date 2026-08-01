// Package tasks exécute les tâches distribuées par le serveur (Étape 8, D7 : « toute
// action est une tâche »).
//
// Le tableau des risques de la spécification distingue `collect_now` (risque nul) des
// actions de production (`install_patches`, `reboot`). Seul `collect_now` est exécuté
// réellement ici, en réutilisant le cycle d'inventaire habituel. Exécuter une installation
// de correctifs ou un redémarrage à l'aveugle depuis cette version de l'agent — sans mode
// contrôlé (fenêtres, marche arrière) — serait dangereux sur un vrai parc ; ces tâches sont
// donc reconnues et remontées en échec explicite plutôt que simulées en succès ou ignorées
// silencieusement (R3 : rien n'est masqué).
//
// update_agent fait exception : contrairement à install_patches/reboot, le remplacement
// d'un fichier exécutable est une opération que Go maîtrise nativement (os.Rename), sans
// dépendance à un outillage OS tiers non éprouvé ici — exécutée réellement sous Linux.
// Windows verrouille en général un .exe en cours d'exécution : plutôt que de risquer un
// remplacement à moitié fait sur une plateforme non vérifiable dans cet environnement,
// update_agent y suit le même principe que install_patches/reboot : échec explicite.
package tasks

import (
	"context"
	"log/slog"
	"os"
	"runtime"

	"github.com/LaLegende971/mirador-agent/internal/api"
)

// Run sonde la file de tâches de cet asset et traite ce qui est en attente. runCollectNow
// est injecté par main pour réutiliser exactement le même cycle d'inventaire que le sondage
// périodique — une seule source de vérité pour « collecter maintenant ».
func Run(ctx context.Context, logger *slog.Logger, client *api.Client, runCollectNow func()) {
	pending, err := client.FetchTasks(ctx)
	if err != nil {
		logger.Warn("sondage des tâches échoué", "err", err)
		return
	}

	for _, task := range pending {
		logger.Info("tâche reçue", "id", task.ID, "kind", task.Kind)

		switch task.Kind {
		case "collect_now":
			report(ctx, logger, client, task.ID, "running", nil)
			runCollectNow()
			report(ctx, logger, client, task.ID, "succeeded", map[string]any{"message": "collecte déclenchée"})
		case "update_agent":
			updateAgent(ctx, logger, client, task.ID)
		case "install_patches", "reboot":
			report(ctx, logger, client, task.ID, "failed", map[string]any{
				"message": "exécution non implémentée dans cette version de l'agent",
			})
		default:
			report(ctx, logger, client, task.ID, "failed", map[string]any{
				"message": "type de tâche inconnu de l'agent : " + task.Kind,
			})
		}
	}
}

// updateAgent télécharge le binaire publié par le serveur pour cet OS et le substitue à
// l'exécutable en cours. Le téléchargement va dans un fichier temporaire du même
// répertoire (donc du même système de fichiers) que l'exécutable cible : os.Rename y est
// atomique, jamais un état intermédiaire à moitié écrit visible d'un autre process. En cas
// d'échec à n'importe quelle étape, l'exécutable en place n'est jamais touché.
func updateAgent(ctx context.Context, logger *slog.Logger, client *api.Client, taskID string) {
	report(ctx, logger, client, taskID, "running", nil)

	if runtime.GOOS == "windows" {
		report(ctx, logger, client, taskID, "failed", map[string]any{
			"message": "mise à jour automatique non implémentée sur Windows dans cette version de l'agent",
		})
		return
	}

	exePath, err := os.Executable()
	if err != nil {
		report(ctx, logger, client, taskID, "failed", map[string]any{"message": "exécutable introuvable : " + err.Error()})
		return
	}
	tmpPath := exePath + ".update"

	if err := client.DownloadBinary(ctx, tmpPath); err != nil {
		os.Remove(tmpPath)
		report(ctx, logger, client, taskID, "failed", map[string]any{"message": "téléchargement échoué : " + err.Error()})
		return
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		os.Remove(tmpPath)
		report(ctx, logger, client, taskID, "failed", map[string]any{"message": "remplacement du binaire échoué : " + err.Error()})
		return
	}

	report(ctx, logger, client, taskID, "succeeded", map[string]any{
		"message": "binaire remplacé, redémarrage du service pour appliquer la mise à jour",
	})
	logger.Info("mise à jour appliquée, arrêt pour redémarrage par systemd (Restart=on-failure)")
	os.Exit(1)
}

func report(ctx context.Context, logger *slog.Logger, client *api.Client, taskID, state string, result map[string]any) {
	if err := client.SubmitTaskResult(ctx, taskID, state, result); err != nil {
		logger.Warn("remontée du résultat de tâche échouée", "id", taskID, "state", state, "err", err)
	}
}
