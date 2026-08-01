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
package tasks

import (
	"context"
	"log/slog"

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

func report(ctx context.Context, logger *slog.Logger, client *api.Client, taskID, state string, result map[string]any) {
	if err := client.SubmitTaskResult(ctx, taskID, state, result); err != nil {
		logger.Warn("remontée du résultat de tâche échouée", "id", taskID, "state", state, "err", err)
	}
}
