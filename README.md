# mirador-agent

Agent Mirador — binaire statique Go, exécuté sur chaque asset supervisé.

Envoie des instantanés déclaratifs au serveur (empreinte + snapshot complet), exécute les
tâches reçues (collecte, correctifs, redémarrage), ne connaît ni les groupes, ni les
surcharges, ni les arbitrages : il reçoit une configuration résolue à plat.

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/<org>/mirador-agent/main/install.sh | sudo bash
```

## Build

```bash
go build -o mirador-agent ./cmd/mirador-agent
```
