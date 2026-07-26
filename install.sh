#!/usr/bin/env bash
#
# Installation universelle de l'agent Mirador.
# Usage : curl -fsSL https://raw.githubusercontent.com/<org>/mirador-agent/main/install.sh | sudo bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Ce script doit être exécuté en root." >&2
  exit 1
fi

echo "Installation de mirador-agent : à compléter (étape 2 de la construction)."
