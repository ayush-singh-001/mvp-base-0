#!/usr/bin/env bash
# stop-network.sh  –  Tear down the DocVerifier Fabric network
# Removes containers, volumes, crypto material, and generated channel artifacts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FABRIC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${FABRIC_DIR}"

echo "Stopping containers..."
docker compose down --volumes --remove-orphans 2>/dev/null || true

echo "Removing generated artefacts..."
rm -rf crypto-config/
rm -rf channel-config/
rm -f  *.tar.gz

echo "Removing any leftover chaincode Docker images..."
docker rmi "$(docker images "dev-peer*docverifier*" -q)" 2>/dev/null || true

echo "Done. Network torn down cleanly."
