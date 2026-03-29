#!/usr/bin/env bash
# start-network.sh  –  Bootstrap the DocVerifier Hyperledger Fabric network
#
# Prerequisites (all must be on PATH):
#   - cryptogen        (fabric-samples/bin or standalone install)
#   - configtxgen      (same bin dir)
#   - osnadmin         (same bin dir, Fabric 2.5+)
#   - peer             (same bin dir)
#   - docker compose   (v2, aliased as 'docker compose')
#
# Run this script from the fabric/ directory:
#   cd fabric && ./scripts/start-network.sh
#
# On Windows: use WSL2 or Git Bash, ensure Docker Desktop is running.

set -euo pipefail

# Prevent Git Bash / MINGW from auto-converting Unix paths in docker exec arguments
# (without this, /opt/gopath/... becomes C:/Program Files/Git/opt/gopath/...)
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FABRIC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHANNEL_NAME="mychannel"
CHAINCODE_NAME="docverifier"
CHAINCODE_VERSION="1.0"
CHAINCODE_SEQUENCE=1
CHAINCODE_PATH="./chaincode/docverifier"

cd "${FABRIC_DIR}"

# ── Prepend local bin/ to PATH so bootstrap-downloaded binaries are found ───
# The Fabric bootstrap script (bootstrap.sh -s) places cryptogen, configtxgen,
# osnadmin, and peer into  fabric/bin/.  Add it first so system installs don't
# shadow the correct version.
if [ -d "${FABRIC_DIR}/bin" ]; then
  export PATH="${FABRIC_DIR}/bin:${PATH}"
fi
export FABRIC_CFG_PATH="${FABRIC_DIR}"

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║   DocVerifier Hyperledger Fabric Network      ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# ── Step 1: Generate crypto material ────────────────────────────────────────
echo "[1/7] Generating crypto material with cryptogen..."
if [ -d "crypto-config" ]; then
  echo "  crypto-config/ already exists – skipping (delete to regenerate)"
else
  cryptogen generate --config=./crypto-config.yaml --output=./crypto-config
  # cryptogen on Windows writes backslash paths into MSP config.yaml files.
  # Normalise all separators to forward-slash so the Linux containers can read them.
  find ./crypto-config -name "config.yaml" -exec sed -i 's/\\/\//g' {} +
  echo "  Done."
fi

# ── Step 2: Generate channel artifacts ──────────────────────────────────────
echo "[2/7] Generating channel artifacts with configtxgen..."
mkdir -p channel-config

# Application channel genesis block (Fabric 2.5 "no system channel" mode).
# osnadmin channel join requires the APPLICATION channel block, not a system channel block.
configtxgen -profile OneOrgChannel \
  -outputBlock ./channel-config/${CHANNEL_NAME}.block \
  -channelID ${CHANNEL_NAME}

# Also copy collections-config.json into channel-config/ so the CLI container
# can reach it at ${CLI_ARTIFACTS}/collections-config.json (avoids docker cp path issues on Windows).
cp "${FABRIC_DIR}/collections-config.json" ./channel-config/collections-config.json

echo "  Done."

# ── Step 3: Start Docker containers ─────────────────────────────────────────
echo "[3/7] Starting Docker containers..."
docker compose up -d --remove-orphans
echo "  Waiting 5s for containers to stabilise..."
sleep 5
echo "  Done."

# ── Paths inside the CLI container ──────────────────────────────────────────
# The CLI container mounts crypto-config → /peer/crypto and
# channel-config → /peer/channel-artifacts.  Docker DNS resolves
# orderer.example.com / peer0.org1.example.com, avoiding TLS hostname issues.
CLI_CRYPTO="/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto"
CLI_ARTIFACTS="/opt/gopath/src/github.com/hyperledger/fabric/peer/channel-artifacts"
CLI_ORDERER_CA="${CLI_CRYPTO}/ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt"
CLI_ORDERER_CERT="${CLI_CRYPTO}/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt"
CLI_ORDERER_KEY="${CLI_CRYPTO}/ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.key"
CLI_PEER_TLS="${CLI_CRYPTO}/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
CLI_PEER_MSP="${CLI_CRYPTO}/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"

# ── Step 4: Create channel ───────────────────────────────────────────────────
echo "[4/7] Creating channel '${CHANNEL_NAME}' via osnadmin (inside CLI container)..."
docker exec cli osnadmin channel join \
  --channelID ${CHANNEL_NAME} \
  --config-block "${CLI_ARTIFACTS}/${CHANNEL_NAME}.block" \
  -o orderer.example.com:7053 \
  --ca-file "${CLI_ORDERER_CA}" \
  --client-cert "${CLI_ORDERER_CERT}" \
  --client-key "${CLI_ORDERER_KEY}"
echo "  Done."

# ── Step 5: Peer joins channel ───────────────────────────────────────────────
echo "[5/7] Peer joining channel (inside CLI container)..."
docker exec \
  -e CORE_PEER_TLS_ENABLED=true \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH="${CLI_PEER_MSP}" \
  -e CORE_PEER_TLS_ROOTCERT_FILE="${CLI_PEER_TLS}" \
  -e CORE_PEER_ADDRESS=peer0.org1.example.com:7051 \
  cli \
  peer channel join -b "${CLI_ARTIFACTS}/${CHANNEL_NAME}.block"

echo "  Anchor peer set via genesis block (skipping deprecated update tx)."
echo "  Done."

# ── Step 6: Package, install, approve, commit chaincode ─────────────────────
echo "[6/7] Deploying chaincode '${CHAINCODE_NAME}' (inside CLI container)..."

CLI_CC_PATH="/opt/gopath/src/github.com/chaincode/docverifier"
CLI_CC_PKG="${CLI_ARTIFACTS}/${CHAINCODE_NAME}.tar.gz"
# collections-config.json was copied into channel-config/ in step 2, which is
# mounted into the CLI container at CLI_ARTIFACTS — no docker cp needed.
CLI_COLLECTIONS="${CLI_ARTIFACTS}/collections-config.json"

# Download Go dependencies
docker exec cli sh -c "cd ${CLI_CC_PATH} && go mod tidy && go mod vendor"

# Package
docker exec \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH="${CLI_PEER_MSP}" \
  cli \
  peer lifecycle chaincode package "${CLI_CC_PKG}" \
    --path "${CLI_CC_PATH}" \
    --lang golang \
    --label "${CHAINCODE_NAME}_${CHAINCODE_VERSION}"

# Install
docker exec \
  -e CORE_PEER_TLS_ENABLED=true \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH="${CLI_PEER_MSP}" \
  -e CORE_PEER_TLS_ROOTCERT_FILE="${CLI_PEER_TLS}" \
  -e CORE_PEER_ADDRESS=peer0.org1.example.com:7051 \
  cli \
  peer lifecycle chaincode install "${CLI_CC_PKG}"

# Get package ID
PACKAGE_ID=$(docker exec \
  -e CORE_PEER_TLS_ENABLED=true \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH="${CLI_PEER_MSP}" \
  -e CORE_PEER_TLS_ROOTCERT_FILE="${CLI_PEER_TLS}" \
  -e CORE_PEER_ADDRESS=peer0.org1.example.com:7051 \
  cli \
  peer lifecycle chaincode queryinstalled 2>&1 \
  | grep "${CHAINCODE_NAME}_${CHAINCODE_VERSION}" \
  | awk -F'Package ID: |, Label' '{print $2}')
echo "  Package ID: ${PACKAGE_ID}"

# Approve for Org1
docker exec \
  -e CORE_PEER_TLS_ENABLED=true \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH="${CLI_PEER_MSP}" \
  -e CORE_PEER_TLS_ROOTCERT_FILE="${CLI_PEER_TLS}" \
  -e CORE_PEER_ADDRESS=peer0.org1.example.com:7051 \
  cli \
  peer lifecycle chaincode approveformyorg \
    -C ${CHANNEL_NAME} \
    -n ${CHAINCODE_NAME} \
    -v ${CHAINCODE_VERSION} \
    --package-id "${PACKAGE_ID}" \
    --sequence ${CHAINCODE_SEQUENCE} \
    --collections-config "${CLI_COLLECTIONS}" \
    -o orderer.example.com:7050 \
    --tls --cafile "${CLI_ORDERER_CA}"

# Commit
docker exec \
  -e CORE_PEER_TLS_ENABLED=true \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH="${CLI_PEER_MSP}" \
  -e CORE_PEER_TLS_ROOTCERT_FILE="${CLI_PEER_TLS}" \
  -e CORE_PEER_ADDRESS=peer0.org1.example.com:7051 \
  cli \
  peer lifecycle chaincode commit \
    -C ${CHANNEL_NAME} \
    -n ${CHAINCODE_NAME} \
    -v ${CHAINCODE_VERSION} \
    --sequence ${CHAINCODE_SEQUENCE} \
    --collections-config "${CLI_COLLECTIONS}" \
    -o orderer.example.com:7050 \
    --tls --cafile "${CLI_ORDERER_CA}" \
    --peerAddresses peer0.org1.example.com:7051 \
    --tlsRootCertFiles "${CLI_PEER_TLS}"

# InitLedger
docker exec \
  -e CORE_PEER_TLS_ENABLED=true \
  -e CORE_PEER_LOCALMSPID=Org1MSP \
  -e CORE_PEER_MSPCONFIGPATH="${CLI_PEER_MSP}" \
  -e CORE_PEER_TLS_ROOTCERT_FILE="${CLI_PEER_TLS}" \
  -e CORE_PEER_ADDRESS=peer0.org1.example.com:7051 \
  cli \
  peer chaincode invoke \
    -C ${CHANNEL_NAME} \
    -n ${CHAINCODE_NAME} \
    -c '{"function":"InitLedger","Args":[]}' \
    -o orderer.example.com:7050 \
    --tls --cafile "${CLI_ORDERER_CA}" \
    --peerAddresses peer0.org1.example.com:7051 \
    --tlsRootCertFiles "${CLI_PEER_TLS}"

echo "  Done."

# ── Step 7: Summary ──────────────────────────────────────────────────────────
echo "[7/7] Network is ready!"
echo ""
echo "  Channel  : ${CHANNEL_NAME}"
echo "  Chaincode: ${CHAINCODE_NAME} v${CHAINCODE_VERSION} (sequence ${CHAINCODE_SEQUENCE})"
echo "  Peer     : localhost:7051"
echo "  Orderer  : localhost:7050"
echo ""
echo "  Connection profile -> fabric/connection-profile.json"
echo ""
echo "  Start backend with FABRIC_ENABLED=true to route to Fabric instead of Ethereum."
echo ""
