package main

/*
 * DocVerifier Chaincode – Hyperledger Fabric 2.5
 *
 * Mirrors the Solidity DocVerifier v3 contract:
 *   - AnchorDocument(docHash, ipfsCid)
 *   - VerifyDocument(docHash) → Document
 *   - RevokeDocument(docHash)
 *   - PauseNetwork() / UnpauseNetwork()
 *   - TransferOwnership(newOwner)
 *
 * Uses Private Data Collections (PDC) to store full metadata in "collectionDocs"
 * while the channel ledger only holds the public hash→state index.
 *
 * Channel: mychannel
 * Chaincode name: docverifier
 */

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ─── Data model ─────────────────────────────────────────────────────────────

// Document is stored in the Private Data Collection "collectionDocs".
type Document struct {
	DocHash   string    `json:"docHash"`
	IpfsCid   string    `json:"ipfsCid"`
	Issuer    string    `json:"issuer"`
	Timestamp time.Time `json:"timestamp"`
	Revoked   bool      `json:"revoked"`
}

// NetworkState is kept on the public ledger (key = "NETWORK_STATE").
type NetworkState struct {
	Paused bool   `json:"paused"`
	Owner  string `json:"owner"`
}

// ─── Contract ────────────────────────────────────────────────────────────────

// DocVerifier implements the Fabric chaincode.
type DocVerifier struct {
	contractapi.Contract
}

const (
	collection    = "collectionDocs"
	stateKey      = "NETWORK_STATE"
	pubKeyPrefix  = "DOC~" // public ledger composite key prefix
)

// ─── Lifecycle ───────────────────────────────────────────────────────────────

// InitLedger bootstraps the network state.  Called once at chaincode instantiation.
func (c *DocVerifier) InitLedger(ctx contractapi.TransactionContextInterface) error {
	caller, err := callerMSP(ctx)
	if err != nil {
		return err
	}
	state := NetworkState{Paused: false, Owner: caller}
	return putState(ctx, stateKey, &state)
}

// ─── Core functions ──────────────────────────────────────────────────────────

// AnchorDocument records a SHA-256 hash on-chain together with optional IPFS CID.
// The full document metadata is written to the Private Data Collection.
// Rejects if the network is paused or the hash was already anchored.
func (c *DocVerifier) AnchorDocument(ctx contractapi.TransactionContextInterface, docHash, ipfsCid string) error {
	if err := requireUnpaused(ctx); err != nil {
		return err
	}
	if docHash == "" {
		return errors.New("docHash cannot be empty")
	}

	// Reject double-anchoring
	existing, err := getDocumentPrivate(ctx, docHash)
	if err == nil && existing != nil {
		return fmt.Errorf("document already anchored: %s", docHash)
	}

	issuer, err := callerMSP(ctx)
	if err != nil {
		return err
	}

	doc := Document{
		DocHash:   docHash,
		IpfsCid:   ipfsCid,
		Issuer:    issuer,
		Timestamp: time.Now().UTC(),
		Revoked:   false,
	}

	// Write full metadata to PDC
	if err := putPrivate(ctx, collection, docHash, &doc); err != nil {
		return err
	}

	// Write lightweight public index (docHash → "1")
	return ctx.GetStub().PutState(pubKeyPrefix+docHash, []byte("1"))
}

// VerifyDocument looks up a document by hash.
// Returns the full Document (from PDC) if found, or an error if not found.
func (c *DocVerifier) VerifyDocument(ctx contractapi.TransactionContextInterface, docHash string) (*Document, error) {
	return getDocumentPrivate(ctx, docHash)
}

// IsRevoked returns true if a previously anchored document has been revoked.
func (c *DocVerifier) IsRevoked(ctx contractapi.TransactionContextInterface, docHash string) (bool, error) {
	doc, err := getDocumentPrivate(ctx, docHash)
	if err != nil {
		return false, err
	}
	return doc.Revoked, nil
}

// RevokeDocument marks a document as revoked.  Only the original issuer or the
// network owner may revoke.
func (c *DocVerifier) RevokeDocument(ctx contractapi.TransactionContextInterface, docHash string) error {
	doc, err := getDocumentPrivate(ctx, docHash)
	if err != nil {
		return err
	}
	if doc.Revoked {
		return fmt.Errorf("document already revoked: %s", docHash)
	}

	caller, err := callerMSP(ctx)
	if err != nil {
		return err
	}
	state, err := getState(ctx)
	if err != nil {
		return err
	}
	if caller != doc.Issuer && caller != state.Owner {
		return errors.New("only the issuer or owner may revoke a document")
	}

	doc.Revoked = true
	return putPrivate(ctx, collection, docHash, doc)
}

// ─── Admin functions ─────────────────────────────────────────────────────────

// PauseNetwork prevents any new documents from being anchored.
func (c *DocVerifier) PauseNetwork(ctx contractapi.TransactionContextInterface) error {
	if err := requireOwner(ctx); err != nil {
		return err
	}
	state, err := getState(ctx)
	if err != nil {
		return err
	}
	if state.Paused {
		return errors.New("network is already paused")
	}
	state.Paused = true
	return putState(ctx, stateKey, state)
}

// UnpauseNetwork re-enables document anchoring.
func (c *DocVerifier) UnpauseNetwork(ctx contractapi.TransactionContextInterface) error {
	if err := requireOwner(ctx); err != nil {
		return err
	}
	state, err := getState(ctx)
	if err != nil {
		return err
	}
	if !state.Paused {
		return errors.New("network is not paused")
	}
	state.Paused = false
	return putState(ctx, stateKey, state)
}

// TransferOwnership changes the network owner to a new MSP identity.
func (c *DocVerifier) TransferOwnership(ctx contractapi.TransactionContextInterface, newOwner string) error {
	if err := requireOwner(ctx); err != nil {
		return err
	}
	if newOwner == "" {
		return errors.New("newOwner cannot be empty")
	}
	state, err := getState(ctx)
	if err != nil {
		return err
	}
	state.Owner = newOwner
	return putState(ctx, stateKey, state)
}

// GetNetworkState returns the current paused/owner state (public).
func (c *DocVerifier) GetNetworkState(ctx contractapi.TransactionContextInterface) (*NetworkState, error) {
	return getState(ctx)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func getState(ctx contractapi.TransactionContextInterface) (*NetworkState, error) {
	raw, err := ctx.GetStub().GetState(stateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read network state: %w", err)
	}
	if raw == nil {
		// Not yet initialised (unit tests that skip InitLedger)
		return &NetworkState{Paused: false, Owner: "Org1MSP"}, nil
	}
	var s NetworkState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("unmarshal network state: %w", err)
	}
	return &s, nil
}

func putState(ctx contractapi.TransactionContextInterface, key string, v interface{}) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", key, err)
	}
	return ctx.GetStub().PutState(key, raw)
}

func getDocumentPrivate(ctx contractapi.TransactionContextInterface, docHash string) (*Document, error) {
	raw, err := ctx.GetStub().GetPrivateData(collection, docHash)
	if err != nil {
		return nil, fmt.Errorf("failed to read private data: %w", err)
	}
	if raw == nil {
		return nil, fmt.Errorf("document not found: %s", docHash)
	}
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal document: %w", err)
	}
	return &doc, nil
}

func putPrivate(ctx contractapi.TransactionContextInterface, coll, key string, v interface{}) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal private data: %w", err)
	}
	return ctx.GetStub().PutPrivateData(coll, key, raw)
}

func callerMSP(ctx contractapi.TransactionContextInterface) (string, error) {
	id, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("get caller MSP: %w", err)
	}
	return id, nil
}

func requireUnpaused(ctx contractapi.TransactionContextInterface) error {
	state, err := getState(ctx)
	if err != nil {
		return err
	}
	if state.Paused {
		return errors.New("network is paused; new anchoring is disabled")
	}
	return nil
}

func requireOwner(ctx contractapi.TransactionContextInterface) error {
	caller, err := callerMSP(ctx)
	if err != nil {
		return err
	}
	state, err := getState(ctx)
	if err != nil {
		return err
	}
	if caller != state.Owner {
		return fmt.Errorf("caller %s is not the owner (%s)", caller, state.Owner)
	}
	return nil
}

// ─── Main ───────────────────────────────────────────────────────────────────

func main() {
	cc, err := contractapi.NewChaincode(&DocVerifier{})
	if err != nil {
		panic(fmt.Sprintf("failed to create chaincode: %v", err))
	}
	if err := cc.Start(); err != nil {
		panic(fmt.Sprintf("failed to start chaincode: %v", err))
	}
}
