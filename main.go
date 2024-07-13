/*
TSS (Threshold Signature Scheme) Tutorial

This tutorial demonstrates how to use the tss-lib to implement a threshold signature scheme.
The process involves distributed key generation and collective signing, which are fundamental
to creating a system where multiple parties can jointly manage encrypted data without any
single party having complete control.

Flow of the program:
1. Generate party IDs for participants
2. Perform distributed key generation (DKG)
3. Use the generated keys to create a threshold signature

This implementation is a simplified version of a system where:
- A group (e.g., a DAO) elects leaders
- Leaders generate a shared public key and individual private key shares
- Data can be encrypted with the public key
- A threshold of leaders can collaborate to decrypt the data
- Leaders can be replaced and shares can be refreshed for security

Note: This example doesn't include the encryption/decryption or share refresh processes,
      focusing instead on the key generation and signing aspects.

Important: This is a proof of concept and should not be used in production without
           further security considerations and error handling.
*/

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// Constants for the number of participants and the threshold
// In a real-world scenario, these might be configurable or determined by the DAO
const (
	threshold    = 2 // Number of parties required to sign
	participants = 3 // Total number of parties
)

func main() {
	log.Println("Starting TSS demonstration")

	// Key Generation
	keys, err := runKeygen()
	if err != nil {
		log.Fatalf("Keygen failed: %v\n", err)
	}
	log.Println("Key generation completed successfully.")

	// Signing
	// Generate a random message to sign
	message := common.GetRandomPrimeInt(rand.Reader, 128)
	log.Printf("Message to sign: %s\n", message.String())

	signature, err := runSigning(message, keys)
	if err != nil {
		log.Fatalf("Signing failed: %v\n", err)
	}
	log.Printf("Signature generated: R=%x, S=%x\n", signature.R, signature.S)

	// Verify signature
	publicKey := &ecdsa.PublicKey{
		Curve: tss.S256(), // We're using the secp256k1 curve
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	R := new(big.Int).SetBytes(signature.R)
	S := new(big.Int).SetBytes(signature.S)
	verified := ecdsa.Verify(publicKey, message.Bytes(), R, S)
	log.Printf("Signature verified: %v\n", verified)
}

// generatePartyIDs creates a sorted list of party IDs for the TSS protocol
// Each party needs a unique identifier for the protocol to work correctly
func generatePartyIDs(count int) tss.SortedPartyIDs {
	var partyIDs tss.UnSortedPartyIDs
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("%d", i+1)
		moniker := fmt.Sprintf("party-%d", i+1)
		key := big.NewInt(int64(i + 1))
		// NewPartyID creates a new party ID with the given id, moniker, and key
		partyIDs = append(partyIDs, tss.NewPartyID(id, moniker, key))
	}
	// SortPartyIDs sorts the party IDs, which is required for the protocol
	return tss.SortPartyIDs(partyIDs)
}

// runKeygen performs the distributed key generation process
func runKeygen() ([]*keygen.LocalPartySaveData, error) {
	log.Println("Starting Key Generation")
	partyIDs := generatePartyIDs(participants)

	// Create a peer context, which holds information about all participants
	peerCtx := tss.NewPeerContext(partyIDs)
	// Create parameters for the TSS protocol
	params := tss.NewParameters(tss.S256(), peerCtx, partyIDs[0], len(partyIDs), threshold)

	// Channels for communication between parties
	outCh := make(chan tss.Message, len(partyIDs))
	endCh := make(chan *keygen.LocalPartySaveData, len(partyIDs))

	parties := make([]*keygen.LocalParty, len(partyIDs))
	for i := 0; i < len(partyIDs); i++ {
		// Create new parameters for each party, ensuring they have the correct PartyID
		params := tss.NewParameters(params.EC(), params.Parties(), partyIDs[i], params.PartyCount(), params.Threshold())
		parties[i] = keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
	}

	// Start each party in a separate goroutine
	for _, p := range parties {
		go func(p *keygen.LocalParty) {
			if err := p.Start(); err != nil {
				log.Printf("Failed to start party: %v\n", err)
			}
		}(p)
	}

	keys := make([]*keygen.LocalPartySaveData, len(partyIDs))
	keyCount := 0
	// Main event loop for key generation
	for {
		select {
		case msg := <-outCh:
			// Handle outgoing messages
			dest := msg.GetTo()
			if dest == nil {
				// Broadcast message
				for _, p := range parties {
					if p.PartyID().Index != msg.GetFrom().Index {
						go handleMessage(p, msg)
					}
				}
			} else {
				// Point-to-point message
				go handleMessage(parties[dest[0].Index], msg)
			}
		case key := <-endCh:
			// Collect key shares from each party
			keys[keyCount] = key
			keyCount++
			log.Printf("Received key share from party %d\n", keyCount)
			if keyCount == len(partyIDs) {
				log.Println("All key shares received")
				return keys, nil
			}
		}
	}
}

// runSigning performs the distributed signing process
func runSigning(message *big.Int, keys []*keygen.LocalPartySaveData) (*common.SignatureData, error) {
	log.Println("Starting Signing Process")
	// For signing, we only need threshold + 1 parties
	signPartyIDs := generatePartyIDs(threshold + 1)

	peerCtx := tss.NewPeerContext(signPartyIDs)
	params := tss.NewParameters(tss.S256(), peerCtx, signPartyIDs[0], len(signPartyIDs), threshold)

	outCh := make(chan tss.Message, len(signPartyIDs))
	endCh := make(chan *common.SignatureData, len(signPartyIDs))

	parties := make([]*signing.LocalParty, len(signPartyIDs))
	for i := 0; i < len(signPartyIDs); i++ {
		params := tss.NewParameters(params.EC(), params.Parties(), signPartyIDs[i], params.PartyCount(), params.Threshold())
		parties[i] = signing.NewLocalParty(message, params, *keys[i], outCh, endCh).(*signing.LocalParty)
	}

	// Start each signing party in a separate goroutine
	for _, p := range parties {
		go func(p *signing.LocalParty) {
			if err := p.Start(); err != nil {
				log.Printf("Failed to start signing party: %v\n", err)
			}
		}(p)
	}

	// Main event loop for signing
	for {
		select {
		case msg := <-outCh:
			// Handle outgoing messages
			dest := msg.GetTo()
			if dest == nil {
				// Broadcast message
				for _, p := range parties {
					if p.PartyID().Index != msg.GetFrom().Index {
						go handleSigningMessage(p, msg)
					}
				}
			} else {
				// Point-to-point message
				go handleSigningMessage(parties[dest[0].Index], msg)
			}
		case signature := <-endCh:
			// Signature is ready
			log.Println("Signature generated")
			return signature, nil
		}
	}
}

// handleMessage processes incoming messages for key generation
func handleMessage(p *keygen.LocalParty, msg tss.Message) {
	bytes, _, err := msg.WireBytes()
	if err != nil {
		log.Printf("Error getting wire bytes: %v\n", err)
		return
	}
	if _, err := p.UpdateFromBytes(bytes, msg.GetFrom(), msg.IsBroadcast()); err != nil {
		log.Printf("Failed to update party: %v\n", err)
	}
}

// handleSigningMessage processes incoming messages for signing
func handleSigningMessage(p *signing.LocalParty, msg tss.Message) {
	bytes, _, err := msg.WireBytes()
	if err != nil {
		log.Printf("Error getting wire bytes: %v\n", err)
		return
	}
	if _, err := p.UpdateFromBytes(bytes, msg.GetFrom(), msg.IsBroadcast()); err != nil {
		log.Printf("Failed to update signing party: %v\n", err)
	}
}

// Note: The current implementation is encountering errors in the signing phase.
// This could be due to issues with how the key shares are being used or how the
// signing parties are communicating. Further investigation and debugging are needed.

// Potential improvements and next steps:
// 1. Implement proper error handling and recovery mechanisms
// 2. Add a timeout mechanism to prevent indefinite waiting
// 3. Implement the encryption and decryption processes using the generated keys
// 4. Add the share refresh process to allow for leader replacement
// 5. Implement secure deletion of old shares after a refresh
// 6. Add more robust logging and monitoring to aid in debugging
// 7. Consider adding a simulation of the DAO voting process for leader election and data decryption