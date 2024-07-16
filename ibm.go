package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	ecdsa_scheme "github.com/IBM/TSS/mpc/binance/ecdsa"
	"github.com/IBM/TSS/threshold"
	. "github.com/IBM/TSS/types"
)

// SimpleLogger implements the Logger interface
type SimpleLogger struct{}

func (l *SimpleLogger) Debugf(format string, a ...interface{}) {
	// Disable this for now
	//log.Printf("DEBUG: "+format, a...)
}

func (l *SimpleLogger) Infof(format string, a ...interface{}) {
	log.Printf("INFO: "+format, a...)
}

func (l *SimpleLogger) Warnf(format string, a ...interface{}) {
	log.Printf("WARN: "+format, a...)
}

func (l *SimpleLogger) Errorf(format string, a ...interface{}) {
	log.Printf("ERROR: "+format, a...)
}

func (l *SimpleLogger) DebugEnabled() bool {
	return true
}

// Global channel to simulate network communication
var messageChan = make(chan Message, 100)

type Message struct {
	From     uint16
	To       []uint16
	MsgType  uint8
	Topic    []byte
	Data     []byte
}

func setupScheme(id uint16, totalParties, partyThreshold int) MpcParty {
	logger := &SimpleLogger{}

	membership := func() map[UniversalID]PartyID {
		m := make(map[UniversalID]PartyID)
		for i := uint16(1); i <= uint16(totalParties); i++ {
			m[UniversalID(i)] = PartyID(i)
		}
		return m
	}

	send := func(msgType uint8, topic []byte, msg []byte, to ...uint16) {
		messageChan <- Message{
			From:    id,
			To:      to,
			MsgType: msgType,
			Topic:   topic,
			Data:    msg,
		}
	}

	kgf := func(id uint16) KeyGenerator {
		return ecdsa_scheme.NewParty(id, logger)
	}

	sf := func(id uint16) Signer {
		return ecdsa_scheme.NewParty(id, logger)
	}

	return threshold.LoudScheme(id, logger, kgf, sf, partyThreshold, send, membership)
}

func runDKG(scheme MpcParty, totalParties, threshold int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	secretData, err := scheme.KeyGen(ctx, totalParties, threshold)
	if err != nil {
		return nil, fmt.Errorf("DKG failed: %v", err)
	}

	return secretData, nil
}

func sign(scheme MpcParty, message string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	msgHash := sha256.Sum256([]byte(message))

	// Use a unique topic for each signing session
	topic := fmt.Sprintf("signing-topic-%s", hex.EncodeToString(msgHash[:8]))

	signature, err := scheme.Sign(ctx, msgHash[:], topic)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %v", err)
	}

	return signature, nil
}

func handleMessages(schemes []MpcParty) {
	for msg := range messageChan {
		for _, to := range msg.To {
			if int(to) <= len(schemes) {
				schemes[to-1].HandleMessage(&IncMessage{
					Source:  msg.From,
					MsgType: msg.MsgType,
					Topic:   msg.Topic,
					Data:    msg.Data,
				})
			}
		}
	}
}

func verifySignature(scheme MpcParty, message string, signature []byte) bool {
	msgHash := sha256.Sum256([]byte(message))
	pubKeyBytes, err := scheme.ThresholdPK()
	if err != nil {
		log.Printf("Failed to get public key: %v", err)
		return false
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		log.Printf("Failed to parse public key: %v", err)
		return false
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		log.Printf("Public key is not an ECDSA key")
		return false
	}

	return ecdsa.VerifyASN1(ecdsaPubKey, msgHash[:], signature)
}

func refreshShares(schemes []MpcParty, totalParties, threshold int) error {
	log.Println("Starting share refresh process")

	var wg sync.WaitGroup
	errorChan := make(chan error, len(schemes))

	for i := range schemes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			// Use a unique topic for each refresh session
			topic := fmt.Sprintf("refresh-topic-%d", time.Now().UnixNano())

			// Perform a new DKG to simulate refresh, using the unique topic
			newShareData, err := schemes[i].KeyGen(ctx, totalParties, threshold)
			if err != nil {
				errorChan <- fmt.Errorf("share refresh failed for party %d: %v", i+1, err)
				return
			}

			// Update the stored data with the new share
			schemes[i].SetStoredData(newShareData)
			log.Printf("Party %d completed share refresh with topic %s", i+1, topic)
		}(i)
	}

	wg.Wait()
	close(errorChan)

	// Check for any errors
	for err := range errorChan {
		if err != nil {
			return err
		}
	}

	log.Println("Share refresh process completed successfully")
	return nil
}

func main() {
	totalParties := 3
	threshold := 2

	// Set up schemes for each party
	schemes := make([]MpcParty, totalParties)
	for i := 0; i < totalParties; i++ {
		schemes[i] = setupScheme(uint16(i+1), totalParties, threshold)
	}

	// Start the message handler
	go handleMessages(schemes)

	// Run initial DKG
	if err := runDKGForAllParties(schemes, totalParties, threshold); err != nil {
		log.Fatalf("Initial DKG failed: %v", err)
	}

	// Sign a message
	message := "Hello, World!"
	signatures, err := signWithAllParties(schemes, message)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}

	// Verify signatures
	for i, sig := range signatures {
		isValid := verifySignature(schemes[0], message, sig)
		log.Printf("Signature from party %d is valid: %v", i+1, isValid)
	}

	// Refresh shares
	if err := refreshShares(schemes, totalParties, threshold); err != nil {
		log.Fatalf("Share refresh failed: %v", err)
	}

	// Sign a new message after refresh to verify everything still works
	newMessage := "Hello after refresh!"
	newSignatures, err := signWithAllParties(schemes, newMessage)
	if err != nil {
		log.Fatalf("Signing after refresh failed: %v", err)
	}

	// Verify new signatures
	for i, sig := range newSignatures {
		isValid := verifySignature(schemes[0], newMessage, sig)
		log.Printf("Signature after refresh from party %d is valid: %v", i+1, isValid)
	}
}

// Helper function to run DKG for all parties
func runDKGForAllParties(schemes []MpcParty, totalParties, threshold int) error {
	var wg sync.WaitGroup
	errorChan := make(chan error, len(schemes))

	for i := range schemes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			secretData, err := runDKG(schemes[i], totalParties, threshold)
			if err != nil {
				errorChan <- fmt.Errorf("DKG failed for party %d: %v", i+1, err)
				return
			}
			schemes[i].SetStoredData(secretData)
			log.Printf("Party %d completed DKG", i+1)
		}(i)
	}

	wg.Wait()
	close(errorChan)

	for err := range errorChan {
		if err != nil {
			return err
		}
	}

	return nil
}

func signWithAllParties(schemes []MpcParty, message string) ([][]byte, error) {
	var wg sync.WaitGroup
	signatureChan := make(chan []byte, len(schemes))
	errorChan := make(chan error, len(schemes))

	for i := range schemes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			signature, err := sign(schemes[i], message)
			if err != nil {
				errorChan <- fmt.Errorf("signing failed for party %d: %v", i+1, err)
				return
			}
			signatureChan <- signature
			log.Printf("Party %d completed signing", i+1)
		}(i)
	}

	wg.Wait()
	close(signatureChan)
	close(errorChan)

	var signatures [][]byte
	for sig := range signatureChan {
		signatures = append(signatures, sig)
	}

	for err := range errorChan {
		if err != nil {
			return nil, err
		}
	}

	return signatures, nil
}
