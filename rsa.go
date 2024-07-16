package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/niclabs/tcrsa"
)

type Party struct {
	ID       int
	KeyShare *tcrsa.KeyShare
}

type OutsideParty struct {
	Name       string
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

func generateThresholdKey(k, l uint16, keySize int) (*tcrsa.KeyMeta, tcrsa.KeyShareList, error) {
	log.Println("Generating threshold key...")
	keyShares, keyMeta, err := tcrsa.NewKey(keySize, k, l, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate threshold key: %v", err)
	}
	log.Println("Threshold key generated successfully")
	return keyMeta, keyShares, nil
}

func generateOutsidePartyKeys(name string) (*OutsideParty, error) {
	log.Printf("Generating keys for %s...", name)
	privateKey, err := ecdsa.GenerateKey(ecies.DefaultCurve, rand.Reader)
	if err != nil {
		return nil, err
	}
	log.Printf("Keys generated successfully for %s", name)
	return &OutsideParty{
		Name:       name,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

func encryptForThresholdPK(data []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	log.Println("Encrypting data with threshold public key...")
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, data)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %v", err)
	}
	log.Println("Data encrypted successfully")
	return encrypted, nil
}

func collectivelyDecryptAndReencrypt(parties []*Party, encryptedData []byte, keyMeta *tcrsa.KeyMeta, consumerPK *ecdsa.PublicKey) ([]byte, error) {
	log.Println("Starting collective decryption and re-encryption process...")

	// Step 1: Prepare the document hash
	docHash := sha256.Sum256(encryptedData)
	digest, err := tcrsa.PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, docHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to prepare document hash: %v", err)
	}

	// Step 2: Collective partial decryptions
	sigShares := make(tcrsa.SigShareList, len(parties))
	for i, party := range parties {
		log.Printf("Party %d creating signature share...", party.ID)
		share, err := party.KeyShare.Sign(digest, crypto.SHA256, keyMeta)
		if err != nil {
			return nil, fmt.Errorf("party %d failed to create signature share: %v", party.ID, err)
		}
		sigShares[i] = share
		log.Printf("Party %d created signature share successfully", party.ID)
	}

	// Step 3: Combine signature shares
	log.Println("Combining signature shares...")
	signature, err := sigShares.Join(digest, keyMeta)
	if err != nil {
		return nil, fmt.Errorf("failed to combine signature shares: %v", err)
	}
	log.Println("Signature shares combined successfully")

	// Step 4: Re-encrypt for the consumer
	log.Println("Re-encrypting data for the consumer...")
	eciesPublicKey := ecies.ImportECDSAPublic(consumerPK)
	reencryptedData, err := ecies.Encrypt(rand.Reader, eciesPublicKey, signature, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("re-encryption failed: %v", err)
	}
	log.Println("Data re-encrypted successfully for the consumer")

	return reencryptedData, nil
}

func (op *OutsideParty) decrypt(encryptedData []byte) ([]byte, error) {
	log.Printf("%s is decrypting the data...", op.Name)
	eciesPrivateKey := ecies.ImportECDSA(op.PrivateKey)
	decrypted, err := eciesPrivateKey.Decrypt(encryptedData, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}
	log.Printf("%s decrypted the data successfully", op.Name)
	return decrypted, nil
}



func main() {
	log.Println("Starting secure data sharing process...")

	// Set up threshold parameters
	k := uint16(2) // threshold
	l := uint16(3) // total number of parties
	keySize := 2048

	// Generate threshold key
	keyMeta, keyShares, err := generateThresholdKey(k, l, keySize)
	if err != nil {
		log.Fatalf("Failed to generate threshold key: %v", err)
	}

	// Create parties
	parties := make([]*Party, l)
	for i := uint16(0); i < l; i++ {
		parties[i] = &Party{
			ID:       int(i + 1),
			KeyShare: keyShares[i],
		}
		log.Printf("Party %d initialized", parties[i].ID)
	}

	dataConsumer, err := generateOutsidePartyKeys("Data Consumer")
	if err != nil {
		log.Fatalf("Failed to generate data consumer keys: %v", err)
	}

	// Get data from user input
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the secret data: ")
	input, _ := reader.ReadString('\n')
	originalData := []byte(strings.TrimSpace(input))

	// Data provider encrypts the data with the threshold public key
	encryptedData, err := encryptForThresholdPK(originalData, keyMeta.PublicKey)
	if err != nil {
		log.Fatalf("Data provider encryption failed: %v", err)
	}
	log.Printf("Data encrypted by provider: %x", encryptedData)

	// Parties collectively decrypt and re-encrypt for the consumer
	reencryptedData, err := collectivelyDecryptAndReencrypt(parties, encryptedData, keyMeta, dataConsumer.PublicKey)
	if err != nil {
		log.Fatalf("Collective decryption and re-encryption failed: %v", err)
	}
	log.Printf("Data re-encrypted for consumer: %x", reencryptedData)

	// Data consumer decrypts the data
	decryptedData, err := dataConsumer.decrypt(reencryptedData)
	if err != nil {
		log.Fatalf("Data consumer decryption failed: %v", err)
	}

	log.Println("Process completed successfully")
	fmt.Printf("\nOriginal data: %s\n", originalData)
	fmt.Printf("Data decrypted by consumer: %x\n", decryptedData)
	fmt.Printf("NOTE: decrypted data is *not* the original data, but a signature derived from the encrypted data. Additional work is needed to securely share the original data with the consumer.\n")

	// Verify the signature
	docHash := sha256.Sum256(encryptedData)
	err = rsa.VerifyPKCS1v15(keyMeta.PublicKey, crypto.SHA256, docHash[:], decryptedData)
	if err == nil {
		fmt.Println("Success: Signature verified!")
	} else {
		fmt.Println("Error: Signature verification failed.")
	}
}