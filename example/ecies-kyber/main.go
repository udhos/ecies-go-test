// Package main implements the tool.
package main

import (
	"log"

	"go.dedis.ch/kyber/v3/encrypt/ecies"
	"go.dedis.ch/kyber/v3/group/nist"
	"go.dedis.ch/kyber/v3/util/random"
)

func main() {

	message := "Hello ECIES"

	suite := nist.NewBlakeSHA256P256()

	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)

	ciphertext, err := ecies.Encrypt(suite, public, []byte(message), suite.Hash)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}

	plaintext, err := ecies.Decrypt(suite, private, ciphertext, suite.Hash)
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}

	plainStr := string(plaintext)
	if plainStr != message {
		log.Fatalf("wanted=[%s] got=[%s]", message, plainStr)
	}

	log.Printf("good")
}
