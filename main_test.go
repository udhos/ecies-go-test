package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"

	havir "github.com/danielhavir/go-ecies/ecies"
	ethereum "github.com/ethereum/go-ethereum/crypto/ecies"
	bitcoin "github.com/gitzhou/bitcoin-ecies"
	obscuren "github.com/obscuren/ecies"
)

type testKey struct {
	name       string
	strPEMPriv string
	strPEMPub  string
}

var testTableKey = []testKey{
	{"key1",
		`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICqetgUe4k7mYXgR/nOKV7JRYO/6ETgmQheWqyL9EIwhoAoGCCqGSM49
AwEHoUQDQgAE83buecyru7JmdZZFoUdY9jn12ht7YYHXMGhMmXjX4dd8gz/VuWdV
I2G4LStZ2hn0cfgzT8VdJCkRo+cynYpTOA==
-----END EC PRIVATE KEY-----
`,
		`
-----BEGIN EC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE83buecyru7JmdZZFoUdY9jn12ht7
YYHXMGhMmXjX4dd8gz/VuWdVI2G4LStZ2hn0cfgzT8VdJCkRo+cynYpTOA==
-----END EC PUBLIC KEY-----
`,
	},
}

type testText struct {
	name string
	text string
}

var testTableText = []testText{
	{"text1", "abc123"},
	//{"text1", "1234567890abc"},
}

type testCode struct {
	name    string
	encrypt func(pub *ecdsa.PublicKey, data []byte) ([]byte, error)
	decrypt func(priv *ecdsa.PrivateKey, data []byte) ([]byte, error)
}

var testTableCode = []testCode{
	{"ethereum", encryptEthereum, decryptEthereum},
	{"havir", encryptHavir, decryptHavir},
	{"obscuren", encryptObscuren, decryptObscuren},
	{"bitcoin", encryptBitcoin, decryptBitcoin},
}

// TestEncryptDecrypt performs several tests.
func TestEncryptDecrypt(t *testing.T) {
	helper(t)
}

func helper(t *testing.T) {

	t.Helper()

	for _, k := range testTableKey {

		privateKey, errKey := privateKeyFromPemStr(k.strPEMPriv)
		if errKey != nil {
			t.Errorf("could not load private key from pem: %v", errKey)
		}

		publicKey, errKey := publicKeyFromPemStr(k.strPEMPub)
		if errKey != nil {
			t.Errorf("could not load public key from pem: %v", errKey)
		}

		for _, txt := range testTableText {

			for _, codeSrc := range testTableCode {

				for _, codeDst := range testTableCode {

					encrypted, errEncrypt := codeSrc.encrypt(publicKey, []byte(txt.text))
					if errEncrypt != nil {
						t.Errorf("key=%4s text=%5s src=%8s dst=%8s error encrypt: %v", k.name, txt.name, codeSrc.name, codeDst.name, errEncrypt)
					}

					decrypted, errDecrypt := codeDst.decrypt(privateKey, encrypted)
					if errEncrypt != nil {
						t.Errorf("key=%4s text=%5s src=%8s dst=%8s error decrypt: %v", k.name, txt.name, codeSrc.name, codeDst.name, errDecrypt)
					}

					decryptedStr := string(decrypted)

					if txt.text != decryptedStr {
						t.Errorf("key=%4s text=%5s src=%8s dst=%8s FAIL wanted=[%s] got=[%s]", k.name, txt.name, codeSrc.name, codeDst.name, txt.text, decryptedStr)
						continue
					}

					t.Logf("key=%4s text=%5s src=%8s dst=%8s good", k.name, txt.name, codeSrc.name, codeDst.name)
				}
			}
		}

	}
}

func encryptEthereum(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {

	publicKey := ethereum.ImportECDSAPublic(pubKey)

	return ethereum.Encrypt(rand.Reader, publicKey, data, nil, nil)
}

func decryptEthereum(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {

	privateKey := ethereum.ImportECDSA(privKey)

	return privateKey.Decrypt(data, nil, nil)
}

func encryptHavir(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {

	curve := pubKey.Curve
	if curve != elliptic.P256() {
		return nil, fmt.Errorf("only P256 is supported")
	}

	publicKey := havir.PublicKey{X: pubKey.X, Y: pubKey.Y, Curve: curve}

	return havir.Encrypt(rand.Reader, &publicKey, data, nil, nil)
}

func decryptHavir(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {

	curve := privKey.Curve
	if curve != elliptic.P256() {
		return nil, fmt.Errorf("only P256 is supported")
	}

	pubKey := havir.PublicKey{Curve: curve}

	privateKey := havir.PrivateKey{
		PublicKey: pubKey,
		D:         new(big.Int).SetBytes(privKey.D.Bytes()),
	}

	return havir.Decrypt(&privateKey, data, nil, nil)
}

func encryptObscuren(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {

	publicKey := obscuren.ImportECDSAPublic(pubKey)

	return obscuren.Encrypt(rand.Reader, publicKey, data, nil, nil)
}

func decryptObscuren(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {

	privateKey := obscuren.ImportECDSA(privKey)

	return privateKey.Decrypt(rand.Reader, data, nil, nil)
}

func encryptBitcoin(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {

	pubKeyBytes := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)

	dataStr, err := bitcoin.EncryptMessage(string(data), pubKeyBytes)

	return []byte(dataStr), err
}

func decryptBitcoin(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {

	privKeyBytes := privKey.D.Bytes()

	dataStr, err := bitcoin.DecryptMessage(string(data), privKeyBytes)

	return []byte(dataStr), err
}

func privateKeyFromPemStr(privPEM string) (*ecdsa.PrivateKey, error) {
	me := "PrivateKeyFromPemStr"

	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, fmt.Errorf("%s: key not found", me)
	}

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", me, err)
	}

	return priv, nil
}

func publicKeyFromPemStr(pubPEM string) (*ecdsa.PublicKey, error) {
	me := "PublicKeyFromPemStr"

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, fmt.Errorf("%s: key not found", me)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", me, err)
	}

	p, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA public key", me)
	}

	return p, nil
}
