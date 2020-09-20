package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/udhos/ecies-go-test/secp256k1"

	btcec "github.com/btcsuite/btcd/btcec"
	havir "github.com/danielhavir/go-ecies/ecies"
	ecies_go "github.com/ecies/go"
	ethereum "github.com/ethereum/go-ethereum/crypto/ecies"
	bitcoin "github.com/gitzhou/bitcoin-ecies"
	sghcrypto "github.com/nnitquan/sghcrypto/util"
	obscuren "github.com/obscuren/ecies"
)

type testKey struct {
	name       string
	curve      string
	strPEMPriv string
	strPEMPub  string
}

var testTableKey = []testKey{
	{"key1",
		"secp256r1",
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
	{"key2",
		"secp256k1",
		`
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIDzz5ityX01CmBOV/fpBlBP3S6+gH8fcCuvcNH9afupmoAcGBSuBBAAK
oUQDQgAExmziEVB0icHwNAnEiFtffewTrjyiWUEF0v61Izskw1hxhr4IDb8T5v75
8y+dkR19dQkxXHdJmLCvUjNT2BkBBA==
-----END EC PRIVATE KEY-----
`,
		`
-----BEGIN EC PUBLIC KEY-----
MFQwDgYFK4EEAAoGBSuBBAAKA0IABMZs4hFQdInB8DQJxIhbX33sE648ollBBdL+
tSM7JMNYcYa+CA2/E+b++fMvnZEdfXUJMVx3SZiwr1IzU9gZAQQ=
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
	curves  map[string]struct{} // supported curves (secp256r1, secp256k1)
	encrypt func(pub *ecdsa.PublicKey, data []byte) ([]byte, error)
	decrypt func(priv *ecdsa.PrivateKey, data []byte) ([]byte, error)
}

var testTableCode = []testCode{
	{"ethereum", map[string]struct{}{"secp256r1": struct{}{}}, encryptEthereum, decryptEthereum},
	{"havir", map[string]struct{}{"secp256r1": struct{}{}}, encryptHavir, decryptHavir},
	{"obscuren", map[string]struct{}{"secp256r1": struct{}{}}, encryptObscuren, decryptObscuren},
	{"bitcoin", map[string]struct{}{"secp256k1": struct{}{}}, encryptBitcoin, decryptBitcoin},
	{"sghcrypto", map[string]struct{}{"secp256k1": struct{}{}}, encryptSghcrypto, decryptSghcrypto},
	{"ecies_go", map[string]struct{}{"secp256k1": struct{}{}}, encryptEciesgo, decryptEciesgo},
	{"btcec", map[string]struct{}{"secp256k1": struct{}{}}, encryptBtcec, decryptBtcec},
}

// TestEncryptDecrypt performs several tests.
func TestEncryptDecrypt(t *testing.T) {
	helper(t)
}

func helper(t *testing.T) {

	t.Helper()

	for _, k := range testTableKey {

		var privateKey *ecdsa.PrivateKey
		var publicKey *ecdsa.PublicKey
		var errKey error

		if k.curve == "secp256r1" {
			privateKey, errKey = privateKeyFromPemStr(k.strPEMPriv)
			if errKey != nil {
				t.Errorf("could not load private key from pem: %v", errKey)
				continue
			}

			publicKey, errKey = publicKeyFromPemStr(k.strPEMPub)
			if errKey != nil {
				t.Errorf("could not load public key from pem: %v", errKey)
				continue
			}
		}

		if k.curve == "secp256k1" {

			priv, errPriv := secp256k1.ParsePrivateKeyPem([]byte(k.strPEMPriv))
			if errPriv != nil {
				t.Errorf("could not load private key curve secp256k1 from pem: %v", errPriv)
				continue
			}

			pub, errPub := secp256k1.ParsePublicKeyPem([]byte(k.strPEMPub))
			if errPub != nil {
				t.Errorf("could not load public key curve secp256k1 from pem: %v", errPub)
				continue
			}

			privateKey = priv.ToECDSA()
			publicKey = pub.ToECDSA()

			//t.Logf("key=%4s(%9s): FIXME WRITEME load keys", k.name, k.curve)
			//continue
		}

		for _, txt := range testTableText {

			for _, codeSrc := range testTableCode {

				if _, found := codeSrc.curves[k.curve]; !found {
					continue // key curve not supported by src code
				}

				for _, codeDst := range testTableCode {

					if _, found := codeDst.curves[k.curve]; !found {
						continue // key curve not supported by dst code
					}

					encrypted, errEncrypt := codeSrc.encrypt(publicKey, []byte(txt.text))
					if errEncrypt != nil {
						t.Errorf("key=%4s(%9s) text=%5s src=%9s dst=%9s error encrypt: %v", k.name, k.curve, txt.name, codeSrc.name, codeDst.name, errEncrypt)
						continue
					}

					decrypted, errDecrypt := codeDst.decrypt(privateKey, encrypted)
					if errEncrypt != nil {
						t.Errorf("key=%4s(%9s) text=%5s src=%9s dst=%9s error decrypt: %v", k.name, k.curve, txt.name, codeSrc.name, codeDst.name, errDecrypt)
						continue
					}

					decryptedStr := string(decrypted)

					if txt.text != decryptedStr {
						t.Errorf("key=%4s(%9s) text=%5s src=%9s dst=%9s FAIL wanted=[%s] got=[%s]", k.name, k.curve, txt.name, codeSrc.name, codeDst.name, txt.text, decryptedStr)
						continue
					}

					t.Logf("key=%4s(%9s) text=%5s src=%9s dst=%9s good", k.name, k.curve, txt.name, codeSrc.name, codeDst.name)
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

func pubKeyBytes(pubKey *ecdsa.PublicKey) []byte {
	b := append([]byte{0x04}, pubKey.X.Bytes()...)
	return append(b, pubKey.Y.Bytes()...)
}

func encryptBitcoin(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {
	pubKeyBytes := pubKeyBytes(pubKey)
	dataStr, err := bitcoin.EncryptMessage(string(data), pubKeyBytes)
	return []byte(dataStr), err
}

func decryptBitcoin(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	privKeyBytes := privKey.D.Bytes()
	dataStr, err := bitcoin.DecryptMessage(string(data), privKeyBytes)
	return []byte(dataStr), err
}

func encryptSghcrypto(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {
	pubKeyBytes := pubKeyBytes(pubKey)
	return sghcrypto.EciesEncrypt(data, pubKeyBytes)
}

func decryptSghcrypto(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	privKeyBytes := privKey.D.Bytes()
	return sghcrypto.EciesDecrypt(data, privKeyBytes)
}

func encryptEciesgo(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {
	pubKeyBytes := pubKeyBytes(pubKey)
	pub, errPub := ecies_go.NewPublicKeyFromBytes(pubKeyBytes)
	if errPub != nil {
		return nil, errPub
	}
	return ecies_go.Encrypt(pub, data)
}

func decryptEciesgo(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	privKeyBytes := privKey.D.Bytes()
	priv := ecies_go.NewPrivateKeyFromBytes(privKeyBytes)
	return ecies_go.Decrypt(priv, data)
}

func encryptBtcec(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {
	pub := btcec.PublicKey(*pubKey)
	return btcec.Encrypt(&pub, data)
}

func decryptBtcec(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	priv := btcec.PrivateKey(*privKey)
	return btcec.Decrypt(&priv, data)
}

func privateKeyFromPemStr(privPEM string) (*ecdsa.PrivateKey, error) {
	me := "privateKeyFromPemStr"

	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, fmt.Errorf("%s: key not found", me)
	}

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", me, err)
	}

	log.Printf("%s: is P256 secp256r1? %v", me, priv.Curve == elliptic.P256())

	return priv, nil
}

func publicKeyFromPemStr(pubPEM string) (*ecdsa.PublicKey, error) {
	me := "publicKeyFromPemStr"

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

	log.Printf("%s: is P256 secp256r1? %v", me, p.Curve == elliptic.P256())

	return p, nil
}
