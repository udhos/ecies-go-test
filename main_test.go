package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/udhos/ecies-go-test/secp256k1"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	"go.dedis.ch/kyber/v3/group/nist"

	btcec "github.com/btcsuite/btcd/btcec"
	ecies_go "github.com/ecies/go/v2"
	ethereum "github.com/ethereum/go-ethereum/crypto/ecies"
	bitcoin "github.com/gitzhou/bitcoin-ecies"
	tink_hybrid "github.com/google/tink/go/hybrid"
	jafgoecies "github.com/kubasiemion/jafgoecies/ecies"
	sghcrypto "github.com/nnitquan/sghcrypto/util"
	obscuren "github.com/obscuren/ecies"
	havir "github.com/udhos/go-ecies/ecies" // "github.com/danielhavir/go-ecies" with modules support
	kyber "go.dedis.ch/kyber/v3/encrypt/ecies"
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
		"secp256r1",
		`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK3z9XNwdVxQ8CCh3gTk3kLifKlYBWpHnFGx4UeLHJ+/oAoGCCqGSM49
AwEHoUQDQgAEv/5Q0Kj50tRkrocn9FbspEMrdlttT8p6boUyWHaw+UmJBY2dZrc2
CLUynQURtT0iEI+lTAN5K9jDrI+Z5aAXYw==
-----END EC PRIVATE KEY-----
`,
		`
-----BEGIN EC PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEv/5Q0Kj50tRkrocn9FbspEMrdltt
T8p6boUyWHaw+UmJBY2dZrc2CLUynQURtT0iEI+lTAN5K9jDrI+Z5aAXYw==
-----END EC PUBLIC KEY-----
`,
	},
	{"key3",
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
	{"key4-openssl",
		"secp256k1",
		`
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIEmcxYieANXo17EjuPS0aR+owhBFqzBKcIXcQ/ReeBWPoAcGBSuBBAAK
oUQDQgAEwzC/yMyG6gkJw2Oy237aHOY3kKU4PGt9P0sCNB4ze84IzMhrJmO7niUv
dRf/NZvnPL7RfcKR3WJBA+bwwUMqxw==
-----END EC PRIVATE KEY-----
`,
		`
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEwzC/yMyG6gkJw2Oy237aHOY3kKU4PGt9
P0sCNB4ze84IzMhrJmO7niUvdRf/NZvnPL7RfcKR3WJBA+bwwUMqxw==
-----END PUBLIC KEY-----
`,
	},
	{"key5-openssl",
		"secp256r1",
		`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPwdUE4SO6Vx3gfy7OcdWCc9JfpJ4/8/RV4uH8ywej3joAoGCCqGSM49
AwEHoUQDQgAEFBikUPNS5IwnXgip9BtOM2qlAo1mFTVD5XiPWHkKIxC4LEvh+P7J
wTQCkUdgjIGZTj06G8QUxv4U0To3ypE2uA==
-----END EC PRIVATE KEY-----
`,
		`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFBikUPNS5IwnXgip9BtOM2qlAo1m
FTVD5XiPWHkKIxC4LEvh+P7JwTQCkUdgjIGZTj06G8QUxv4U0To3ypE2uA==
-----END PUBLIC KEY-----
`,
	},
}

type testText struct {
	name string
	text string
}

var testTableText = []testText{
	{"text1", "abc123"},
	//{"text2", "1234567890abc"},
}

type testCode struct {
	name    string
	curves  map[string]struct{} // supported curves (secp256r1, secp256k1)
	encrypt func(pub *ecdsa.PublicKey, data []byte) ([]byte, error)
	decrypt func(priv *ecdsa.PrivateKey, data []byte) ([]byte, error)
}

var testTableCode = []testCode{
	{"ethereum", map[string]struct{}{"secp256k1": {}, "secp256r1": {}}, encryptEthereum, decryptEthereum},
	{"havir", map[string]struct{}{"secp256k1": {}, "secp256r1": {}}, encryptHavir, decryptHavir},
	{"obscuren", map[string]struct{}{"secp256r1": {}}, encryptObscuren, decryptObscuren},
	{"bitcoin", map[string]struct{}{"secp256k1": {}}, encryptBitcoin, decryptBitcoin},
	{"sghcrypto", map[string]struct{}{"secp256k1": {}}, encryptSghcrypto, decryptSghcrypto},
	{"ecies_go", map[string]struct{}{"secp256k1": {}}, encryptEciesgo, decryptEciesgo},
	{"btcec", map[string]struct{}{"secp256k1": {}}, encryptBtcec, decryptBtcec},
	{"kyber", map[string]struct{}{"secp256r1": {}}, encryptKyber, decryptKyber},
	{"eciespy", map[string]struct{}{"secp256k1": {}}, encryptEciespy, decryptEciespy},
	//{"eciespy_api", map[string]struct{}{"secp256k1": {}}, encryptEciespyAPI, decryptEciespyAPI},
	{"tink_hybrid", map[string]struct{}{"secp256k1": {}}, encryptTinkHybrid, decryptTinkHybrid},
	{"jafgoecies_t", map[string]struct{}{"secp256k1": {}}, encryptJafgoeciesTrue, decryptJafgoeciesTrue},
	{"jafgoecies_f", map[string]struct{}{"secp256k1": {}}, encryptJafgoeciesFalse, decryptJafgoeciesFalse},
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

		switch {
		case k.curve == "secp256r1":
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
		case k.curve == "secp256k1":

			priv, errPriv := secp256k1.ParsePrivateKeyPem([]byte(k.strPEMPriv))
			if errPriv != nil {
				t.Errorf("could not load private key curve secp256k1 from pem: %s: %v", k.name, errPriv)
				continue
			}

			pub, errPub := secp256k1.ParsePublicKeyPem([]byte(k.strPEMPub))
			if errPub != nil {
				t.Errorf("could not load public key curve secp256k1 from pem: %s: %v", k.name, errPub)
				continue
			}

			privateKey = priv.ToECDSA()
			publicKey = pub.ToECDSA()
		default:
			log.Fatalf("uknown curve: %s", k.curve)
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
						t.Errorf("key=%4s(%9s) text=%5s src=%12s dst=%12s error encrypt: %v", k.name, k.curve, txt.name, codeSrc.name, codeDst.name, errEncrypt)
						continue
					}

					decrypted, errDecrypt := codeDst.decrypt(privateKey, encrypted)
					if errEncrypt != nil {
						t.Errorf("key=%4s(%9s) text=%5s src=%12s dst=%12s error decrypt: %v", k.name, k.curve, txt.name, codeSrc.name, codeDst.name, errDecrypt)
						continue
					}

					decryptedStr := string(decrypted)

					if txt.text != decryptedStr {
						t.Errorf("key=%4s(%9s) text=%5s src=%12s dst=%12s FAIL  wanted=[%s] got=[%s]", k.name, k.curve, txt.name, codeSrc.name, codeDst.name, txt.text, decryptedStr)
						continue
					}

					result := "good "
					if codeSrc.name != codeDst.name {
						result = "good!"
					}

					t.Logf("key=%4s(%9s) text=%5s src=%12s dst=%12s %s wanted=[%s] got=[%s]", k.name, k.curve, txt.name, codeSrc.name, codeDst.name, result, txt.text, decryptedStr)
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
		log.Print("encryptHavir: only P256 is supported")
		//return nil, fmt.Errorf("only P256 is supported")
	}

	publicKey := havir.PublicKey{X: pubKey.X, Y: pubKey.Y, Curve: curve}

	return havir.Encrypt(rand.Reader, &publicKey, data, nil, nil)
}

func decryptHavir(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {

	curve := privKey.Curve
	if curve != elliptic.P256() {
		log.Print("decryptHavir: only P256 is supported")
		//return nil, fmt.Errorf("only P256 is supported")
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

func encryptJafgoeciesTrue(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {
	pub := btcec.PublicKey(*pubKey)
	return jafgoecies.ECEncryptPub(&pub, data, true)
}

func decryptJafgoeciesTrue(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	priv := btcec.PrivateKey(*privKey)
	return jafgoecies.ECDecryptPriv(&priv, data, true)
}

func encryptJafgoeciesFalse(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {
	pub := btcec.PublicKey(*pubKey)
	return jafgoecies.ECEncryptPub(&pub, data, false)
}

func decryptJafgoeciesFalse(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	priv := btcec.PrivateKey(*privKey)
	return jafgoecies.ECDecryptPriv(&priv, data, false)
}

func encryptKyber(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {
	suite := nist.NewBlakeSHA256P256()
	public := suite.Point()
	if err := public.UnmarshalBinary(pubKeyBytes(pubKey)); err != nil {
		return nil, err
	}
	return kyber.Encrypt(suite, public, data, suite.Hash)
}

func decryptKyber(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	suite := nist.NewBlakeSHA256P256()
	private := suite.Scalar().SetBytes(privKey.D.Bytes())
	return kyber.Decrypt(suite, private, data, suite.Hash)
}

var priv *keyset.Handle
var salt = []byte("--salt--")

func init() {
	p, errNewH := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())
	if errNewH != nil {
		panic("init keyset.NewHandle")
	}
	priv = p
}

func encryptTinkHybrid(_ /*pubKey*/ *ecdsa.PublicKey, data []byte) ([]byte, error) {
	pub, errPub := priv.Public() // FIXME use pubKey *ecdsa.PublicKey
	if errPub != nil {
		return nil, errPub
	}
	he, errNewEnc := tink_hybrid.NewHybridEncrypt(pub)
	if errNewEnc != nil {
		return nil, errNewEnc
	}
	cipher, errEnc := he.Encrypt(data, salt)
	if errEnc != nil {
		return nil, errEnc
	}
	return cipher, nil
}

func decryptTinkHybrid(_ /*privKey*/ *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hd, errNewDec := hybrid.NewHybridDecrypt(priv) // FIXME use privKey *ecdsa.PrivateKey
	if errNewDec != nil {
		return nil, errNewDec
	}
	plain, errDec := hd.Decrypt(data, salt)
	if errDec != nil {
		return nil, errDec
	}
	return plain, nil
}

func encryptEciespy(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {

	//eciespy -e -k KEY

	pubBytes := pubKeyBytes(pubKey)
	keyBuf := make([]byte, hex.EncodedLen(len(pubBytes)))
	hex.Encode(keyBuf, pubBytes)

	filePubHex := "eciespy.pubkey"
	if errWrite := os.WriteFile(filePubHex, keyBuf, 0640); errWrite != nil {
		return nil, errWrite
	}

	args := []string{"-e", "-k", filePubHex}

	cmdEncrypt := exec.Command("eciespy", args...)

	out := bytes.Buffer{}

	cmdEncrypt.Stdin = bytes.NewBuffer(data)
	cmdEncrypt.Stdout = &out

	if errEncrypt := cmdEncrypt.Run(); errEncrypt != nil {
		return nil, errEncrypt
	}

	encryptedBytesHex := out.Bytes()

	dataEncrypted := make([]byte, hex.DecodedLen(len(encryptedBytesHex)))
	_, errHex := hex.Decode(dataEncrypted, encryptedBytesHex)
	if errHex != nil {
		return nil, errHex
	}

	return dataEncrypted, nil
}

func decryptEciespy(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {

	//eciespy -d -k KEY

	privKeyBytes := privKey.D.Bytes()
	keyBuf := make([]byte, hex.EncodedLen(len(privKeyBytes)))
	hex.Encode(keyBuf, privKeyBytes)

	filePrivHex := "eciespy.privkey"
	if errWrite := os.WriteFile(filePrivHex, keyBuf, 0640); errWrite != nil {
		return nil, errWrite
	}

	args := []string{"-d", "-k", filePrivHex}

	cmdDecrypt := exec.Command("eciespy", args...)

	out := bytes.Buffer{}

	dataHex := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(dataHex, data)

	cmdDecrypt.Stdin = bytes.NewBuffer(dataHex)
	cmdDecrypt.Stdout = &out

	if errDecrypt := cmdDecrypt.Run(); errDecrypt != nil {
		return nil, errDecrypt
	}

	return out.Bytes(), nil
}

func encryptEciespyAPI(pubKey *ecdsa.PublicKey, data []byte) ([]byte, error) {

	form := url.Values{}
	form.Set("data", string(data))
	form.Set("pub", hex.EncodeToString(pubKeyBytes(pubKey)))

	bodyStr := form.Encode()
	log.Printf("encryptEciespyApi: request body: [%s]", bodyStr)
	body := strings.NewReader(bodyStr)

	req, errReq := http.NewRequest("POST", "https://eciespy.herokuapp.com/", body)
	if errReq != nil {
		return nil, errReq
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("cache-control", "no-cache")

	client := http.DefaultClient

	resp, errDo := client.Do(req)
	if errDo != nil {
		return nil, errDo
	}

	defer resp.Body.Close()

	respBody, errBody := io.ReadAll(resp.Body)
	if errBody != nil {
		return nil, errBody
	}

	if resp.StatusCode != 200 {
		log.Printf("encryptEciespyApi: bad http status: %d", resp.StatusCode)
	}

	log.Printf("encryptEciespyApi: response body: [%s]", string(respBody))

	dataEncrypted := make([]byte, hex.DecodedLen(len(respBody)))
	_, errHex := hex.Decode(dataEncrypted, respBody)
	if errHex != nil {
		return nil, errHex
	}

	return dataEncrypted, nil
}

func decryptEciespyAPI(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {

	form := url.Values{}
	form.Set("data", hex.EncodeToString(data))
	form.Set("prv", hex.EncodeToString(privKey.D.Bytes()))

	bodyStr := form.Encode()
	log.Printf("decryptEciespyApi: request body: [%s]", bodyStr)
	body := strings.NewReader(bodyStr)

	req, errReq := http.NewRequest("POST", "https://eciespy.herokuapp.com/", body)
	if errReq != nil {
		return nil, errReq
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("cache-control", "no-cache")

	client := http.DefaultClient

	resp, errDo := client.Do(req)
	if errDo != nil {
		return nil, errDo
	}

	defer resp.Body.Close()

	respBody, errBody := io.ReadAll(resp.Body)
	if errBody != nil {
		return nil, errBody
	}

	if resp.StatusCode != 200 {
		log.Printf("decryptEciespyApi: bad http status: %d", resp.StatusCode)
	}

	log.Printf("decryptEciespyApi: response body: [%s]", string(respBody))

	return respBody, nil
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
