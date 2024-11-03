// Package main implements the tool.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

var (
	oidNamedCurveSecP256r1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveSecP256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

func main() {

	privKeyPem, pubKeyPem := generate()

	showPem(privKeyPem, pubKeyPem)

	privKey, pubKey := parsePem(privKeyPem, pubKeyPem)

	privKeyPem2, pubKeyPem2 := exportPem(privKey, pubKey)

	showPem(privKeyPem2, pubKeyPem2)

	if string(privKeyPem) != string(privKeyPem2) {
		log.Fatalf("priv key mismatch")
	}

	if string(pubKeyPem) != string(pubKeyPem2) {
		log.Fatalf("pub key mismatch")
	}

	clearText := "abc123"

	encrypted, errEnc := btcec.Encrypt(pubKey, []byte(clearText))
	if errEnc != nil {
		log.Fatalf("encrypt: %v", errEnc)
	}

	decrypted, errDec := btcec.Decrypt(privKey, encrypted)
	if errDec != nil {
		log.Fatalf("decrypt: %v", errDec)
	}

	decStr := string(decrypted)

	if decStr != clearText {
		log.Fatalf("wanted=[%s] got=[%s]", clearText, decStr)
	}

	log.Printf("ok")
}

func showPem(priv, pub []byte) {
	fmt.Println("priv:")
	fmt.Println(string(priv))
	fmt.Println("pub:")
	fmt.Println(string(pub))
}

func parsePem(privKeyPem, pubKeyPem []byte) (*btcec.PrivateKey, *btcec.PublicKey) {
	priv, errPriv := parsePrivateKeyPem(privKeyPem)
	if errPriv != nil {
		log.Fatalf("parse private key pem: %v", errPriv)
	}
	pub, errPub := parsePublicKeyPem(pubKeyPem)
	if errPub != nil {
		log.Fatalf("parse public key pem: %v", errPub)
	}
	return priv, pub
}

func parsePrivateKeyPem(priv []byte) (*btcec.PrivateKey, error) {

	me := "parsePrivateKeyPem"

	block, _ := pem.Decode(priv)
	if block == nil {
		return nil, fmt.Errorf("%s: key not found", me)
	}

	/*
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", me, err)
		}
	*/
	//privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), block.Bytes)

	return parseECPrivateKey(block.Bytes)
}

func parsePublicKeyPem(pub []byte) (*btcec.PublicKey, error) {

	me := "parsePublicKeyPem"

	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, fmt.Errorf("%s: key not found", me)
	}

	return parseECPublicKey(block.Bytes)
}

func generate() ([]byte, []byte) {
	priv, errPriv := btcec.NewPrivateKey(btcec.S256())
	if errPriv != nil {
		log.Fatalf("new priv key: %v", errPriv)
	}

	return exportPem(priv, priv.PubKey())
}

func exportPem(priv *btcec.PrivateKey, pub *btcec.PublicKey) ([]byte, []byte) {
	privKeyPem, errPrivExp := exportPrivateKeyAsPem(priv)
	if errPrivExp != nil {
		log.Fatalf("export priv key: %v", errPrivExp)
	}

	pubKeyPem, _ := exportPublicKeyAsPem(pub)

	return privKeyPem, pubKeyPem
}

func exportPrivateKeyAsPem(priv *btcec.PrivateKey) ([]byte, error) {
	privEDSA := priv.ToECDSA()

	privBytes, errMarshalPriv := marshalECPrivateKeyWithOID(privEDSA, oidNamedCurveSecP256k1)
	if errMarshalPriv != nil {
		return nil, errMarshalPriv
	}

	privKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privBytes,
		},
	)

	return privKeyPem, nil
}

func exportPublicKeyAsPem(pub *btcec.PublicKey) ([]byte, error) {
	pubEDSA := pub.ToECDSA()

	pubBytes, errMarshal := marshalECPublicKey(pubEDSA)
	if errMarshal != nil {
		return nil, errMarshal
	}

	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PUBLIC KEY",
			Bytes: pubBytes,
		},
	)

	return pubKeyPem, nil
}

// ecPrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
// References:
//
//	RFC 5915
//	SEC1 - http://www.secg.org/sec1-v2.pdf
//
// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// marshalECPrivateKey marshals an EC private key into ASN.1, DER format and
// sets the curve ID to the given OID, or omits it if OID is nil.
func marshalECPrivateKeyWithOID(key *ecdsa.PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
	privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.D.FillBytes(privateKey),
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

func marshalECPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	var err error

	if publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(pub); err != nil {
		return nil, err
	}

	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	ret, _ := asn1.Marshal(pkix)
	return ret, nil
}

func marshalPublicKey(pub *ecdsa.PublicKey) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {

	publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	/*
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
		}
	*/
	oid := oidNamedCurveSecP256k1
	publicKeyAlgorithm.Algorithm = oidNamedCurveSecP256k1
	var paramBytes []byte
	paramBytes, err = asn1.Marshal(oid)
	if err != nil {
		return
	}
	publicKeyAlgorithm.Parameters.FullBytes = paramBytes

	return publicKeyBytes, publicKeyAlgorithm, nil
}

func parseECPrivateKey(der []byte) (key *btcec.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != 1 {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}

	/*
		var curve elliptic.Curve
		if namedCurveOID != nil {
			curve = namedCurveFromOID(*namedCurveOID)
		} else {
			curve = namedCurveFromOID(privKey.NamedCurveOID)
		}
		if curve == nil {
			return nil, errors.New("x509: unknown elliptic curve")
		}
	*/
	curve := btcec.S256()

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	//priv := new(ecdsa.PrivateKey)
	priv := new(btcec.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	//p := btcec.PrivateKey{priv}

	return priv, nil
}

func parseECPublicKey(derBytes []byte) (*btcec.PublicKey, error) {
	var pki publicKeyInfo
	rest, err := asn1.Unmarshal(derBytes, &pki)
	//log.Printf("parseECPublicKey: asn1.Unmarshal: %v", err)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	if !pki.Algorithm.Algorithm.Equal(oidNamedCurveSecP256k1) {
		return nil, errors.New("x509: unknown public key algorithm")
	}

	return parsePublicKey(&pki)
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func parsePublicKey(keyData *publicKeyInfo) (*btcec.PublicKey, error) {
	paramsData := keyData.Algorithm.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
	if err != nil {
		return nil, errors.New("x509: failed to parse ECDSA parameters as named curve")
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ECDSA parameters")
	}
	/*
		namedCurve := namedCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil, errors.New("x509: unsupported elliptic curve")
		}
	*/
	namedCurve := btcec.S256()
	asn1Data := keyData.PublicKey.RightAlign()
	x, y := elliptic.Unmarshal(namedCurve, asn1Data)
	if x == nil {
		return nil, errors.New("x509: failed to unmarshal elliptic curve point")
	}
	//pub := &ecdsa.PublicKey{
	pub := &btcec.PublicKey{
		Curve: namedCurve,
		X:     x,
		Y:     y,
	}
	return pub, nil
}
