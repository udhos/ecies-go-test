package secp256k1

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

var (
	//oidNamedCurveSecP256r1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveSecP256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

// ParsePrivateKeyPem loads private key with curve secp256k1 from PEM.
func ParsePrivateKeyPem(priv []byte) (*btcec.PrivateKey, error) {

	me := "ParsePrivateKeyPem"

	block, _ := pem.Decode(priv)
	if block == nil {
		return nil, fmt.Errorf("%s: key not found", me)
	}

	return parseECPrivateKey(block.Bytes)
}

// ParsePublicKeyPem loads public key with curve secp256k1 from PEM.
func ParsePublicKeyPem(pub []byte) (*btcec.PublicKey, error) {

	me := "ParsePublicKeyPem"

	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, fmt.Errorf("%s: key not found", me)
	}

	return parseECPublicKey(block.Bytes)
}

// ecPrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
// References:
//   RFC 5915
//   SEC1 - http://www.secg.org/sec1-v2.pdf
// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
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

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func parseECPublicKey(derBytes []byte) (*btcec.PublicKey, error) {
	var pki publicKeyInfo
	rest, err := asn1.Unmarshal(derBytes, &pki)
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
