# ecies-go-test

## Curve P256 secp256r1

> P256 returns a Curve which implements NIST P-256 (FIPS 186-3, section D.2.3), also known as secp256r1 or prime256v1. The CurveParams.Name of this Curve is "P-256".

https://golang.org/pkg/crypto/elliptic/#P256

## Usage

### test suite

```
python3 -m pip install eciespy ;# install eciespy cli

git clone https://github.com/udhos/ecies-go-test
cd ecies-go-test
go test
```

Current results as of 2022-04-02:

```
$ go test | grep good
    main_test.go:164: key=key1(secp256r1) text=text1 src=    ethereum dst=    ethereum good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key1(secp256r1) text=text1 src=    ethereum dst=    obscuren good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key1(secp256r1) text=text1 src=       havir dst=       havir good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key1(secp256r1) text=text1 src=    obscuren dst=    ethereum good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key1(secp256r1) text=text1 src=    obscuren dst=    obscuren good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key1(secp256r1) text=text1 src=       kyber dst=       kyber good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key2(secp256r1) text=text1 src=    ethereum dst=    ethereum good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key2(secp256r1) text=text1 src=    ethereum dst=    obscuren good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key2(secp256r1) text=text1 src=       havir dst=       havir good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key2(secp256r1) text=text1 src=    obscuren dst=    ethereum good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key2(secp256r1) text=text1 src=    obscuren dst=    obscuren good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key2(secp256r1) text=text1 src=       kyber dst=       kyber good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src=       havir dst=       havir good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src=     bitcoin dst=     bitcoin good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src=   sghcrypto dst=   sghcrypto good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src=    ecies_go dst=    ecies_go good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src=    ecies_go dst=     eciespy good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src=    ecies_go dst= eciespy_api good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src=       btcec dst=       btcec good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src=     eciespy dst=    ecies_go good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src=     eciespy dst=     eciespy good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src=     eciespy dst= eciespy_api good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src= eciespy_api dst=    ecies_go good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src= eciespy_api dst=     eciespy good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src= eciespy_api dst= eciespy_api good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src= tink_hybrid dst= tink_hybrid good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src=jafgoecies_t dst=jafgoecies_t good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key3(secp256k1) text=text1 src=jafgoecies_f dst=jafgoecies_f good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src=       havir dst=       havir good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src=     bitcoin dst=     bitcoin good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src=   sghcrypto dst=   sghcrypto good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src=    ecies_go dst=    ecies_go good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src=    ecies_go dst=     eciespy good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src=    ecies_go dst= eciespy_api good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src=       btcec dst=       btcec good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src=     eciespy dst=    ecies_go good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src=     eciespy dst=     eciespy good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src=     eciespy dst= eciespy_api good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src= eciespy_api dst=    ecies_go good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src= eciespy_api dst=     eciespy good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src= eciespy_api dst= eciespy_api good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src= tink_hybrid dst= tink_hybrid good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src=jafgoecies_t dst=jafgoecies_t good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key4-openssl(secp256k1) text=text1 src=jafgoecies_f dst=jafgoecies_f good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key5-openssl(secp256r1) text=text1 src=    ethereum dst=    ethereum good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key5-openssl(secp256r1) text=text1 src=    ethereum dst=    obscuren good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key5-openssl(secp256r1) text=text1 src=       havir dst=       havir good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key5-openssl(secp256r1) text=text1 src=    obscuren dst=    ethereum good! wanted=[abc123] got=[abc123]
    main_test.go:164: key=key5-openssl(secp256r1) text=text1 src=    obscuren dst=    obscuren good  wanted=[abc123] got=[abc123]
    main_test.go:164: key=key5-openssl(secp256r1) text=text1 src=       kyber dst=       kyber good  wanted=[abc123] got=[abc123]
```

### ecies-btc

```
git clone https://github.com/udhos/ecies-go-test
cd ecies-go-test
go install ./example/ecies-btc
ecies-btc
```

## Recipe for EC keys

```
openssl ecparam -name secp256k1 -genkey -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
```
