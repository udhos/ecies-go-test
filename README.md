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
