module github.com/udhos/ecies-go-test

go 1.15

//replace github.com/danielhavir/go-ecies => ../go-ecies
//replace github.com/danielhavir/go-ecies => /home/evsilma/dev/go-ecies

require (
	github.com/btcsuite/btcd v0.21.0-beta
	github.com/ecies/go v1.0.2-0.20200608070154-92e322fcd976
	github.com/ethereum/go-ethereum v1.9.21
	github.com/gitzhou/bitcoin-ecies v0.0.0-20190123122136-256022cb3655
	github.com/nnitquan/sghcrypto v0.0.0-20191220061915-7ee05b04659c
	github.com/obscuren/ecies v0.0.0-20150213224233-7c0f4a9b18d9
	github.com/udhos/go-ecies v0.0.0-20200924013448-bdc61070c903
	go.dedis.ch/kyber/v3 v3.0.13
	golang.org/x/sys v0.0.0-20200918174421-af09f7315aff // indirect
)
