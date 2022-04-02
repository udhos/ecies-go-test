module github.com/udhos/ecies-go-test

go 1.18

//replace github.com/danielhavir/go-ecies => ../go-ecies
//replace github.com/danielhavir/go-ecies => /home/evsilma/dev/go-ecies

require (
	github.com/btcsuite/btcd v0.21.0-beta
	github.com/ecies/go/v2 v2.0.3
	github.com/ethereum/go-ethereum v1.9.21
	github.com/gitzhou/bitcoin-ecies v0.0.0-20190123122136-256022cb3655
	github.com/google/tink/go v1.4.0
	github.com/kubasiemion/jafgoecies v0.0.0-20210920105008-5b74a8ba4d8e
	github.com/nnitquan/sghcrypto v0.0.0-20191220061915-7ee05b04659c
	github.com/obscuren/ecies v0.0.0-20150213224233-7c0f4a9b18d9
	github.com/udhos/go-ecies v0.0.0-20200924013448-bdc61070c903
	go.dedis.ch/kyber/v3 v3.0.13
)

require (
	github.com/decred/dcrd/dcrec/secp256k1 v1.0.1 // indirect
	github.com/fomichev/secp256k1 v0.0.0-20180413221153-00116ff8c62f // indirect
	github.com/golang/protobuf v1.4.2 // indirect
	go.dedis.ch/fixbuf v1.0.3 // indirect
	golang.org/x/crypto v0.0.0-20220331220935-ae2d96664a29 // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
	google.golang.org/protobuf v1.23.0 // indirect
)
