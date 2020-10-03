// https://asecuritysite.com/encryption/go_tink05
package main

import (
	"fmt"
	"os"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

func main() {

	msg := "Bob's ID"
	additional := "NHS Salt"

	argCount := len(os.Args[1:])
	if argCount > 0 {
		msg = (os.Args[1])
	}
	if argCount > 1 {
		additional = (os.Args[1])
	}

	fmt.Printf("Plaintext input: %s\n", msg)

	// Use 128-bit AES GCM or use 128-bit AES CTR
	//AlicePriv, _ := keyset.NewHandle(hybrid.ECIESHKDFAES128GCMKeyTemplate())

	AlicePriv, _ := keyset.NewHandle(hybrid.ECIESHKDFAES128CTRHMACSHA256KeyTemplate())

	exportedPriv := &keyset.MemReaderWriter{}
	insecurecleartextkeyset.Write(AlicePriv, exportedPriv)

	AlicePub, _ := AlicePriv.Public()

	exportedPub := &keyset.MemReaderWriter{}
	insecurecleartextkeyset.Write(AlicePub, exportedPub)

	/// Bob encrypts for Alice using her public key

	he, _ := hybrid.NewHybridEncrypt(AlicePub)

	ct, _ := he.Encrypt([]byte(msg), []byte(additional))

	fmt.Printf("Cipher text: %x\n", ct)

	/// Alice receives cipher (ct) and he will use her private key to decrypt

	hd, _ := hybrid.NewHybridDecrypt(AlicePriv)

	pt, _ := hd.Decrypt(ct, []byte(additional))

	fmt.Printf("Plaintext text: %s\n", pt)

	fmt.Printf("\n\nAlice's Private Key ID: %d\n\n", exportedPriv.Keyset.GetPrimaryKeyId())
	fmt.Printf("Alice's Private Key %s:\n\n", exportedPriv.Keyset.GetKey())
	fmt.Printf("Alice's Public Key ID: %d\n\n", exportedPub.Keyset.GetPrimaryKeyId())
	fmt.Printf("Alice's Public Key %s:\n\n", exportedPub.Keyset.GetKey())
}
