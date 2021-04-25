package p100

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

const RSABits = 1024

func DumpRSAPEM(pubKey *rsa.PublicKey) (pubPEM []byte) {
	pubKeyPKIX, _ := x509.MarshalPKIXPublicKey(pubKey)

	pubPEM = pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyPKIX,
		},
	)

	return
}

func GenerateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	key, err := rsa.GenerateKey(rand.Reader, RSABits)
	if err != nil {
		panic(err)
	}

	return key, key.Public().(*rsa.PublicKey)
}
