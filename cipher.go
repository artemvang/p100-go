package p100

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/mergermarket/go-pkcs7"
)

type P100Cipher struct {
	key []byte
	iv  []byte
}

func (c *P100Cipher) Encrypt(payload []byte) []byte {
	block, _ := aes.NewCipher(c.key)
	encrypter := cipher.NewCBCEncrypter(block, c.iv)

	paddedPayload, _ := pkcs7.Pad(payload, aes.BlockSize)
	encryptedPayload := make([]byte, len(paddedPayload))
	encrypter.CryptBlocks(encryptedPayload, paddedPayload)

	return encryptedPayload
}

func (c *P100Cipher) Decrypt(payload []byte) []byte {
	block, _ := aes.NewCipher(c.key)
	encrypter := cipher.NewCBCDecrypter(block, c.iv)

	decryptedPayload := make([]byte, len(payload))
	encrypter.CryptBlocks(decryptedPayload, payload)

	unpaddedPayload, _ := pkcs7.Unpad(decryptedPayload, aes.BlockSize)

	return unpaddedPayload
}
