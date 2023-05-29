package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/pkg/errors"
)

type Client interface {
	Decrypt(key []byte, value []byte) (decryptedTarget []byte, err error)
	DecryptWithBase64(key []byte, valueBase64 string) (decryptedTarget []byte, err error)
	Encrypt(key []byte, value []byte) (encryptedTarget []byte, err error)
	EncryptFromString(key []byte, valueStr string) (encryptedTarget []byte, err error)
}

type aesClient struct{}

func (a *aesClient) Decrypt(key []byte, value []byte) (decryptedTarget []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "create cipher.Block failed.")
	}
	decryptedText := make([]byte, len(value[aes.BlockSize:]))
	decryptStream := cipher.NewCTR(block, value[:aes.BlockSize])
	decryptStream.XORKeyStream(decryptedText, value[aes.BlockSize:])
	return decryptedText, nil
}

func (a *aesClient) DecryptWithBase64(key []byte, valueBase64 string) (decryptedTarget []byte, err error) {
	value, err := base64.StdEncoding.DecodeString(valueBase64)
	if err != nil {
		return nil, errors.Wrap(err, "base64 decode failed.")
	}
	data, err := a.Decrypt(key, value)
	if err != nil {
		return nil, errors.Wrap(err, "Encrypt failed.")
	}
	return data, nil
}

func (a *aesClient) Encrypt(key []byte, value []byte) (encryptedTarget []byte, err error) {
	// Create new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "create cipher.Block failed.")
	}

	// Create IV
	cipherText := make([]byte, aes.BlockSize+len(value))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.Wrap(err, "failed to read IV.")
	}

	// Encrypt
	encryptStream := cipher.NewCTR(block, iv)
	encryptStream.XORKeyStream(cipherText[aes.BlockSize:], value)
	return cipherText, nil
}

func (a *aesClient) EncryptFromString(key []byte, valueStr string) (encryptedTarget []byte, err error) {
	return a.Encrypt(key, []byte(valueStr))
}

func NewClient() *aesClient {
	return &aesClient{}
}
