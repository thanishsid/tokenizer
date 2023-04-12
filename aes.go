package tokenizer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

func encryptAES(key []byte, str string) (string, error) {
	// create cipher
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	enc := gcm.Seal(nonce, nonce, []byte(str), nil)

	return hex.EncodeToString(enc[:]), nil
}

func decryptAES(key []byte, text string) (string, error) {
	ct, err := hex.DecodeString(text)
	if err != nil {
		return "", err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ct) < nonceSize {
		return "", errors.New("cipher text too short")
	}

	nonce, ct := ct[:nonceSize], ct[nonceSize:]

	dec, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}

	return string(dec), nil
}
