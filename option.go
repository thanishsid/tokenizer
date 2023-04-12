package tokenizer

import (
	"crypto"
	"crypto/rsa"
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

type Config interface {
	GetSigningMethod() jwt.SigningMethod
	GetPrivateKey() any
	GetPublicKey() any
	GetEncryptionKey() []byte
}

// HMAC
type HMAC struct {
	SigningMethod jwt.SigningMethod
	SigningKey    []byte
	EncryptionKey []byte
}

func (h *HMAC) GetSigningMethod() jwt.SigningMethod {
	return h.SigningMethod
}

func (h *HMAC) GetPrivateKey() any {
	return h.SigningKey
}

func (h *HMAC) GetPublicKey() any {
	return nil
}

func (h *HMAC) GetEncryptionKey() []byte {
	return h.EncryptionKey
}

// RSA
type RSA struct {
	SigningMethod jwt.SigningMethod
	PrivateKey    *rsa.PrivateKey
	PublicKey     *rsa.PublicKey
	EncryptionKey []byte
}

func (h *RSA) GetSigningMethod() jwt.SigningMethod {
	return h.SigningMethod
}

func (h *RSA) GetPrivateKey() any {
	return h.PrivateKey
}

func (h *RSA) GetPublicKey() any {
	return h.PublicKey
}

func (h *RSA) GetEncryptionKey() []byte {
	return h.EncryptionKey
}

// ED
type ED struct {
	SigningMethod jwt.SigningMethod
	PrivateKey    crypto.PrivateKey
	PublicKey     crypto.PublicKey
	EncryptionKey []byte
}

func (h *ED) GetSigningMethod() jwt.SigningMethod {
	return h.SigningMethod
}

func (h *ED) GetPrivateKey() any {
	return h.PrivateKey
}

func (h *ED) GetPublicKey() any {
	return h.PublicKey
}

func (h *ED) GetEncryptionKey() []byte {
	return h.EncryptionKey
}

// New Hmac configuration
func NewHMAC(sm jwt.SigningMethod, signingKey, encryptionKey []byte) (*HMAC, error) {
	if _, ok := sm.(*jwt.SigningMethodHMAC); !ok {
		return nil, errors.New("invalid signing method for hmac")
	}

	return &HMAC{
		SigningMethod: sm,
		SigningKey:    signingKey,
		EncryptionKey: encryptionKey,
	}, nil
}

// New RSA configuration
func NewRSA(sm jwt.SigningMethod, privateKeyPem, publicKeyPem, encryptionKey []byte) (*RSA, error) {
	if _, ok := sm.(*jwt.SigningMethodRSA); !ok {
		return nil, errors.New("invalid signing method for rsa")
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPem)
	if err != nil {
		return nil, err
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPem)
	if err != nil {
		return nil, err
	}

	return &RSA{
		SigningMethod: sm,
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		EncryptionKey: encryptionKey,
	}, nil
}

// New ED configuration
func NewED(sm jwt.SigningMethod, privateKeyPem, publicKeyPem, encryptionKey []byte) (*ED, error) {
	if _, ok := sm.(*jwt.SigningMethodEd25519); !ok {
		return nil, errors.New("invalid signing method for hmac")
	}

	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	var err error

	if privateKeyPem != nil {
		privateKey, err = jwt.ParseEdPrivateKeyFromPEM(privateKeyPem)
		if err != nil {
			return nil, err
		}
	}

	if publicKeyPem != nil {
		publicKey, err = jwt.ParseEdPublicKeyFromPEM(publicKeyPem)
		if err != nil {
			return nil, err
		}
	}

	return &ED{
		SigningMethod: sm,
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		EncryptionKey: encryptionKey,
	}, nil
}

// // New ED Public Only
// func NewEDPublicOnly(sm jwt.SigningMethod, publicKeyPem )
