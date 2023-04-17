package tokenizer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

type Config interface {
	GetSigningMethod() jwt.SigningMethod
	GetPrivateKey() any
	GetPublicKey() any
}

// HMAC
type HMAC struct {
	SigningMethod jwt.SigningMethod
	SigningKey    []byte
}

func (h *HMAC) GetSigningMethod() jwt.SigningMethod {
	return h.SigningMethod
}

func (h *HMAC) GetPrivateKey() any {
	return h.SigningKey
}

func (h *HMAC) GetPublicKey() any {
	return h.SigningKey
}

// RSA
type RSA struct {
	SigningMethod jwt.SigningMethod
	PrivateKey    *rsa.PrivateKey
	PublicKey     *rsa.PublicKey
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

// ED
type ED struct {
	SigningMethod jwt.SigningMethod
	PrivateKey    crypto.PrivateKey
	PublicKey     crypto.PublicKey
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

// EC
type EC struct {
	SigningMethod jwt.SigningMethod
	PrivateKey    *ecdsa.PrivateKey
	PublicKey     *ecdsa.PublicKey
}

func (h *EC) GetSigningMethod() jwt.SigningMethod {
	return h.SigningMethod
}

func (h *EC) GetPrivateKey() any {
	return h.PrivateKey
}

func (h *EC) GetPublicKey() any {
	return h.PublicKey
}

// New Hmac configuration
func NewHMAC(sm jwt.SigningMethod, signingKey []byte) (*HMAC, error) {
	if _, ok := sm.(*jwt.SigningMethodHMAC); !ok {
		return nil, errors.New("invalid signing method for hmac")
	}

	return &HMAC{
		SigningMethod: sm,
		SigningKey:    signingKey,
	}, nil
}

// New RSA configuration
func NewRSA(sm jwt.SigningMethod, privateKeyPem, publicKeyPem []byte) (*RSA, error) {
	if _, ok := sm.(*jwt.SigningMethodRSA); !ok {
		return nil, errors.New("invalid signing method for rsa")
	}

	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey
	var err error

	if privateKeyPem != nil {
		privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyPem)
		if err != nil {
			return nil, err
		}
	}

	if publicKeyPem != nil {
		publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyPem)
		if err != nil {
			return nil, err
		}
	}

	return &RSA{
		SigningMethod: sm,
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
	}, nil
}

// New ED configuration
func NewED(sm jwt.SigningMethod, privateKeyPem, publicKeyPem []byte) (*ED, error) {
	if _, ok := sm.(*jwt.SigningMethodEd25519); !ok {
		return nil, errors.New("invalid signing method for EdDSA")
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
	}, nil
}

// New ES
func NewEC(sm jwt.SigningMethod, privateKeyPem, publicKeyPem []byte) (*EC, error) {
	if _, ok := sm.(*jwt.SigningMethodECDSA); !ok {
		return nil, errors.New("invalid signing method for ECDSA")
	}

	var privateKey *ecdsa.PrivateKey
	var publicKey *ecdsa.PublicKey
	var err error

	if privateKeyPem != nil {
		privateKey, err = jwt.ParseECPrivateKeyFromPEM(privateKeyPem)
		if err != nil {
			return nil, err
		}
	}

	if publicKeyPem != nil {
		publicKey, err = jwt.ParseECPublicKeyFromPEM(publicKeyPem)
		if err != nil {
			return nil, err
		}
	}

	return &EC{
		SigningMethod: sm,
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
	}, nil
}
