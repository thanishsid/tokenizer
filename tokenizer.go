package tokenizer

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/golang-jwt/jwt/v4"
)

var ErrNonPointerClaim = errors.New("invalid claims type, the claims must be a pointer")
var ErrTokenExpired = errors.New("token expired")

// Create a new jwt token.
func CreateToken(ctx context.Context, c Config, claims jwt.Claims) (string, error) {
	token, err := jwt.NewWithClaims(c.GetSigningMethod(), claims).SignedString(c.GetPrivateKey())
	if err != nil {
		return "", err
	}

	return token, nil
}

// Verify jwt token signature and deserialize the claims to the provided dst.
func ParseToken(ctx context.Context, c Config, token string, claims jwt.Claims) error {

	if reflect.ValueOf(claims).Kind() != reflect.Pointer {
		return ErrNonPointerClaim
	}

	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {

		if t.Method != c.GetSigningMethod() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return c.GetPublicKey(), nil
	})

	if errors.Is(err, jwt.ErrTokenExpired) {
		return ErrTokenExpired
	}

	if err != nil {
		return err
	}

	return nil
}
