package tokenizer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
)

type TestClaims struct {
	Name string
	jwt.RegisteredClaims
}

func TestTokenHMAC(t *testing.T) {
	t.Parallel()

	hmacConfig, err := NewHMAC(jwt.SigningMethodHS256, []byte("ZJnqMeONCnzrkMPFGvMydTG9ShuO5oxD"))
	require.NoError(t, err)

	tc := TestClaims{
		Name: "Thanish",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Time{}.Add(time.Hour * 24 * 365 * 50).Local()),
		},
	}

	tok, err := CreateToken(context.Background(), hmacConfig, tc)
	require.NoError(t, err)

	fmt.Printf("token: %s\n", tok)

	var pc TestClaims

	err = ParseToken(context.Background(), hmacConfig, tok, &pc)
	require.NoError(t, err)

	fmt.Printf("parsed claims: \n%+v", pc)

	require.Equal(t, tc, pc)
}

var edPrivateKey = []byte(
	`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINMwmtW0Jyl78eTujtjAGy9/aC8c2z69K3wcL8o7q0dD
-----END PRIVATE KEY-----`,
)

var edPublicKey = []byte(
	`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAghUPrxN3cxeQl+b9dbml+dI1u7xVOuckbIrqdTUGhHs=
-----END PUBLIC KEY-----
`,
)

func TestTokenED(t *testing.T) {
	t.Parallel()

	edConfig, err := NewED(jwt.SigningMethodEdDSA, edPrivateKey, edPublicKey)
	require.NoError(t, err)

	tc := TestClaims{
		Name: "Thanish",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Time{}.Add(time.Hour * 24 * 365 * 50).Local()),
		},
	}

	tok, err := CreateToken(context.Background(), edConfig, tc)
	require.NoError(t, err)

	fmt.Printf("token: %s\n", tok)

	var pc TestClaims

	err = ParseToken(context.Background(), edConfig, tok, &pc)
	require.NoError(t, err)

	fmt.Printf("parsed claims: \n%+v", pc)

	require.Equal(t, tc, pc)
}

var ecPrivateKey = []byte(
	`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAZkBFNLqFrekxZrfE6tyceEuREDhlcmg6mp3yxwtvUvQ8eyLqfl3j
32OPFf3UxK0PdTDIRY/fpjiq5E1+ml3MKTmgBwYFK4EEACOhgYkDgYYABAG8Jf7o
Al467tVI5ZicquFwW5NymHgOSAZ3gLqHXtSVy5FWzgk9r2sBgshAgGHIFTVTC6cD
q/kStCBb4veBOVrZmQGGf2dbDIrRBHalpfvrmozBfhewFfmeEygmOouvd3TGjKgv
MXSOkn4bgqISzRX3ZKi4e1xVReMylEVJVLFxwPiJ4g==
-----END EC PRIVATE KEY-----`,
)

var ecPublicKey = []byte(
	`-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBvCX+6AJeOu7VSOWYnKrhcFuTcph4
DkgGd4C6h17UlcuRVs4JPa9rAYLIQIBhyBU1UwunA6v5ErQgW+L3gTla2ZkBhn9n
WwyK0QR2paX765qMwX4XsBX5nhMoJjqLr3d0xoyoLzF0jpJ+G4KiEs0V92SouHtc
VUXjMpRFSVSxccD4ieI=
-----END PUBLIC KEY-----`,
)

func TestTokenEC(t *testing.T) {
	t.Parallel()

	ecConfig, err := NewEC(jwt.SigningMethodES512, ecPrivateKey, ecPublicKey)
	require.NoError(t, err)

	tc := TestClaims{
		Name: "Thanish",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Time{}.Add(time.Hour * 24 * 365 * 50).Local()),
		},
	}

	tok, err := CreateToken(context.Background(), ecConfig, tc)
	require.NoError(t, err)

	fmt.Printf("token: %s\n", tok)

	var pc TestClaims

	err = ParseToken(context.Background(), ecConfig, tok, &pc)
	require.NoError(t, err)

	fmt.Printf("parsed claims: \n%+v", pc)

	require.Equal(t, tc, pc)
}
