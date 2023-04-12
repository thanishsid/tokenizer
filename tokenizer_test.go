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

var encyryptionKey = []byte("nLiZc4KmmUehr5nBNzviWbDU3HdogoLy")

func TestTokenHMAC(t *testing.T) {
	hmacConfig, err := NewHMAC(jwt.SigningMethodHS256, []byte("ZJnqMeONCnzrkMPFGvMydTG9ShuO5oxD"), encyryptionKey)
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

func TestEncryptedTokenHMAC(t *testing.T) {
	hmacConfig, err := NewHMAC(jwt.SigningMethodHS256, []byte("ZJnqMeONCnzrkMPFGvMydTG9ShuO5oxD"), encyryptionKey)
	require.NoError(t, err)

	tc := TestClaims{
		Name: "Thanish",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Time{}.Add(time.Hour * 24 * 365 * 50).Local()),
		},
	}

	tok, err := CreateEncryptedToken(context.Background(), hmacConfig, tc)
	require.NoError(t, err)

	fmt.Printf("encrypted token: %s\n", tok)

	var pc TestClaims

	err = ParseEncryptedToken(context.Background(), hmacConfig, tok, &pc)
	require.NoError(t, err)

	fmt.Printf("parsed claims: \n%+v", pc)

	require.Equal(t, tc, pc)
}

var edPrivateKey = []byte("-----BEGIN PRIVATE KEY-----\n" + "MC4CAQAwBQYDK2VwBCIEIGVf32pq9XzKWuLl725SUoWqJbVo6nCNrM+oLlYPRos4\n" + "-----END PRIVATE KEY-----")

var edPublicKey = []byte("-----BEGIN PUBLIC KEY-----\n" + "MCowBQYDK2VwAyEArdRGoBiHxIaKPou8Izca+bTT2sPWbTiiOrG78ixBllw=\n" + "-----END PUBLIC KEY-----")

func TestTokenED(t *testing.T) {

	edConfig, err := NewED(jwt.SigningMethodEdDSA, edPrivateKey, edPublicKey, encyryptionKey)
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

func TestEncryptedTokenED(t *testing.T) {
	edConfig, err := NewED(jwt.SigningMethodEdDSA, edPrivateKey, edPublicKey, encyryptionKey)
	require.NoError(t, err)

	tc := TestClaims{
		Name: "Thanish",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Time{}.Add(time.Hour * 24 * 365 * 50).Local()),
		},
	}

	tok, err := CreateEncryptedToken(context.Background(), edConfig, tc)
	require.NoError(t, err)

	fmt.Printf("encrypted token: %s\n", tok)

	var pc TestClaims

	err = ParseEncryptedToken(context.Background(), edConfig, tok, &pc)
	require.NoError(t, err)

	fmt.Printf("parsed claims: \n%+v", pc)

	require.Equal(t, tc, pc)
}

func TestParseTokenEDWithoutPrivateKey(t *testing.T) {

	edConfigSign, err := NewED(jwt.SigningMethodEdDSA, edPrivateKey, edPublicKey, encyryptionKey)
	require.NoError(t, err)

	edConfigParse, err := NewED(jwt.SigningMethodEdDSA, nil, edPublicKey, encyryptionKey)
	require.NoError(t, err)

	tc := TestClaims{
		Name: "Thanish",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Time{}.Add(time.Hour * 24 * 365 * 50).Local()),
		},
	}

	tok, err := CreateToken(context.Background(), edConfigSign, tc)
	require.NoError(t, err)

	fmt.Printf("token: %s\n", tok)

	var pc TestClaims

	err = ParseToken(context.Background(), edConfigParse, tok, &pc)
	require.NoError(t, err)

	fmt.Printf("parsed claims: \n%+v", pc)

	require.Equal(t, tc, pc)
}
