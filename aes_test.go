package tokenizer

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("nLiZc4KmmUehr5nBNzviWbDU3HdogoLy")
	data := "test_string"

	encryptedString, err := encryptAES(key, data)
	require.NoError(t, err)
	fmt.Println(encryptedString)

	decData, err := decryptAES(key, encryptedString)
	require.NoError(t, err)

	require.Equal(t, data, decData)
}
