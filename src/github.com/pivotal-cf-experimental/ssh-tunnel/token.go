package main

import (
	"crypto/rand"
	"encoding/base64"
)

// TODO:
// - use math.Rand
// - be sure the token is alphanumeric, 16 characters
func GenerateToken() (string, error) {
	b, err := generateRandomBytes(32)
	return base64.URLEncoding.EncodeToString(b), err
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
