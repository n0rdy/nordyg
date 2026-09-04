package contract

import (
	"crypto/rand"
	"encoding/hex"
)

// randomCookie returns an 8-byte client cookie as hex (RFC 7873 §4).
func randomCookie() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
