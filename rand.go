package password

import (
	"crypto/rand"
	"encoding/base64"
)

var b64 = base64.RawStdEncoding.Strict()

// Rand returns n random bytes
func Rand(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	return buf, err
}

// DefaultSessionLength is a number of bytes generated as a Session
const DefaultSessionLength = 16

// Session returns a string that can be used as a session (16 random bytes in base64)
func Session() (string, error) {
	b, err := Rand(DefaultSessionLength)
	return b64.EncodeToString(b), err
}
