package helpers

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

var (
	entropy     = ulid.Monotonic(rand.Reader, 0)
	entropyLock sync.Mutex
)

// NewULID generates a new ULID string.
// Returns an error if entropy source fails.
func NewULID() (string, error) {
	entropyLock.Lock()
	defer entropyLock.Unlock()

	id, err := ulid.New(ulid.Timestamp(time.Now()), entropy)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// MustNewULID generates a new ULID string.
// Panics if entropy source fails.
func MustNewULID() string {
	id, err := NewULID()
	if err != nil {
		panic(err)
	}
	return id
}
