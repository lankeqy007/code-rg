package sentinel

import (
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand"
	"time"
)

// randomHex generates a random hex string of the given byte length.
func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// randomInt generates a random int in [0, max).
func randomInt(max int) int {
	return mrand.Intn(max)
}

// randomChoice picks a random element from a string slice.
func randomChoice(choices []string) string {
	if len(choices) == 0 {
		return ""
	}
	return choices[mrand.Intn(len(choices))]
}

// seeded creates a new seeded random source.
func seeded() *mrand.Rand {
	return mrand.New(mrand.NewSource(time.Now().UnixNano()))
}
