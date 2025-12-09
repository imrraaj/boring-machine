package main

import (
	"crypto/rand"
	"fmt"
)

func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
