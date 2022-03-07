package main

import (
	"crypto/rand"
	"fmt"
)

func tokenGenerator() string {
	b := make([]byte, TokenLength/2)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
