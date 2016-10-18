package easyauth

import (
	"log"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	log.Printf("Random key: %s", RandomString(64))
}
