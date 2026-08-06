package security

import "testing"

func TestTokenManager(t *testing.T) {
	manager, err := NewTokenManager([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	raw, digest, err := manager.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !manager.ValidFormat(raw) {
		t.Fatal("generated token should be valid")
	}
	if digest != manager.Digest(raw) {
		t.Fatal("digest mismatch")
	}
	if manager.ValidFormat(raw + "x") {
		t.Fatal("invalid token accepted")
	}
}
