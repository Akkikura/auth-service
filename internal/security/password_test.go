package security

import "testing"

func TestPasswordHasher(t *testing.T) {
	hasher, err := NewPasswordHasher(Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hasher.Hash("a very strong password")
	if err != nil {
		t.Fatal(err)
	}
	valid, err := hasher.Verify("a very strong password", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected password to be valid")
	}
	valid, err = hasher.Verify("wrong password", hash)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected password to be invalid")
	}
}

func TestInvalidHash(t *testing.T) {
	hasher, _ := NewPasswordHasher(Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if _, err := hasher.Verify("password", "invalid"); err == nil {
		t.Fatal("expected error")
	}
}
