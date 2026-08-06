package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

var ErrInvalidPasswordHash = errors.New("invalid password hash")

const maxArgon2MemoryKB uint32 = 256 * 1024

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

type PasswordHasher struct {
	params Argon2Params
}

func NewPasswordHasher(params Argon2Params) (*PasswordHasher, error) {
	if params.Memory < 8*1024 || params.Memory > maxArgon2MemoryKB ||
		params.Iterations < 1 || params.Iterations > 10 ||
		params.Parallelism < 1 || params.Parallelism > 16 ||
		params.SaltLength < 16 || params.SaltLength > 64 ||
		params.KeyLength < 16 || params.KeyLength > 64 {
		return nil, errors.New("unsafe Argon2 parameters")
	}
	return &PasswordHasher{params: params}, nil
}

func (h *PasswordHasher) Hash(password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.params.Memory,
		h.params.Iterations,
		h.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func (h *PasswordHasher) Verify(password, encoded string) (bool, error) {
	params, salt, expected, err := parseArgon2Hash(encoded)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(expected)))
	// так время проверки всегда одинаковое
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func (h *PasswordHasher) NeedsRehash(encoded string) bool {
	params, salt, key, err := parseArgon2Hash(encoded)
	if err != nil {
		return true
	}
	return params.Memory != h.params.Memory ||
		params.Iterations != h.params.Iterations ||
		params.Parallelism != h.params.Parallelism ||
		uint32(len(salt)) != h.params.SaltLength ||
		uint32(len(key)) != h.params.KeyLength
}

func parseArgon2Hash(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil || version != argon2.Version {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}
	var memory, iterations uint32
	var parallelism uint8
	// TODO отдельно проверяю строку потому что Sscanf пропускает лишнее
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil ||
		parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", memory, iterations, parallelism) {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 16 {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(key) < 16 {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}
	if memory < 8*1024 || memory > maxArgon2MemoryKB || iterations < 1 || iterations > 10 || parallelism < 1 || parallelism > 16 || len(salt) > 64 || len(key) > 64 {
		return Argon2Params{}, nil, nil, ErrInvalidPasswordHash
	}
	return Argon2Params{Memory: memory, Iterations: iterations, Parallelism: parallelism}, salt, key, nil
}
