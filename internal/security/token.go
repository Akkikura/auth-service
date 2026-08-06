package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const tokenBytes = 32

type TokenManager struct {
	key []byte
}

func NewTokenManager(key []byte) (*TokenManager, error) {
	if len(key) < 32 {
		return nil, errors.New("token HMAC key must contain at least 32 bytes")
	}
	copyKey := append([]byte(nil), key...)
	return &TokenManager{key: copyKey}, nil
}

func (m *TokenManager) Generate() (raw string, digest string, err error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	// клиенту отдаю токен а храню только его хеш
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, m.Digest(raw), nil
}

func (m *TokenManager) Digest(raw string) string {
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *TokenManager) ValidFormat(raw string) bool {
	if len(raw) != base64.RawURLEncoding.EncodedLen(tokenBytes) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	return err == nil && len(decoded) == tokenBytes && strings.TrimSpace(raw) == raw
}

func (m *TokenManager) Identifier(value string) string {
	// TODO префикс отделяет обычные хеши от служебных
	return m.Digest("identifier:" + strings.ToLower(strings.TrimSpace(value)))
}
