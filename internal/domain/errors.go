package domain

import "errors"

var (
	ErrInvalidInput       = errors.New("invalid input")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidSession     = errors.New("invalid session")
	ErrUnavailable        = errors.New("dependency unavailable")
)
