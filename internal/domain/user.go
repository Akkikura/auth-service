package domain

import "time"

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

type PublicUser struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func (u User) Public() PublicUser {
	return PublicUser{ID: u.ID, Email: u.Email, CreatedAt: u.CreatedAt}
}
