CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_email_normalized CHECK (email = lower(btrim(email))),
    CONSTRAINT users_email_length CHECK (char_length(email) BETWEEN 3 AND 254),
    CONSTRAINT users_password_hash_not_empty CHECK (char_length(password_hash) > 0)
);
