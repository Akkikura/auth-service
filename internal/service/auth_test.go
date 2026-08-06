package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/domain"
	"github.com/acme/auth-service/internal/security"
)

type fakeUsers struct {
	byEmail   map[string]domain.User
	byID      map[int64]domain.User
	updateErr error
}

func (f *fakeUsers) Create(_ context.Context, email, hash string) (domain.User, error) {
	if _, ok := f.byEmail[email]; ok {
		return domain.User{}, domain.ErrEmailAlreadyExists
	}
	u := domain.User{ID: int64(len(f.byID) + 1), Email: email, PasswordHash: hash, CreatedAt: time.Now().UTC()}
	f.byEmail[email], f.byID[u.ID] = u, u
	return u, nil
}
func (f *fakeUsers) FindByEmail(_ context.Context, email string) (domain.User, error) {
	u, ok := f.byEmail[email]
	if !ok {
		return domain.User{}, domain.ErrUserNotFound
	}
	return u, nil
}
func (f *fakeUsers) FindByID(_ context.Context, id int64) (domain.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return domain.User{}, domain.ErrUserNotFound
	}
	return u, nil
}
func (f *fakeUsers) UpdatePasswordHash(_ context.Context, id int64, hash string) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	u, ok := f.byID[id]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.PasswordHash = hash
	f.byID[id] = u
	f.byEmail[u.Email] = u
	return nil
}

type fakeSessions struct{ values map[string]int64 }

func (f *fakeSessions) Create(_ context.Context, digest string, id int64, _ time.Duration) error {
	f.values[digest] = id
	return nil
}
func (f *fakeSessions) GetUserID(_ context.Context, digest string) (int64, error) {
	id, ok := f.values[digest]
	if !ok {
		return 0, domain.ErrInvalidSession
	}
	return id, nil
}
func (f *fakeSessions) Delete(_ context.Context, digest string) error {
	delete(f.values, digest)
	return nil
}

func newTestService(t *testing.T) *AuthService {
	t.Helper()
	passwords, err := security.NewPasswordHasher(security.Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := security.NewTokenManager([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewAuthService(&fakeUsers{byEmail: map[string]domain.User{}, byID: map[int64]domain.User{}}, &fakeSessions{values: map[string]int64{}}, passwords, tokens, time.Minute, 12, 128, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestAuthFlow(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	registered, err := svc.Register(ctx, " User@Example.com ", "strong-password")
	if err != nil {
		t.Fatal(err)
	}
	if registered.Email != "user@example.com" {
		t.Fatalf("unexpected email: %s", registered.Email)
	}
	token, _, err := svc.Login(ctx, "user@example.com", "strong-password")
	if err != nil {
		t.Fatal(err)
	}
	me, err := svc.Authenticate(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if me.ID != registered.ID {
		t.Fatalf("unexpected user id: %d", me.ID)
	}
	if err := svc.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, token); !errors.Is(err, domain.ErrInvalidSession) {
		t.Fatalf("expected invalid session, got %v", err)
	}
}

func TestLoginDoesNotRevealMissingUser(t *testing.T) {
	svc := newTestService(t)
	_, _, err := svc.Login(context.Background(), "missing@example.com", "wrong-password")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegisterValidatesInputAndRejectsDuplicate(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	invalid := []struct {
		name     string
		email    string
		password string
	}{
		{name: "empty email", email: "", password: "strong-password"},
		{name: "display name", email: "User <user@example.com>", password: "strong-password"},
		{name: "header injection", email: "user@example.com\r\nBcc: other@example.com", password: "strong-password"},
		{name: "short password", email: "user@example.com", password: "short"},
		{name: "blank password", email: "user@example.com", password: "            "},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := svc.Register(ctx, test.email, test.password); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("expected invalid input, got %v", err)
			}
		})
	}

	if _, err := svc.Register(ctx, "user@example.com", "strong-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Register(ctx, " USER@example.com ", "another-password"); !errors.Is(err, domain.ErrEmailAlreadyExists) {
		t.Fatalf("expected duplicate email, got %v", err)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Register(ctx, "user@example.com", "strong-password"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Login(ctx, "user@example.com", "wrong-password"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestAuthenticateRejectsMalformedToken(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.Authenticate(context.Background(), "not-a-session-token"); !errors.Is(err, domain.ErrInvalidSession) {
		t.Fatalf("expected invalid session, got %v", err)
	}
}

func TestPasswordHashCapacityHonorsContext(t *testing.T) {
	svc := newTestService(t)
	for i := 0; i < cap(svc.passwordSlots); i++ {
		svc.passwordSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(svc.passwordSlots); i++ {
			<-svc.passwordSlots
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, _, err := svc.Login(ctx, "missing@example.com", "wrong-password")
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected unavailable when password capacity is exhausted, got %v", err)
	}
}

func TestRehashFailureIsObservedWithoutBreakingLogin(t *testing.T) {
	oldHasher, err := security.NewPasswordHasher(security.Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	currentHasher, err := security.NewPasswordHasher(security.Argon2Params{Memory: 8 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := oldHasher.Hash("strong-password")
	if err != nil {
		t.Fatal(err)
	}
	user := domain.User{ID: 1, Email: "user@example.com", PasswordHash: hash, CreatedAt: time.Now().UTC()}
	users := &fakeUsers{
		byEmail:   map[string]domain.User{user.Email: user},
		byID:      map[int64]domain.User{user.ID: user},
		updateErr: errors.New("database write failed"),
	}
	tokens, err := security.NewTokenManager([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan error, 1)
	svc, err := NewAuthService(
		users,
		&fakeSessions{values: map[string]int64{}},
		currentHasher,
		tokens,
		time.Minute,
		12,
		128,
		2,
		RehashObserverFunc(func(err error) { observed <- err }),
	)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := svc.Login(context.Background(), user.Email, "strong-password")
	if err != nil {
		t.Fatalf("login must succeed despite rehash failure: %v", err)
	}
	if token == "" {
		t.Fatal("missing token")
	}
	select {
	case err := <-observed:
		if err == nil {
			t.Fatal("observer received nil error")
		}
	default:
		t.Fatal("rehash failure was not observed")
	}
}
