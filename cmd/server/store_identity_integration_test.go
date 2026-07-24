//go:build integration

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestPostgresLocalPasswordResetIsAtomicAndOneTime(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := newPostgresStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.close)

	const username = "identity-integration-user"
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = store.pool.Exec(cleanupContext, "DELETE FROM local_users WHERE username = $1", username)
	})
	_, _ = store.pool.Exec(ctx, "DELETE FROM local_users WHERE username = $1", username)
	oldHash, err := bcrypt.GenerateFromPassword([]byte("initial-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.createLocalUser(ctx, LocalUser{
		Username: username, FirstName: "Integration", LastName: "User",
		Email: "identity-integration@example.test", PasswordHash: string(oldHash),
		Roles: []string{"viewer"}, Active: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	const rawToken = "integration-reset-token-that-is-long-and-random-enough"
	if _, err := store.createPasswordResetToken(
		ctx, user, rawToken, time.Now().Add(time.Minute), "integration-test",
	); err != nil {
		t.Fatal(err)
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte("new-secure-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.consumePasswordResetToken(ctx, rawToken, string(newHash))
	if err != nil {
		t.Fatal(err)
	}
	if updated.AuthVersion != user.AuthVersion+1 {
		t.Fatalf("password reset must invalidate sessions: before=%d after=%d", user.AuthVersion, updated.AuthVersion)
	}
	if _, err := store.consumePasswordResetToken(ctx, rawToken, string(newHash)); !errors.Is(err, errPasswordResetInvalid) {
		t.Fatalf("second token consumption must fail, got %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("new-secure-password")) != nil {
		t.Fatal("new password hash was not persisted")
	}
}
