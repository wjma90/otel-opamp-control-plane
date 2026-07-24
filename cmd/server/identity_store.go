package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	errLocalUserNotFound    = errors.New("local user not found")
	errLocalUserConflict    = errors.New("username or email already exists")
	errPasswordResetInvalid = errors.New("password reset token is invalid or expired")
	errRootUserProtected    = errors.New("root user is protected")
	errLocalUserInactive    = errors.New("local user is inactive")
)

// LocalUser is the internal persistence model. PasswordHash and AuthVersion
// are deliberately excluded from JSON so handlers cannot leak either field by
// serializing this type accidentally.
type LocalUser struct {
	Username     string    `json:"username"`
	FirstName    string    `json:"firstName"`
	LastName     string    `json:"lastName"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Roles        []string  `json:"roles"`
	Active       bool      `json:"active"`
	Root         bool      `json:"root"`
	AuthVersion  int64     `json:"revision"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type LocalUserRepository interface {
	localUser(context.Context, string) (LocalUser, error)
	localUserByUsernameOrEmail(context.Context, string) (LocalUser, error)
	localUsers(context.Context) ([]LocalUser, error)
	createLocalUser(context.Context, LocalUser) (LocalUser, error)
	updateLocalUserProfile(context.Context, LocalUser) (LocalUser, error)
	updateLocalUser(context.Context, LocalUser) (LocalUser, error)
	updateLocalUserPassword(context.Context, string, string) (LocalUser, error)
	deactivateLocalUser(context.Context, string) error
	createPasswordResetToken(context.Context, LocalUser, string, time.Time, string) (LocalUser, error)
	consumePasswordResetToken(context.Context, string, string) (LocalUser, error)
}

func (s *PostgresStore) migrateLocalIdentity(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS local_users (
    username TEXT PRIMARY KEY CHECK (username ~ '^[a-z0-9][a-z0-9._-]{2,63}$'),
    first_name TEXT NOT NULL DEFAULT '',
    last_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    roles JSONB NOT NULL DEFAULT '["viewer"]'::jsonb,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    is_root BOOLEAN NOT NULL DEFAULT FALSE,
    auth_version BIGINT NOT NULL DEFAULT 1 CHECK (auth_version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS local_users_email_unique_idx
    ON local_users (LOWER(email))
    WHERE email <> '';

CREATE UNIQUE INDEX IF NOT EXISTS local_users_single_root_idx
    ON local_users (is_root)
    WHERE is_root;

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES local_users(username) ON DELETE CASCADE,
    auth_version BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL
);

ALTER TABLE password_reset_tokens
    ADD COLUMN IF NOT EXISTS auth_version BIGINT;

UPDATE password_reset_tokens AS token
SET auth_version = users.auth_version
FROM local_users AS users
WHERE token.username = users.username
  AND token.auth_version IS NULL;

ALTER TABLE password_reset_tokens
    ALTER COLUMN auth_version SET NOT NULL;

CREATE INDEX IF NOT EXISTS password_reset_tokens_lookup_idx
    ON password_reset_tokens (username, expires_at DESC)
    WHERE consumed_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS password_reset_tokens_one_active_idx
    ON password_reset_tokens (username)
    WHERE consumed_at IS NULL;`
	if _, err := s.pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("migrate local identity schema: %w", err)
	}
	return nil
}

func (s *PostgresStore) bootstrapRootUser(
	ctx context.Context,
	username string,
	passwordHash string,
	email string,
) error {
	username = normalizeUsername(username)
	if username == "" || passwordHash == "" {
		return errors.New("root username and password hash are required")
	}
	now := time.Now().UTC()
	result, err := s.pool.Exec(ctx, `
INSERT INTO local_users (
    username, first_name, last_name, email, password_hash, roles,
    active, is_root, auth_version, created_at, updated_at
)
SELECT $1, 'O11y', 'Administrator', $2, $3, '["admin"]'::jsonb,
       TRUE, TRUE, 1, $4, $4
WHERE NOT EXISTS (SELECT 1 FROM local_users WHERE is_root)`,
		username, normalizeEmail(email), passwordHash, now,
	)
	if err != nil {
		return fmt.Errorf("bootstrap root user: %w", err)
	}
	if result.RowsAffected() == 1 {
		emitAuditLog("auth.local.root.created", "system-bootstrap", map[string]any{
			"auth.user": username,
		})
	}
	return nil
}

const localUserColumns = `
    username, first_name, last_name, email, password_hash, roles,
    active, is_root, auth_version, created_at, updated_at`

func scanLocalUser(row pgx.Row) (LocalUser, error) {
	var user LocalUser
	var rolesJSON []byte
	if err := row.Scan(
		&user.Username,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.PasswordHash,
		&rolesJSON,
		&user.Active,
		&user.Root,
		&user.AuthVersion,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LocalUser{}, errLocalUserNotFound
		}
		return LocalUser{}, err
	}
	if err := json.Unmarshal(rolesJSON, &user.Roles); err != nil {
		return LocalUser{}, fmt.Errorf("decode roles for %s: %w", user.Username, err)
	}
	return user, nil
}

func (s *PostgresStore) localUser(ctx context.Context, username string) (LocalUser, error) {
	user, err := scanLocalUser(s.pool.QueryRow(ctx, `SELECT `+localUserColumns+`
FROM local_users
WHERE username = $1`, normalizeUsername(username)))
	if err != nil && !errors.Is(err, errLocalUserNotFound) {
		return LocalUser{}, fmt.Errorf("query local user: %w", err)
	}
	return user, err
}

func (s *PostgresStore) localUserByUsernameOrEmail(
	ctx context.Context,
	value string,
) (LocalUser, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	user, err := scanLocalUser(s.pool.QueryRow(ctx, `SELECT `+localUserColumns+`
FROM local_users
WHERE username = $1 OR (email <> '' AND LOWER(email) = $1)
LIMIT 1`, normalized))
	if err != nil && !errors.Is(err, errLocalUserNotFound) {
		return LocalUser{}, fmt.Errorf("query local user for password recovery: %w", err)
	}
	return user, err
}

func (s *PostgresStore) localUsers(ctx context.Context) ([]LocalUser, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+localUserColumns+`
FROM local_users
ORDER BY is_root DESC, username`)
	if err != nil {
		return nil, fmt.Errorf("query local users: %w", err)
	}
	defer rows.Close()
	users := []LocalUser{}
	for rows.Next() {
		user, scanErr := scanLocalUser(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan local user: %w", scanErr)
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *PostgresStore) createLocalUser(
	ctx context.Context,
	user LocalUser,
) (LocalUser, error) {
	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return LocalUser{}, err
	}
	now := time.Now().UTC()
	created, err := scanLocalUser(s.pool.QueryRow(ctx, `
INSERT INTO local_users (
    username, first_name, last_name, email, password_hash, roles,
    active, is_root, auth_version, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, 1, $8, $8)
RETURNING `+localUserColumns,
		normalizeUsername(user.Username), strings.TrimSpace(user.FirstName),
		strings.TrimSpace(user.LastName), normalizeEmail(user.Email),
		user.PasswordHash, rolesJSON, user.Active, now,
	))
	if err != nil {
		return LocalUser{}, translateLocalUserWriteError("create local user", err)
	}
	return created, nil
}

func (s *PostgresStore) updateLocalUserProfile(
	ctx context.Context,
	user LocalUser,
) (LocalUser, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LocalUser{}, fmt.Errorf("begin local profile update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var previousEmail string
	err = tx.QueryRow(ctx, `
SELECT email
FROM local_users
WHERE username = $1
  AND active
  AND auth_version = $2
FOR UPDATE`, normalizeUsername(user.Username), user.AuthVersion).Scan(&previousEmail)
	if errors.Is(err, pgx.ErrNoRows) {
		return LocalUser{}, errLocalUserConflict
	}
	if err != nil {
		return LocalUser{}, fmt.Errorf("lock local user profile: %w", err)
	}
	updated, err := scanLocalUser(tx.QueryRow(ctx, `
UPDATE local_users
SET first_name = $2,
    last_name = $3,
    email = $4,
    updated_at = $6
WHERE username = $1
  AND active
  AND auth_version = $5
RETURNING `+localUserColumns,
		normalizeUsername(user.Username), strings.TrimSpace(user.FirstName),
		strings.TrimSpace(user.LastName), normalizeEmail(user.Email),
		user.AuthVersion, time.Now().UTC(),
	))
	if err != nil {
		return LocalUser{}, translateLocalUserWriteError("update local user profile", err)
	}
	if !strings.EqualFold(previousEmail, updated.Email) {
		if _, err = tx.Exec(ctx, `
UPDATE password_reset_tokens
SET consumed_at = NOW()
WHERE username = $1 AND consumed_at IS NULL`, updated.Username); err != nil {
			return LocalUser{}, fmt.Errorf("revoke reset tokens after email change: %w", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return LocalUser{}, fmt.Errorf("commit local profile update: %w", err)
	}
	return updated, nil
}

func (s *PostgresStore) updateLocalUser(
	ctx context.Context,
	user LocalUser,
) (LocalUser, error) {
	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return LocalUser{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LocalUser{}, fmt.Errorf("begin local user update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var previousEmail string
	var currentVersion int64
	var root bool
	err = tx.QueryRow(ctx, `
SELECT email, auth_version, is_root
FROM local_users
WHERE username = $1
FOR UPDATE`, normalizeUsername(user.Username)).Scan(&previousEmail, &currentVersion, &root)
	if errors.Is(err, pgx.ErrNoRows) {
		return LocalUser{}, errLocalUserNotFound
	}
	if err != nil {
		return LocalUser{}, fmt.Errorf("lock local user: %w", err)
	}
	if currentVersion != user.AuthVersion {
		return LocalUser{}, errLocalUserConflict
	}
	if root && (!user.Active || !containsString(user.Roles, "admin")) {
		return LocalUser{}, errRootUserProtected
	}
	updated, err := scanLocalUser(tx.QueryRow(ctx, `
UPDATE local_users
SET first_name = $2,
    last_name = $3,
    email = $4,
    roles = $5,
    active = $6,
    auth_version = auth_version + CASE
        WHEN email IS DISTINCT FROM $4
          OR roles IS DISTINCT FROM $5::jsonb
          OR active IS DISTINCT FROM $6 THEN 1
        ELSE 0
    END,
	updated_at = $8
WHERE username = $1
	AND auth_version = $7
RETURNING `+localUserColumns,
		normalizeUsername(user.Username), strings.TrimSpace(user.FirstName),
		strings.TrimSpace(user.LastName), normalizeEmail(user.Email), rolesJSON,
		user.Active, user.AuthVersion, time.Now().UTC(),
	))
	if err != nil {
		if errors.Is(err, errLocalUserNotFound) {
			return LocalUser{}, errLocalUserConflict
		}
		return LocalUser{}, translateLocalUserWriteError("update local user", err)
	}
	if !strings.EqualFold(previousEmail, updated.Email) {
		if _, err = tx.Exec(ctx, `
UPDATE password_reset_tokens
SET consumed_at = NOW()
WHERE username = $1 AND consumed_at IS NULL`, updated.Username); err != nil {
			return LocalUser{}, fmt.Errorf("revoke reset tokens after administrative email change: %w", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return LocalUser{}, fmt.Errorf("commit local user update: %w", err)
	}
	return updated, nil
}

func (s *PostgresStore) updateLocalUserPassword(
	ctx context.Context,
	username string,
	passwordHash string,
) (LocalUser, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LocalUser{}, fmt.Errorf("begin local password update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	updated, err := scanLocalUser(tx.QueryRow(ctx, `
UPDATE local_users
SET password_hash = $2,
    auth_version = auth_version + 1,
    updated_at = $3
WHERE username = $1 AND active
RETURNING `+localUserColumns,
		normalizeUsername(username), passwordHash, time.Now().UTC(),
	))
	if err != nil {
		if errors.Is(err, errLocalUserNotFound) {
			return LocalUser{}, errLocalUserInactive
		}
		return LocalUser{}, fmt.Errorf("update local user password: %w", err)
	}
	if _, err = tx.Exec(ctx, `
UPDATE password_reset_tokens
SET consumed_at = NOW()
WHERE username = $1 AND consumed_at IS NULL`, normalizeUsername(username)); err != nil {
		return LocalUser{}, fmt.Errorf("revoke password reset tokens: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return LocalUser{}, fmt.Errorf("commit local password update: %w", err)
	}
	return updated, nil
}

func (s *PostgresStore) deactivateLocalUser(ctx context.Context, username string) error {
	result, err := s.pool.Exec(ctx, `
UPDATE local_users
SET active = FALSE, auth_version = auth_version + 1, updated_at = $2
WHERE username = $1 AND NOT is_root`, normalizeUsername(username), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("deactivate local user: %w", err)
	}
	if result.RowsAffected() == 0 {
		user, lookupErr := s.localUser(ctx, username)
		if lookupErr != nil {
			return lookupErr
		}
		if user.Root {
			return errRootUserProtected
		}
	}
	return nil
}

func passwordResetTokenHash(rawToken string) string {
	hash := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hash[:])
}

func (s *PostgresStore) createPasswordResetToken(
	ctx context.Context,
	expected LocalUser,
	rawToken string,
	expiresAt time.Time,
	createdBy string,
) (LocalUser, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LocalUser{}, fmt.Errorf("begin password reset token: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := scanLocalUser(tx.QueryRow(ctx, `
SELECT `+localUserColumns+`
FROM local_users
WHERE username = $1
  AND active
  AND auth_version = $2
  AND LOWER(email) = LOWER($3)
FOR UPDATE`, normalizeUsername(expected.Username), expected.AuthVersion, normalizeEmail(expected.Email)))
	if errors.Is(err, errLocalUserNotFound) {
		return LocalUser{}, errLocalUserConflict
	}
	if err != nil {
		return LocalUser{}, fmt.Errorf("lock password reset recipient: %w", err)
	}
	if _, err = tx.Exec(ctx, `
UPDATE password_reset_tokens
SET consumed_at = NOW()
WHERE username = $1 AND consumed_at IS NULL`, current.Username); err != nil {
		return LocalUser{}, fmt.Errorf("revoke previous password reset tokens: %w", err)
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO password_reset_tokens (
	token_hash, username, auth_version, expires_at, consumed_at, created_at, created_by
) VALUES ($1, $2, $3, $4, NULL, $5, $6)`,
		passwordResetTokenHash(rawToken), current.Username, current.AuthVersion,
		expiresAt, time.Now().UTC(), createdBy,
	); err != nil {
		return LocalUser{}, fmt.Errorf("create password reset token: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return LocalUser{}, fmt.Errorf("commit password reset token: %w", err)
	}
	return current, nil
}

func (s *PostgresStore) consumePasswordResetToken(
	ctx context.Context,
	rawToken string,
	passwordHash string,
) (LocalUser, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LocalUser{}, fmt.Errorf("begin password reset: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var username string
	var authVersion int64
	err = tx.QueryRow(ctx, `
SELECT username, auth_version
FROM password_reset_tokens
WHERE token_hash = $1
  AND consumed_at IS NULL
  AND expires_at > NOW()
FOR UPDATE`, passwordResetTokenHash(rawToken)).Scan(&username, &authVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return LocalUser{}, errPasswordResetInvalid
	}
	if err != nil {
		return LocalUser{}, fmt.Errorf("lookup password reset token: %w", err)
	}
	user, err := scanLocalUser(tx.QueryRow(ctx, `
UPDATE local_users
SET password_hash = $2,
    auth_version = auth_version + 1,
    updated_at = $3
WHERE username = $1 AND active AND auth_version = $4
RETURNING `+localUserColumns, username, passwordHash, time.Now().UTC(), authVersion))
	if err != nil {
		if errors.Is(err, errLocalUserNotFound) {
			return LocalUser{}, errPasswordResetInvalid
		}
		return LocalUser{}, fmt.Errorf("apply password reset: %w", err)
	}
	if _, err = tx.Exec(ctx, `
UPDATE password_reset_tokens
SET consumed_at = NOW()
WHERE username = $1 AND consumed_at IS NULL`, username); err != nil {
		return LocalUser{}, fmt.Errorf("consume password reset token: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return LocalUser{}, fmt.Errorf("commit password reset: %w", err)
	}
	return user, nil
}

func translateLocalUserWriteError(operation string, err error) error {
	if errors.Is(err, errLocalUserNotFound) {
		return err
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return errLocalUserConflict
	}
	return fmt.Errorf("%s: %w", operation, err)
}
