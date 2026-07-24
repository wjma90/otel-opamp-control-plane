package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const (
	passwordResetTTL      = 15 * time.Minute
	maxIdentityBody       = 64 << 10
	localPasswordHashCost = 12
)

var localUsernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

var invalidLocalPasswordHash = func() []byte {
	hash, _ := bcrypt.GenerateFromPassword([]byte(randomToken(32)), localPasswordHashCost)
	return hash
}()

type profileUpdateRequest struct {
	FirstName       string `json:"firstName"`
	LastName        string `json:"lastName"`
	Email           string `json:"email"`
	CurrentPassword string `json:"currentPassword,omitempty"`
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

type passwordForgotRequest struct {
	UsernameOrEmail string `json:"usernameOrEmail"`
}

type passwordResetRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

type createLocalUserRequest struct {
	Username  string   `json:"username"`
	FirstName string   `json:"firstName"`
	LastName  string   `json:"lastName"`
	Email     string   `json:"email"`
	Password  string   `json:"password"`
	Roles     []string `json:"roles"`
	Active    *bool    `json:"active"`
}

type updateLocalUserRequest struct {
	FirstName string   `json:"firstName"`
	LastName  string   `json:"lastName"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	Active    *bool    `json:"active"`
	Revision  int64    `json:"revision"`
}

func normalizeUsername(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeEmail(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validateUsername(value string) error {
	if !localUsernamePattern.MatchString(normalizeUsername(value)) {
		return errors.New("username must contain 3-64 lowercase letters, numbers, dots, underscores or hyphens")
	}
	return nil
}

func validateProfile(firstName string, lastName string, email string) error {
	if strings.TrimSpace(firstName) == "" || strings.TrimSpace(lastName) == "" {
		return errors.New("firstName and lastName are required")
	}
	if utf8.RuneCountInString(strings.TrimSpace(firstName)) > 120 ||
		utf8.RuneCountInString(strings.TrimSpace(lastName)) > 120 {
		return errors.New("firstName and lastName must not exceed 120 characters")
	}
	email = normalizeEmail(email)
	if email == "" {
		return errors.New("email is required")
	}
	if len(email) > 320 {
		return errors.New("email must not exceed 320 characters")
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || !strings.EqualFold(parsed.Address, email) {
		return errors.New("email is invalid")
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 12 {
		return errors.New("password must contain at least 12 characters")
	}
	// bcrypt rejects inputs larger than 72 bytes; reject them explicitly rather
	// than turning a validation error into a server error during hashing.
	if len(password) > 72 {
		return errors.New("password must not exceed 72 bytes")
	}
	return nil
}

func normalizeAndValidateRoles(roles []string) ([]string, error) {
	set := map[string]bool{}
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if _, known := rolePermissions[role]; !known {
			return nil, fmt.Errorf("unknown role %q", role)
		}
		set[role] = true
	}
	if len(set) == 0 {
		return nil, errors.New("at least one role is required")
	}
	normalized := make([]string, 0, len(set))
	for role := range set {
		normalized = append(normalized, role)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func identityFromLocalUser(user LocalUser) Identity {
	identity := Identity{
		Username:    user.Username,
		FirstName:   user.FirstName,
		LastName:    user.LastName,
		Email:       user.Email,
		Provider:    "local",
		Roles:       append([]string(nil), user.Roles...),
		AuthVersion: user.AuthVersion,
	}
	identity.Permissions = permissionsForRoles(identity.Roles)
	return identity
}

func authenticateStoredLocalUser(
	ctx context.Context,
	repository LocalUserRepository,
	username string,
	password string,
) (LocalUser, bool) {
	user, err := repository.localUser(ctx, normalizeUsername(username))
	passwordHash := invalidLocalPasswordHash
	if err == nil {
		passwordHash = []byte(user.PasswordHash)
	}
	passwordMatches := bcrypt.CompareHashAndPassword(passwordHash, []byte(password)) == nil
	if err != nil || !user.Active || !passwordMatches {
		return LocalUser{}, false
	}
	return user, true
}

func localIdentityRepository() LocalUserRepository {
	if authenticator == nil {
		return nil
	}
	return authenticator.localUsers
}

func initializeLocalIdentity(
	ctx context.Context,
	store *PostgresStore,
	auth *Authenticator,
) error {
	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(auth.masterPassword), localPasswordHashCost,
	)
	if err != nil {
		return fmt.Errorf("hash root bootstrap password: %w", err)
	}
	if err := store.bootstrapRootUser(
		ctx,
		auth.masterUsername,
		string(passwordHash),
		strings.TrimSpace(envOr("MASTER_EMAIL", "")),
	); err != nil {
		return err
	}
	auth.localUsers = store
	// MASTER_PASSWORD is bootstrap-only once PostgreSQL is authoritative.
	auth.masterPassword = ""
	return nil
}

func authProfile(w http.ResponseWriter, r *http.Request) {
	identity, ok := authenticatedIdentity(r)
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if identity.Provider != "local" {
		jsonOut(w, identity)
		return
	}
	repository := localIdentityRepository()
	if repository == nil {
		jsonOut(w, identity)
		return
	}
	user, err := repository.localUser(r.Context(), identity.Username)
	if err != nil {
		http.Error(w, "profile unavailable", http.StatusInternalServerError)
		return
	}
	jsonOut(w, identityFromLocalUser(user))
}

func updateAuthProfile(w http.ResponseWriter, r *http.Request) {
	identity, ok := authenticatedIdentity(r)
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if identity.Provider != "local" {
		http.Error(w, "profile is managed by the external identity provider", http.StatusConflict)
		return
	}
	var payload profileUpdateRequest
	if err := decodeIdentityJSON(w, r, &payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateProfile(payload.FirstName, payload.LastName, payload.Email); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	repository := localIdentityRepository()
	user, err := repository.localUser(r.Context(), identity.Username)
	if err != nil {
		http.Error(w, "profile unavailable", http.StatusInternalServerError)
		return
	}
	if normalizeEmail(payload.Email) != user.Email &&
		bcrypt.CompareHashAndPassword(
			[]byte(user.PasswordHash), []byte(payload.CurrentPassword),
		) != nil {
		http.Error(w, "current password is required to change the recovery email", http.StatusUnauthorized)
		return
	}
	user.FirstName = strings.TrimSpace(payload.FirstName)
	user.LastName = strings.TrimSpace(payload.LastName)
	user.Email = normalizeEmail(payload.Email)
	user, err = repository.updateLocalUserProfile(r.Context(), user)
	if errors.Is(err, errLocalUserConflict) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "profile could not be updated", http.StatusInternalServerError)
		return
	}
	emitAuditLog("auth.profile.updated", identity.Username, map[string]any{
		"auth.user": identity.Username,
	})
	jsonOut(w, identityFromLocalUser(user))
}

func changeLocalPassword(w http.ResponseWriter, r *http.Request) {
	identity, ok := authenticatedIdentity(r)
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if identity.Provider != "local" {
		http.Error(w, "password is managed by the external identity provider", http.StatusConflict)
		return
	}
	var payload passwordChangeRequest
	if err := decodeIdentityJSON(w, r, &payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validatePassword(payload.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	repository := localIdentityRepository()
	user, err := repository.localUser(r.Context(), identity.Username)
	if err != nil || bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash), []byte(payload.CurrentPassword),
	) != nil {
		http.Error(w, "current password is invalid", http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(payload.NewPassword)) == nil {
		http.Error(w, "new password must be different", http.StatusUnprocessableEntity)
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(payload.NewPassword), localPasswordHashCost)
	if err != nil {
		http.Error(w, "password could not be changed", http.StatusInternalServerError)
		return
	}
	user, err = repository.updateLocalUserPassword(r.Context(), user.Username, string(passwordHash))
	if err != nil {
		http.Error(w, "password could not be changed", http.StatusInternalServerError)
		return
	}
	updatedIdentity := identityFromLocalUser(user)
	setSessionCookie(w, r, authenticator.issueSession(updatedIdentity), 8*60*60)
	emitAuditLog("auth.password.changed", user.Username, map[string]any{
		"auth.user": user.Username,
	})
	w.WriteHeader(http.StatusNoContent)
}

func passwordRecoveryStatus(w http.ResponseWriter, r *http.Request) {
	_, publicURLConfigured := configuredPasswordRecoveryBaseURL()
	enabled := publicURLConfigured && passwordRecoveryMailer != nil &&
		passwordRecoveryMailer.Available(r.Context())
	jsonOut(w, map[string]bool{"enabled": enabled})
}

func forgotLocalPassword(w http.ResponseWriter, r *http.Request) {
	var payload passwordForgotRequest
	if err := decodeIdentityJSON(w, r, &payload); err != nil {
		// Malformed requests still receive the generic response so this endpoint
		// cannot be used to distinguish registered users.
		passwordForgotAccepted(w)
		return
	}
	repository := localIdentityRepository()
	_, publicURLConfigured := configuredPasswordRecoveryBaseURL()
	if repository == nil || !publicURLConfigured || passwordRecoveryMailer == nil ||
		!passwordRecoveryMailer.Available(r.Context()) {
		emitAuditLog("auth.password.recovery.requested", "anonymous", map[string]any{
			"delivery.status": "unavailable",
		})
		passwordForgotAccepted(w)
		return
	}
	user, err := repository.localUserByUsernameOrEmail(r.Context(), payload.UsernameOrEmail)
	if err != nil || !user.Active || user.Email == "" {
		emitAuditLog("auth.password.recovery.requested", "anonymous", map[string]any{
			"delivery.status": "not-scheduled",
		})
		passwordForgotAccepted(w)
		return
	}
	if !schedulePasswordReset(r, user, "self-service") {
		emitAuditLog("auth.password.recovery.requested", "anonymous", map[string]any{
			"delivery.status": "failed",
		})
	} else {
		emitAuditLog("auth.password.recovery.requested", "anonymous", map[string]any{
			"delivery.status": "scheduled",
		})
	}
	passwordForgotAccepted(w)
}

func passwordForgotAccepted(w http.ResponseWriter) {
	identityJSON(w, http.StatusAccepted, map[string]string{
		"message": "If the account can be recovered, password reset instructions will be sent.",
	})
}

func schedulePasswordReset(r *http.Request, user LocalUser, createdBy string) bool {
	repository := localIdentityRepository()
	if repository == nil || passwordRecoveryMailer == nil || user.Email == "" {
		return false
	}
	rawToken := randomToken(32)
	expiresAt := time.Now().UTC().Add(passwordResetTTL)
	current, err := repository.createPasswordResetToken(
		r.Context(), user, rawToken, expiresAt, createdBy,
	)
	if err != nil {
		return false
	}
	baseURL, validBaseURL := configuredPasswordRecoveryBaseURL()
	if !validBaseURL {
		return false
	}
	resetURL := strings.TrimRight(baseURL, "/") +
		"/reset-password#token=" + url.QueryEscape(rawToken)
	message := PasswordResetMessage{
		ToEmail:   current.Email,
		Username:  current.Username,
		Token:     rawToken,
		ExpiresAt: expiresAt,
		ResetURL:  resetURL,
	}
	// Delivery uses a bounded context independent from the browser request.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := passwordRecoveryMailer.SendPasswordReset(ctx, message); err != nil {
			emitAuditLog("auth.password.recovery.delivery.failed", "system", map[string]any{
				"delivery.status": "failed",
			})
			return
		}
		emitAuditLog("auth.password.recovery.delivery.succeeded", "system", map[string]any{
			"delivery.status": "sent",
		})
	}()
	return true
}

func configuredPasswordRecoveryBaseURL() (string, bool) {
	if authenticator == nil {
		return "", false
	}
	baseURL := strings.TrimRight(strings.TrimSpace(authenticator.publicURL), "/")
	parsed, err := url.ParseRequestURI(baseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return "", false
	}
	return baseURL, true
}

func resetLocalPassword(w http.ResponseWriter, r *http.Request) {
	var payload passwordResetRequest
	if err := decodeIdentityJSON(w, r, &payload); err != nil ||
		len(strings.TrimSpace(payload.Token)) < 32 || len(payload.Token) > 512 {
		http.Error(w, errPasswordResetInvalid.Error(), http.StatusBadRequest)
		return
	}
	if err := validatePassword(payload.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(payload.NewPassword), localPasswordHashCost)
	if err != nil {
		http.Error(w, "password could not be reset", http.StatusInternalServerError)
		return
	}
	user, err := localIdentityRepository().consumePasswordResetToken(
		r.Context(), payload.Token, string(passwordHash),
	)
	if errors.Is(err, errPasswordResetInvalid) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "password could not be reset", http.StatusInternalServerError)
		return
	}
	emitAuditLog("auth.password.reset", user.Username, map[string]any{
		"auth.user": user.Username,
	})
	w.WriteHeader(http.StatusNoContent)
}

func listLocalUsers(w http.ResponseWriter, r *http.Request) {
	users, err := localIdentityRepository().localUsers(r.Context())
	if err != nil {
		http.Error(w, "users unavailable", http.StatusInternalServerError)
		return
	}
	jsonOut(w, map[string]any{"users": users})
}

func getLocalUserHandler(w http.ResponseWriter, r *http.Request) {
	user, err := localIdentityRepository().localUser(
		r.Context(), normalizeUsername(r.PathValue("username")),
	)
	if errors.Is(err, errLocalUserNotFound) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	jsonOut(w, user)
}

func createLocalUserHandler(w http.ResponseWriter, r *http.Request) {
	var payload createLocalUserRequest
	if err := decodeIdentityJSON(w, r, &payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	payload.Username = normalizeUsername(payload.Username)
	if err := validateUsername(payload.Username); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := validateProfile(payload.FirstName, payload.LastName, payload.Email); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := validatePassword(payload.Password); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	roles, err := normalizeAndValidateRoles(payload.Roles)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	identity, _ := authenticatedIdentity(r)
	if !canDelegateRoles(identity, roles) {
		http.Error(w, "cannot assign a role with permissions the current user does not possess", http.StatusForbidden)
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(payload.Password), localPasswordHashCost)
	if err != nil {
		http.Error(w, "user could not be created", http.StatusInternalServerError)
		return
	}
	active := true
	if payload.Active != nil {
		active = *payload.Active
	}
	user, err := localIdentityRepository().createLocalUser(r.Context(), LocalUser{
		Username: payload.Username, FirstName: payload.FirstName, LastName: payload.LastName,
		Email: payload.Email, PasswordHash: string(passwordHash), Roles: roles, Active: active,
	})
	if errors.Is(err, errLocalUserConflict) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "user could not be created", http.StatusInternalServerError)
		return
	}
	emitAuditLog("auth.local.user.created", identity.Username, map[string]any{
		"auth.user": user.Username,
	})
	identityJSON(w, http.StatusCreated, user)
}

func updateLocalUserHandler(w http.ResponseWriter, r *http.Request) {
	username := normalizeUsername(r.PathValue("username"))
	var payload updateLocalUserRequest
	if err := decodeIdentityJSON(w, r, &payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateProfile(payload.FirstName, payload.LastName, payload.Email); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	roles, err := normalizeAndValidateRoles(payload.Roles)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	identity, _ := authenticatedIdentity(r)
	if !canDelegateRoles(identity, roles) {
		http.Error(w, "cannot assign a role with permissions the current user does not possess", http.StatusForbidden)
		return
	}
	repository := localIdentityRepository()
	user, err := repository.localUser(r.Context(), username)
	if errors.Is(err, errLocalUserNotFound) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	if user.Root {
		http.Error(w, "the root account can only be changed from its own profile", http.StatusConflict)
		return
	}
	if payload.Revision <= 0 || payload.Revision != user.AuthVersion {
		http.Error(w, "user changed since it was loaded; reload before saving", http.StatusConflict)
		return
	}
	if !canDelegateRoles(identity, user.Roles) {
		http.Error(w, "cannot manage a user with permissions the current user does not possess", http.StatusForbidden)
		return
	}
	active := user.Active
	if payload.Active != nil {
		active = *payload.Active
	}
	user.FirstName = strings.TrimSpace(payload.FirstName)
	user.LastName = strings.TrimSpace(payload.LastName)
	user.Email = normalizeEmail(payload.Email)
	user.Roles = roles
	user.Active = active
	user, err = repository.updateLocalUser(r.Context(), user)
	if errors.Is(err, errLocalUserConflict) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if errors.Is(err, errRootUserProtected) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "user could not be updated", http.StatusInternalServerError)
		return
	}
	emitAuditLog("auth.local.user.updated", identity.Username, map[string]any{
		"auth.user": user.Username,
	})
	jsonOut(w, user)
}

func deleteLocalUserHandler(w http.ResponseWriter, r *http.Request) {
	username := normalizeUsername(r.PathValue("username"))
	repository := localIdentityRepository()
	user, err := repository.localUser(r.Context(), username)
	if errors.Is(err, errLocalUserNotFound) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	if user.Root {
		http.Error(w, errRootUserProtected.Error(), http.StatusConflict)
		return
	}
	identity, _ := authenticatedIdentity(r)
	if !canDelegateRoles(identity, user.Roles) {
		http.Error(w, "cannot manage a user with permissions the current user does not possess", http.StatusForbidden)
		return
	}
	err = repository.deactivateLocalUser(r.Context(), username)
	if errors.Is(err, errLocalUserNotFound) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if errors.Is(err, errRootUserProtected) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "user could not be deactivated", http.StatusInternalServerError)
		return
	}
	emitAuditLog("auth.local.user.deactivated", identity.Username, map[string]any{
		"auth.user": username,
	})
	w.WriteHeader(http.StatusNoContent)
}

func adminPasswordReset(w http.ResponseWriter, r *http.Request) {
	username := normalizeUsername(r.PathValue("username"))
	user, err := localIdentityRepository().localUser(r.Context(), username)
	if errors.Is(err, errLocalUserNotFound) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	if user.Root {
		http.Error(w, "the root account uses the public recovery flow", http.StatusConflict)
		return
	}
	identity, _ := authenticatedIdentity(r)
	if !canDelegateRoles(identity, user.Roles) {
		http.Error(w, "cannot manage a user with permissions the current user does not possess", http.StatusForbidden)
		return
	}
	status := "not-scheduled"
	_, publicURLConfigured := configuredPasswordRecoveryBaseURL()
	if user.Active && user.Email != "" && publicURLConfigured && passwordRecoveryMailer != nil &&
		passwordRecoveryMailer.Available(r.Context()) && schedulePasswordReset(r, user, identity.Username) {
		status = "scheduled"
	}
	emitAuditLog("auth.local.user.password-reset-requested", identity.Username, map[string]any{
		"auth.user":       username,
		"delivery.status": status,
	})
	identityJSON(w, http.StatusAccepted, map[string]string{"status": status})
}

func authRoles(w http.ResponseWriter, r *http.Request) {
	identity, _ := authenticatedIdentity(r)
	roleIDs := make([]string, 0, len(rolePermissions))
	for role := range rolePermissions {
		roleIDs = append(roleIDs, role)
	}
	sort.Strings(roleIDs)
	roles := make([]map[string]any, 0, len(roleIDs))
	for _, role := range roleIDs {
		roles = append(roles, map[string]any{
			"id":          role,
			"permissions": rolePermissions[role],
			"assignable":  canDelegateRoles(identity, []string{role}),
		})
	}
	jsonOut(w, map[string]any{"roles": roles})
}

func decodeIdentityJSON(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxIdentityBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid JSON body")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON body")
	}
	return nil
}

func identityJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
