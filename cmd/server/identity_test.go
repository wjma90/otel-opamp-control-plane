package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type memoryLocalUserRepository struct {
	mu     sync.Mutex
	users  map[string]LocalUser
	tokens map[string]memoryPasswordResetToken
}

type memoryPasswordResetToken struct {
	username    string
	authVersion int64
	expiresAt   time.Time
	consumed    bool
}

func (repository *memoryLocalUserRepository) localUser(
	_ context.Context,
	username string,
) (LocalUser, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	user, ok := repository.users[normalizeUsername(username)]
	if !ok {
		return LocalUser{}, errLocalUserNotFound
	}
	return user, nil
}

func (repository *memoryLocalUserRepository) localUserByUsernameOrEmail(
	_ context.Context,
	value string,
) (LocalUser, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	value = strings.ToLower(strings.TrimSpace(value))
	for _, user := range repository.users {
		if user.Username == value || strings.EqualFold(user.Email, value) {
			return user, nil
		}
	}
	return LocalUser{}, errLocalUserNotFound
}

func (repository *memoryLocalUserRepository) localUsers(context.Context) ([]LocalUser, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	users := make([]LocalUser, 0, len(repository.users))
	for _, user := range repository.users {
		users = append(users, user)
	}
	return users, nil
}

func (repository *memoryLocalUserRepository) createLocalUser(
	_ context.Context,
	user LocalUser,
) (LocalUser, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.users[user.Username]; exists {
		return LocalUser{}, errLocalUserConflict
	}
	user.AuthVersion = 1
	user.CreatedAt = time.Now()
	user.UpdatedAt = user.CreatedAt
	repository.users[user.Username] = user
	return user, nil
}

func (repository *memoryLocalUserRepository) updateLocalUserProfile(
	_ context.Context,
	user LocalUser,
) (LocalUser, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current, exists := repository.users[user.Username]
	if !exists || !current.Active || current.AuthVersion != user.AuthVersion {
		return LocalUser{}, errLocalUserConflict
	}
	current.FirstName = user.FirstName
	current.LastName = user.LastName
	previousEmail := current.Email
	current.Email = user.Email
	current.UpdatedAt = time.Now()
	repository.users[user.Username] = current
	if !strings.EqualFold(previousEmail, current.Email) {
		for hash, token := range repository.tokens {
			if token.username == user.Username {
				token.consumed = true
				repository.tokens[hash] = token
			}
		}
	}
	return current, nil
}

func (repository *memoryLocalUserRepository) updateLocalUser(
	_ context.Context,
	user LocalUser,
) (LocalUser, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current, exists := repository.users[user.Username]
	if !exists {
		return LocalUser{}, errLocalUserNotFound
	}
	if current.AuthVersion != user.AuthVersion {
		return LocalUser{}, errLocalUserConflict
	}
	if current.Root && (!user.Active || !containsString(user.Roles, "admin")) {
		return LocalUser{}, errRootUserProtected
	}
	previousEmail := current.Email
	if !strings.EqualFold(previousEmail, user.Email) ||
		strings.Join(current.Roles, ",") != strings.Join(user.Roles, ",") ||
		current.Active != user.Active {
		user.AuthVersion++
	}
	user.PasswordHash = current.PasswordHash
	user.Root = current.Root
	user.CreatedAt = current.CreatedAt
	user.UpdatedAt = time.Now()
	repository.users[user.Username] = user
	if !strings.EqualFold(previousEmail, user.Email) {
		for hash, token := range repository.tokens {
			if token.username == user.Username {
				token.consumed = true
				repository.tokens[hash] = token
			}
		}
	}
	return user, nil
}

func (repository *memoryLocalUserRepository) updateLocalUserPassword(
	_ context.Context,
	username string,
	passwordHash string,
) (LocalUser, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	user, exists := repository.users[username]
	if !exists || !user.Active {
		return LocalUser{}, errLocalUserInactive
	}
	user.PasswordHash = passwordHash
	user.AuthVersion++
	user.UpdatedAt = time.Now()
	repository.users[username] = user
	for hash, token := range repository.tokens {
		if token.username == username {
			token.consumed = true
			repository.tokens[hash] = token
		}
	}
	return user, nil
}

func (repository *memoryLocalUserRepository) deactivateLocalUser(
	_ context.Context,
	username string,
) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	user, exists := repository.users[username]
	if !exists {
		return errLocalUserNotFound
	}
	if user.Root {
		return errRootUserProtected
	}
	user.Active = false
	user.AuthVersion++
	repository.users[username] = user
	return nil
}

func (repository *memoryLocalUserRepository) createPasswordResetToken(
	_ context.Context,
	expected LocalUser,
	rawToken string,
	expiresAt time.Time,
	_ string,
) (LocalUser, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current, exists := repository.users[expected.Username]
	if !exists || !current.Active || current.AuthVersion != expected.AuthVersion ||
		!strings.EqualFold(current.Email, expected.Email) {
		return LocalUser{}, errLocalUserConflict
	}
	for hash, token := range repository.tokens {
		if token.username == current.Username {
			token.consumed = true
			repository.tokens[hash] = token
		}
	}
	repository.tokens[passwordResetTokenHash(rawToken)] = memoryPasswordResetToken{
		username: current.Username, authVersion: current.AuthVersion, expiresAt: expiresAt,
	}
	return current, nil
}

func (repository *memoryLocalUserRepository) consumePasswordResetToken(
	_ context.Context,
	rawToken string,
	passwordHash string,
) (LocalUser, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	hash := passwordResetTokenHash(rawToken)
	token, exists := repository.tokens[hash]
	if !exists || token.consumed || !token.expiresAt.After(time.Now()) {
		return LocalUser{}, errPasswordResetInvalid
	}
	user := repository.users[token.username]
	if !user.Active || user.AuthVersion != token.authVersion {
		return LocalUser{}, errPasswordResetInvalid
	}
	user.PasswordHash = passwordHash
	user.AuthVersion++
	repository.users[user.Username] = user
	token.consumed = true
	repository.tokens[hash] = token
	return user, nil
}

type capturePasswordRecoveryMailer struct {
	available bool
	messages  chan PasswordResetMessage
}

func (mailer *capturePasswordRecoveryMailer) Available(context.Context) bool {
	return mailer.available
}

func (mailer *capturePasswordRecoveryMailer) SendPasswordReset(
	_ context.Context,
	message PasswordResetMessage,
) error {
	mailer.messages <- message
	return nil
}

func localUserFixture(t *testing.T, username string, password string, root bool) LocalUser {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return LocalUser{
		Username: username, FirstName: "Ana", LastName: "Admin",
		Email: username + "@example.test", PasswordHash: string(hash),
		Roles: []string{"admin"}, Active: true, Root: root, AuthVersion: 1,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
}

func useIdentityTestState(t *testing.T, repository *memoryLocalUserRepository) *Authenticator {
	t.Helper()
	previousAuthenticator := authenticator
	previousMailer := passwordRecoveryMailer
	auth := &Authenticator{
		signingKey: []byte("identity-test-signing-key"),
		publicURL:  "http://localhost:8080",
		localUsers: repository,
	}
	authenticator = auth
	passwordRecoveryMailer = unavailablePasswordRecoveryMailer{}
	t.Cleanup(func() {
		authenticator = previousAuthenticator
		passwordRecoveryMailer = previousMailer
	})
	return auth
}

func TestStoredLocalLoginAndPasswordChangeInvalidatePreviousSession(t *testing.T) {
	const oldPassword = "correct-old-password"
	repository := &memoryLocalUserRepository{
		users:  map[string]LocalUser{"o11y-admin": localUserFixture(t, "o11y-admin", oldPassword, true)},
		tokens: map[string]memoryPasswordResetToken{},
	}
	auth := useIdentityTestState(t, repository)
	const previouslyIssuedResetToken = "previously-issued-reset-token-with-enough-entropy"
	if _, err := repository.createPasswordResetToken(
		context.Background(), repository.users["o11y-admin"], previouslyIssuedResetToken,
		time.Now().Add(15*time.Minute), "test",
	); err != nil {
		t.Fatal(err)
	}
	oldToken, identity, ok := auth.login("O11Y-ADMIN", oldPassword)
	if !ok || identity.Email != "o11y-admin@example.test" {
		t.Fatalf("expected persisted local login, got %#v", identity)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"http://control-plane/api/auth/password/change",
		strings.NewReader(`{"currentPassword":"correct-old-password","newPassword":"a-different-password"}`),
	)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: oldToken})
	recorder := httptest.NewRecorder()
	requirePermission("agents.view", changeLocalPassword).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected password change 204, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, valid := auth.localIdentity(oldToken); valid {
		t.Fatal("previous session must be invalid after password change")
	}
	if len(recorder.Result().Cookies()) != 1 {
		t.Fatal("password change must renew the browser session")
	}
	if _, _, valid := auth.login("o11y-admin", oldPassword); valid {
		t.Fatal("old password must no longer authenticate")
	}
	if _, _, valid := auth.login("o11y-admin", "a-different-password"); !valid {
		t.Fatal("new password must authenticate")
	}
	if _, err := repository.consumePasswordResetToken(
		context.Background(), previouslyIssuedResetToken, "unused-hash",
	); !errors.Is(err, errPasswordResetInvalid) {
		t.Fatalf("password change must revoke previously issued reset tokens, got %v", err)
	}
}

func TestPasswordResetTokenIsOneTimeAndNeverReturned(t *testing.T) {
	repository := &memoryLocalUserRepository{
		users:  map[string]LocalUser{"o11y-admin": localUserFixture(t, "o11y-admin", "initial-password", true)},
		tokens: map[string]memoryPasswordResetToken{},
	}
	auth := useIdentityTestState(t, repository)
	mailer := &capturePasswordRecoveryMailer{available: true, messages: make(chan PasswordResetMessage, 1)}
	passwordRecoveryMailer = mailer

	forgotRequest := httptest.NewRequest(
		http.MethodPost,
		"http://control-plane/api/auth/password/forgot",
		strings.NewReader(`{"usernameOrEmail":"o11y-admin"}`),
	)
	forgotRecorder := httptest.NewRecorder()
	forgotLocalPassword(forgotRecorder, forgotRequest)
	if forgotRecorder.Code != http.StatusAccepted || strings.Contains(forgotRecorder.Body.String(), "token") {
		t.Fatalf("forgot response must be generic and token-free: %d %s", forgotRecorder.Code, forgotRecorder.Body.String())
	}

	var message PasswordResetMessage
	select {
	case message = <-mailer.messages:
	case <-time.After(time.Second):
		t.Fatal("expected password reset email")
	}
	if message.Token == "" || !strings.Contains(message.ResetURL, "#token=") {
		t.Fatalf("expected reset message with URL, got %#v", message)
	}
	resetBody := `{"token":"` + message.Token + `","newPassword":"new-secure-password"}`
	resetRecorder := httptest.NewRecorder()
	resetLocalPassword(resetRecorder, httptest.NewRequest(http.MethodPost, "/api/auth/password/reset", strings.NewReader(resetBody)))
	if resetRecorder.Code != http.StatusNoContent {
		t.Fatalf("expected reset 204, got %d: %s", resetRecorder.Code, resetRecorder.Body.String())
	}
	secondRecorder := httptest.NewRecorder()
	resetLocalPassword(secondRecorder, httptest.NewRequest(http.MethodPost, "/api/auth/password/reset", strings.NewReader(resetBody)))
	if secondRecorder.Code != http.StatusBadRequest {
		t.Fatalf("one-time token must be rejected on reuse, got %d", secondRecorder.Code)
	}
	if _, _, valid := auth.login("o11y-admin", "new-secure-password"); !valid {
		t.Fatal("reset password must authenticate")
	}
}

func TestForgotPasswordDoesNotEnumerateUsers(t *testing.T) {
	repository := &memoryLocalUserRepository{
		users:  map[string]LocalUser{"o11y-admin": localUserFixture(t, "o11y-admin", "initial-password", true)},
		tokens: map[string]memoryPasswordResetToken{},
	}
	useIdentityTestState(t, repository)
	passwordRecoveryMailer = &capturePasswordRecoveryMailer{
		available: true,
		messages:  make(chan PasswordResetMessage, 1),
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/password/forgot",
		strings.NewReader(`{"usernameOrEmail":"missing-user"}`),
	)
	recorder := httptest.NewRecorder()
	forgotLocalPassword(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("unknown user must receive generic 202, got %d", recorder.Code)
	}
	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response["message"] == "" {
		t.Fatalf("expected generic JSON response, got %s", recorder.Body.String())
	}
}

func TestRootUserCannotBeDeactivatedOrLoseAdminRole(t *testing.T) {
	root := localUserFixture(t, "o11y-admin", "initial-password", true)
	repository := &memoryLocalUserRepository{
		users:  map[string]LocalUser{root.Username: root},
		tokens: map[string]memoryPasswordResetToken{},
	}
	useIdentityTestState(t, repository)
	if err := repository.deactivateLocalUser(context.Background(), root.Username); !errors.Is(err, errRootUserProtected) {
		t.Fatalf("root deactivation must be rejected, got %v", err)
	}
	root.Roles = []string{"viewer"}
	if _, err := repository.updateLocalUser(context.Background(), root); !errors.Is(err, errRootUserProtected) {
		t.Fatalf("root role degradation must be rejected, got %v", err)
	}
}

func TestSecurityAdminCannotEscalateRolesOrManageRootAccount(t *testing.T) {
	root := localUserFixture(t, "o11y-admin", "root-password", true)
	repository := &memoryLocalUserRepository{
		users:  map[string]LocalUser{root.Username: root},
		tokens: map[string]memoryPasswordResetToken{},
	}
	useIdentityTestState(t, repository)
	securityAdmin := Identity{
		Username: "security", Provider: "local", Roles: []string{"security-admin"},
	}
	securityAdmin.Permissions = permissionsForRoles(securityAdmin.Roles)
	if canDelegateRoles(securityAdmin, []string{"admin"}) {
		t.Fatal("security-admin must not be able to grant the unrestricted admin role")
	}
	if canDelegateRoles(securityAdmin, []string{"collector-editor"}) {
		t.Fatal("security-admin must not grant permissions it does not possess")
	}
	if !canDelegateRoles(securityAdmin, []string{"viewer", "security-admin"}) {
		t.Fatal("security-admin must be able to delegate roles within its own permissions")
	}
	rootIdentity := identityFromLocalUser(root)

	updateRequest := httptest.NewRequest(
		http.MethodPut,
		"/api/auth/users/o11y-admin",
		strings.NewReader(`{"firstName":"Captured","lastName":"Root","email":"attacker@example.test","roles":["admin"],"active":true}`),
	)
	updateRequest.SetPathValue("username", root.Username)
	updateRequest = updateRequest.WithContext(context.WithValue(
		updateRequest.Context(), authContextKey{}, rootIdentity,
	))
	updateResponse := httptest.NewRecorder()
	updateLocalUserHandler(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusConflict {
		t.Fatalf("root administrative update must be rejected, got %d", updateResponse.Code)
	}

	resetRequest := httptest.NewRequest(
		http.MethodPost, "/api/auth/users/o11y-admin/password-reset", nil,
	)
	resetRequest.SetPathValue("username", root.Username)
	resetRequest = resetRequest.WithContext(context.WithValue(
		resetRequest.Context(), authContextKey{}, rootIdentity,
	))
	resetResponse := httptest.NewRecorder()
	adminPasswordReset(resetResponse, resetRequest)
	if resetResponse.Code != http.StatusConflict {
		t.Fatalf("root administrative recovery must be rejected, got %d", resetResponse.Code)
	}
}

func TestAdministrativeEmailChangeRevokesExistingResetTokens(t *testing.T) {
	user := localUserFixture(t, "ana", "initial-password", false)
	repository := &memoryLocalUserRepository{
		users:  map[string]LocalUser{user.Username: user},
		tokens: map[string]memoryPasswordResetToken{},
	}
	const resetToken = "reset-token-issued-before-admin-email-change"
	if _, err := repository.createPasswordResetToken(
		context.Background(), user, resetToken,
		time.Now().Add(15*time.Minute), "security-admin",
	); err != nil {
		t.Fatal(err)
	}
	user.Email = "new-address@example.test"
	if _, err := repository.updateLocalUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.consumePasswordResetToken(
		context.Background(), resetToken, "unused-hash",
	); !errors.Is(err, errPasswordResetInvalid) {
		t.Fatalf("administrative email change must revoke old reset links, got %v", err)
	}
}

func TestResetTokenCannotReviveAfterDeactivateAndReactivate(t *testing.T) {
	user := localUserFixture(t, "ana", "initial-password", false)
	user.Roles = []string{"viewer"}
	repository := &memoryLocalUserRepository{
		users:  map[string]LocalUser{user.Username: user},
		tokens: map[string]memoryPasswordResetToken{},
	}
	const resetToken = "reset-token-issued-before-deactivation"
	if _, err := repository.createPasswordResetToken(
		context.Background(), user, resetToken,
		time.Now().Add(15*time.Minute), "admin",
	); err != nil {
		t.Fatal(err)
	}
	if err := repository.deactivateLocalUser(context.Background(), user.Username); err != nil {
		t.Fatal(err)
	}
	reactivated, err := repository.localUser(context.Background(), user.Username)
	if err != nil {
		t.Fatal(err)
	}
	reactivated.Active = true
	if _, err := repository.updateLocalUser(context.Background(), reactivated); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.consumePasswordResetToken(
		context.Background(), resetToken, "unused-hash",
	); !errors.Is(err, errPasswordResetInvalid) {
		t.Fatalf("old reset token must remain invalid after reactivation, got %v", err)
	}
}

func TestProfileEmailChangeRequiresPasswordAndRevokesResetTokens(t *testing.T) {
	const password = "current-secure-password"
	root := localUserFixture(t, "o11y-admin", password, true)
	repository := &memoryLocalUserRepository{
		users:  map[string]LocalUser{root.Username: root},
		tokens: map[string]memoryPasswordResetToken{},
	}
	auth := useIdentityTestState(t, repository)
	token, _, ok := auth.login(root.Username, password)
	if !ok {
		t.Fatal("expected local login")
	}
	const resetToken = "reset-token-issued-to-previous-email-address"
	if _, err := repository.createPasswordResetToken(
		context.Background(), root, resetToken,
		time.Now().Add(15*time.Minute), "test",
	); err != nil {
		t.Fatal(err)
	}

	withoutPassword := httptest.NewRequest(
		http.MethodPut,
		"/api/auth/profile",
		strings.NewReader(`{"firstName":"Ana","lastName":"Admin","email":"new@example.test"}`),
	)
	withoutPassword.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	denied := httptest.NewRecorder()
	requirePermission("agents.view", updateAuthProfile).ServeHTTP(denied, withoutPassword)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("email change without current password must fail, got %d", denied.Code)
	}

	withPassword := httptest.NewRequest(
		http.MethodPut,
		"/api/auth/profile",
		strings.NewReader(`{"firstName":"Ana","lastName":"Admin","email":"new@example.test","currentPassword":"current-secure-password"}`),
	)
	withPassword.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	updated := httptest.NewRecorder()
	requirePermission("agents.view", updateAuthProfile).ServeHTTP(updated, withPassword)
	if updated.Code != http.StatusOK {
		t.Fatalf("email change with password must succeed, got %d: %s", updated.Code, updated.Body.String())
	}
	if _, err := repository.consumePasswordResetToken(
		context.Background(), resetToken, "unused-hash",
	); !errors.Is(err, errPasswordResetInvalid) {
		t.Fatalf("email change must revoke old reset links, got %v", err)
	}
}

func TestStaleProfileUpdateCannotRestoreRolesOrActiveState(t *testing.T) {
	root := localUserFixture(t, "o11y-admin", "current-secure-password", true)
	repository := &memoryLocalUserRepository{
		users:  map[string]LocalUser{root.Username: root},
		tokens: map[string]memoryPasswordResetToken{},
	}
	stale, err := repository.localUser(context.Background(), root.Username)
	if err != nil {
		t.Fatal(err)
	}
	current := stale
	current.Roles = []string{"admin", "security-admin"}
	if _, err := repository.updateLocalUser(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	stale.FirstName = "Stale"
	if _, err := repository.updateLocalUserProfile(context.Background(), stale); !errors.Is(err, errLocalUserConflict) {
		t.Fatalf("stale profile write must be rejected, got %v", err)
	}
	after, err := repository.localUser(context.Background(), root.Username)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(after.Roles, "security-admin") || after.FirstName == "Stale" {
		t.Fatalf("stale profile restored protected state: %#v", after)
	}
}

func TestStaleAdministrativeUserFormReturnsConflict(t *testing.T) {
	root := localUserFixture(t, "o11y-admin", "root-password", true)
	target := localUserFixture(t, "managed-user", "managed-password", false)
	target.Roles = []string{"viewer"}
	target.AuthVersion = 2
	repository := &memoryLocalUserRepository{
		users:  map[string]LocalUser{root.Username: root, target.Username: target},
		tokens: map[string]memoryPasswordResetToken{},
	}
	useIdentityTestState(t, repository)
	request := httptest.NewRequest(
		http.MethodPut,
		"/api/auth/users/managed-user",
		strings.NewReader(`{"firstName":"Stale","lastName":"Editor","email":"stale@example.test","roles":["viewer"],"active":true,"revision":1}`),
	)
	request.SetPathValue("username", target.Username)
	request = request.WithContext(context.WithValue(
		request.Context(), authContextKey{}, identityFromLocalUser(root),
	))
	response := httptest.NewRecorder()
	updateLocalUserHandler(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale user form must receive 409, got %d: %s", response.Code, response.Body.String())
	}
	after, err := repository.localUser(context.Background(), target.Username)
	if err != nil {
		t.Fatal(err)
	}
	if after.FirstName == "Stale" || after.Email == "stale@example.test" {
		t.Fatalf("stale payload overwrote current identity state: %#v", after)
	}
}

func TestLocalUserJSONNeverContainsPasswordMaterial(t *testing.T) {
	encoded, err := json.Marshal(localUserFixture(t, "o11y-admin", "initial-password", true))
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "password") || strings.Contains(text, "authVersion") {
		t.Fatalf("local user JSON leaked security material: %s", text)
	}
}

func TestLocalUserAdministrationRequiresAuthAdmin(t *testing.T) {
	viewer := localUserFixture(t, "local-viewer", "initial-password", false)
	viewer.Roles = []string{"viewer"}
	repository := &memoryLocalUserRepository{
		users:  map[string]LocalUser{viewer.Username: viewer},
		tokens: map[string]memoryPasswordResetToken{},
	}
	auth := useIdentityTestState(t, repository)
	token := auth.issueSession(identityFromLocalUser(viewer))
	request := httptest.NewRequest(http.MethodGet, "/api/auth/users", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	recorder := httptest.NewRecorder()
	requirePermission("auth.admin", listLocalUsers).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("viewer must not list local users, got %d", recorder.Code)
	}

	profileRequest := httptest.NewRequest(http.MethodGet, "/api/auth/profile", nil)
	profileRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	profileRecorder := httptest.NewRecorder()
	requirePermission("agents.view", authProfile).ServeHTTP(profileRecorder, profileRequest)
	if profileRecorder.Code != http.StatusOK || strings.Contains(profileRecorder.Body.String(), "password") {
		t.Fatalf("viewer must read only its safe profile: %d %s", profileRecorder.Code, profileRecorder.Body.String())
	}
}
