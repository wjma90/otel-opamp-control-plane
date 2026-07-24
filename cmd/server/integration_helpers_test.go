//go:build integration

package main

import (
	"os"
	"strings"
	"testing"
)

func integrationDatabaseURL(t *testing.T) string {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("O11Y_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("PostgreSQL integration test skipped: set O11Y_TEST_DATABASE_URL")
	}
	return databaseURL
}
