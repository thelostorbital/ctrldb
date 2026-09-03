// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/redact"
)

func TestSanitizeJSONRedactsNestedSecrets(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"name":"database","password":"SECRET_MARKER_PASSWORD","nested":{"accessToken":"SECRET_MARKER_TOKEN","secretRef":"projects/example-project/secrets/database-uri","sessionId":"session-123"},"items":[{"api_key":"SECRET_MARKER_API_KEY"}]}`)

	got := redact.SanitizeJSON(raw).String()
	want := `{"items":[{"api_key":"[redacted]"}],"name":"database","nested":{"accessToken":"[redacted]","secretRef":"projects/example-project/secrets/database-uri","sessionId":"session-123"},"password":"[redacted]"}`
	if got != want {
		t.Fatalf("SanitizeJSON() = %s, want %s", got, want)
	}
	if strings.Contains(got, "SECRET_MARKER_") {
		t.Fatalf("SanitizeJSON() leaked a marker: %s", got)
	}
}

func TestSanitizeJSONRedactsEntireServiceAccountKey(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"outer":{"type":"service_account","client_email":"fake@example.com","private_key":"SECRET_MARKER_PRIVATE_KEY"}}`)
	want := `{"outer":"[redacted-sa-key]"}`

	if got := redact.SanitizeJSON(raw).String(); got != want {
		t.Fatalf("SanitizeJSON() = %s, want %s", got, want)
	}
}

func TestSanitizeJSONRejectsUnsafeReferenceExemption(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"secretRef":"SECRET_MARKER_NOT_A_RESOURCE!","tokenNames":["valid-name","invalid value"]}`)
	want := `{"secretRef":"[redacted]","tokenNames":"[redacted]"}`

	if got := redact.SanitizeJSON(raw).String(); got != want {
		t.Fatalf("SanitizeJSON() = %s, want %s", got, want)
	}
}

func TestSanitizeJSONFailsClosedOnInvalidOrTrailingInput(t *testing.T) {
	t.Parallel()

	inputs := [][]byte{
		[]byte(`{"password":"SECRET_MARKER_BROKEN"`),
		[]byte(`{"ok":true} {"password":"SECRET_MARKER_TRAILING"}`),
	}

	for _, raw := range inputs {
		digest := sha256.Sum256(raw)
		want := "[unparseable-json sha256=" + hex.EncodeToString(digest[:])
		got := redact.SanitizeJSON(raw).String()
		if !strings.HasPrefix(got, want) {
			t.Errorf("SanitizeJSON() = %q, want digest prefix %q", got, want)
		}
		if strings.Contains(got, "SECRET_MARKER_") {
			t.Errorf("SanitizeJSON() leaked invalid input: %q", got)
		}
	}
}
