// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/redact"
)

func TestSanitizeKnownSecretShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "mongodb userinfo and query password",
			raw:  "connect mongodb://alice:SECRET_MARKER_URI@db.example/admin?password=SECRET_MARKER_QUERY&authSource=admin",
			want: "connect mongodb://[redacted]@db.example/admin?password=[redacted]&authSource=admin",
		},
		{
			name: "mongodb srv auth mechanism properties",
			raw:  "mongodb+srv://db.example/app?authMechanismProperties=SECRET_MARKER_AUTH&retryWrites=true",
			want: "mongodb+srv://db.example/app?authMechanismProperties=[redacted]&retryWrites=true",
		},
		{
			name: "bearer token",
			raw:  "Authorization: Bearer SECRET_MARKER_BEARER_123456789",
			want: "Authorization: [redacted-token]",
		},
		{
			name: "google oauth token",
			raw:  "request failed for ya29.SECRET_MARKER_OAUTH_123",
			want: "request failed for [redacted-token]",
		},
		{
			name: "google refresh token",
			raw:  "refresh=1//SECRET_MARKER_REFRESH_123456789",
			want: "refresh=[redacted-token]",
		},
		{
			name: "signed URL",
			raw:  "GET https://storage.example/object?X-Goog-Credential=SECRET_MARKER_SIGNED&X-Goog-Signature=abc",
			want: "GET https://storage.example/object?[redacted]",
		},
		{
			name: "PEM block",
			raw:  "before\n-----BEGIN PRIVATE KEY-----\nSECRET_MARKER_PEM\n-----END PRIVATE KEY-----\nafter",
			want: "before\n[redacted-pem]\nafter",
		},
		{
			name: "environment value",
			raw:  "DATABASE_PASSWORD=SECRET_MARKER_ENV",
			want: "DATABASE_PASSWORD=[redacted]",
		},
		{
			name: "inline key-value secret",
			raw:  `request failed: password="SECRET_MARKER_INLINE value" status=unauthorized`,
			want: "request failed: password=[redacted] status=unauthorized",
		},
		{
			name: "resource reference remains reviewable",
			raw:  "secretRef: projects/example-project/secrets/database-uri",
			want: "secretRef: projects/example-project/secrets/database-uri",
		},
		{
			name: "invalid resource reference is redacted",
			raw:  "secretRef: mongodb://user:SECRET_MARKER_REF@host/db",
			want: "secretRef: [redacted]",
		},
		{
			name: "terminal escapes and controls",
			raw:  "safe\x1b[31mred\x1b[0m\x1b\rSECRET_MARKER_CONTROL",
			want: "safered\\x0dSECRET_MARKER_CONTROL",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := redact.Sanitize(test.raw).String()
			if got != test.want {
				t.Fatalf("Sanitize() = %q, want %q", got, test.want)
			}
			if strings.Contains(got, "SECRET_MARKER_") && !strings.Contains(test.want, "SECRET_MARKER_") {
				t.Fatalf("Sanitize() leaked a marker: %q", got)
			}
		})
	}
}

func TestSanitizeEvidencePseudonymizesHumanEmailOnlyInEvidence(t *testing.T) {
	t.Parallel()

	raw := "operator person.name+prod@example.com"
	if got := redact.Sanitize(raw).String(); got != raw {
		t.Fatalf("Sanitize() = %q, want attributable audit text", got)
	}
	if got := redact.SanitizeEvidence(raw).String(); got != "operator p…@example.com" {
		t.Fatalf("SanitizeEvidence() = %q, want pseudonymized address", got)
	}
}

func TestTextJSONSerializationContainsOnlySanitizedText(t *testing.T) {
	t.Parallel()

	text := redact.Sanitize("token=SECRET_MARKER_JSON_TEXT")
	encoded, err := json.Marshal(text)
	if err != nil {
		t.Fatalf("json.Marshal() returned an error: %v", err)
	}
	if string(encoded) != `"token=[redacted]"` {
		t.Fatalf("json.Marshal() = %s, want sanitized text", encoded)
	}
}

func FuzzSanitizeNeverEmitsTerminalEscape(f *testing.F) {
	f.Add("plain text")
	f.Add("\x1b[2Jspoof")
	f.Add("password=SECRET_MARKER_FUZZ")
	f.Add("mongodb://user:pass@host/db")

	f.Fuzz(func(t *testing.T, raw string) {
		output := redact.Sanitize(raw).String()
		if strings.ContainsRune(output, '\x1b') {
			t.Fatalf("Sanitize() retained an escape byte: %q", output)
		}
	})
}
