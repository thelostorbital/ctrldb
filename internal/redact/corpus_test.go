// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/redact"
)

const minimumRedactionCorpusSize = 200

type corpusCase struct {
	name     string
	category string
	marker   string
	input    string
	want     string
	sanitize func(string) string
}

func TestRedactionCorpus(t *testing.T) {
	t.Parallel()

	cases := redactionCorpus()
	if len(cases) < minimumRedactionCorpusSize {
		t.Fatalf("redaction corpus has %d cases, want at least %d", len(cases), minimumRedactionCorpusSize)
	}

	requiredCategories := map[string]bool{
		"api-error":        false,
		"compose":          false,
		"evidence":         false,
		"gcloud":           false,
		"json":             false,
		"mongodb-uri":      false,
		"mongosh":          false,
		"oauth":            false,
		"pbm":              false,
		"pem":              false,
		"refresh-token":    false,
		"service-account":  false,
		"signed-url":       false,
		"systemd":          false,
		"terminal-control": false,
	}

	seenMarkers := make(map[string]struct{}, len(cases))
	for _, test := range cases {
		if test.marker == "" || !strings.Contains(test.input, test.marker) {
			t.Fatalf("input %q does not contain planted marker %q", test.name, test.marker)
		}
		if _, duplicate := seenMarkers[test.marker]; duplicate {
			t.Fatalf("marker %q is not unique", test.marker)
		}
		seenMarkers[test.marker] = struct{}{}

		if _, required := requiredCategories[test.category]; !required {
			t.Fatalf("corpus case %q has unknown category %q", test.name, test.category)
		}
		requiredCategories[test.category] = true

		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := test.sanitize(test.input)
			if got != test.want {
				t.Fatalf("sanitized output = %q, want %q", got, test.want)
			}
			if strings.Contains(got, "SECRET_MARKER_") || strings.Contains(got, test.marker) {
				t.Fatalf("sanitized output leaked marker: %q", got)
			}
		})
	}

	for category, covered := range requiredCategories {
		if !covered {
			t.Errorf("redaction corpus does not cover category %q", category)
		}
	}
}

func redactionCorpus() []corpusCase {
	const variations = 20

	cases := make([]corpusCase, 0, variations*15)
	sequence := 0
	for variation := range variations {
		add := func(category, input, want string, sanitize func(string) string) {
			sequence++
			marker := fmt.Sprintf("SECRET_MARKER_%03d_%s", sequence, strings.Repeat("x", 24))
			formattedWant := want
			if strings.Contains(want, "%") {
				formattedWant = fmt.Sprintf(want, variation)
			}
			cases = append(cases, corpusCase{
				name:     fmt.Sprintf("%s-%02d", category, variation),
				category: category,
				marker:   marker,
				input:    fmt.Sprintf(input, marker, variation),
				want:     formattedWant,
				sanitize: sanitize,
			})
		}

		add(
			"gcloud",
			"gcloud error: access_token=%s request=req-%02d",
			"gcloud error: access_token=[redacted] request=req-%02d",
			sanitizeText,
		)
		add(
			"mongosh",
			`mongosh error: password="%s" user=fixture-%02d`,
			"mongosh error: password=[redacted] user=fixture-%02d",
			sanitizeText,
		)
		add(
			"pbm",
			"pbm status: storageCredential=%s backup=fixture-%02d",
			"pbm status: storageCredential=[redacted] backup=fixture-%02d",
			sanitizeText,
		)
		add(
			"compose",
			"compose: DATABASE_PASSWORD=%s service=mongod-%02d",
			"compose: DATABASE_PASSWORD=[redacted] service=mongod-%02d",
			sanitizeText,
		)
		add(
			"systemd",
			"ctrldb-agent[%[2]02d]: Authorization: Bearer %[1]s",
			"ctrldb-agent[%[1]02d]: Authorization: [redacted-token]",
			sanitizeText,
		)
		add(
			"api-error",
			"api error: session=%s status=%02d",
			"api error: session=[redacted] status=%02d",
			sanitizeText,
		)
		add(
			"signed-url",
			"GET https://storage.example.test/object-%[2]02d?X-Goog-Signature=%[1]s&X-Goog-Expires=60",
			"GET https://storage.example.test/object-%[1]02d?[redacted]",
			sanitizeText,
		)
		add(
			"mongodb-uri",
			"dial mongodb://fixture:%[1]s@db-%[2]02d.example.test/admin?authSource=admin",
			"dial mongodb://[redacted]@db-%[1]02d.example.test/admin?authSource=admin",
			sanitizeText,
		)
		add(
			"pem",
			"certificate-%[2]02d\n-----BEGIN PRIVATE KEY-----\n%[1]s\n-----END PRIVATE KEY-----",
			"certificate-%[1]02d\n[redacted-pem]",
			sanitizeText,
		)
		add(
			"oauth",
			"gcloud stderr: token ya29.%[1]s rejected for request-%[2]02d",
			"gcloud stderr: token [redacted-token] rejected for request-%[1]02d",
			sanitizeText,
		)
		add(
			"refresh-token",
			"refresh token 1//%s request-%02d",
			"refresh token [redacted-token] request-%02d",
			sanitizeText,
		)
		add(
			"terminal-control",
			"event-%[2]02d \x1b[31mpassword=%[1]s\x1b[0m\r",
			"event-%[1]02d password=[redacted]\\x0d",
			sanitizeText,
		)
		add(
			"json",
			`{"tool":"gcloud","password":"%[1]s","attempt":%[2]d}`,
			`{"attempt":%[1]d,"password":"[redacted]","tool":"gcloud"}`,
			sanitizeJSON,
		)
		add(
			"service-account",
			`{"payload":{"type":"service_account","private_key":"%[1]s","client_email":"fixture-%[2]02d@example.test"},"attempt":%[2]d}`,
			`{"attempt":%[1]d,"payload":"[redacted-sa-key]"}`,
			sanitizeJSON,
		)
		add(
			"evidence",
			"operator %s-%02d@example.test",
			"operator S…@example.test",
			sanitizeEvidence,
		)
	}

	return cases
}

func sanitizeText(input string) string {
	return redact.Sanitize(input).String()
}

func sanitizeEvidence(input string) string {
	return redact.SanitizeEvidence(input).String()
}

func sanitizeJSON(input string) string {
	return redact.SanitizeJSON([]byte(input)).String()
}
