// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestValidateNoSecretShapesPositiveCorpus(t *testing.T) {
	t.Parallel()

	tests := positiveSecretShapeCorpus()
	if len(tests) < 40 {
		t.Fatalf("positive corpus has %d cases; want at least 40", len(tests))
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			document := map[string]any{"spec": map[string]any{test.key: test.value}}
			err := ValidateNoSecretShapes(document)
			if !errors.Is(err, ErrSecretShapedValue) {
				t.Fatalf("ValidateNoSecretShapes() error = %v; want ErrSecretShapedValue", err)
			}
			if strings.Contains(err.Error(), fmt.Sprint(test.value)) {
				t.Fatal("error rendered the offending value")
			}
		})
	}
}

func TestValidateNoSecretShapesNegativeCorpus(t *testing.T) {
	t.Parallel()

	tests := negativeSecretShapeCorpus()
	if len(tests) < 40 {
		t.Fatalf("negative corpus has %d cases; want at least 40", len(tests))
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			document := map[string]any{"spec": map[string]any{test.key: test.value}}
			if err := ValidateNoSecretShapes(document); err != nil {
				t.Fatalf("ValidateNoSecretShapes() unexpected error: %v", err)
			}
		})
	}
}

func TestValidateNoSecretShapesReportsSortedPathsWithoutValues(t *testing.T) {
	t.Parallel()

	marker := "ya29.ThisMustNeverAppearInTheError"
	document := map[string]any{
		"z":           "mongodb://operator:another-marker@example.invalid/admin",
		"a":           []any{map[string]any{"oauth": marker}},
		"private_key": "not echoed",
	}

	err := ValidateNoSecretShapes(document)
	var shapeErr *SecretShapeError
	if !errors.As(err, &shapeErr) {
		t.Fatalf("ValidateNoSecretShapes() error = %v; want *SecretShapeError", err)
	}
	want := []string{"/a/0/oauth", "/private_key", "/z"}
	if got := shapeErr.Paths(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Paths() = %v; want %v", got, want)
	}
	if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "another-marker") {
		t.Fatal("error rendered an offending value")
	}

	paths := shapeErr.Paths()
	paths[0] = "/mutated"
	if got := shapeErr.Paths()[0]; got != want[0] {
		t.Fatalf("Paths() exposed mutable state: got %q; want %q", got, want[0])
	}
}

func TestValidateNoSecretShapesRedactsUnsafeMapKeyInPath(t *testing.T) {
	t.Parallel()

	secretKey := "AIza" + strings.Repeat("0", 35)
	err := ValidateNoSecretShapes(map[string]any{secretKey: "mongodb://user:password@example.invalid/admin"})
	if !errors.Is(err, ErrSecretShapedValue) {
		t.Fatalf("ValidateNoSecretShapes() error = %v; want ErrSecretShapedValue", err)
	}
	if strings.Contains(err.Error(), secretKey) {
		t.Fatal("error rendered a credential-shaped map key")
	}
	if !strings.Contains(err.Error(), "/redacted-key-") {
		t.Fatalf("error = %q; want redacted key path", err)
	}
}

func TestValidateNoSecretShapesRejectsUnsupportedValue(t *testing.T) {
	t.Parallel()

	err := ValidateNoSecretShapes(map[string]any{"spec": map[int]string{1: "value"}})
	if !errors.Is(err, ErrUnsupportedManifestValue) {
		t.Fatalf("ValidateNoSecretShapes() error = %v; want ErrUnsupportedManifestValue", err)
	}
	if got := err.Error(); got != "unsupported manifest value at /spec" {
		t.Fatalf("error = %q; want path-only unsupported value error", got)
	}
}

func TestValidateNoSecretShapesPreservesSensitiveArrayContext(t *testing.T) {
	t.Parallel()

	value := "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo012345="
	err := ValidateNoSecretShapes(map[string]any{"tokens": []any{"runtime-reference", value}})
	if !errors.Is(err, ErrSecretShapedValue) {
		t.Fatalf("ValidateNoSecretShapes() error = %v; want ErrSecretShapedValue", err)
	}
	if got := err.Error(); got != "secret-shaped value at /tokens/1" {
		t.Fatalf("error = %q; want array element path", got)
	}
	if strings.Contains(err.Error(), value) {
		t.Fatal("error rendered the offending array value")
	}
}

type secretShapeCase struct {
	name  string
	key   string
	value any
}

func positiveSecretShapeCorpus() []secretShapeCase {
	cases := make([]secretShapeCase, 0, 46)

	for index, uri := range []string{
		"mongodb://user:password@example.invalid/admin",
		"mongodb+srv://user:password@example.invalid/admin",
		"prefix mongodb://user:p%40ss@example.invalid/db suffix",
		"MONGODB://user:password@example.invalid/admin",
		"mongodb://user-name:password@example.invalid/admin",
		"mongodb://user:pass:word@example.invalid/admin",
		"mongodb+srv://user.name:password@example.invalid/db?retryWrites=true",
		"mongodb://:password@example.invalid/admin",
	} {
		cases = append(cases, secretShapeCase{fmt.Sprintf("mongodb-uri-%02d", index), "endpoint", uri})
	}

	for index, label := range []string{"", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED ", "DSA "} {
		value := "-----BEGIN " + label + "PRIVATE KEY-----\nsynthetic\n-----END " + label + "PRIVATE KEY-----"
		cases = append(cases, secretShapeCase{fmt.Sprintf("private-key-%02d", index), "certificate", value})
	}

	for index := range 6 {
		value := fmt.Sprintf("AIza%035d", index)
		cases = append(cases, secretShapeCase{fmt.Sprintf("google-api-key-%02d", index), "provider", value})
	}

	for index := range 6 {
		value := fmt.Sprintf("ya29.synthetic_oauth_token_%02d", index)
		cases = append(cases, secretShapeCase{fmt.Sprintf("google-oauth-%02d", index), "provider", value})
	}

	for index, key := range []string{"private_key", "PRIVATE_KEY", "Private_Key", "PrIvAtE_kEy", "private_Key", "PRIVATE_key"} {
		cases = append(cases, secretShapeCase{fmt.Sprintf("service-account-field-%02d", index), key, "short"})
	}

	for index, key := range []string{
		"password", "dbPassword", "secret", "clientSecret", "token",
		"accessToken", "apiKey", "keyMaterial", "credential", "credentialsRef",
	} {
		value := fmt.Sprintf("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo%05d=", index)
		cases = append(cases, secretShapeCase{fmt.Sprintf("sensitive-base64-%02d", index), key, value})
	}

	return cases
}

func negativeSecretShapeCorpus() []secretShapeCase {
	return []secretShapeCase{
		{name: "mongodb-no-userinfo", key: "endpoint", value: "mongodb://example.invalid/admin"},
		{name: "mongodb-no-password", key: "endpoint", value: "mongodb://user@example.invalid/admin"},
		{name: "mongodb-env-reference", key: "endpoint", value: "${MONGODB_URI}"},
		{name: "mongodb-secret-manager-reference", key: "secretRef", value: "projects/example/secrets/database-uri"},
		{name: "mongodb-host-list", key: "hosts", value: "db-1.invalid:27017,db-2.invalid:27017"},
		{name: "mongodb-redacted-password", key: "endpoint", value: "mongodb://user:[redacted]"},
		{name: "https-userinfo", key: "endpoint", value: "https://user:password@example.invalid"},
		{name: "mongodb-label", key: "description", value: "mongodb+srv is supported"},
		{name: "public-key-pem", key: "certificate", value: "-----BEGIN PUBLIC KEY-----"},
		{name: "certificate-pem", key: "certificate", value: "-----BEGIN CERTIFICATE-----"},
		{name: "certificate-request", key: "certificate", value: "-----BEGIN CERTIFICATE REQUEST-----"},
		{name: "private-word", key: "description", value: "PRIVATE KEY rotation is required"},
		{name: "pem-reference", key: "caFile", value: "/etc/ctrldb/ca.pem"},
		{name: "secret-manager-ca-reference", key: "caBundleSecretRef", value: "projects/example/secrets/ca-bundle"},
		{name: "api-key-short", key: "provider", value: "AIza_short"},
		{name: "api-key-interrupted", key: "provider", value: "AIza012345678901234567.89012345678901234"},
		{name: "api-key-bad-character", key: "provider", value: "AIza0123456789012345678901234567890123!"},
		{name: "api-key-word", key: "description", value: "AIza credentials are forbidden"},
		{name: "api-key-prefix-only", key: "provider", value: "AIza"},
		{name: "api-key-reference", key: "secretRef", value: "projects/example/secrets/google-api-key"},
		{name: "oauth-prefix-only", key: "provider", value: "ya29."},
		{name: "oauth-wrong-prefix", key: "provider", value: "ya28.synthetic"},
		{name: "oauth-invalid-first-character", key: "provider", value: "ya29.!synthetic"},
		{name: "oauth-description", key: "description", value: "OAuth token is obtained at runtime"},
		{name: "oauth-secret-reference", key: "secretRef", value: "projects/example/secrets/oauth-token"},
		{name: "oauth-null", key: "oauth", value: nil},
		{name: "private-key-reference-field", key: "privateKeyRef", value: "projects/example/secrets/key"},
		{name: "private-key-file-field", key: "privateKeyFile", value: "/etc/ctrldb/key.pem"},
		{name: "public-key-field", key: "publicKey", value: "ssh-ed25519 synthetic"},
		{name: "tag-key-field", key: "tagKey", value: "tagKeys/123456"},
		{name: "key-short-base64", key: "apiKey", value: "QUJDRA=="},
		{name: "password-placeholder", key: "passwordRef", value: "<secret-manager-reference>"},
		{name: "secret-reference", key: "secretRef", value: "projects/demo-project/secrets/app-database-url"},
		{name: "token-reference", key: "tokenRef", value: "projects/demo-project/secrets/provider-token"},
		{name: "credential-reference", key: "credentialRef", value: "projects/demo-project/secrets/credential"},
		{name: "key-non-base64", key: "keyMaterial", value: "synthetic-value-with-hyphens-that-is-not-base64"},
		{name: "long-benign-description", key: "description", value: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"},
		{name: "long-resource-name", key: "resource", value: "ctrldb-production-resource-with-a-long-but-benign-name"},
		{name: "long-sha256", key: "imageDigest", value: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{name: "long-domain", key: "domain", value: "mongodb-production.internal.example.invalid"},
		{name: "boolean", key: "tokenEnabled", value: true},
		{name: "number", key: "keyRotationDays", value: float64(90)},
		{name: "empty", key: "clientSecret", value: ""},
		{name: "short-alphanumeric", key: "credential", value: "runtime-reference"},
	}
}
