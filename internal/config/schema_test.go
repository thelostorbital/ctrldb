// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

const manifestFixturePath = "testdata/manifest-v1alpha1.yaml"

func TestManifestSchemaCompiles(t *testing.T) {
	t.Parallel()

	schema, err := compiledManifestSchema()
	if err != nil {
		t.Fatalf("compiledManifestSchema() unexpected error: %v", err)
	}
	if schema == nil {
		t.Fatal("compiledManifestSchema() returned nil schema")
	}
}

func TestManifestSchemaHasNoDuplicateKeys(t *testing.T) {
	t.Parallel()

	var schema map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(manifestSchemaJSON), yaml.Strict())
	if err := decoder.Decode(&schema); err != nil {
		t.Fatalf("embedded schema contains a duplicate key or invalid JSON: %v", err)
	}
}

func TestDecodeManifestAcceptsCompleteFixture(t *testing.T) {
	t.Parallel()

	document, err := DecodeManifest(readManifestFixture(t))
	if err != nil {
		t.Fatalf("DecodeManifest() unexpected error: %v", err)
	}
	if got := document.Identity().Metadata.Name; got != "staging" {
		t.Fatalf("Identity().Metadata.Name = %q; want staging", got)
	}
}

func TestDecodeManifestRejectsUnknownNestedField(t *testing.T) {
	t.Parallel()

	manifest := manifestFixtureMap(t)
	host := nestedMap(t, manifest, "spec", "host")
	host["unexpectedField"] = true

	_, err := DecodeManifest(marshalManifest(t, manifest))
	assertSchemaViolation(t, err, SchemaViolation{
		Path:    "/spec/host/unexpectedField",
		Keyword: "additionalProperties",
	})
}

func TestSchemaErrorsRedactCredentialShapedPropertyNames(t *testing.T) {
	t.Parallel()

	marker := "ya29.UnknownPropertyMustNotAppear"
	manifest := manifestFixtureMap(t)
	host := nestedMap(t, manifest, "spec", "host")
	host[marker] = true

	_, err := DecodeManifest(marshalManifest(t, manifest))
	if !errors.Is(err, ErrManifestSchemaViolation) {
		t.Fatalf("DecodeManifest() error = %v; want ErrManifestSchemaViolation", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("schema error rendered a credential-shaped property name")
	}
	if !strings.Contains(err.Error(), "/spec/host/redacted-key-") {
		t.Fatalf("schema error = %q; want hashed property path", err)
	}
}

func TestDecodeManifestReportsMissingRequiredProperty(t *testing.T) {
	t.Parallel()

	manifest := manifestFixtureMap(t)
	delete(nestedMap(t, manifest, "spec", "gcp"), "region")

	_, err := DecodeManifest(marshalManifest(t, manifest))
	assertSchemaViolation(t, err, SchemaViolation{
		Path:    "/spec/gcp/region",
		Keyword: "required",
	})
}

func TestSchemaErrorsPreserveArrayIndices(t *testing.T) {
	t.Parallel()

	manifest := manifestFixtureMap(t)
	members := nestedMap(t, manifest, "spec", "host")["members"].([]any)
	members[0].(map[string]any)["ordinal"] = 0

	_, err := DecodeManifest(marshalManifest(t, manifest))
	assertSchemaViolation(t, err, SchemaViolation{
		Path:    "/spec/host/members/0/ordinal",
		Keyword: "minimum",
	})
}

func TestManifestSchemaAssertsFormats(t *testing.T) {
	t.Parallel()

	manifest := manifestFixtureMap(t)
	channels := nestedMap(t, manifest, "spec", "monitoring", "channels")
	channels["email"] = []any{"not-an-email"}

	_, err := DecodeManifest(marshalManifest(t, manifest))
	assertSchemaViolation(t, err, SchemaViolation{
		Path:    "/spec/monitoring/channels/email/0",
		Keyword: "format",
	})
}

func TestSchemaErrorsDoNotRenderRejectedValues(t *testing.T) {
	t.Parallel()

	marker := "INVALID_ENUM_VALUE_MUST_NOT_APPEAR"
	manifest := manifestFixtureMap(t)
	nestedMap(t, manifest, "spec", "gcp", "identity")["mutation"] = marker

	_, err := DecodeManifest(marshalManifest(t, manifest))
	if !errors.Is(err, ErrManifestSchemaViolation) {
		t.Fatalf("DecodeManifest() error = %v; want ErrManifestSchemaViolation", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("schema error rendered the rejected enum value")
	}
	assertManifestSchemaErrorDoesNotRetainRawError(t, err)
}

func TestProductionRequiresImpersonatedMutation(t *testing.T) {
	t.Parallel()

	manifest := manifestFixtureMap(t)
	metadata := nestedMap(t, manifest, "metadata")
	metadata["name"] = "production"
	metadata["class"] = "production"

	_, err := DecodeManifest(marshalManifest(t, manifest))
	assertSchemaViolation(t, err, SchemaViolation{
		Path:    "/spec/gcp/identity/mutation",
		Keyword: "const",
	})

	nestedMap(t, manifest, "spec", "gcp", "identity")["mutation"] = "impersonate"
	nestedMap(t, manifest, "spec", "policy")["dataDestructiveCoolingOff"] = "10m"
	if _, err := DecodeManifest(marshalManifest(t, manifest)); err != nil {
		t.Fatalf("DecodeManifest(production impersonation) unexpected error: %v", err)
	}
}

func TestDecodeManifestIncludesLocalPolicyValidation(t *testing.T) {
	t.Parallel()

	manifest := manifestFixtureMap(t)
	nestedMap(t, manifest, "spec", "pbm", "verification", "network")["vpc"] = "other-vpc"
	encoded := marshalManifest(t, manifest)

	document, err := DecodeManifestEnvelope(encoded)
	if err != nil {
		t.Fatalf("DecodeManifestEnvelope() unexpected error: %v", err)
	}
	if err := ValidateManifestSchema(document); err != nil {
		t.Fatalf("ValidateManifestSchema() unexpected error: %v", err)
	}
	if _, err := DecodeManifest(encoded); !errors.Is(err, ErrManifestPolicyViolation) {
		t.Fatalf("DecodeManifest() error = %v; want ErrManifestPolicyViolation", err)
	}
}

func TestTestIsolationIsLimitedToDisposableManifests(t *testing.T) {
	t.Parallel()

	manifest := manifestFixtureMap(t)
	nestedMap(t, manifest, "spec")["testIsolation"] = validTestIsolation()

	_, err := DecodeManifest(marshalManifest(t, manifest))
	if !errors.Is(err, ErrManifestSchemaViolation) {
		t.Fatalf("DecodeManifest(staging testIsolation) error = %v; want schema violation", err)
	}

	metadata := nestedMap(t, manifest, "metadata")
	metadata["name"] = "disposable-test"
	metadata["class"] = "disposable"
	if _, err := DecodeManifest(marshalManifest(t, manifest)); err != nil {
		t.Fatalf("DecodeManifest(disposable testIsolation) unexpected error: %v", err)
	}
}

func TestSchemaClosesEveryObjectShape(t *testing.T) {
	t.Parallel()

	var schema any
	if err := json.Unmarshal(manifestSchemaJSON, &schema); err != nil {
		t.Fatalf("json.Unmarshal(schema) unexpected error: %v", err)
	}

	var openPaths []string
	walkSchema(schema, "", func(value map[string]any, path string) {
		if value["type"] == "object" {
			additional, ok := value["additionalProperties"]
			if !ok {
				openPaths = append(openPaths, path)
				return
			}
			if allowed, ok := additional.(bool); ok && !allowed {
				return
			}
			if path != "/$defs/secretDiscovery/properties/labels" {
				openPaths = append(openPaths, path)
			}
		}
	})
	if len(openPaths) > 0 {
		t.Fatalf("object schemas without additionalProperties: %v", openPaths)
	}
}

func TestSchemaSpecPropertiesMatchContract(t *testing.T) {
	t.Parallel()

	var schema map[string]any
	if err := json.Unmarshal(manifestSchemaJSON, &schema); err != nil {
		t.Fatalf("json.Unmarshal(schema) unexpected error: %v", err)
	}
	definitions := schema["$defs"].(map[string]any)
	spec := definitions["spec"].(map[string]any)
	properties := spec["properties"].(map[string]any)

	got := make([]string, 0, len(properties))
	for name := range properties {
		got = append(got, name)
	}
	sort.Strings(got)
	want := []string{
		"access", "application", "automations", "capacity", "control", "docs", "failover",
		"gapsAcceptedIn", "gcp", "host", "indexes", "migration", "mongodb", "monitoring",
		"patch", "pbm", "policy", "reconciler", "testIsolation", "topology", "upgrade", "users",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("spec properties = %v; want %v", got, want)
	}
}

func TestValidateManifestSchemaFailsClosedForInvalidDocument(t *testing.T) {
	t.Parallel()

	document := ManifestDocument{normalizedJSON: []byte("not-json")}
	err := ValidateManifestSchema(document)
	if !errors.Is(err, ErrManifestSchemaUnavailable) {
		t.Fatalf("ValidateManifestSchema() error = %v; want ErrManifestSchemaUnavailable", err)
	}
}

func TestManifestSchemaErrorViolationsReturnsCopy(t *testing.T) {
	t.Parallel()

	err := &ManifestSchemaError{violations: []SchemaViolation{{Path: "/spec/gcp", Keyword: "required"}}}
	violations := err.Violations()
	violations[0].Path = "/changed"
	if got := err.Violations()[0].Path; got != "/spec/gcp" {
		t.Fatalf("Violations() exposed mutable state: got %q", got)
	}
}

func readManifestFixture(t *testing.T) []byte {
	t.Helper()

	content, err := os.ReadFile(manifestFixturePath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) unexpected error: %v", manifestFixturePath, err)
	}
	return content
}

func manifestFixtureMap(t *testing.T) map[string]any {
	t.Helper()

	document, err := DecodeManifestEnvelope(readManifestFixture(t))
	if err != nil {
		t.Fatalf("DecodeManifestEnvelope(fixture) unexpected error: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(document.JSON(), &manifest); err != nil {
		t.Fatalf("json.Unmarshal(fixture) unexpected error: %v", err)
	}
	return manifest
}

func nestedMap(t *testing.T, value map[string]any, path ...string) map[string]any {
	t.Helper()

	current := value
	for _, token := range path {
		next, ok := current[token].(map[string]any)
		if !ok {
			t.Fatalf("fixture path %q is not an object", strings.Join(path, "/"))
		}
		current = next
	}
	return current
}

func marshalManifest(t *testing.T, manifest map[string]any) []byte {
	t.Helper()

	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("json.Marshal(manifest) unexpected error: %v", err)
	}
	return content
}

func assertSchemaViolation(t *testing.T, err error, want SchemaViolation) {
	t.Helper()

	if !errors.Is(err, ErrManifestSchemaViolation) {
		t.Fatalf("error = %v; want ErrManifestSchemaViolation", err)
	}
	var schemaErr *ManifestSchemaError
	if !errors.As(err, &schemaErr) {
		t.Fatalf("error type = %T; want *ManifestSchemaError", err)
	}
	for _, got := range schemaErr.Violations() {
		if got == want {
			return
		}
	}
	t.Fatalf("violations = %v; want to contain %v", schemaErr.Violations(), want)
}

func assertManifestSchemaErrorDoesNotRetainRawError(t *testing.T, err error) {
	t.Helper()

	if got := reflect.TypeOf(err).String(); got != "*config.ManifestSchemaError" {
		t.Fatalf("schema error type = %q; want *config.ManifestSchemaError", got)
	}
}

func validTestIsolation() map[string]any {
	return map[string]any{
		"namePrefix":                "ctrldb-test-",
		"labels":                    map[string]any{"managed-by": "ctrldb", "environment": "disposable", "purpose": "test"},
		"operatorServiceAccount":    "ctrldb-test-operator@example-project.iam.gserviceaccount.com",
		"destructiveServiceAccount": "ctrldb-test-destructive@example-project.iam.gserviceaccount.com",
		"network": map[string]any{
			"vpc": "ctrldb-test-vpc", "subnet": "ctrldb-test-subnet", "cidr": "10.40.0.0/24", "nat": "ctrldb-test-nat",
		},
		"ciPrincipal": "principalSet://example-ci",
		"caps": map[string]any{
			"maxMachineType": "e2-medium", "maxDiskGiB": 100, "maxInstances": 3,
			"maxLifetime": "8h", "maxEstimatedUSDPerRun": 25,
		},
		"monitoringTests": "manual-only",
	}
}

func walkSchema(value any, path string, visit func(map[string]any, string)) {
	switch typed := value.(type) {
	case map[string]any:
		visit(typed, rootPath(path))
		for key, child := range typed {
			walkSchema(child, path+"/"+key, visit)
		}
	case []any:
		for index, child := range typed {
			walkSchema(child, path+"/"+fmt.Sprintf("%d", index), visit)
		}
	}
}
