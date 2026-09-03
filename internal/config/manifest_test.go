// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

func TestDecodeManifestEnvelopeYAML(t *testing.T) {
	t.Parallel()

	spec := manifestLines(
		"  gcp:",
		"    project: example-project",
		"  capacity:",
		"    maxDataDiskGiB: 200",
	)
	document, err := DecodeManifestEnvelope([]byte(validManifestYAMLForClass("production", "production", spec)))
	if err != nil {
		t.Fatalf("DecodeManifestEnvelope() unexpected error: %v", err)
	}

	wantIdentity := ManifestIdentity{
		APIVersion: ManifestAPIVersion,
		Kind:       ManifestKind,
		Metadata: ManifestMetadata{
			Name:  "production",
			Class: domain.EnvironmentProduction,
		},
	}
	if got := document.Identity(); got != wantIdentity {
		t.Fatalf("Identity() = %#v; want %#v", got, wantIdentity)
	}

	wantJSON := `{"apiVersion":"ctrldb.ctrlboard.dev/v1alpha1","kind":"MongoEnvironment","metadata":{"class":"production","name":"production"},"spec":{"capacity":{"maxDataDiskGiB":200},"gcp":{"project":"example-project"}}}`
	if got := string(document.JSON()); got != wantJSON {
		t.Fatalf("JSON() = %s; want %s", got, wantJSON)
	}
}

func TestDecodeManifestEnvelopeAcceptsJSON(t *testing.T) {
	t.Parallel()

	input := `{"kind":"MongoEnvironment","metadata":{"class":"staging","name":"stage"},"spec":{},"apiVersion":"ctrldb.ctrlboard.dev/v1alpha1"}`
	document, err := DecodeManifestEnvelope([]byte(input))
	if err != nil {
		t.Fatalf("DecodeManifestEnvelope() unexpected error: %v", err)
	}
	if got := document.Identity().Metadata.Class; got != domain.EnvironmentStaging {
		t.Fatalf("Identity().Metadata.Class = %q; want %q", got, domain.EnvironmentStaging)
	}
}

func TestDecodeManifestEnvelopeResolvesAnchorsDeterministically(t *testing.T) {
	t.Parallel()

	anchored := validManifestYAML("stage", manifestLines(
		"  defaults: &capacity",
		"    maxDataDiskGiB: 200",
		"    maxInstances: 2",
		"  capacity: *capacity",
	))
	expanded := validManifestYAML("stage", manifestLines(
		"  defaults:",
		"    maxDataDiskGiB: 200",
		"    maxInstances: 2",
		"  capacity:",
		"    maxDataDiskGiB: 200",
		"    maxInstances: 2",
	))

	anchoredDocument, err := DecodeManifestEnvelope([]byte(anchored))
	if err != nil {
		t.Fatalf("DecodeManifestEnvelope(anchored) unexpected error: %v", err)
	}
	expandedDocument, err := DecodeManifestEnvelope([]byte(expanded))
	if err != nil {
		t.Fatalf("DecodeManifestEnvelope(expanded) unexpected error: %v", err)
	}
	if got, want := string(anchoredDocument.JSON()), string(expandedDocument.JSON()); got != want {
		t.Fatalf("anchored JSON = %s; want expanded JSON %s", got, want)
	}
}

func TestDecodeManifestEnvelopeRejectsDuplicateKeysWithoutEchoingInput(t *testing.T) {
	t.Parallel()

	marker := "ya29.DuplicateValueMustNotAppear"
	input := validManifestYAML("stage", manifestLines(
		"  endpoint: runtime-reference",
		"  endpoint: "+marker,
	))

	_, err := DecodeManifestEnvelope([]byte(input))
	if !errors.Is(err, ErrInvalidManifestYAML) {
		t.Fatalf("DecodeManifestEnvelope() error = %v; want ErrInvalidManifestYAML", err)
	}
	assertSafeDecodeError(t, err, marker, "endpoint")
	if !strings.Contains(err.Error(), "duplicate mapping key") {
		t.Fatalf("error = %q; want duplicate-key category", err)
	}
}

func TestDecodeManifestEnvelopeRejectsUnknownEnvelopeFieldsSafely(t *testing.T) {
	t.Parallel()

	marker := "ya29.UnknownFieldNameMustNotAppear"
	input := validManifestYAML("stage", "  enabled: true\n") + marker + ": true\n"

	_, err := DecodeManifestEnvelope([]byte(input))
	if !errors.Is(err, ErrInvalidManifestYAML) {
		t.Fatalf("DecodeManifestEnvelope() error = %v; want ErrInvalidManifestYAML", err)
	}
	assertSafeDecodeError(t, err, marker)
	if !strings.Contains(err.Error(), "unknown manifest field") {
		t.Fatalf("error = %q; want unknown-field category", err)
	}
}

func TestDecodeManifestEnvelopeRejectsUnknownMetadataFields(t *testing.T) {
	t.Parallel()

	input := manifestLines(
		"apiVersion: ctrldb.ctrlboard.dev/v1alpha1",
		"kind: MongoEnvironment",
		"metadata:",
		"  name: stage",
		"  class: staging",
		"  unexpected: true",
		"spec: {}",
	)
	_, err := DecodeManifestEnvelope([]byte(input))
	if !errors.Is(err, ErrInvalidManifestYAML) {
		t.Fatalf("DecodeManifestEnvelope() error = %v; want ErrInvalidManifestYAML", err)
	}
	assertSafeDecodeError(t, err, "unexpected")
}

func TestDecodeManifestEnvelopeRejectsMultipleDocuments(t *testing.T) {
	t.Parallel()

	input := validManifestYAML("stage", "  enabled: true\n") + "---\n" + validManifestYAML("other", "  enabled: false\n")
	_, err := DecodeManifestEnvelope([]byte(input))
	if !errors.Is(err, ErrInvalidManifestEnvelope) {
		t.Fatalf("DecodeManifestEnvelope() error = %v; want ErrInvalidManifestEnvelope", err)
	}
	if got := err.Error(); got != "invalid manifest envelope: multiple documents are not allowed" {
		t.Fatalf("error = %q; want fixed multiple-document error", got)
	}
}

func TestDecodeManifestEnvelopeRejectsSyntaxErrorsWithoutSource(t *testing.T) {
	t.Parallel()

	marker := "mongodb://operator:SyntaxMarkerMustNotAppear@example.invalid/admin"
	input := validManifestYAML("stage", "  endpoints: [\""+marker+"\"\n")
	_, err := DecodeManifestEnvelope([]byte(input))
	if !errors.Is(err, ErrInvalidManifestYAML) {
		t.Fatalf("DecodeManifestEnvelope() error = %v; want ErrInvalidManifestYAML", err)
	}
	assertSafeDecodeError(t, err, marker)
}

func TestDecodeManifestEnvelopeRunsSecretShapeValidation(t *testing.T) {
	t.Parallel()

	marker := "mongodb://operator:SecretMarkerMustNotAppear@example.invalid/admin"
	input := validManifestYAML("stage", "  endpoint: \""+marker+"\"\n")
	_, err := DecodeManifestEnvelope([]byte(input))
	if !errors.Is(err, ErrSecretShapedValue) {
		t.Fatalf("DecodeManifestEnvelope() error = %v; want ErrSecretShapedValue", err)
	}
	if got := err.Error(); got != "secret-shaped value at /spec/endpoint" {
		t.Fatalf("error = %q; want path-only secret error", got)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("error rendered the credential-shaped value")
	}
}

func TestDecodeManifestEnvelopeRequiresObjectSpec(t *testing.T) {
	t.Parallel()

	for _, spec := range []string{"null", "[]", "value", "42"} {
		t.Run(spec, func(t *testing.T) {
			t.Parallel()

			input := manifestLines(
				"apiVersion: "+ManifestAPIVersion,
				"kind: "+ManifestKind,
				"metadata: {name: stage, class: staging}",
				"spec: "+spec,
			)
			_, err := DecodeManifestEnvelope([]byte(input))
			if !errors.Is(err, ErrInvalidManifestEnvelope) {
				t.Fatalf("DecodeManifestEnvelope() error = %v; want ErrInvalidManifestEnvelope", err)
			}
		})
	}
}

func TestDecodeManifestEnvelopeRejectsEmptyAndInvalidIdentity(t *testing.T) {
	t.Parallel()

	_, err := DecodeManifestEnvelope(nil)
	if !errors.Is(err, ErrInvalidManifestEnvelope) {
		t.Fatalf("DecodeManifestEnvelope(nil) error = %v; want ErrInvalidManifestEnvelope", err)
	}

	_, err = DecodeManifestEnvelope([]byte(validManifestYAML("UPPERCASE", "  enabled: true\n")))
	if !errors.Is(err, ErrInvalidManifestIdentity) {
		t.Fatalf("DecodeManifestEnvelope(invalid identity) error = %v; want ErrInvalidManifestIdentity", err)
	}
}

func TestDecodeManifestEnvelopePreservesNumbersAndDoesNotExpandEnvironment(t *testing.T) {
	t.Parallel()

	input := validManifestYAML("stage", manifestLines(
		"  exactInteger: 9007199254740993",
		"  runtimeReference: ${DATABASE_SECRET_REF}",
	))
	document, err := DecodeManifestEnvelope([]byte(input))
	if err != nil {
		t.Fatalf("DecodeManifestEnvelope() unexpected error: %v", err)
	}
	got := string(document.JSON())
	if !strings.Contains(got, `"exactInteger":9007199254740993`) {
		t.Fatalf("JSON() lost integer precision: %s", got)
	}
	if !strings.Contains(got, `"runtimeReference":"${DATABASE_SECRET_REF}"`) {
		t.Fatalf("JSON() expanded environment reference: %s", got)
	}
}

func TestManifestDocumentJSONReturnsCopy(t *testing.T) {
	t.Parallel()

	document, err := DecodeManifestEnvelope([]byte(validManifestYAML("stage", "  enabled: true\n")))
	if err != nil {
		t.Fatalf("DecodeManifestEnvelope() unexpected error: %v", err)
	}

	first := document.JSON()
	first[0] = '['
	if got := document.JSON()[0]; got != '{' {
		t.Fatalf("JSON() exposed mutable state: first byte = %q; want '{'", got)
	}
}

func validManifestYAML(name, spec string) string {
	return validManifestYAMLForClass(name, "staging", spec)
}

func validManifestYAMLForClass(name, class, spec string) string {
	return manifestLines(
		"apiVersion: "+ManifestAPIVersion,
		"kind: "+ManifestKind,
		"metadata:",
		"  name: "+name,
		"  class: "+class,
		"spec:",
	) + spec
}

func manifestLines(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

func assertSafeDecodeError(t *testing.T, err error, forbidden ...string) {
	t.Helper()

	var decodeErr *ManifestDecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("error = %T %v; want *ManifestDecodeError", err, err)
	}
	if decodeErr.Line() < 1 || decodeErr.Column() < 1 {
		t.Fatalf("decode error position = %d:%d; want positive line and column", decodeErr.Line(), decodeErr.Column())
	}
	for _, value := range forbidden {
		if strings.Contains(err.Error(), value) {
			t.Fatalf("error rendered forbidden input %q", value)
		}
	}
}
