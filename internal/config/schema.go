// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

const manifestSchemaURL = "https://ctrldb.ctrlboard.dev/schemas/manifest-v1alpha1.json"

var (
	// ErrManifestSchemaViolation marks a structurally invalid manifest.
	ErrManifestSchemaViolation = errors.New("manifest schema violation")
	// ErrManifestSchemaUnavailable marks an invalid embedded schema or an
	// internal failure to decode a previously normalized manifest.
	ErrManifestSchemaUnavailable = errors.New("manifest schema unavailable")

	//go:embed schema/manifest-v1alpha1.json
	manifestSchemaJSON []byte

	manifestSchemaOnce sync.Once
	manifestSchema     *jsonschema.Schema
	manifestSchemaErr  error
)

// SchemaViolation identifies one validation failure without retaining or
// rendering the rejected manifest value.
type SchemaViolation struct {
	Path    string
	Keyword string
}

// ManifestSchemaError contains a deterministic, sanitized list of schema
// violations. It deliberately does not retain the validator's raw error.
type ManifestSchemaError struct {
	violations []SchemaViolation
}

// Error implements error using only safe paths and schema keywords.
func (err *ManifestSchemaError) Error() string {
	if len(err.violations) == 1 {
		violation := err.violations[0]
		return fmt.Sprintf("manifest schema violation at %s (%s)", violation.Path, violation.Keyword)
	}

	parts := make([]string, 0, len(err.violations))
	for _, violation := range err.violations {
		parts = append(parts, fmt.Sprintf("%s (%s)", violation.Path, violation.Keyword))
	}
	return "manifest schema violations at " + strings.Join(parts, ", ")
}

// Unwrap allows errors.Is(err, ErrManifestSchemaViolation).
func (err *ManifestSchemaError) Unwrap() error {
	return ErrManifestSchemaViolation
}

// Violations returns a copy of the deterministically ordered violations.
func (err *ManifestSchemaError) Violations() []SchemaViolation {
	return append([]SchemaViolation(nil), err.violations...)
}

// DecodeManifest performs safe envelope decoding followed by full structural
// JSON Schema validation. Policy validation is a later boundary.
func DecodeManifest(input []byte) (ManifestDocument, error) {
	document, err := DecodeManifestEnvelope(input)
	if err != nil {
		return ManifestDocument{}, err
	}
	if err := ValidateManifestSchema(document); err != nil {
		return ManifestDocument{}, err
	}
	return document, nil
}

// ValidateManifestSchema validates a decoded manifest against the embedded,
// version-pinned v1alpha1 schema.
func ValidateManifestSchema(document ManifestDocument) error {
	schema, err := compiledManifestSchema()
	if err != nil {
		return ErrManifestSchemaUnavailable
	}

	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(document.JSON()))
	if err != nil {
		return ErrManifestSchemaUnavailable
	}
	if err := schema.Validate(instance); err != nil {
		var validationErr *jsonschema.ValidationError
		if !errors.As(err, &validationErr) {
			return ErrManifestSchemaUnavailable
		}
		return newManifestSchemaError(validationErr)
	}
	return nil
}

func compiledManifestSchema() (*jsonschema.Schema, error) {
	manifestSchemaOnce.Do(func() {
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(manifestSchemaJSON))
		if err != nil {
			manifestSchemaErr = err
			return
		}

		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertFormat()
		if err := compiler.AddResource(manifestSchemaURL, document); err != nil {
			manifestSchemaErr = err
			return
		}
		manifestSchema, manifestSchemaErr = compiler.Compile(manifestSchemaURL)
	})
	return manifestSchema, manifestSchemaErr
}

func newManifestSchemaError(validationErr *jsonschema.ValidationError) error {
	violations := make([]SchemaViolation, 0)
	collectSchemaViolations(validationErr, &violations)
	if len(violations) == 0 {
		violations = append(violations, SchemaViolation{Path: "/", Keyword: "validation"})
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Path == violations[j].Path {
			return violations[i].Keyword < violations[j].Keyword
		}
		return violations[i].Path < violations[j].Path
	})
	violations = compactViolations(violations)
	return &ManifestSchemaError{violations: violations}
}

func collectSchemaViolations(validationErr *jsonschema.ValidationError, violations *[]SchemaViolation) {
	if len(validationErr.Causes) > 0 {
		for _, cause := range validationErr.Causes {
			collectSchemaViolations(cause, violations)
		}
		return
	}

	switch errorKind := validationErr.ErrorKind.(type) {
	case *kind.AdditionalProperties:
		for _, property := range errorKind.Properties {
			*violations = append(*violations, SchemaViolation{
				Path:    safeJSONPointer(appendCopy(validationErr.InstanceLocation, property)),
				Keyword: "additionalProperties",
			})
		}
	case *kind.Required:
		for _, property := range errorKind.Missing {
			*violations = append(*violations, SchemaViolation{
				Path:    safeJSONPointer(appendCopy(validationErr.InstanceLocation, property)),
				Keyword: "required",
			})
		}
	default:
		*violations = append(*violations, SchemaViolation{
			Path:    safeJSONPointer(validationErr.InstanceLocation),
			Keyword: safeSchemaKeyword(validationErr.ErrorKind),
		})
	}
}

func safeSchemaKeyword(errorKind jsonschema.ErrorKind) string {
	if errorKind == nil {
		return "validation"
	}
	path := errorKind.KeywordPath()
	if len(path) == 0 {
		return "validation"
	}
	keyword := path[0]
	if !safePathKeyPattern.MatchString(keyword) {
		return "validation"
	}
	return keyword
}

func safeJSONPointer(tokens []string) string {
	if len(tokens) == 0 {
		return "/"
	}

	safe := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if _, err := strconv.ParseUint(token, 10, 64); err == nil {
			safe = append(safe, token)
			continue
		}
		safe = append(safe, safePathKey(token))
	}
	return "/" + strings.Join(safe, "/")
}

func appendCopy(values []string, value string) []string {
	result := make([]string, len(values), len(values)+1)
	copy(result, values)
	return append(result, value)
}

func compactViolations(values []SchemaViolation) []SchemaViolation {
	if len(values) < 2 {
		return values
	}

	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
