// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/thelostorbital/ctrldb/internal/domain"
)

var (
	// ErrInvalidManifestYAML marks input that cannot be decoded as one safe
	// YAML document.
	ErrInvalidManifestYAML = errors.New("invalid manifest YAML")
	// ErrInvalidManifestEnvelope marks a syntactically valid document whose
	// top-level identity or shape is invalid.
	ErrInvalidManifestEnvelope = errors.New("invalid manifest envelope")
)

// ManifestDocument is a syntax-checked manifest envelope. DecodeManifest
// returns a document that has also passed every local validation boundary;
// lower-level tooling must complete schema and policy validation explicitly.
type ManifestDocument struct {
	identity       ManifestIdentity
	normalizedJSON []byte
}

// Identity returns the validated manifest API, kind, name, and class.
func (document ManifestDocument) Identity() ManifestIdentity {
	return document.identity
}

// JSON returns a copy of the normalized JSON document. YAML aliases are
// resolved and mapping keys are ordered deterministically.
func (document ManifestDocument) JSON() []byte {
	return append([]byte(nil), document.normalizedJSON...)
}

// ManifestDecodeError contains only a parser-owned category and source
// position. It deliberately does not retain the parser error or input bytes.
type ManifestDecodeError struct {
	reason string
	line   int
	column int
}

// Error implements error without source snippets, field names, or values.
func (err *ManifestDecodeError) Error() string {
	if err.line > 0 && err.column > 0 {
		return fmt.Sprintf("%s at line %d, column %d", err.reason, err.line, err.column)
	}
	return err.reason
}

// Unwrap allows errors.Is(err, ErrInvalidManifestYAML).
func (err *ManifestDecodeError) Unwrap() error {
	return ErrInvalidManifestYAML
}

// Line returns the one-based source line, or zero when unavailable.
func (err *ManifestDecodeError) Line() int {
	return err.line
}

// Column returns the one-based source column, or zero when unavailable.
func (err *ManifestDecodeError) Column() int {
	return err.column
}

// DecodeManifestEnvelope decodes exactly one YAML or JSON document, rejects
// duplicate and unknown envelope fields, validates its identity, resolves YAML
// aliases, and rejects credential-shaped values. It does not perform full JSON
// Schema or policy validation. It is intended for migration and schema
// tooling, never as the planning or mutation entry point.
func DecodeManifestEnvelope(input []byte) (ManifestDocument, error) {
	var wire manifestEnvelopeWire
	decoder := yaml.NewDecoder(bytes.NewReader(input), yaml.Strict())
	if err := decoder.Decode(&wire); err != nil {
		if errors.Is(err, io.EOF) {
			return ManifestDocument{}, fmt.Errorf("%w: document is empty", ErrInvalidManifestEnvelope)
		}
		return ManifestDocument{}, safeManifestDecodeError(err)
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return ManifestDocument{}, fmt.Errorf("%w: multiple documents are not allowed", ErrInvalidManifestEnvelope)
		}
		return ManifestDocument{}, safeManifestDecodeError(err)
	}

	identity := ManifestIdentity{
		APIVersion: wire.APIVersion,
		Kind:       wire.Kind,
		Metadata: ManifestMetadata{
			Name:  wire.Metadata.Name,
			Class: wire.Metadata.Class,
		},
	}
	if err := ValidateManifestIdentity(identity); err != nil {
		return ManifestDocument{}, err
	}

	normalized, decoded, err := normalizeManifestJSON(input)
	if err != nil {
		return ManifestDocument{}, err
	}
	if _, ok := decoded["spec"].(map[string]any); !ok {
		return ManifestDocument{}, fmt.Errorf("%w: spec must be an object", ErrInvalidManifestEnvelope)
	}
	if err := ValidateNoSecretShapes(decoded); err != nil {
		return ManifestDocument{}, err
	}

	return ManifestDocument{identity: identity, normalizedJSON: normalized}, nil
}

type manifestEnvelopeWire struct {
	APIVersion string               `yaml:"apiVersion"`
	Kind       string               `yaml:"kind"`
	Metadata   manifestMetadataWire `yaml:"metadata"`
	Spec       any                  `yaml:"spec"`
}

type manifestMetadataWire struct {
	Name  string                  `yaml:"name"`
	Class domain.EnvironmentClass `yaml:"class"`
}

func normalizeManifestJSON(input []byte) ([]byte, map[string]any, error) {
	encoded, err := yaml.YAMLToJSON(input)
	if err != nil {
		return nil, nil, safeManifestDecodeError(err)
	}

	var decoded map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, nil, fmt.Errorf("%w: document is not JSON-compatible", ErrInvalidManifestEnvelope)
	}
	if decoded == nil {
		return nil, nil, fmt.Errorf("%w: document must be an object", ErrInvalidManifestEnvelope)
	}

	normalized, err := json.Marshal(decoded)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: document is not JSON-compatible", ErrInvalidManifestEnvelope)
	}
	return normalized, decoded, nil
}

func safeManifestDecodeError(parseErr error) error {
	reason := "invalid manifest YAML"

	var duplicateErr *yaml.DuplicateKeyError
	var syntaxErr *yaml.SyntaxError
	var unknownErr *yaml.UnknownFieldError
	var typeErr *yaml.TypeError
	switch {
	case errors.As(parseErr, &duplicateErr):
		reason = "duplicate mapping key"
	case errors.As(parseErr, &syntaxErr) &&
		(strings.Contains(strings.ToLower(syntaxErr.GetMessage()), "duplicate") ||
			strings.Contains(strings.ToLower(syntaxErr.GetMessage()), "already defined")):
		reason = "duplicate mapping key"
	case errors.As(parseErr, &unknownErr):
		reason = "unknown manifest field"
	case errors.As(parseErr, &typeErr):
		reason = "invalid manifest value type"
	}

	result := &ManifestDecodeError{reason: reason}
	var yamlErr yaml.Error
	if errors.As(parseErr, &yamlErr) {
		token := yamlErr.GetToken()
		if token != nil && token.Position != nil {
			result.line = token.Position.Line
			result.column = token.Position.Column
		}
	}
	return result
}
