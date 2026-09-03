// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	// ErrSecretShapedValue marks a manifest value that resembles a credential.
	ErrSecretShapedValue = errors.New("secret-shaped manifest value")
	// ErrUnsupportedManifestValue marks input outside the JSON-compatible data
	// model consumed by the manifest validator.
	ErrUnsupportedManifestValue = errors.New("unsupported manifest value")
)

var (
	mongoCredentialPattern = regexp.MustCompile(`(?i)mongodb(?:\+srv)?://[^/\s]*:[^@\s]+@`)
	privateKeyPEMPattern   = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	googleAPIKeyPattern    = regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)
	googleOAuthPattern     = regexp.MustCompile(`ya29\.[0-9A-Za-z_-]+`)
	sensitiveKeyPattern    = regexp.MustCompile(`(?i)(pass|secret|token|key|cred)`)
	base64LikePattern      = regexp.MustCompile(`^[A-Za-z0-9+/=]{32,}$`)
	safePathKeyPattern     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)
)

// SecretShapeError reports credential-shaped manifest locations without ever
// retaining or rendering the offending values.
type SecretShapeError struct {
	paths []string
}

// Error implements error using paths only. It never includes manifest values.
func (err *SecretShapeError) Error() string {
	if len(err.paths) == 1 {
		return "secret-shaped value at " + err.paths[0]
	}
	return "secret-shaped values at " + strings.Join(err.paths, ", ")
}

// Unwrap allows errors.Is(err, ErrSecretShapedValue).
func (err *SecretShapeError) Unwrap() error {
	return ErrSecretShapedValue
}

// Paths returns a copy of the deterministically ordered JSON Pointer paths.
func (err *SecretShapeError) Paths() []string {
	return append([]string(nil), err.paths...)
}

// ValidateNoSecretShapes rejects credential-shaped strings in a decoded
// manifest. Input must use the JSON-compatible map[string]any, []any, and
// scalar model produced by the manifest decoder.
func ValidateNoSecretShapes(document any) error {
	paths := make([]string, 0)
	if err := scanManifestValue(document, "", "", &paths); err != nil {
		return err
	}
	if len(paths) == 0 {
		return nil
	}

	sort.Strings(paths)
	paths = compactStrings(paths)
	return &SecretShapeError{paths: paths}
}

func scanManifestValue(value any, path, key string, paths *[]string) error {
	switch typed := value.(type) {
	case nil, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, json.Number,
		string:
		if text, ok := typed.(string); ok && secretShapedString(key, text) {
			*paths = append(*paths, rootPath(path))
		}
		return nil
	case []any:
		for index, child := range typed {
			childPath := path + "/" + fmt.Sprintf("%d", index)
			if err := scanManifestValue(child, childPath, key, paths); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for childKey := range typed {
			keys = append(keys, childKey)
		}
		sort.Strings(keys)

		for _, childKey := range keys {
			childPath := path + "/" + safePathKey(childKey)
			if strings.EqualFold(childKey, "private_key") {
				*paths = append(*paths, childPath)
			}
			if err := scanManifestValue(typed[childKey], childPath, childKey, paths); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%w at %s", ErrUnsupportedManifestValue, rootPath(path))
	}
}

func secretShapedString(key, value string) bool {
	if mongoCredentialPattern.MatchString(value) ||
		privateKeyPEMPattern.MatchString(value) ||
		googleAPIKeyPattern.MatchString(value) ||
		googleOAuthPattern.MatchString(value) {
		return true
	}

	return sensitiveKeyPattern.MatchString(key) && base64LikePattern.MatchString(value)
}

func safePathKey(key string) string {
	if safePathKeyPattern.MatchString(key) && !secretShapedString("", key) {
		return strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
	}
	digest := sha256.Sum256([]byte(key))
	return fmt.Sprintf("redacted-key-%x", digest[:6])
}

func rootPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func compactStrings(values []string) []string {
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
