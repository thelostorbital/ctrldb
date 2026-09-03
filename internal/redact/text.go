// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package redact removes known secret shapes and terminal control sequences
// before text crosses a persistence or rendering boundary.
package redact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	redactedValue = "[redacted]"
	redactedToken = "[redacted-token]"
)

// ErrNilTextDestination is returned when decoding targets a nil Text pointer.
var ErrNilTextDestination = errors.New("redact: nil Text destination")

var (
	ansiCSI = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	ansiOSC = regexp.MustCompile(`(?s)\x1b\].*?(?:\x07|\x1b\\)`)
	ansiTwo = regexp.MustCompile(`\x1b[@-_]`)

	pemBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----`)

	mongoURI         = regexp.MustCompile(`(?i)\bmongodb(?:\+srv)?://[^\s"'<>]+`)
	mongoQuerySecret = regexp.MustCompile(`(?i)([?&](?:password|authMechanismProperties|tlsCertificateKeyFilePassword)=)[^&#\s]*`)

	httpURL            = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)
	signedURLParameter = regexp.MustCompile(`(?i)(?:^|[?&])(?:X-Goog-Signature|Signature|X-Goog-Credential|Expires)=`)

	bearerToken        = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`)
	googleOAuthToken   = regexp.MustCompile(`\bya29\.[A-Za-z0-9\-._]+`)
	googleRefreshToken = regexp.MustCompile(`\b1//[A-Za-z0-9\-._]{20,}`)

	secretLine = regexp.MustCompile(`(?i)^(\s*(?:--)?["']?([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|credential|authorization|cookie|session)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*)(.*)$`)
	secretPair = regexp.MustCompile(`(?i)(^|[[:space:],{])((?:--)?["']?([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|credential|authorization|cookie|session)[A-Za-z0-9_.-]*)["']?[[:space:]]*[:=][[:space:]]*)("[^"]*"|'[^']*'|[^[:space:],}]+)`)

	humanEmail = regexp.MustCompile(`([A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})`)

	secretKey          = regexp.MustCompile(`(?i)^(.*)(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|credential|authorization|cookie|session)(.*)$`)
	referenceKey       = regexp.MustCompile(`(?i)(Ref|Name|Id|Names|Ids)$`)
	gcpName            = regexp.MustCompile(`^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	secretResourceName = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/secrets/[A-Za-z0-9_-]{1,255}(?:/versions/[0-9]+)?$`)
)

// Text is safe to render or persist. Its value can only be constructed by this
// package's sanitizers.
type Text struct {
	value string
}

// Sanitize removes known secret shapes and terminal control sequences.
func Sanitize(raw string) Text {
	return Text{value: sanitizeUnstructured(raw, false)}
}

// SanitizeEvidence applies general redaction and pseudonymizes human email
// addresses. Audit records should use Sanitize so their operator field remains
// attributable.
func SanitizeEvidence(raw string) Text {
	return Text{value: sanitizeUnstructured(raw, true)}
}

// String returns the sanitized text.
func (text Text) String() string {
	return text.value
}

// MarshalText implements encoding.TextMarshaler.
func (text Text) MarshalText() ([]byte, error) {
	return []byte(text.value), nil
}

// MarshalJSON implements json.Marshaler.
func (text Text) MarshalJSON() ([]byte, error) {
	return json.Marshal(text.value)
}

// UnmarshalText sanitizes serialized text before storing it in Text.
func (text *Text) UnmarshalText(value []byte) error {
	if text == nil {
		return ErrNilTextDestination
	}

	*text = Sanitize(string(value))

	return nil
}

// UnmarshalJSON sanitizes a serialized JSON string before storing it in Text.
func (text *Text) UnmarshalJSON(value []byte) error {
	if text == nil {
		return ErrNilTextDestination
	}

	var raw string
	if err := json.Unmarshal(value, &raw); err != nil {
		return fmt.Errorf("redact: decode Text: %w", err)
	}

	*text = Sanitize(raw)

	return nil
}

// SanitizeJSON parses and recursively redacts a JSON document. Invalid or
// trailing input is replaced by a digest and byte count; raw input is never
// returned on a parse failure.
func SanitizeJSON(raw []byte) Text {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var document any
	if err := decoder.Decode(&document); err != nil {
		return unparseableJSON(raw)
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return unparseableJSON(raw)
	}

	encoded, err := json.Marshal(sanitizeJSONValue(document))
	if err != nil {
		return unparseableJSON(raw)
	}

	return Text{value: string(encoded)}
}

func sanitizeUnstructured(raw string, redactEmails bool) string {
	value := stripANSI(raw)
	value = pemBlock.ReplaceAllString(value, "[redacted-pem]")
	value = httpURL.ReplaceAllStringFunc(value, sanitizeSignedURL)
	value = mongoURI.ReplaceAllStringFunc(value, sanitizeMongoURI)
	value = bearerToken.ReplaceAllString(value, redactedToken)
	value = googleOAuthToken.ReplaceAllString(value, redactedToken)
	value = googleRefreshToken.ReplaceAllString(value, redactedToken)
	value = sanitizeSecretLines(value)
	if redactEmails {
		value = humanEmail.ReplaceAllString(value, `${1}…@${2}`)
	}

	return escapeControlCharacters(value)
}

func stripANSI(value string) string {
	value = ansiOSC.ReplaceAllString(value, "")
	value = ansiCSI.ReplaceAllString(value, "")
	value = ansiTwo.ReplaceAllString(value, "")

	return strings.ReplaceAll(value, "\x1b", "")
}

func sanitizeSignedURL(value string) string {
	question := strings.IndexByte(value, '?')
	if question < 0 || !signedURLParameter.MatchString(value[question:]) {
		return value
	}

	return value[:question] + "?[redacted]"
}

func sanitizeMongoURI(value string) string {
	schemeEnd := strings.Index(value, "://")
	if schemeEnd < 0 {
		return "[redacted-mongodb-uri]"
	}

	authorityStart := schemeEnd + len("://")
	authorityEnd := len(value)
	if offset := strings.IndexAny(value[authorityStart:], "/?#"); offset >= 0 {
		authorityEnd = authorityStart + offset
	}

	authority := value[authorityStart:authorityEnd]
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		value = value[:authorityStart] + "[redacted]@" + authority[at+1:] + value[authorityEnd:]
	}

	return mongoQuerySecret.ReplaceAllString(value, `${1}[redacted]`)
}

func sanitizeSecretLines(value string) string {
	lines := strings.SplitAfter(value, "\n")
	for index, line := range lines {
		newline := ""
		body := line
		if strings.HasSuffix(body, "\n") {
			body = strings.TrimSuffix(body, "\n")
			newline = "\n"
		}

		body = sanitizeSecretLine(body)
		lines[index] = body + newline
	}

	return strings.Join(lines, "")
}

func sanitizeSecretLine(line string) string {
	if matches := secretLine.FindStringSubmatch(line); len(matches) == 4 {
		candidate := strings.TrimSpace(matches[3])
		if isRedactionMarker(candidate) || safeReference(matches[2], candidate) {
			return line
		}

		return matches[1] + redactedValue
	}

	return secretPair.ReplaceAllStringFunc(line, func(pair string) string {
		matches := secretPair.FindStringSubmatch(pair)
		if len(matches) != 5 || isRedactionMarker(matches[4]) || safeReference(matches[3], matches[4]) {
			return pair
		}

		return matches[1] + matches[2] + redactedValue
	})
}

func isRedactionMarker(value string) bool {
	switch value {
	case redactedValue, redactedToken, "[redacted-pem]", "[redacted-sa-key]":
		return true
	default:
		return false
	}
}

func escapeControlCharacters(value string) string {
	const hexadecimal = "0123456789abcdef"

	var output strings.Builder
	output.Grow(len(value))

	for _, character := range value {
		switch {
		case character == '\n' || character == '\t':
			output.WriteRune(character)
		case character < 0x20 || character == 0x7f:
			output.WriteString(`\x`)
			output.WriteByte(hexadecimal[byte(character)>>4])
			output.WriteByte(hexadecimal[byte(character)&0x0f])
		case character >= 0x80 && character <= 0x9f:
			output.WriteString(`\u00`)
			output.WriteByte(hexadecimal[byte(character)>>4])
			output.WriteByte(hexadecimal[byte(character)&0x0f])
		default:
			output.WriteRune(character)
		}
	}

	return output.String()
}

func sanitizeJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		if serviceAccountKey(typed) {
			return "[redacted-sa-key]"
		}

		result := make(map[string]any, len(typed))
		for key, child := range typed {
			if secretKey.MatchString(key) && !safeReferenceValue(key, child) {
				result[key] = redactedValue
				continue
			}
			result[key] = sanitizeJSONValue(child)
		}

		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = sanitizeJSONValue(child)
		}

		return result
	case string:
		return sanitizeUnstructured(typed, false)
	default:
		return value
	}
}

func serviceAccountKey(value map[string]any) bool {
	kind, kindOK := value["type"].(string)
	_, privateKeyOK := value["private_key"]

	return kindOK && kind == "service_account" && privateKeyOK
}

func safeReferenceValue(key string, value any) bool {
	if !referenceKey.MatchString(key) {
		return false
	}

	switch typed := value.(type) {
	case string:
		return safeResourceName(typed)
	case []any:
		if len(typed) == 0 {
			return false
		}
		for _, child := range typed {
			name, ok := child.(string)
			if !ok || !safeResourceName(name) {
				return false
			}
		}

		return true
	default:
		return false
	}
}

func safeReference(key, value string) bool {
	if !secretKey.MatchString(key) || !referenceKey.MatchString(key) {
		return false
	}

	value = strings.Trim(value, `"'`)

	return safeResourceName(value)
}

func safeResourceName(value string) bool {
	return gcpName.MatchString(value) || secretResourceName.MatchString(value)
}

func unparseableJSON(raw []byte) Text {
	digest := sha256.Sum256(raw)
	marker := fmt.Sprintf(
		"[unparseable-json sha256=%s bytes=%d]",
		hex.EncodeToString(digest[:]),
		len(raw),
	)

	return Text{value: marker}
}
