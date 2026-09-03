// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package runner defines the I/O-free contract shared by subprocess adapters.
// Process creation belongs only to the adapter packages permitted to import
// os/exec.
package runner

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/thelostorbital/ctrldb/internal/redact"
)

const (
	// MaxStdoutBytes is the largest permitted stdout capture for one process.
	MaxStdoutBytes int64 = 8 << 20
	// MaxStderrBytes is the largest permitted stderr capture for one process.
	MaxStderrBytes int64 = 1 << 20
	// MaxTimeout is the longest permitted lifetime for one process invocation.
	MaxTimeout = 15 * time.Minute
)

var ErrInvalidRequest = errors.New("invalid runner request")

var environmentNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

var allowedEnvironment = map[string]struct{}{
	"PATH":                                  {},
	"HOME":                                  {},
	"CLOUDSDK_CONFIG":                       {},
	"CLOUDSDK_CORE_DISABLE_PROMPTS":         {},
	"CLOUDSDK_CORE_DISABLE_USAGE_REPORTING": {},
	"NO_COLOR":                              {},
	"LANG":                                  {},
	"LC_ALL":                                {},
}

var forbiddenExecutables = map[string]struct{}{
	"bash":           {},
	"cmd":            {},
	"cmd.exe":        {},
	"csh":            {},
	"dash":           {},
	"env":            {},
	"fish":           {},
	"ksh":            {},
	"powershell":     {},
	"powershell.exe": {},
	"pwsh":           {},
	"sh":             {},
	"tcsh":           {},
	"zsh":            {},
}

var fixedEnvironment = []EnvironmentVariable{
	{Name: "CLOUDSDK_CORE_DISABLE_PROMPTS", Value: "1"},
	{Name: "CLOUDSDK_CORE_DISABLE_USAGE_REPORTING", Value: "1"},
	{Name: "NO_COLOR", Value: "1"},
}

// EnvironmentVariable is one explicit child-process environment entry.
type EnvironmentVariable struct {
	Name  string
	Value string
}

// Request is an executable plus an argument vector. It intentionally has no
// command-string or shell field.
type Request struct {
	Executable       string
	Arguments        []string
	Environment      []EnvironmentVariable
	Timeout          time.Duration
	StdoutLimitBytes int64
	StderrLimitBytes int64
}

// Result is the in-memory result returned by an adapter. Stderr is sanitized
// at the boundary; callers must parse stdout or sanitize it before display or
// persistence.
type Result struct {
	ExitCode     int
	Stdout       []byte
	StdoutSHA256 string
	Stderr       redact.Text
	StderrSHA256 string
	StartedAt    time.Time
	EndedAt      time.Time
}

// Runner executes validated requests without invoking a shell.
type Runner interface {
	Run(context.Context, Request) (Result, error)
}

// ValidateRequest enforces the shared process boundary before an adapter may
// execute anything.
func ValidateRequest(request Request) error {
	if err := validateExecutable(request.Executable); err != nil {
		return err
	}
	for index, argument := range request.Arguments {
		if containsControl(argument) {
			return requestError(fmt.Sprintf("arguments[%d]", index), "contains a control character")
		}
	}
	if err := validateEnvironment(request.Environment); err != nil {
		return err
	}
	if request.Timeout <= 0 || request.Timeout > MaxTimeout {
		return requestError("timeout", "must be positive and at most 15 minutes")
	}
	if request.StdoutLimitBytes <= 0 || request.StdoutLimitBytes > MaxStdoutBytes {
		return requestError("stdoutLimitBytes", "must be positive and at most 8 MiB")
	}
	if request.StderrLimitBytes <= 0 || request.StderrLimitBytes > MaxStderrBytes {
		return requestError("stderrLimitBytes", "must be positive and at most 1 MiB")
	}

	return nil
}

// EnvironmentStrings validates and returns a stable NAME=value vector for an
// adapter. The returned slice never aliases request storage.
func EnvironmentStrings(request Request) ([]string, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}

	environment := make([]EnvironmentVariable, len(request.Environment))
	copy(environment, request.Environment)
	sort.Slice(environment, func(left, right int) bool {
		return environment[left].Name < environment[right].Name
	})

	result := make([]string, len(environment))
	for index, variable := range environment {
		result[index] = variable.Name + "=" + variable.Value
	}

	return result, nil
}

func validateExecutable(executable string) error {
	if executable == "" {
		return requestError("executable", "must not be empty")
	}
	if containsControlOrSpace(executable) {
		return requestError("executable", "must be one path or program name without whitespace or control characters")
	}
	if strings.ContainsRune(executable, filepath.Separator) {
		if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
			return requestError("executable", "path must be absolute and clean")
		}
	}
	if _, forbidden := forbiddenExecutables[strings.ToLower(filepath.Base(executable))]; forbidden {
		return requestError("executable", "shells and generic command launchers are forbidden")
	}

	return nil
}

func validateEnvironment(environment []EnvironmentVariable) error {
	values := make(map[string]string, len(environment))
	for index, variable := range environment {
		path := fmt.Sprintf("environment[%d]", index)
		if !environmentNamePattern.MatchString(variable.Name) {
			return requestError(path+".name", "must be an uppercase environment name")
		}
		if _, allowed := allowedEnvironment[variable.Name]; !allowed {
			return requestError(path+".name", "is not in the minimal environment allowlist")
		}
		if _, duplicate := values[variable.Name]; duplicate {
			return requestError(path+".name", "is duplicated")
		}
		if variable.Value == "" || containsControl(variable.Value) {
			return requestError(path+".value", "must be non-empty and contain no control characters")
		}
		values[variable.Name] = variable.Value
	}

	for _, name := range []string{"PATH", "HOME", "CLOUDSDK_CONFIG"} {
		if values[name] == "" {
			return requestError("environment", "is missing "+name)
		}
	}
	if values["LANG"] == "" && values["LC_ALL"] == "" {
		return requestError("environment", "must contain LANG or LC_ALL")
	}
	for _, variable := range fixedEnvironment {
		if values[variable.Name] != variable.Value {
			return requestError("environment."+variable.Name, "must equal 1")
		}
	}
	if !filepath.IsAbs(values["HOME"]) || !filepath.IsAbs(values["CLOUDSDK_CONFIG"]) {
		return requestError("environment", "HOME and CLOUDSDK_CONFIG must be absolute paths")
	}
	for _, element := range filepath.SplitList(values["PATH"]) {
		if element == "" || !filepath.IsAbs(element) {
			return requestError("environment.PATH", "must contain only absolute non-empty paths")
		}
	}

	return nil
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

func containsControlOrSpace(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsControl(character) || unicode.IsSpace(character)
	}) >= 0
}

func requestError(path, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidRequest, path, reason)
}
