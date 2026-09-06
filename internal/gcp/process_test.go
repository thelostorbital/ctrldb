// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/runner"
)

func TestProcessBoundaryRunsWithoutShellOrAmbientEnvironment(t *testing.T) {
	executable := helperExecutable(t)
	boundary := mustProcessBoundary(t, executable)

	ambientName := "CTRLDB_SYNTHETIC_AMBIENT_VALUE"
	t.Setenv(ambientName, "must-not-leak")
	marker := filepath.Join(t.TempDir(), "shell-side-effect")
	argument := "$(touch " + marker + "); still-one-argument"
	request := validProcessRequest(executable)
	request.Arguments = helperArguments("inspect", ambientName, argument)

	result, err := boundary.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := string(result.Stdout), "ambient=\nargument="+argument; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shell-shaped argument caused a side effect: %v", err)
	}
	if result.ExitCode != 0 || !result.StartedAt.Before(result.EndedAt) {
		t.Fatalf("result metadata = %#v", result)
	}
}

func TestProcessBoundarySanitizesDiagnosticsAndHashesStreams(t *testing.T) {
	t.Parallel()

	executable := helperExecutable(t)
	boundary := mustProcessBoundary(t, executable)
	request := validProcessRequest(executable)
	request.Arguments = helperArguments("success-with-diagnostics")

	result, err := boundary.Run(context.Background(), request)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := string(result.Stdout), `{"status":"ok"}`; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if got := result.Stderr.String(); got != "token=[redacted]" || strings.Contains(got, "SYNTHETIC") {
		t.Fatalf("sanitized stderr = %q", got)
	}
	if got, want := result.StdoutSHA256, digest(`{"status":"ok"}`); got != want {
		t.Fatalf("stdout digest = %q, want %q", got, want)
	}
	if got, want := result.StderrSHA256, digest("token=SYNTHETIC_PROCESS_TOKEN"); got != want {
		t.Fatalf("stderr digest = %q, want %q", got, want)
	}
}

func TestProcessBoundaryRejectsInvalidConstruction(t *testing.T) {
	t.Parallel()

	executable := helperExecutable(t)
	environment := validProcessEnvironment()
	nonExecutable := filepath.Join(t.TempDir(), "gcloud")
	if err := os.WriteFile(nonExecutable, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write non-executable fixture: %v", err)
	}

	tests := []struct {
		name        string
		executable  string
		environment []runner.EnvironmentVariable
	}{
		{name: "empty executable", executable: "", environment: environment},
		{name: "relative executable", executable: "bin/gcloud", environment: environment},
		{name: "unclean executable", executable: filepath.Dir(executable) + "/../" + filepath.Base(filepath.Dir(executable)) + "/gcloud", environment: environment},
		{name: "wrong executable", executable: os.Args[0], environment: environment},
		{name: "missing executable", executable: filepath.Join(t.TempDir(), "gcloud"), environment: environment},
		{name: "directory", executable: filepath.Join(t.TempDir(), "gcloud"), environment: environment},
		{name: "non executable", executable: nonExecutable, environment: environment},
		{name: "invalid environment", executable: executable, environment: environment[:len(environment)-1]},
	}
	if err := os.Mkdir(tests[5].executable, 0o700); err != nil {
		t.Fatalf("create directory fixture: %v", err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := newProcessBoundary(test.executable, test.environment)
			assertProcessFailure(t, err, processFailureInvalid)
		})
	}
}

func TestProcessBoundaryRejectsRequestDrift(t *testing.T) {
	t.Parallel()

	executable := helperExecutable(t)
	boundary := mustProcessBoundary(t, executable)
	tests := []struct {
		name   string
		mutate func(*runner.Request)
	}{
		{name: "different executable", mutate: func(request *runner.Request) { request.Executable = filepath.Join(t.TempDir(), "gcloud") }},
		{name: "different environment", mutate: func(request *runner.Request) { request.Environment[0].Value = "/different" }},
		{name: "zero timeout", mutate: func(request *runner.Request) { request.Timeout = 0 }},
		{name: "excess timeout", mutate: func(request *runner.Request) { request.Timeout = runner.MaxTimeout + time.Nanosecond }},
		{name: "zero stdout limit", mutate: func(request *runner.Request) { request.StdoutLimitBytes = 0 }},
		{name: "excess stderr limit", mutate: func(request *runner.Request) { request.StderrLimitBytes = runner.MaxStderrBytes + 1 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validProcessRequest(executable)
			test.mutate(&request)
			_, err := boundary.Run(context.Background(), request)
			assertProcessFailure(t, err, processFailureInvalid)
		})
	}

	request := validProcessRequest(executable)
	_, err := boundary.Run(nil, request)
	assertProcessFailure(t, err, processFailureInvalid)
}

func TestProcessBoundaryClassifiesCancellationAndTimeout(t *testing.T) {
	t.Parallel()

	executable := helperExecutable(t)
	boundary := mustProcessBoundary(t, executable)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	request := validProcessRequest(executable)
	request.Arguments = helperArguments("sleep")
	result, err := boundary.Run(canceled, request)
	assertProcessFailure(t, err, processFailureCanceled)
	assertFailureResultHasNoStdout(t, result)

	request = validProcessRequest(executable)
	request.Arguments = helperArguments("sleep")
	request.Timeout = 50 * time.Millisecond
	result, err = boundary.Run(context.Background(), request)
	assertProcessFailure(t, err, processFailureTimeout)
	assertFailureResultHasNoStdout(t, result)

	deadline, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	request = validProcessRequest(executable)
	request.Arguments = helperArguments("sleep")
	result, err = boundary.Run(deadline, request)
	assertProcessFailure(t, err, processFailureTimeout)
	assertFailureResultHasNoStdout(t, result)
}

func TestProcessBoundaryClassifiesExitAndRedactsFailureOutput(t *testing.T) {
	t.Parallel()

	executable := helperExecutable(t)
	boundary := mustProcessBoundary(t, executable)
	request := validProcessRequest(executable)
	request.Arguments = helperArguments("fail")

	result, err := boundary.Run(context.Background(), request)
	assertProcessFailure(t, err, processFailureExit)
	assertFailureResultHasNoStdout(t, result)
	if result.ExitCode != 23 {
		t.Fatalf("exit code = %d, want 23", result.ExitCode)
	}
	if got := result.Stderr.String(); got != "password=[redacted]" || strings.Contains(got, "SYNTHETIC") {
		t.Fatalf("sanitized stderr = %q", got)
	}
	if strings.Contains(err.Error(), "SYNTHETIC") || strings.Contains(err.Error(), "password") {
		t.Fatalf("error leaked process output: %q", err)
	}
}

func TestProcessBoundaryClassifiesOutputLimits(t *testing.T) {
	t.Parallel()

	executable := helperExecutable(t)
	boundary := mustProcessBoundary(t, executable)
	tests := []struct {
		name string
		mode string
		kind processFailureKind
	}{
		{name: "stdout", mode: "overflow-stdout", kind: processFailureStdoutLimit},
		{name: "stderr", mode: "overflow-stderr", kind: processFailureStderrLimit},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validProcessRequest(executable)
			request.Arguments = helperArguments(test.mode)
			request.StdoutLimitBytes = 32
			request.StderrLimitBytes = 32
			result, err := boundary.Run(context.Background(), request)
			assertProcessFailure(t, err, test.kind)
			assertFailureResultHasNoStdout(t, result)
			if strings.Contains(err.Error(), "SYNTHETIC") {
				t.Fatalf("error leaked output: %q", err)
			}
		})
	}
}

func TestProcessHelper(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		return
	}

	arguments := os.Args[separator+1:]
	switch arguments[0] {
	case "inspect":
		fmt.Printf("ambient=%s\nargument=%s", os.Getenv(arguments[1]), arguments[2])
	case "success-with-diagnostics":
		fmt.Fprint(os.Stdout, `{"status":"ok"}`)
		fmt.Fprint(os.Stderr, "token=SYNTHETIC_PROCESS_TOKEN")
	case "sleep":
		time.Sleep(5 * time.Second)
	case "fail":
		fmt.Fprint(os.Stdout, "token=SYNTHETIC_STDOUT_TOKEN")
		fmt.Fprint(os.Stderr, "password=SYNTHETIC_PROCESS_PASSWORD")
		os.Exit(23)
	case "overflow-stdout":
		fmt.Fprint(os.Stdout, strings.Repeat("SYNTHETIC-STDOUT-", 16))
	case "overflow-stderr":
		fmt.Fprint(os.Stderr, strings.Repeat("SYNTHETIC-STDERR-", 16))
	default:
		os.Exit(24)
	}
	os.Exit(0)
}

func helperExecutable(t *testing.T) string {
	t.Helper()
	current, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	executable := filepath.Join(t.TempDir(), "gcloud")
	if err := os.Symlink(current, executable); err != nil {
		t.Fatalf("create gcloud test link: %v", err)
	}
	return executable
}

func mustProcessBoundary(t *testing.T, executable string) *processBoundary {
	t.Helper()
	boundary, err := newProcessBoundary(executable, validProcessEnvironment())
	if err != nil {
		t.Fatalf("newProcessBoundary() error = %v", err)
	}
	return boundary
}

func validProcessRequest(executable string) runner.Request {
	return runner.Request{
		Executable:       executable,
		Arguments:        helperArguments("success-with-diagnostics"),
		Environment:      validProcessEnvironment(),
		Timeout:          5 * time.Second,
		StdoutLimitBytes: 1024,
		StderrLimitBytes: 1024,
	}
}

func validProcessEnvironment() []runner.EnvironmentVariable {
	return []runner.EnvironmentVariable{
		{Name: "PATH", Value: "/usr/bin:/bin"},
		{Name: "HOME", Value: "/tmp/ctrldb-synthetic-home"},
		{Name: "CLOUDSDK_CONFIG", Value: "/tmp/ctrldb-synthetic-config"},
		{Name: "CLOUDSDK_CORE_DISABLE_PROMPTS", Value: "1"},
		{Name: "CLOUDSDK_CORE_DISABLE_USAGE_REPORTING", Value: "1"},
		{Name: "NO_COLOR", Value: "1"},
		{Name: "LANG", Value: "C.UTF-8"},
	}
}

func helperArguments(mode string, arguments ...string) []string {
	result := []string{"-test.run=^TestProcessHelper$", "--", mode}
	return append(result, arguments...)
}

func assertProcessFailure(t *testing.T, err error, want processFailureKind) {
	t.Helper()
	var failure *processFailure
	if !errors.As(err, &failure) || failure.kind != want {
		t.Fatalf("error = %#v, want process failure kind %d", err, want)
	}
}

func assertFailureResultHasNoStdout(t *testing.T, result runner.Result) {
	t.Helper()
	if result.Stdout != nil {
		t.Fatalf("failure stdout = %q, want nil", result.Stdout)
	}
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
