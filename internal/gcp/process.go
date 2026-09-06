// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package gcp contains typed Google Cloud adapters. Process creation is sealed
// in this file; callers outside this package receive provider operations rather
// than an argv execution capability.
package gcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/thelostorbital/ctrldb/internal/redact"
	"github.com/thelostorbital/ctrldb/internal/runner"
)

const processWaitDelay = 2 * time.Second

type processFailureKind uint8

const (
	processFailureInvalid processFailureKind = iota + 1
	processFailureStart
	processFailureExit
	processFailureTimeout
	processFailureCanceled
	processFailureStdoutLimit
	processFailureStderrLimit
)

type processFailure struct {
	kind     processFailureKind
	exitCode int
}

func (failure *processFailure) Error() string {
	switch failure.kind {
	case processFailureInvalid:
		return "gcp process request rejected"
	case processFailureStart:
		return "gcp process could not start"
	case processFailureExit:
		return fmt.Sprintf("gcp process exited unsuccessfully with status %d", failure.exitCode)
	case processFailureTimeout:
		return "gcp process timed out"
	case processFailureCanceled:
		return "gcp process was canceled"
	case processFailureStdoutLimit:
		return "gcp process stdout exceeded its limit"
	case processFailureStderrLimit:
		return "gcp process stderr exceeded its limit"
	default:
		return "gcp process failed"
	}
}

// processBoundary is deliberately unexported. Later provider adapters in this
// package may use it, but no caller can obtain a general-purpose executor.
type processBoundary struct {
	configuredExecutable string
	resolvedExecutable   string
	environment          []string
}

var _ runner.Runner = (*processBoundary)(nil)

func newProcessBoundary(executable string, environment []runner.EnvironmentVariable) (*processBoundary, error) {
	validationRequest := runner.Request{
		Executable:       executable,
		Environment:      environment,
		Timeout:          time.Second,
		StdoutLimitBytes: 1,
		StderrLimitBytes: 1,
	}
	if err := runner.ValidateRequest(validationRequest); err != nil {
		return nil, &processFailure{kind: processFailureInvalid}
	}
	if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable || filepath.Base(executable) != "gcloud" {
		return nil, &processFailure{kind: processFailureInvalid}
	}

	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return nil, &processFailure{kind: processFailureInvalid}
	}
	resolvedRequest := validationRequest
	resolvedRequest.Executable = resolved
	if err := runner.ValidateRequest(resolvedRequest); err != nil || filepath.Base(resolved) != "gcloud" {
		return nil, &processFailure{kind: processFailureInvalid}
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, &processFailure{kind: processFailureInvalid}
	}

	environmentStrings, err := runner.EnvironmentStrings(validationRequest)
	if err != nil {
		return nil, &processFailure{kind: processFailureInvalid}
	}

	return &processBoundary{
		configuredExecutable: executable,
		resolvedExecutable:   resolved,
		environment:          append([]string(nil), environmentStrings...),
	}, nil
}

func (boundary *processBoundary) Run(ctx context.Context, request runner.Request) (runner.Result, error) {
	if boundary == nil || ctx == nil {
		return runner.Result{}, &processFailure{kind: processFailureInvalid}
	}
	if err := runner.ValidateRequest(request); err != nil {
		return runner.Result{}, &processFailure{kind: processFailureInvalid}
	}
	environment, err := runner.EnvironmentStrings(request)
	if err != nil || request.Executable != boundary.configuredExecutable || !equalStrings(environment, boundary.environment) {
		return runner.Result{}, &processFailure{kind: processFailureInvalid}
	}

	stdout := newBoundedCapture(request.StdoutLimitBytes)
	stderr := newBoundedCapture(request.StderrLimitBytes)
	runContext, cancel := context.WithTimeout(ctx, request.Timeout)
	defer cancel()

	command := exec.CommandContext(runContext, boundary.resolvedExecutable, request.Arguments...)
	command.Env = append([]string(nil), boundary.environment...)
	command.Stdin = nil
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = processWaitDelay
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}

	startedAt := time.Now().UTC()
	runErr := command.Run()
	endedAt := time.Now().UTC()
	result := processResult(command, stdout, stderr, startedAt, endedAt, runErr)

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return failureResult(result), &processFailure{kind: processFailureTimeout}
	}
	if ctx.Err() != nil {
		return failureResult(result), &processFailure{kind: processFailureCanceled}
	}
	if runContext.Err() != nil {
		return failureResult(result), &processFailure{kind: processFailureTimeout}
	}
	if stdout.exceeded {
		return failureResult(result), &processFailure{kind: processFailureStdoutLimit}
	}
	if stderr.exceeded {
		return stderrOverflowResult(result), &processFailure{kind: processFailureStderrLimit}
	}
	if runErr != nil {
		var exitError *exec.ExitError
		if errors.As(runErr, &exitError) {
			return failureResult(result), &processFailure{kind: processFailureExit, exitCode: exitError.ExitCode()}
		}
		return failureResult(result), &processFailure{kind: processFailureStart}
	}

	return result, nil
}

func processResult(
	command *exec.Cmd,
	stdout *boundedCapture,
	stderr *boundedCapture,
	startedAt time.Time,
	endedAt time.Time,
	runErr error,
) runner.Result {
	exitCode := 0
	if runErr != nil {
		exitCode = -1
		if command.ProcessState != nil {
			exitCode = command.ProcessState.ExitCode()
		}
	}
	return runner.Result{
		ExitCode:     exitCode,
		Stdout:       append([]byte(nil), stdout.bytes()...),
		StdoutSHA256: stdout.digest(),
		Stderr:       redact.Sanitize(string(stderr.bytes())),
		StderrSHA256: stderr.digest(),
		StartedAt:    startedAt,
		EndedAt:      endedAt,
	}
}

func failureResult(result runner.Result) runner.Result {
	result.Stdout = nil
	return result
}

func stderrOverflowResult(result runner.Result) runner.Result {
	result = failureResult(result)
	result.Stderr = redact.Sanitize("")
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type boundedCapture struct {
	buffer   bytes.Buffer
	hash     hash.Hash
	limit    int64
	written  int64
	exceeded bool
}

func newBoundedCapture(limit int64) *boundedCapture {
	return &boundedCapture{hash: sha256.New(), limit: limit}
}

func (capture *boundedCapture) Write(value []byte) (int, error) {
	_, _ = capture.hash.Write(value)
	capture.written += int64(len(value))
	remaining := capture.limit - int64(capture.buffer.Len())
	if remaining > 0 {
		length := int64(len(value))
		if length > remaining {
			length = remaining
		}
		_, _ = capture.buffer.Write(value[:length])
	}
	if capture.written > capture.limit {
		capture.exceeded = true
	}
	return len(value), nil
}

func (capture *boundedCapture) bytes() []byte {
	return capture.buffer.Bytes()
}

func (capture *boundedCapture) digest() string {
	return hex.EncodeToString(capture.hash.Sum(nil))
}
