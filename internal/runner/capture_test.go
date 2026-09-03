// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package runner_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/runner"
)

func TestBoundedCaptureReturnsCompletePayloadAtLimit(t *testing.T) {
	t.Parallel()

	capture, err := runner.NewBoundedCapture(6)
	if err != nil {
		t.Fatalf("NewBoundedCapture() error = %v", err)
	}
	for _, payload := range [][]byte{[]byte("abc"), []byte("def")} {
		written, writeErr := capture.Write(payload)
		if writeErr != nil || written != len(payload) {
			t.Fatalf("Write(%q) = (%d, %v)", payload, written, writeErr)
		}
	}

	got, err := capture.Bytes()
	if err != nil {
		t.Fatalf("Bytes() error = %v", err)
	}
	if string(got) != "abcdef" {
		t.Fatalf("Bytes() = %q, want %q", got, "abcdef")
	}
	if capture.SizeBytes() != 6 || capture.Exceeded() {
		t.Fatalf("capture metadata = (size %d, exceeded %t)", capture.SizeBytes(), capture.Exceeded())
	}
	const wantDigest = "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
	if capture.SHA256() != wantDigest {
		t.Fatalf("SHA256() = %q, want %q", capture.SHA256(), wantDigest)
	}

	got[0] = 'X'
	again, err := capture.Bytes()
	if err != nil || string(again) != "abcdef" {
		t.Fatalf("Bytes() aliases internal storage: (%q, %v)", again, err)
	}
}

func TestBoundedCaptureDrainsAndHidesOverflow(t *testing.T) {
	t.Parallel()

	capture, err := runner.NewBoundedCapture(5)
	if err != nil {
		t.Fatalf("NewBoundedCapture() error = %v", err)
	}
	const fullPayload = "topsecrettail"
	for _, payload := range []string{"top", "secret", "tail"} {
		written, writeErr := capture.Write([]byte(payload))
		if writeErr != nil || written != len(payload) {
			t.Fatalf("Write(%q) = (%d, %v)", payload, written, writeErr)
		}
	}

	got, err := capture.Bytes()
	if got != nil || !errors.Is(err, runner.ErrOutputLimitExceeded) {
		t.Fatalf("Bytes() = (%q, %v), want (nil, ErrOutputLimitExceeded)", got, err)
	}
	if !capture.Exceeded() || capture.SizeBytes() != int64(len(fullPayload)) {
		t.Fatalf("capture metadata = (size %d, exceeded %t)", capture.SizeBytes(), capture.Exceeded())
	}
	wantDigest := fmt.Sprintf("%x", sha256.Sum256([]byte(fullPayload)))
	if capture.SHA256() != wantDigest {
		t.Fatalf("SHA256() = %q, want %q", capture.SHA256(), wantDigest)
	}
	if strings.Contains(err.Error(), "top") || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "tail") {
		t.Fatalf("overflow error leaks payload: %v", err)
	}

	var limitError *runner.OutputLimitError
	if !errors.As(err, &limitError) {
		t.Fatalf("Bytes() error type = %T, want *OutputLimitError", err)
	}
	if limitError.LimitBytes != 5 || limitError.SizeBytes != int64(len(fullPayload)) || limitError.SHA256 != wantDigest {
		t.Fatalf("OutputLimitError = %#v", limitError)
	}
}

func TestBoundedCaptureSupportsConcurrentWriters(t *testing.T) {
	t.Parallel()

	capture, err := runner.NewBoundedCapture(32)
	if err != nil {
		t.Fatalf("NewBoundedCapture() error = %v", err)
	}

	var writers sync.WaitGroup
	for range 32 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			if _, writeErr := capture.Write([]byte("x")); writeErr != nil {
				t.Errorf("Write() error = %v", writeErr)
			}
		}()
	}
	writers.Wait()

	got, err := capture.Bytes()
	if err != nil {
		t.Fatalf("Bytes() error = %v", err)
	}
	if string(got) != strings.Repeat("x", 32) {
		t.Fatalf("Bytes() = %q", got)
	}
	if capture.SizeBytes() != 32 || capture.Exceeded() {
		t.Fatalf("capture metadata = (size %d, exceeded %t)", capture.SizeBytes(), capture.Exceeded())
	}
}

func TestBoundedCaptureRejectsInvalidLimitAndHandlesNilReceiver(t *testing.T) {
	t.Parallel()

	for _, limit := range []int64{0, -1} {
		capture, err := runner.NewBoundedCapture(limit)
		if capture != nil || !errors.Is(err, runner.ErrInvalidCaptureLimit) {
			t.Fatalf("NewBoundedCapture(%d) = (%#v, %v)", limit, capture, err)
		}
	}

	var capture *runner.BoundedCapture
	if written, err := capture.Write([]byte("payload")); written != 0 || !errors.Is(err, runner.ErrInvalidCaptureLimit) {
		t.Fatalf("nil Write() = (%d, %v)", written, err)
	}
	if payload, err := capture.Bytes(); payload != nil || !errors.Is(err, runner.ErrInvalidCaptureLimit) {
		t.Fatalf("nil Bytes() = (%q, %v)", payload, err)
	}
	if capture.SizeBytes() != 0 || capture.SHA256() != "" || capture.Exceeded() {
		t.Fatal("nil capture metadata methods returned non-zero values")
	}
}
