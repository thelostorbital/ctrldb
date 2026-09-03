// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"math"
	"sync"
)

var (
	// ErrInvalidCaptureLimit is returned when a bounded capture has no limit.
	ErrInvalidCaptureLimit = errors.New("invalid capture limit")
	// ErrOutputLimitExceeded is returned instead of a partial payload.
	ErrOutputLimitExceeded = errors.New("output limit exceeded")
)

// OutputLimitError reports overflow using only size and digest metadata.
type OutputLimitError struct {
	LimitBytes int64
	SizeBytes  int64
	SHA256     string
}

// Error implements error without including captured output.
func (failure *OutputLimitError) Error() string {
	return fmt.Sprintf(
		"%s: limit=%d bytes size=%d bytes sha256=%s",
		ErrOutputLimitExceeded,
		failure.LimitBytes,
		failure.SizeBytes,
		failure.SHA256,
	)
}

// Unwrap supports errors.Is with ErrOutputLimitExceeded.
func (failure *OutputLimitError) Unwrap() error {
	return ErrOutputLimitExceeded
}

// BoundedCapture drains and hashes an entire stream while retaining bytes only
// when the complete stream remains within its configured limit.
type BoundedCapture struct {
	mu       sync.Mutex
	limit    int64
	size     int64
	exceeded bool
	digest   hash.Hash
	buffer   bytes.Buffer
}

// NewBoundedCapture creates a stream capture with a positive byte limit.
func NewBoundedCapture(limitBytes int64) (*BoundedCapture, error) {
	if limitBytes <= 0 {
		return nil, fmt.Errorf("%w: must be positive", ErrInvalidCaptureLimit)
	}

	return &BoundedCapture{limit: limitBytes, digest: sha256.New()}, nil
}

// Write implements io.Writer. Overflow never stops draining the producer.
func (capture *BoundedCapture) Write(payload []byte) (int, error) {
	if capture == nil {
		return 0, fmt.Errorf("%w: nil capture", ErrInvalidCaptureLimit)
	}

	capture.mu.Lock()
	defer capture.mu.Unlock()

	_, _ = capture.digest.Write(payload)
	if int64(len(payload)) > math.MaxInt64-capture.size {
		capture.size = math.MaxInt64
		capture.exceeded = true
		capture.buffer.Reset()
		return len(payload), nil
	}
	capture.size += int64(len(payload))
	if capture.exceeded || capture.size > capture.limit {
		capture.exceeded = true
		capture.buffer.Reset()
		return len(payload), nil
	}
	_, _ = capture.buffer.Write(payload)

	return len(payload), nil
}

// Bytes returns a copy of the complete payload, or an error containing only
// safe size and digest metadata after overflow.
func (capture *BoundedCapture) Bytes() ([]byte, error) {
	if capture == nil {
		return nil, fmt.Errorf("%w: nil capture", ErrInvalidCaptureLimit)
	}

	capture.mu.Lock()
	defer capture.mu.Unlock()

	if capture.exceeded {
		return nil, &OutputLimitError{
			LimitBytes: capture.limit,
			SizeBytes:  capture.size,
			SHA256:     fmt.Sprintf("%x", capture.digest.Sum(nil)),
		}
	}

	result := make([]byte, capture.buffer.Len())
	copy(result, capture.buffer.Bytes())

	return result, nil
}

// SizeBytes returns the number of bytes observed, including overflow bytes.
func (capture *BoundedCapture) SizeBytes() int64 {
	if capture == nil {
		return 0
	}

	capture.mu.Lock()
	defer capture.mu.Unlock()

	return capture.size
}

// SHA256 returns the digest of every byte observed so far.
func (capture *BoundedCapture) SHA256() string {
	if capture == nil {
		return ""
	}

	capture.mu.Lock()
	defer capture.mu.Unlock()

	return fmt.Sprintf("%x", capture.digest.Sum(nil))
}

// Exceeded reports whether the complete payload is unavailable by policy.
func (capture *BoundedCapture) Exceeded() bool {
	if capture == nil {
		return false
	}

	capture.mu.Lock()
	defer capture.mu.Unlock()

	return capture.exceeded
}
