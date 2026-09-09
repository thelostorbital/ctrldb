// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	envelopeFilePrefix  = "bootstrap-envelope-"
	handoffDirPrefix    = "bootstrap-handoff-"
	privateFileMode     = fs.FileMode(0o600)
	privateDirMode      = fs.FileMode(0o700)
	temporaryNamePrefix = "."
)

var (
	// ErrInvalidStateDirectory is returned when the CtrlDB state directory is
	// absent, not a directory, reachable through a symlink, or not private.
	ErrInvalidStateDirectory = errors.New("invalid CtrlDB state directory")
	// ErrEnvelopeConflict is returned when the state directory already holds
	// an envelope for the operation with a different hash.
	ErrEnvelopeConflict = errors.New("bootstrap envelope conflict")
	// ErrStateFileConflict is returned when an exclusive create finds the
	// target already present.
	ErrStateFileConflict = errors.New("state file already exists")
	// ErrInvalidStateFile is returned when a state file is not a private
	// regular file or cannot be read within bounds.
	ErrInvalidStateFile = errors.New("invalid state file")

	stateFileNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)
)

// StateDirectory is an explicit, validated, owner-private CtrlDB state
// directory. There is no default location.
type StateDirectory struct{ path string }

// NewStateDirectory validates an existing private directory given as an
// absolute clean path. It never creates or repairs the directory.
func NewStateDirectory(path string) (StateDirectory, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return StateDirectory{}, fmt.Errorf("%w: path must be absolute and clean", ErrInvalidStateDirectory)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return StateDirectory{}, fmt.Errorf("%w: must be an existing owner-private directory", ErrInvalidStateDirectory)
	}
	return StateDirectory{path: path}, nil
}

// Path returns the validated directory path.
func (directory StateDirectory) Path() string { return directory.path }

func (directory StateDirectory) envelopePath(operationID string) (string, error) {
	if directory.path == "" || !operationIDPattern.MatchString(operationID) {
		return "", fmt.Errorf("%w: envelope path", ErrInvalidStateDirectory)
	}
	return filepath.Join(directory.path, envelopeFilePrefix+operationID+".json"), nil
}

func (directory StateDirectory) handoffPath(operationID string) (string, error) {
	if directory.path == "" || !operationIDPattern.MatchString(operationID) {
		return "", fmt.Errorf("%w: handoff path", ErrInvalidStateDirectory)
	}
	return filepath.Join(directory.path, handoffDirPrefix+operationID), nil
}

// WriteBootstrapEnvelope publishes the envelope with exclusive create, mode
// 0600, fsync, and an atomic exclusive publish. An existing envelope is never
// overwritten; there is deliberately no removal function.
func WriteBootstrapEnvelope(directory StateDirectory, envelope BootstrapEnvelopeV1) error {
	encoded, err := envelope.CanonicalJSON()
	if err != nil {
		return err
	}
	target, err := directory.envelopePath(envelope.OperationID())
	if err != nil {
		return err
	}
	if err := writePrivateFileExclusive(target, encoded); err != nil {
		if errors.Is(err, ErrStateFileConflict) {
			return fmt.Errorf("%w: envelope already exists", ErrEnvelopeConflict)
		}
		return err
	}
	return nil
}

// ReadBootstrapEnvelope strictly reads and verifies the stored envelope.
func ReadBootstrapEnvelope(directory StateDirectory, operationID string) (BootstrapEnvelopeV1, error) {
	target, err := directory.envelopePath(operationID)
	if err != nil {
		return BootstrapEnvelopeV1{}, err
	}
	encoded, err := readPrivateFile(target, MaxEnvelopeBytes)
	if err != nil {
		return BootstrapEnvelopeV1{}, err
	}
	envelope, err := ParseBootstrapEnvelope(encoded)
	if err != nil {
		return BootstrapEnvelopeV1{}, err
	}
	if envelope.OperationID() != operationID {
		return BootstrapEnvelopeV1{}, invalidEnvelope("operation identity")
	}
	return envelope, nil
}

// EnsureBootstrapEnvelope writes the envelope when absent and otherwise
// accepts only a stored envelope with the identical hash (D-158 retry rule).
func EnsureBootstrapEnvelope(directory StateDirectory, envelope BootstrapEnvelopeV1) (BootstrapEnvelopeV1, error) {
	err := WriteBootstrapEnvelope(directory, envelope)
	if err == nil {
		return envelope, nil
	}
	if !errors.Is(err, ErrEnvelopeConflict) {
		return BootstrapEnvelopeV1{}, err
	}
	stored, readErr := ReadBootstrapEnvelope(directory, envelope.OperationID())
	if readErr != nil {
		return BootstrapEnvelopeV1{}, fmt.Errorf("%w: existing envelope is unreadable: %v", ErrEnvelopeConflict, readErr)
	}
	if stored.SHA256() != envelope.SHA256() {
		return BootstrapEnvelopeV1{}, fmt.Errorf("%w: existing envelope hash differs", ErrEnvelopeConflict)
	}
	return stored, nil
}

func writePrivateFileExclusive(target string, content []byte) error {
	directory := filepath.Dir(target)
	base := filepath.Base(target)
	if !stateFileNamePattern.MatchString(base) {
		return fmt.Errorf("%w: file name", ErrInvalidStateFile)
	}
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("%w: %s", ErrStateFileConflict, base)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrInvalidStateFile, base)
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Errorf("%w: temporary name", ErrInvalidStateFile)
	}
	temporary := filepath.Join(directory, temporaryNamePrefix+base+".tmp-"+hex.EncodeToString(suffix))
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateFileMode)
	if err != nil {
		return fmt.Errorf("%w: exclusive create", ErrInvalidStateFile)
	}
	if err := writeAndSync(file, content); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("%w: close", ErrInvalidStateFile)
	}
	// Link publishes atomically and fails closed when the target appeared
	// meanwhile; a rename would silently replace a concurrent writer's file.
	if err := os.Link(temporary, target); err != nil {
		_ = os.Remove(temporary)
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrStateFileConflict, base)
		}
		return fmt.Errorf("%w: publish", ErrInvalidStateFile)
	}
	_ = os.Remove(temporary)
	return syncDirectory(directory)
}

func writeAndSync(file *os.File, content []byte) error {
	if err := file.Chmod(privateFileMode); err != nil {
		return fmt.Errorf("%w: mode", ErrInvalidStateFile)
	}
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("%w: write", ErrInvalidStateFile)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("%w: fsync", ErrInvalidStateFile)
	}
	return nil
}

func syncDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("%w: directory", ErrInvalidStateFile)
	}
	defer func() { _ = handle.Close() }()
	if err := handle.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("%w: directory fsync", ErrInvalidStateFile)
	}
	return nil
}

func readPrivateFile(target string, limit int64) ([]byte, error) {
	info, err := os.Lstat(target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %w", ErrInvalidStateFile, fs.ErrNotExist)
		}
		return nil, fmt.Errorf("%w: stat", ErrInvalidStateFile)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != privateFileMode || info.Size() > limit || info.Size() == 0 {
		return nil, fmt.Errorf("%w: must be a non-empty private regular file within bounds", ErrInvalidStateFile)
	}
	file, err := os.Open(target)
	if err != nil {
		return nil, fmt.Errorf("%w: open", ErrInvalidStateFile)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("%w: file changed during read", ErrInvalidStateFile)
	}
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(io.LimitReader(file, limit+1)); err != nil || int64(buffer.Len()) != info.Size() {
		return nil, fmt.Errorf("%w: read", ErrInvalidStateFile)
	}
	return buffer.Bytes(), nil
}

// listStateFiles returns the sorted regular-file names in directory, ignoring
// temporary publish names.
func listStateFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: list", ErrInvalidStateFile)
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, temporaryNamePrefix) {
			continue
		}
		if !entry.Type().IsRegular() || !stateFileNamePattern.MatchString(name) {
			return nil, fmt.Errorf("%w: unexpected entry", ErrInvalidStateFile)
		}
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(path, privateDirMode); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: create", ErrInvalidStateDirectory)
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: must be an owner-private directory", ErrInvalidStateDirectory)
	}
	return nil
}
