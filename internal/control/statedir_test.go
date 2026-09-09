// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateDirectoryRejectsUnsafeLocations(t *testing.T) {
	t.Parallel()
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkParent := t.TempDir()
	if err := os.Chmod(linkParent, 0o700); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(linkParent, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(linkParent, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(real, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"relative": "state", "unclean": t.TempDir() + "/./", "missing": filepath.Join(t.TempDir(), "missing"),
		"group readable": shared, "regular file": file,
		"symlink component": filepath.Join(linkParent, "link", "state"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewStateDirectory(path); !errors.Is(err, ErrInvalidStateDirectory) {
				t.Fatalf("NewStateDirectory(%q) error = %v", path, err)
			}
		})
	}
}

func TestEnvelopeWriteIsExclusivePrivateAndDurable(t *testing.T) {
	t.Parallel()
	directory := fixtureStateDirectory(t)
	envelope := fixtureEnvelope(t)
	if err := WriteBootstrapEnvelope(directory, envelope); err != nil {
		t.Fatalf("WriteBootstrapEnvelope() error: %v", err)
	}
	path := filepath.Join(directory.Path(), "bootstrap-envelope-"+fixtureOperationID+".json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("envelope file = %v, %v", info, err)
	}
	entries, _ := os.ReadDir(directory.Path())
	if len(entries) != 1 {
		t.Fatalf("temporary publish names remain: %v", entries)
	}
	if err := WriteBootstrapEnvelope(directory, envelope); !errors.Is(err, ErrEnvelopeConflict) {
		t.Fatalf("second write error = %v, want ErrEnvelopeConflict", err)
	}
	stored, err := ReadBootstrapEnvelope(directory, fixtureOperationID)
	if err != nil || stored.SHA256() != envelope.SHA256() {
		t.Fatalf("ReadBootstrapEnvelope() = %v, %v", stored.SHA256(), err)
	}
	ensured, err := EnsureBootstrapEnvelope(directory, envelope)
	if err != nil || ensured.SHA256() != envelope.SHA256() {
		t.Fatalf("EnsureBootstrapEnvelope(same) = %v, %v", ensured.SHA256(), err)
	}

	// A retry with any other envelope hash for the same operation is refused.
	seed := fixtureSeed(t)
	seed.SealedAt = seed.SealedAt.Add(time.Second)
	different, err := SealBootstrapEnvelope(seed)
	if err != nil || different.SHA256() == envelope.SHA256() {
		t.Fatalf("could not build a differing envelope: %v", err)
	}
	if _, err := EnsureBootstrapEnvelope(directory, different); !errors.Is(err, ErrEnvelopeConflict) {
		t.Fatalf("EnsureBootstrapEnvelope(different) error = %v", err)
	}
	if _, err := ReadBootstrapEnvelope(directory, "op-fedcba9876543210"); !errors.Is(err, ErrInvalidStateFile) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing envelope error = %v", err)
	}
}

func TestEnvelopeReadRejectsTamperedOrUnsafeFiles(t *testing.T) {
	t.Parallel()
	envelope := fixtureEnvelope(t)
	encoded, _ := envelope.CanonicalJSON()
	path := func(directory StateDirectory) string {
		return filepath.Join(directory.Path(), "bootstrap-envelope-"+fixtureOperationID+".json")
	}

	tampered := fixtureStateDirectory(t)
	mutated := append([]byte(nil), encoded...)
	mutated[len(mutated)/2] ^= 0x02
	if err := os.WriteFile(path(tampered), mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBootstrapEnvelope(tampered, fixtureOperationID); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("tampered read error = %v", err)
	}
	if _, err := EnsureBootstrapEnvelope(tampered, envelope); !errors.Is(err, ErrEnvelopeConflict) {
		t.Fatalf("ensure over tampered error = %v", err)
	}

	loose := fixtureStateDirectory(t)
	if err := os.WriteFile(path(loose), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBootstrapEnvelope(loose, fixtureOperationID); !errors.Is(err, ErrInvalidStateFile) {
		t.Fatalf("world-readable read error = %v", err)
	}

	linked := fixtureStateDirectory(t)
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path(linked)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBootstrapEnvelope(linked, fixtureOperationID); !errors.Is(err, ErrInvalidStateFile) {
		t.Fatalf("symlink read error = %v", err)
	}
	if err := WriteBootstrapEnvelope(linked, envelope); !errors.Is(err, ErrEnvelopeConflict) {
		t.Fatalf("write over symlink error = %v", err)
	}

	empty := fixtureStateDirectory(t)
	if err := os.WriteFile(path(empty), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBootstrapEnvelope(empty, fixtureOperationID); !errors.Is(err, ErrInvalidStateFile) {
		t.Fatalf("empty read error = %v", err)
	}
}
