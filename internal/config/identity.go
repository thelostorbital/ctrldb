// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package config defines and validates CtrlDB's non-secret configuration
// boundary without performing file, process, network, or cloud I/O.
package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

const (
	// ManifestAPIVersion is the only manifest API version understood by this
	// release line.
	ManifestAPIVersion = "ctrldb.ctrlboard.dev/v1alpha1"
	// ManifestKind is the only top-level manifest kind understood by CtrlDB.
	ManifestKind = "MongoEnvironment"
)

var ErrInvalidManifestIdentity = errors.New("invalid manifest identity")

var environmentNamePattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ManifestIdentity is the stable header shared by every manifest version.
type ManifestIdentity struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Metadata   ManifestMetadata `json:"metadata"`
}

// ManifestMetadata selects the environment and its baseline safety class.
type ManifestMetadata struct {
	Name  string                  `json:"name"`
	Class domain.EnvironmentClass `json:"class"`
}

// ValidateManifestIdentity rejects unknown versions, kinds, classes, and
// environment names outside the stable DNS-label-style grammar.
func ValidateManifestIdentity(identity ManifestIdentity) error {
	if identity.APIVersion != ManifestAPIVersion {
		return identityError("apiVersion", "must equal "+ManifestAPIVersion)
	}
	if identity.Kind != ManifestKind {
		return identityError("kind", "must equal "+ManifestKind)
	}
	if !environmentNamePattern.MatchString(identity.Metadata.Name) {
		return identityError("metadata.name", "must be a lowercase DNS-label-style name of 1 to 63 characters")
	}
	if !identity.Metadata.Class.Valid() {
		return identityError("metadata.class", "unknown value")
	}
	if identity.Metadata.Class != domain.EnvironmentDisposable &&
		(identity.Metadata.Name == "test" || strings.HasPrefix(identity.Metadata.Name, "test-")) {
		return identityError("metadata.name", "the test namespace is reserved for disposable environments")
	}

	return nil
}

func identityError(path, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidManifestIdentity, path, reason)
}
