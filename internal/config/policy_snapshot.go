// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
)

var ErrPolicySnapshotUnavailable = errors.New("policy snapshot unavailable")

// PolicySnapshot is the immutable canonical representation and digest of the
// manifest fields that require separate approval before production use.
type PolicySnapshot struct {
	sha256        string
	canonicalJSON []byte
}

// SHA256 returns the lowercase hexadecimal digest of CanonicalJSON.
func (snapshot PolicySnapshot) SHA256() string {
	return snapshot.sha256
}

// CanonicalJSON returns a copy of the exact bytes covered by SHA256.
func (snapshot PolicySnapshot) CanonicalJSON() []byte {
	return append([]byte(nil), snapshot.canonicalJSON...)
}

// BuildPolicySnapshot extracts exactly access, capacity, gcp.identity, and
// policy from a structurally valid manifest and canonicalizes their fixed
// approval envelope. Schema defaults are never inserted.
func BuildPolicySnapshot(document ManifestDocument) (PolicySnapshot, error) {
	if err := ValidateManifestSchema(document); err != nil {
		return PolicySnapshot{}, err
	}

	var source policySnapshotSource
	if err := json.Unmarshal(document.JSON(), &source); err != nil {
		return PolicySnapshot{}, ErrPolicySnapshotUnavailable
	}
	if len(source.Spec.Access) == 0 || len(source.Spec.Capacity) == 0 ||
		len(source.Spec.GCP.Identity) == 0 || len(source.Spec.Policy) == 0 {
		return PolicySnapshot{}, ErrPolicySnapshotUnavailable
	}

	canonical := jsontext.Value(buildPolicyEnvelope(source))
	if !canonical.IsValid() {
		return PolicySnapshot{}, ErrPolicySnapshotUnavailable
	}
	if err := canonical.Canonicalize(jsontext.CanonicalizeRawInts(false)); err != nil {
		return PolicySnapshot{}, ErrPolicySnapshotUnavailable
	}

	digest := sha256.Sum256(canonical)
	return PolicySnapshot{
		sha256:        fmt.Sprintf("%x", digest),
		canonicalJSON: append([]byte(nil), canonical...),
	}, nil
}

type policySnapshotSource struct {
	Spec struct {
		Access   json.RawMessage `json:"access"`
		Capacity json.RawMessage `json:"capacity"`
		GCP      struct {
			Identity json.RawMessage `json:"identity"`
		} `json:"gcp"`
		Policy json.RawMessage `json:"policy"`
	} `json:"spec"`
}

func buildPolicyEnvelope(source policySnapshotSource) []byte {
	result := make([]byte, 0,
		len(source.Spec.Access)+len(source.Spec.Capacity)+
			len(source.Spec.GCP.Identity)+len(source.Spec.Policy)+64,
	)
	result = append(result, `{"access":`...)
	result = append(result, source.Spec.Access...)
	result = append(result, `,"capacity":`...)
	result = append(result, source.Spec.Capacity...)
	result = append(result, `,"identity":`...)
	result = append(result, source.Spec.GCP.Identity...)
	result = append(result, `,"policy":`...)
	result = append(result, source.Spec.Policy...)
	result = append(result, '}')
	return result
}
