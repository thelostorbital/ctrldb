// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestBuildPolicySnapshotKnownVector(t *testing.T) {
	t.Parallel()

	document, err := DecodeManifest(readManifestFixture(t))
	if err != nil {
		t.Fatalf("DecodeManifest() unexpected error: %v", err)
	}
	snapshot, err := BuildPolicySnapshot(document)
	if err != nil {
		t.Fatalf("BuildPolicySnapshot() unexpected error: %v", err)
	}

	const wantDigest = "664820dbb919cf8fcfc1a88d6570a407f60df9d95c7b718fb0b4a598cec58434"
	if got := snapshot.SHA256(); got != wantDigest {
		t.Fatalf("SHA256() = %q; want known vector %q", got, wantDigest)
	}
	digest := sha256.Sum256(snapshot.CanonicalJSON())
	if got := fmt.Sprintf("%x", digest); got != snapshot.SHA256() {
		t.Fatalf("SHA256() = %q; canonical bytes hash to %q", snapshot.SHA256(), got)
	}
}

func TestPolicySnapshotCoversExactlyApprovedSubtrees(t *testing.T) {
	t.Parallel()

	base := snapshotForManifest(t, manifestFixtureMap(t))

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "access", mutate: func(manifest map[string]any) {
			nestedMap(t, manifest, "spec", "access")["maxLeaseHours"] = 23
		}},
		{name: "capacity", mutate: func(manifest map[string]any) {
			nestedMap(t, manifest, "spec", "capacity")["maxDataDiskGiB"] = 501
		}},
		{name: "identity", mutate: func(manifest map[string]any) {
			nestedMap(t, manifest, "spec", "gcp", "identity")["discovery"] = "impersonate"
		}},
		{name: "policy", mutate: func(manifest map[string]any) {
			nestedMap(t, manifest, "spec", "policy")["rpoMinutes"] = 14
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			manifest := manifestFixtureMap(t)
			test.mutate(manifest)
			changed := snapshotForManifest(t, manifest)
			if changed.SHA256() == base.SHA256() {
				t.Fatalf("changing %s did not change the policy digest", test.name)
			}
		})
	}

	for index := range 40 {
		manifest := manifestFixtureMap(t)
		spec := nestedMap(t, manifest, "spec")
		spec["docs"].(map[string]any)["repositoryPath"] = fmt.Sprintf("./docs-%d", index)
		spec["mongodb"].(map[string]any)["replicaSet"] = fmt.Sprintf("rs%d", index)
		spec["migration"].(map[string]any)["sourceRunningDays"] = index
		nestedMap(t, manifest, "metadata")["name"] = fmt.Sprintf("staging-%d", index)

		got := snapshotForManifest(t, manifest)
		if got.SHA256() != base.SHA256() {
			t.Fatalf("non-policy fixture %d changed the policy digest", index)
		}
	}
}

func TestPolicySnapshotCanonicalizesEquivalentManifestSyntax(t *testing.T) {
	t.Parallel()

	anchored := string(readManifestFixture(t))
	anchored = strings.Replace(anchored, "maxLeaseHours: 24", "maxLeaseHours: &lease 24", 1)
	anchored = strings.Replace(anchored, "maxTotalLeaseHours: 72", "maxTotalLeaseHours: *lease", 1)
	anchored = strings.Replace(anchored, "destructiveOperations: interactive-only", `destructiveOperations: "interactive-only"`, 1)
	anchored = strings.Replace(
		anchored,
		"    rpoMinutes: 15\n    regionalDisasterRpoMinutes: 60",
		"    regionalDisasterRpoMinutes: 60\n    rpoMinutes: 15",
		1,
	)

	expanded := string(readManifestFixture(t))
	expanded = strings.Replace(expanded, "maxTotalLeaseHours: 72", "maxTotalLeaseHours: 24", 1)

	anchoredDocument, err := DecodeManifest([]byte(anchored))
	if err != nil {
		t.Fatalf("DecodeManifest(anchored) unexpected error: %v", err)
	}
	expandedDocument, err := DecodeManifest([]byte(expanded))
	if err != nil {
		t.Fatalf("DecodeManifest(expanded) unexpected error: %v", err)
	}
	anchoredSnapshot, err := BuildPolicySnapshot(anchoredDocument)
	if err != nil {
		t.Fatalf("BuildPolicySnapshot(anchored) unexpected error: %v", err)
	}
	expandedSnapshot, err := BuildPolicySnapshot(expandedDocument)
	if err != nil {
		t.Fatalf("BuildPolicySnapshot(expanded) unexpected error: %v", err)
	}
	if anchoredSnapshot.SHA256() != expandedSnapshot.SHA256() {
		t.Fatalf("equivalent YAML produced different digests: %s != %s", anchoredSnapshot.SHA256(), expandedSnapshot.SHA256())
	}
}

func TestPolicySnapshotCanonicalizesEquivalentNumberSyntax(t *testing.T) {
	t.Parallel()

	manifest := marshalManifest(t, manifestFixtureMap(t))
	decimal := strings.Replace(
		string(manifest),
		`"costCeilingUSDPerMonth":300`,
		`"costCeilingUSDPerMonth":300.0`,
		1,
	)
	if decimal == string(manifest) {
		t.Fatal("test fixture did not contain expected numeric token")
	}

	integerDocument, err := DecodeManifest(manifest)
	if err != nil {
		t.Fatalf("DecodeManifest(integer) unexpected error: %v", err)
	}
	decimalDocument, err := DecodeManifest([]byte(decimal))
	if err != nil {
		t.Fatalf("DecodeManifest(decimal) unexpected error: %v", err)
	}
	integerSnapshot, err := BuildPolicySnapshot(integerDocument)
	if err != nil {
		t.Fatalf("BuildPolicySnapshot(integer) unexpected error: %v", err)
	}
	decimalSnapshot, err := BuildPolicySnapshot(decimalDocument)
	if err != nil {
		t.Fatalf("BuildPolicySnapshot(decimal) unexpected error: %v", err)
	}
	if integerSnapshot.SHA256() != decimalSnapshot.SHA256() {
		t.Fatalf("equivalent numbers produced different digests: %s != %s", integerSnapshot.SHA256(), decimalSnapshot.SHA256())
	}
}

func TestPolicySnapshotPreservesDistinctLargeIntegers(t *testing.T) {
	t.Parallel()

	first := manifestFixtureMap(t)
	nestedMap(t, first, "spec", "policy")["costCeilingUSDPerMonth"] = json.Number("9007199254740992")
	second := manifestFixtureMap(t)
	nestedMap(t, second, "spec", "policy")["costCeilingUSDPerMonth"] = json.Number("9007199254740993")

	firstSnapshot := snapshotForManifest(t, first)
	secondSnapshot := snapshotForManifest(t, second)
	if firstSnapshot.SHA256() == secondSnapshot.SHA256() {
		t.Fatal("distinct large integer policy values produced the same digest")
	}
	if !strings.Contains(string(secondSnapshot.CanonicalJSON()), "9007199254740993") {
		t.Fatal("canonical policy snapshot rounded a large integer")
	}
}

func TestPolicySnapshotEnvelopeIsClosedAndStable(t *testing.T) {
	t.Parallel()

	snapshot := snapshotForManifest(t, manifestFixtureMap(t))
	var envelope map[string]any
	if err := json.Unmarshal(snapshot.CanonicalJSON(), &envelope); err != nil {
		t.Fatalf("json.Unmarshal(CanonicalJSON()) unexpected error: %v", err)
	}
	got := make([]string, 0, len(envelope))
	for key := range envelope {
		got = append(got, key)
	}
	sort.Strings(got)
	want := []string{"access", "capacity", "identity", "policy"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("policy snapshot keys = %v; want %v", got, want)
	}

	first := snapshot.CanonicalJSON()
	first[0] = '['
	if got := snapshot.CanonicalJSON()[0]; got != '{' {
		t.Fatalf("CanonicalJSON() exposed mutable state: first byte = %q", got)
	}
}

func TestBuildPolicySnapshotRejectsInvalidManifest(t *testing.T) {
	t.Parallel()

	manifest := manifestFixtureMap(t)
	delete(nestedMap(t, manifest, "spec"), "policy")
	document, err := DecodeManifestEnvelope(marshalManifest(t, manifest))
	if err != nil {
		t.Fatalf("DecodeManifestEnvelope() unexpected error: %v", err)
	}
	_, err = BuildPolicySnapshot(document)
	if !errors.Is(err, ErrManifestSchemaViolation) {
		t.Fatalf("BuildPolicySnapshot() error = %v; want ErrManifestSchemaViolation", err)
	}
}

func snapshotForManifest(t *testing.T, manifest map[string]any) PolicySnapshot {
	t.Helper()

	document, err := DecodeManifest(marshalManifest(t, manifest))
	if err != nil {
		t.Fatalf("DecodeManifest() unexpected error: %v", err)
	}
	snapshot, err := BuildPolicySnapshot(document)
	if err != nil {
		t.Fatalf("BuildPolicySnapshot() unexpected error: %v", err)
	}
	return snapshot
}
