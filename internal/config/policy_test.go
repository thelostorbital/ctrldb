// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestValidateManifestPolicyAcceptsCompleteFixture(t *testing.T) {
	t.Parallel()

	document := decodePolicyManifest(t, manifestFixtureMap(t))
	if err := ValidateManifestPolicy(document); err != nil {
		t.Fatalf("ValidateManifestPolicy() unexpected error: %v", err)
	}
}

func TestValidateManifestPolicyAppliesClassCoolingOffDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		class    string
		cooling  string
		validity string
	}{
		{class: "production", cooling: "10m", validity: "40m"},
		{class: "staging", cooling: "5m", validity: "35m"},
		{class: "rehearsal", cooling: "0s", validity: "30m"},
		{class: "disposable", cooling: "0s", validity: "30m"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.class, func(t *testing.T) {
			t.Parallel()

			manifest := manifestFixtureMap(t)
			metadata := nestedMap(t, manifest, "metadata")
			metadata["name"] = test.class
			metadata["class"] = test.class
			if test.class == "production" {
				nestedMap(t, manifest, "spec", "gcp", "identity")["mutation"] = "impersonate"
			}
			policy := nestedMap(t, manifest, "spec", "policy")
			policy["dataDestructiveCoolingOff"] = test.cooling
			policy["planValidity"] = test.validity

			if err := ValidateManifestPolicy(decodePolicyManifest(t, manifest)); err != nil {
				t.Fatalf("ValidateManifestPolicy() unexpected error: %v", err)
			}
		})
	}
}

func TestValidateManifestPolicyRequiresAcknowledgementForRelaxedClassDefault(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		class   string
		cooling string
	}{
		{class: "production", cooling: "9m"},
		{class: "staging", cooling: "4m"},
	} {
		test := test
		t.Run(test.class, func(t *testing.T) {
			t.Parallel()

			manifest := manifestFixtureMap(t)
			metadata := nestedMap(t, manifest, "metadata")
			metadata["name"] = test.class
			metadata["class"] = test.class
			if test.class == "production" {
				nestedMap(t, manifest, "spec", "gcp", "identity")["mutation"] = "impersonate"
			}
			policy := nestedMap(t, manifest, "spec", "policy")
			policy["dataDestructiveCoolingOff"] = test.cooling
			policy["planValidity"] = "1h"

			err := ValidateManifestPolicy(decodePolicyManifest(t, manifest))
			assertPolicyViolation(t, err, ManifestPolicyViolation{
				Rule: "CFG-02", Path: "/spec/policy/dataDestructiveCoolingOff",
			})

			nestedMap(t, manifest, "spec", "policy", "overrides")["acknowledged"] = true
			if err := ValidateManifestPolicy(decodePolicyManifest(t, manifest)); err != nil {
				t.Fatalf("ValidateManifestPolicy(acknowledged) unexpected error: %v", err)
			}
		})
	}
}

func TestValidateManifestPolicyRequiresPlanValidityBeyondCoolingOff(t *testing.T) {
	t.Parallel()

	manifest := manifestFixtureMap(t)
	policy := nestedMap(t, manifest, "spec", "policy")
	policy["dataDestructiveCoolingOff"] = "10m"
	policy["planValidity"] = "39m"
	err := ValidateManifestPolicy(decodePolicyManifest(t, manifest))
	assertPolicyViolation(t, err, ManifestPolicyViolation{
		Rule: "CFG-02", Path: "/spec/policy/planValidity",
	})

	policy["planValidity"] = "40m"
	if err := ValidateManifestPolicy(decodePolicyManifest(t, manifest)); err != nil {
		t.Fatalf("ValidateManifestPolicy(boundary) unexpected error: %v", err)
	}
}

func TestValidateManifestPolicyHandlesUnboundedDurationsWithoutOverflow(t *testing.T) {
	t.Parallel()

	manifest := manifestFixtureMap(t)
	policy := nestedMap(t, manifest, "spec", "policy")
	policy["dataDestructiveCoolingOff"] = "999999999999999999999999h"
	policy["planValidity"] = "1h"

	err := ValidateManifestPolicy(decodePolicyManifest(t, manifest))
	assertPolicyViolation(t, err, ManifestPolicyViolation{
		Rule: "CFG-02", Path: "/spec/policy/planValidity",
	})
}

func TestValidateManifestPolicyEnforcesResidencyAcrossReferencedLocations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		path   string
		mutate func(*testing.T, map[string]any)
	}{
		{name: "GCP region", path: "/spec/gcp/region", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "gcp")["region"] = "europe-west1"
		}},
		{name: "GCP zone", path: "/spec/gcp/zone", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "gcp")["zone"] = "europe-west1-b"
		}},
		{name: "topology home region", path: "/spec/topology/homeRegion", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "topology")["homeRegion"] = "europe-west1"
		}},
		{name: "host member zone", path: "/spec/host/members/0/zone", mutate: func(t *testing.T, manifest map[string]any) {
			members := nestedMap(t, manifest, "spec", "host")["members"].([]any)
			members[0].(map[string]any)["zone"] = "europe-west1-b"
		}},
		{name: "regional disk zone", path: "/spec/host/dataDisk/replicaZones/0", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "host", "dataDisk")["replicaZones"] = []any{"europe-west1-b"}
		}},
		{name: "secrets escrow region", path: "/spec/host/secretsEscrow/replicationRegions/0", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "host", "secretsEscrow")["replicationRegions"] = []any{"europe-west1"}
		}},
		{name: "topology member zone", path: "/spec/topology/members/0/zone", mutate: func(t *testing.T, manifest map[string]any) {
			members := nestedMap(t, manifest, "spec", "topology")["members"].([]any)
			members[0].(map[string]any)["zone"] = "europe-west1-b"
		}},
		{name: "topology member region mismatch", path: "/spec/topology/members/0/region", mutate: func(t *testing.T, manifest map[string]any) {
			members := nestedMap(t, manifest, "spec", "topology")["members"].([]any)
			members[0].(map[string]any)["region"] = "us-east1"
		}},
		{name: "backup replication region", path: "/spec/pbm/replication/regions/0", mutate: func(t *testing.T, manifest map[string]any) {
			nestedMap(t, manifest, "spec", "pbm", "replication")["regions"] = []any{"europe-west1"}
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			manifest := manifestFixtureMap(t)
			test.mutate(t, manifest)
			err := ValidateManifestPolicy(decodePolicyManifest(t, manifest))
			assertPolicyViolation(t, err, ManifestPolicyViolation{Rule: "CFG-09", Path: test.path})
		})
	}
}

func TestManifestPolicyViolationsAreSortedDeduplicatedAndCopied(t *testing.T) {
	t.Parallel()

	manifest := manifestFixtureMap(t)
	nestedMap(t, manifest, "spec", "gcp")["zone"] = "europe-west1-b"
	nestedMap(t, manifest, "spec", "topology")["homeRegion"] = "europe-west1"

	err := ValidateManifestPolicy(decodePolicyManifest(t, manifest))
	var policyErr *ManifestPolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("error type = %T; want *ManifestPolicyError", err)
	}
	want := []ManifestPolicyViolation{
		{Rule: "CFG-09", Path: "/spec/gcp/zone"},
		{Rule: "CFG-09", Path: "/spec/topology/homeRegion"},
	}
	if got := policyErr.Violations(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Violations() = %v; want %v", got, want)
	}

	violations := policyErr.Violations()
	violations[0].Path = "/changed"
	if got := policyErr.Violations(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Violations() exposed mutable state: got %v; want %v", got, want)
	}
}

func TestManifestPolicyErrorsDoNotRenderRejectedValues(t *testing.T) {
	t.Parallel()

	const marker = "europe-west1"
	manifest := manifestFixtureMap(t)
	nestedMap(t, manifest, "spec", "topology")["homeRegion"] = marker

	err := ValidateManifestPolicy(decodePolicyManifest(t, manifest))
	if !errors.Is(err, ErrManifestPolicyViolation) {
		t.Fatalf("error = %v; want ErrManifestPolicyViolation", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("policy error rendered the rejected value")
	}
}

func TestValidateManifestPolicyRejectsStructurallyInvalidManifest(t *testing.T) {
	t.Parallel()

	manifest := manifestFixtureMap(t)
	delete(nestedMap(t, manifest, "spec"), "policy")
	document, err := DecodeManifestEnvelope(marshalManifest(t, manifest))
	if err != nil {
		t.Fatalf("DecodeManifestEnvelope() unexpected error: %v", err)
	}
	err = ValidateManifestPolicy(document)
	if !errors.Is(err, ErrManifestSchemaViolation) {
		t.Fatalf("ValidateManifestPolicy() error = %v; want ErrManifestSchemaViolation", err)
	}
}

func decodePolicyManifest(t *testing.T, manifest map[string]any) ManifestDocument {
	t.Helper()

	document, err := DecodeManifest(marshalManifest(t, manifest))
	if err != nil {
		t.Fatalf("DecodeManifest() unexpected error: %v", err)
	}
	return document
}

func assertPolicyViolation(t *testing.T, err error, want ManifestPolicyViolation) {
	t.Helper()

	if !errors.Is(err, ErrManifestPolicyViolation) {
		t.Fatalf("error = %v; want ErrManifestPolicyViolation", err)
	}
	var policyErr *ManifestPolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("error type = %T; want *ManifestPolicyError", err)
	}
	for _, got := range policyErr.Violations() {
		if got == want {
			return
		}
	}
	t.Fatalf("violations = %v; want to contain %v", policyErr.Violations(), want)
}
