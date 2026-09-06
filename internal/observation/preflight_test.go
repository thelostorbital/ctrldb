// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package observation

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestHarnessPreflightCanonicalizesAndDetachesValues(t *testing.T) {
	seed := validSeed()
	seed.Regions = append(seed.Regions, Region{Name: "test-region2", Availability: AvailabilityDown, ProviderID: provider("regions/test-region2")})
	seed.Zones = append(seed.Zones, Zone{Name: "test-region2-a", Region: "test-region2", Availability: AvailabilityUp, ProviderID: provider("zones/test-region2-a")})
	seed.MachineTypes = append(seed.MachineTypes, MachineType{Name: "legacy-small", Zone: testZone, GuestCPUs: 1, MemoryMiB: 1024, Deprecated: true, ProviderID: provider("zones/" + testZone + "/machineTypes/legacy-small")})
	seed.Resources = []Resource{
		{Kind: ResourceDisk, Name: "ctrldb-test-run-data", Project: testProject, Location: testZone, ProviderID: provider("zones/" + testZone + "/disks/ctrldb-test-run-data")},
		{Kind: ResourceNetwork, Name: "ctrldb-test-vpc", Project: testProject, Location: "global", ProviderID: provider("global/networks/ctrldb-test-vpc")},
	}
	first, err := NewHarnessPreflight(seed)
	if err != nil {
		t.Fatalf("NewHarnessPreflight() error = %v", err)
	}

	reordered := seed
	slices.Reverse(reordered.Regions)
	slices.Reverse(reordered.Resources)
	slices.Reverse(reordered.Schemas)
	second, err := NewHarnessPreflight(reordered)
	if err != nil {
		t.Fatalf("reordered NewHarnessPreflight() error = %v", err)
	}
	if first.Revision() != second.Revision() {
		t.Fatalf("revision changed after reordering: %s != %s", first.Revision(), second.Revision())
	}
	rediscovered := seed
	rediscovered.ObservedAt = seed.ObservedAt.Add(time.Minute)
	rediscovered.ValidUntil = seed.ValidUntil.Add(time.Minute)
	third := mustPreflight(t, rediscovered)
	if first.Revision() != third.Revision() {
		t.Fatal("content revision changed only because the observation window advanced")
	}
	if first.CompletenessPolicy() != GcloudCompletenessPolicy {
		t.Fatalf("CompletenessPolicy() = %q", first.CompletenessPolicy())
	}

	resources := first.Resources()
	resources[0].Name = "tampered"
	if first.Resources()[0].Name == "tampered" {
		t.Fatal("Resources() leaked mutable storage")
	}
	firewalls := first.Firewalls()
	firewalls[0].SourceRanges[0] = "192.0.2.0/24"
	if first.Firewalls()[0].SourceRanges[0] == "192.0.2.0/24" {
		t.Fatal("Firewalls() leaked nested mutable storage")
	}
	if !first.HasCollision(ResourceNetwork, "ctrldb-test-vpc") || first.HasCollision(ResourceNetwork, "absent") {
		t.Fatal("collision lookup did not use exact kind and name")
	}
	if got := first.CompatibleRegions(); len(got) != 1 || got[0].Name != testRegion {
		t.Fatalf("CompatibleRegions() = %v", got)
	}
	if got := first.CompatibleZones(); len(got) != 1 || got[0].Name != testZone {
		t.Fatalf("CompatibleZones() = %v", got)
	}
	if got := first.CompatibleMachineTypes(); len(got) != 1 || got[0].Name != "e2-standard-2" {
		t.Fatalf("CompatibleMachineTypes() = %v", got)
	}
	present, err := first.ProvesAbsenceAt(ResourceNetwork, "ctrldb-test-vpc", first.ObservedAt())
	if err != nil || present {
		t.Fatalf("present resource absence = %v, %v", present, err)
	}
	absent, err := first.ProvesAbsenceAt(ResourceNetwork, "absent", first.ObservedAt())
	if err != nil || !absent {
		t.Fatalf("absent resource proof = %v, %v", absent, err)
	}
	if _, err := first.ProvesAbsenceAt("unknown.kind", "absent", first.ObservedAt()); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("unknown kind error = %v", err)
	}
	if _, err := first.ProvesAbsenceAt(ResourceBucket, "globally-unique-name", first.ObservedAt()); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("project-local bucket absence error = %v", err)
	}
	if _, err := first.ProvesAbsenceAt(ResourceNetwork, "absent", first.ValidUntil()); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("stale absence error = %v", err)
	}
	if !first.FreshAt(first.ObservedAt()) || first.FreshAt(first.ValidUntil()) || first.FreshAt(first.ObservedAt().In(time.FixedZone("offset", 3600))) {
		t.Fatal("FreshAt() accepted an invalid freshness boundary")
	}
}

func TestHarnessPreflightAcceptsCompleteComputeProtocolDomain(t *testing.T) {
	seed := validSeed()
	seed.Firewalls[0].Allowed = []Protocol{
		{Name: "ipip"},
		{Name: "50", Ports: []string{"0", "0-65535"}},
	}
	if _, err := NewHarnessPreflight(seed); err != nil {
		t.Fatalf("NewHarnessPreflight() rejected supported protocols: %v", err)
	}
}

func TestServiceAccountImmutableIdentityChangesRevision(t *testing.T) {
	seed := validSeed()
	seed.Resources = []Resource{{
		Kind: ResourceServiceAccount, Name: "fixture@example-proj1.iam.gserviceaccount.com",
		Project: testProject, Location: "global",
		ProviderID:  "projects/example-proj1/serviceAccounts/fixture@example-proj1.iam.gserviceaccount.com",
		ImmutableID: "123456789012345678901",
	}, {
		Kind: ResourceServiceAccount, Name: "123456789-compute@developer.gserviceaccount.com",
		Project: testProject, Location: "global",
		ProviderID:  "projects/example-proj1/serviceAccounts/123456789-compute@developer.gserviceaccount.com",
		ImmutableID: "323456789012345678901",
	}}
	first := mustPreflight(t, seed)
	seed.Resources[0].ImmutableID = "223456789012345678901"
	second := mustPreflight(t, seed)
	if first.Revision() == second.Revision() {
		t.Fatal("service-account recreation did not change the observation revision")
	}
}

func TestHarnessPreflightCIDROverlapBoundaries(t *testing.T) {
	value := mustPreflight(t, validSeed())
	tests := []struct {
		cidr    string
		overlap bool
		invalid bool
	}{
		{cidr: "10.44.0.0/25", overlap: true},
		{cidr: "10.44.1.0/24", overlap: false},
		{cidr: "10.43.255.0/24", overlap: false},
		{cidr: "10.44.0.1/24", invalid: true},
		{cidr: "198.51.100.0/24", invalid: true},
		{cidr: "not-a-cidr", invalid: true},
	}
	for _, test := range tests {
		t.Run(test.cidr, func(t *testing.T) {
			got, err := value.CIDROverlapsAt(test.cidr, value.ObservedAt())
			if (err != nil) != test.invalid || got != test.overlap {
				t.Fatalf("CIDROverlaps() = %v, %v", got, err)
			}
		})
	}
	if _, err := value.CIDROverlapsAt("10.44.1.0/24", value.ValidUntil()); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("stale CIDR comparison error = %v", err)
	}
}

func TestHarnessPreflightDetectsOnlyEnabledPublicMongoDBIngress(t *testing.T) {
	seed := validSeed()
	seed.Firewalls = []FirewallRule{
		firewall("direct", "INGRESS", false, []string{"0.0.0.0/0"}, []Protocol{{Name: "tcp", Ports: []string{"27017"}}}),
		firewall("range", "INGRESS", false, []string{"0.0.0.0/0"}, []Protocol{{Name: "tcp", Ports: []string{"27000-27100"}}}),
		firewall("all-tcp", "INGRESS", false, []string{"0.0.0.0/0"}, []Protocol{{Name: "tcp"}}),
		firewall("udp", "INGRESS", false, []string{"0.0.0.0/0"}, []Protocol{{Name: "udp", Ports: []string{"27017"}}}),
		firewall("disabled", "INGRESS", true, []string{"0.0.0.0/0"}, []Protocol{{Name: "tcp", Ports: []string{"27017"}}}),
		firewall("egress", "EGRESS", false, []string{"0.0.0.0/0"}, []Protocol{{Name: "tcp", Ports: []string{"27017"}}}),
		firewall("private", "INGRESS", false, []string{"10.0.0.0/8"}, []Protocol{{Name: "tcp", Ports: []string{"27017"}}}),
		firewall("numeric-tcp", "INGRESS", false, []string{"0.0.0.0/0"}, []Protocol{{Name: "6"}}),
	}
	value := mustPreflight(t, seed)
	got, err := value.PublicMongoDBIngressAt(value.ObservedAt())
	if want := []string{"all-tcp", "direct", "numeric-tcp", "range"}; err != nil || !slices.Equal(got, want) {
		t.Fatalf("PublicMongoDBIngress() = %v, want %v", got, want)
	}
	if _, err := value.PublicMongoDBIngressAt(value.ValidUntil()); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("stale firewall evaluation error = %v", err)
	}
}

func TestHarnessPreflightRejectsIncompleteAmbiguousAndCrossProjectEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Seed)
	}{
		{name: "not exhaustive", mutate: func(seed *Seed) { seed.Exhaustive = false }},
		{name: "missing schema", mutate: func(seed *Seed) { seed.Schemas = seed.Schemas[1:] }},
		{name: "duplicate schema", mutate: func(seed *Seed) { seed.Schemas[0] = seed.Schemas[1] }},
		{name: "unsupported version", mutate: func(seed *Seed) { seed.GcloudVersion = "561.0.0" }},
		{name: "missing completeness policy", mutate: func(seed *Seed) { seed.CompletenessPolicy = "" }},
		{name: "cross project region", mutate: func(seed *Seed) {
			seed.Regions[0].ProviderID = "https://compute.googleapis.com/compute/v1/projects/other-proj1/regions/" + testRegion
		}},
		{name: "cross project resource", mutate: func(seed *Seed) {
			seed.Resources = []Resource{{Kind: ResourceDisk, Name: "fixture", Project: "other-proj1", Location: testZone, ProviderID: provider("zones/" + testZone + "/disks/fixture")}}
		}},
		{name: "resource provider path mismatch", mutate: func(seed *Seed) {
			seed.Resources = []Resource{{Kind: ResourceDisk, Name: "fixture", Project: testProject, Location: testZone, ProviderID: provider("zones/" + testZone + "/disks/other")}}
		}},
		{name: "malformed compute resource name", mutate: func(seed *Seed) {
			seed.Resources = []Resource{{Kind: ResourceNetwork, Name: "Invalid", Project: testProject, Location: "global", ProviderID: provider("global/networks/Invalid")}}
		}},
		{name: "zone provider path mismatch", mutate: func(seed *Seed) {
			seed.Zones[0].ProviderID = provider("zones/other-zone1-a")
		}},
		{name: "duplicate resource", mutate: func(seed *Seed) {
			item := Resource{Kind: ResourceNetwork, Name: "fixture", Project: testProject, Location: "global", ProviderID: provider("global/networks/fixture")}
			seed.Resources = []Resource{item, item}
		}},
		{name: "unsupported resource", mutate: func(seed *Seed) {
			seed.Resources = []Resource{{Kind: "compute.unknown", Name: "fixture", Project: testProject, Location: "global", ProviderID: provider("global/unknown/fixture")}}
		}},
		{name: "service account without immutable identity", mutate: func(seed *Seed) {
			seed.Resources = []Resource{{Kind: ResourceServiceAccount, Name: "fixture@example-proj1.iam.gserviceaccount.com", Project: testProject, Location: "global", ProviderID: "projects/example-proj1/serviceAccounts/fixture@example-proj1.iam.gserviceaccount.com"}}
		}},
		{name: "unexpected immutable identity", mutate: func(seed *Seed) {
			seed.Resources = []Resource{{Kind: ResourceDisk, Name: "fixture", Project: testProject, Location: testZone, ProviderID: provider("zones/" + testZone + "/disks/fixture"), ImmutableID: "123"}}
		}},
		{name: "unknown api", mutate: func(seed *Seed) { seed.APIs[0].State = APIUnknown }},
		{name: "duplicate api", mutate: func(seed *Seed) { seed.APIs = append(seed.APIs, seed.APIs[0]) }},
		{name: "zone outside region", mutate: func(seed *Seed) { seed.Zone = "other-region1-a" }},
		{name: "selected region down", mutate: func(seed *Seed) { seed.Regions[0].Availability = AvailabilityDown }},
		{name: "machine cross zone", mutate: func(seed *Seed) { seed.MachineTypes[0].Zone = "test-region1-b" }},
		{name: "noncanonical subnet", mutate: func(seed *Seed) { seed.SubnetRanges[0].CIDR = "10.44.0.1/24" }},
		{name: "invalid firewall port", mutate: func(seed *Seed) { seed.Firewalls[0].Allowed[0].Ports = []string{"27017x"} }},
		{name: "noncanonical firewall port", mutate: func(seed *Seed) { seed.Firewalls[0].Allowed[0].Ports = []string{"027017"} }},
		{name: "noncanonical firewall source", mutate: func(seed *Seed) { seed.Firewalls[0].SourceRanges = []string{"0.0.0.1/0"} }},
		{name: "duplicate firewall protocol", mutate: func(seed *Seed) {
			seed.Firewalls[0].Allowed = append(seed.Firewalls[0].Allowed, Protocol{Name: "tcp", Ports: []string{"22"}})
		}},
		{name: "out of range numeric firewall protocol", mutate: func(seed *Seed) { seed.Firewalls[0].Allowed[0].Name = "256" }},
		{name: "long evidence", mutate: func(seed *Seed) { seed.ValidUntil = seed.ObservedAt.Add(MaxEvidenceLifetime + time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := validSeed()
			test.mutate(&seed)
			_, err := NewHarnessPreflight(seed)
			if !errors.Is(err, ErrInvalidObservation) {
				t.Fatalf("error = %v, want ErrInvalidObservation", err)
			}
		})
	}
}

const (
	testProject = "example-proj1"
	testRegion  = "test-region1"
	testZone    = "test-region1-a"
)

func validSeed() Seed {
	observedAt := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	return Seed{
		Account: "operator@example.invalid", Project: testProject, Region: testRegion, Zone: testZone,
		GcloudVersion: SupportedGcloudVersion, CompletenessPolicy: GcloudCompletenessPolicy,
		ObservedAt: observedAt, ValidUntil: observedAt.Add(time.Minute),
		Schemas: RequiredSchemas(), Exhaustive: true,
		Regions:      []Region{{Name: testRegion, Availability: AvailabilityUp, ProviderID: provider("regions/" + testRegion)}},
		Zones:        []Zone{{Name: testZone, Region: testRegion, Availability: AvailabilityUp, ProviderID: provider("zones/" + testZone)}},
		MachineTypes: []MachineType{{Name: "e2-standard-2", Zone: testZone, GuestCPUs: 2, MemoryMiB: 8192, ProviderID: provider("zones/" + testZone + "/machineTypes/e2-standard-2")}},
		SubnetRanges: []SubnetRange{{Name: "existing-subnet", Project: testProject, Region: testRegion, CIDR: "10.44.0.0/24", ProviderID: provider("regions/" + testRegion + "/subnetworks/existing-subnet")}},
		APIs:         []APIService{{Name: "compute.googleapis.com", State: APIEnabled}},
		Firewalls:    []FirewallRule{firewall("safe", "INGRESS", false, []string{"10.0.0.0/8"}, []Protocol{{Name: "tcp", Ports: []string{"27017"}}})},
	}
}

func provider(suffix string) string {
	return "https://compute.googleapis.com/compute/v1/projects/" + testProject + "/" + suffix
}
func firewall(name, direction string, disabled bool, sources []string, allowed []Protocol) FirewallRule {
	return FirewallRule{Name: name, Project: testProject, ProviderID: provider("global/firewalls/" + name), Direction: direction, Disabled: disabled, SourceRanges: sources, Allowed: allowed}
}
func mustPreflight(t *testing.T, seed Seed) HarnessPreflight {
	t.Helper()
	value, err := NewHarnessPreflight(seed)
	if err != nil {
		t.Fatalf("NewHarnessPreflight() error = %v", err)
	}
	return value
}
