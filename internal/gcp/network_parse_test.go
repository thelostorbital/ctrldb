// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"strings"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
)

func TestNetworkDesiredFingerprintsMatchTheCompiledPlan(t *testing.T) {
	target := networkTarget(t)
	for _, kind := range networkKinds {
		intent := networkIntent(kind)
		expected, err := expectedNetworkResources(intent, networkStepResources(kind), target)
		if err != nil {
			t.Fatalf("%s expectedNetworkResources() error = %v", kind, err)
		}
		for index, resource := range expected {
			golden := goldenNetworkResources()[intent.ResourceIDs[index]]
			if resource.resource != golden {
				t.Fatalf("%s derived resource %#v != compiled %#v", kind, resource.resource, golden)
			}
		}
	}
	description := networkOwnershipDescription(goldenNetworkResources()["test-iap-firewall"])
	if description != "ctrldb-ownership/v1 workflow=WF-TEST-01 permanence=permanent-singleton resource=test-iap-firewall fingerprint=6c4eb5096ad2b4368afce138710ef7a9f766b4b715b14dbce4529fc4130964e1" {
		t.Fatalf("ownership description = %q", description)
	}
}

func TestNetworkParseRejectsHostileProviderOutputWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		kind   bootstrap.IntentKind
		output string
	}{
		{name: "empty", kind: bootstrap.IntentNetwork, output: ``},
		{name: "null", kind: bootstrap.IntentNetwork, output: `null`},
		{name: "object instead of array", kind: bootstrap.IntentNetwork, output: `{}`},
		{name: "malformed", kind: bootstrap.IntentNetwork, output: `[`},
		{name: "trailing", kind: bootstrap.IntentNetwork, output: presentNetwork + `{}`},
		{name: "duplicate key", kind: bootstrap.IntentNetwork, output: strings.Replace(presentNetwork, `"autoCreateSubnetworks":false`, `"autoCreateSubnetworks":false,"autoCreateSubnetworks":false`, 1)},
		{name: "unknown key", kind: bootstrap.IntentNetwork, output: strings.Replace(presentNetwork, `"autoCreateSubnetworks":false`, `"autoCreateSubnetworks":false,"unexpected":1`, 1)},
		{name: "two entries", kind: bootstrap.IntentNetwork, output: `[` + strings.TrimSuffix(strings.TrimPrefix(presentNetwork, "["), "]") + `,` + strings.TrimSuffix(strings.TrimPrefix(presentNetwork, "["), "]") + `]`},
		{name: "filter disobeyed", kind: bootstrap.IntentNetwork, output: strings.Replace(presentNetwork, `"name":"ctrldb-test-vpc"`, `"name":"ctrldb-test-vpc2"`, 1)},
		{name: "cross-project self link", kind: bootstrap.IntentNetwork, output: strings.Replace(presentNetwork, "projects/example-project/global", "projects/foreign-project/global", 1)},
		{name: "unknown api base", kind: bootstrap.IntentNetwork, output: strings.Replace(presentNetwork, "https://www.googleapis.com/compute/v1/", "https://example.invalid/compute/v1/", 1)},
		{name: "beta api base", kind: bootstrap.IntentNetwork, output: strings.Replace(presentNetwork, "compute/v1/", "compute/beta/", 1)},
		{name: "subnet cross-region", kind: bootstrap.IntentSubnet, output: strings.Replace(presentSubnet, `"region":"`+computeBase+`regions/us-central1"`, `"region":"`+computeBase+`regions/us-east1"`, 1)},
		{name: "subnet cross-project region", kind: bootstrap.IntentSubnet, output: strings.Replace(presentSubnet, `"region":"`+computeBase+`regions/us-central1"`, `"region":"https://www.googleapis.com/compute/v1/projects/foreign-project/regions/us-central1"`, 1)},
		{name: "router cross-region", kind: bootstrap.IntentNAT, output: strings.Replace(presentRouter, `"region":"`+computeBase+`regions/us-central1"`, `"region":"`+computeBase+`regions/us-east1"`, 1)},
		{name: "invalid utf-8", kind: bootstrap.IntentNetwork, output: strings.Replace(presentNetwork, "ctrldb-test-vpc", "ctrldb-test-\xffvpc", 1)},
		{name: "oversized", kind: bootstrap.IntentNetwork, output: strings.Repeat(" ", int(readStdoutLimit)+1) + presentNetwork},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := networkIntent(test.kind)
			target := networkTarget(t)
			client, fake := testNetworkClient(t, ok(test.output))
			result, err := client.ApplyStep(context.Background(), networkAuthorization(intent, target.Preflight), intent, networkStepResources(test.kind), target)
			assertNetworkFailure(t, test.name, err, NetworkFailureSchema, domain.MutationNotOccurred)
			assertNoCreate(t, fake.calls)
			if len(fake.calls) != 1 || len(result.Created) != 0 {
				t.Fatalf("calls = %d created = %d", len(fake.calls), len(result.Created))
			}
		})
	}
	// NAT observation rejects duplicates and hostile status output separately.
	nat := networkIntent(bootstrap.IntentNAT)
	for name, script := range map[string][]networkFakeStep{
		"duplicate nat":    {ok(presentRouter), ok(`[` + strings.Trim(presentNAT, "[]") + `,` + strings.Trim(presentNAT, "[]") + `]`)},
		"nat unknown key":  {ok(presentRouter), ok(strings.Replace(presentNAT, `"type":"PUBLIC"`, `"type":"PUBLIC","natIpAllocateOptio":"x"`, 1))},
		"status malformed": {ok(presentRouter), ok(presentNAT), ok(`{"result":`)},
		"status trailing":  {ok(presentRouter), ok(presentNAT), ok(presentStatus + `[]`)},
	} {
		target := networkTarget(t)
		client, fake := testNetworkClient(t, script...)
		_, err := client.ApplyStep(context.Background(), networkAuthorization(nat, target.Preflight), nat, networkStepResources(nat.Kind), target)
		assertNetworkFailure(t, name, err, NetworkFailureSchema, domain.MutationNotOccurred)
		assertNoCreate(t, fake.calls)
	}
}

func TestNetworkSelfLinkMatchingIsExact(t *testing.T) {
	providerID := "projects/example-project/global/networks/ctrldb-test-vpc"
	valid := []string{"https://www.googleapis.com/compute/v1/" + providerID, "https://compute.googleapis.com/compute/v1/" + providerID}
	for _, link := range valid {
		if !computeSelfLinkMatches(link, providerID) {
			t.Fatalf("valid link rejected: %s", link)
		}
	}
	invalid := []string{"", providerID, "https://www.googleapis.com/compute/v1/" + providerID + "/", "https://www.googleapis.com/compute/v1/" + providerID + "2",
		"https://www.googleapis.com/compute/beta/" + providerID, "http://www.googleapis.com/compute/v1/" + providerID}
	for _, link := range invalid {
		if computeSelfLinkMatches(link, providerID) {
			t.Fatalf("invalid link accepted: %s", link)
		}
	}
	for _, cidr := range []string{"10.40.0.0/24", "192.168.1.0/24", "172.16.0.0/12"} {
		if !canonicalPrivateIPv4Prefix(cidr) {
			t.Fatalf("private prefix rejected: %s", cidr)
		}
	}
	for _, cidr := range []string{"", "10.40.0.1/24", "203.0.113.0/24", "0.0.0.0/0", "10.40.0.0/32", "fd00::/64", "10.40.0.0"} {
		if canonicalPrivateIPv4Prefix(cidr) {
			t.Fatalf("non-canonical or public prefix accepted: %s", cidr)
		}
	}
}
