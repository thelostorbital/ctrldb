// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/observation"
)

func ownSubnetRange() observation.SubnetRange {
	return observation.SubnetRange{Name: "ctrldb-test-subnet", Project: networkTestProject, Region: networkTestRegion, CIDR: "10.40.0.0/24",
		ProviderID: computeBase + "regions/us-central1/subnetworks/ctrldb-test-subnet"}
}

func TestNetworkClientRejectsOverlappingCIDRFromTheFreshPreflightBeforeAnyProcess(t *testing.T) {
	intent := networkIntent(bootstrap.IntentSubnet)
	foreign := func(cidr string) observation.SubnetRange {
		return observation.SubnetRange{Name: "shared-services", Project: networkTestProject, Region: "us-east1", CIDR: cidr,
			ProviderID: computeBase + "regions/us-east1/subnetworks/shared-services"}
	}
	sameNameElsewhere := ownSubnetRange()
	sameNameElsewhere.Region = "us-east1"
	sameNameElsewhere.ProviderID = computeBase + "regions/us-east1/subnetworks/ctrldb-test-subnet"
	secondary := ownSubnetRange()
	secondary.Secondary = true
	widerOwn := ownSubnetRange()
	widerOwn.CIDR = "10.40.0.0/23"
	overlapping := map[string][]observation.SubnetRange{
		"exact foreign range":         {foreign("10.40.0.0/24")},
		"wider foreign range":         {foreign("10.40.0.0/16")},
		"narrower foreign range":      {foreign("10.40.0.128/25")},
		"same name in another region": {sameNameElsewhere},
		"own name as secondary range": {secondary},
		"own name with wider range":   {widerOwn},
		"own plus foreign":            {ownSubnetRange(), foreign("10.40.0.0/24")},
	}
	for name, ranges := range overlapping {
		target := networkTarget(t)
		target.Preflight = networkPreflight(t, ranges)
		client, fake := testNetworkClient(t, createScript(bootstrap.IntentSubnet)...)
		_, err := client.ApplyStep(context.Background(), networkAuthorization(intent, target.Preflight), intent, networkStepResources(intent.Kind), target)
		assertNetworkFailure(t, name, err, NetworkFailureTarget, domain.MutationNotOccurred)
		if len(fake.calls) != 0 {
			t.Fatalf("%s reached a process", name)
		}
	}
	// A non-overlapping discovered range and the desired subnet's own exact
	// primary range (a retry after a successful create) are both admitted.
	for name, ranges := range map[string][]observation.SubnetRange{"disjoint": {foreign("10.41.0.0/24")}, "own exact range": {ownSubnetRange()}} {
		target := networkTarget(t)
		target.Preflight = networkPreflight(t, ranges)
		client, fake := testNetworkClient(t, presentScript(bootstrap.IntentSubnet)...)
		result, err := client.ApplyStep(context.Background(), networkAuthorization(intent, target.Preflight), intent, networkStepResources(intent.Kind), target)
		if err != nil || result.Resources[0].Outcome != NetworkResourceAlreadyPresent {
			t.Fatalf("%s error = %v result = %#v", name, err, result)
		}
		assertNoCreate(t, fake.calls)
	}
}

func TestNetworkClientRetriesConvergeWithoutASecondCreate(t *testing.T) {
	for _, kind := range networkKinds {
		intent := networkIntent(kind)
		target := networkTarget(t)
		// Attempt 1: the create succeeds but the post-create observation is
		// cut off by a process failure, so the step reports an occurred but
		// unverified mutation.
		client, fake := testNetworkClient(t, ok("[]"), ok(""), networkFakeStep{err: errors.New("interrupted")})
		first := networkAuthorization(intent, target.Preflight)
		result, err := client.ApplyStep(context.Background(), first, intent, networkStepResources(kind), target)
		assertNetworkFailure(t, string(kind)+" attempt 1", err, NetworkFailureUnverified, domain.MutationOccurred)
		if len(result.Created) != 1 || result.Created[0].ResourceID != intent.ResourceIDs[0] {
			t.Fatalf("%s attempt 1 created = %#v", kind, result.Created)
		}
		creates := countCreates(fake.calls)
		// Attempt 2 with the same fresh observation finds the resource and
		// continues with the remaining resources; no create is repeated.
		second := first
		second.Attempt = 2
		second.ClaimGeneration = 2
		client, fake = testNetworkClient(t, append(presentObservations(kind)[0], createScript(kind)[len(presentObservations(kind)[0])+2:]...)...)
		result, err = client.ApplyStep(context.Background(), second, intent, networkStepResources(kind), target)
		if err != nil {
			t.Fatalf("%s attempt 2 error = %v", kind, err)
		}
		if result.Resources[0].Outcome != NetworkResourceAlreadyPresent || len(result.Created) != len(intent.ResourceIDs)-1 {
			t.Fatalf("%s attempt 2 result = %#v", kind, result)
		}
		if creates+countCreates(fake.calls) != len(intent.ResourceIDs) {
			t.Fatalf("%s created %d times across attempts", kind, creates+countCreates(fake.calls))
		}
	}
}

func countCreates(calls [][]string) int {
	count := 0
	for _, call := range calls {
		for _, argument := range call {
			if argument == "create" {
				count++
			}
		}
	}
	return count
}

func createdRecords(authorization NetworkMutationAuthorization, intent bootstrap.StepIntent, ids ...string) []NetworkCreatedResource {
	records := make([]NetworkCreatedResource, 0, len(ids))
	for _, id := range ids {
		golden := goldenNetworkResources()[id]
		records = append(records, NetworkCreatedResource{OperationID: authorization.OperationID, StepID: intent.StepID, Attempt: authorization.Attempt,
			ResourceID: id, Kind: golden.Kind, Name: golden.Name, Project: golden.Project, Location: golden.Location, ProviderID: golden.ProviderID})
	}
	return records
}

func compensateScript(kind bootstrap.IntentKind) []networkFakeStep {
	present := presentObservations(kind)
	var script []networkFakeStep
	for index := len(present) - 1; index >= 0; index-- {
		script = append(script, present[index]...)
		if kind == bootstrap.IntentNAT && index == 0 {
			script = append(script, ok("[]"))
		}
		script = append(script, ok(""), ok("[]"))
	}
	return script
}

func TestNetworkClientCompensatesOnlyRecordedResourcesWithByteExactArgv(t *testing.T) {
	for _, kind := range networkKinds {
		t.Run(string(kind), func(t *testing.T) {
			intent := networkIntent(kind)
			target := networkTarget(t)
			authorization := networkAuthorization(intent, target.Preflight)
			authorization.Attempt = 2
			records := createdRecords(authorization, intent, intent.ResourceIDs...)
			records[0].Attempt = 1
			client, fake := testNetworkClient(t, compensateScript(kind)...)
			result, err := client.CompensateStep(context.Background(), authorization, intent, networkStepResources(kind), target, records)
			if err != nil {
				t.Fatalf("CompensateStep() error = %v", err)
			}
			if got, want := encodeCalls(t, fake.calls), readGoldenArgv(t, intent.StepID+"-compensate"); got != want {
				t.Fatalf("argv differs from fixture:\n got: %s\nwant: %s", got, want)
			}
			assertClosedCommandShape(t, fake.calls, kind, "delete")
			if len(result.Resources) != len(intent.ResourceIDs) || len(result.Created) != 0 {
				t.Fatalf("result = %#v", result)
			}
			for index, resource := range result.Resources {
				if resource.Outcome != NetworkResourceDeleted || resource.ResourceID != intent.ResourceIDs[len(intent.ResourceIDs)-1-index] {
					t.Fatalf("resource %d = %#v", index, resource)
				}
			}
		})
	}
}

func TestNetworkClientCompensationIsIdempotentAndPartial(t *testing.T) {
	intent := networkIntent(bootstrap.IntentFirewall)
	target := networkTarget(t)
	authorization := networkAuthorization(intent, target.Preflight)
	resources := networkStepResources(intent.Kind)

	// Only the IAP rule was recorded: the internal rule is never observed or
	// touched, even though it is part of the step.
	client, fake := testNetworkClient(t, ok(presentFirewall("test-iap-firewall")), ok(""), ok("[]"))
	result, err := client.CompensateStep(context.Background(), authorization, intent, resources, target, createdRecords(authorization, intent, "test-iap-firewall"))
	if err != nil || len(result.Resources) != 1 || result.Resources[0].ResourceID != "test-iap-firewall" || result.Resources[0].Outcome != NetworkResourceDeleted || len(fake.calls) != 3 {
		t.Fatalf("partial compensation error = %v result = %#v calls = %d", err, result, len(fake.calls))
	}
	for _, call := range fake.calls {
		if strings.Contains(strings.Join(call, " "), "ctrldb-test-internal") {
			t.Fatalf("unrecorded rule was touched: %q", call)
		}
	}

	// A recorded resource which is already gone is reported absent; nothing is deleted.
	client, fake = testNetworkClient(t, ok("[]"))
	result, err = client.CompensateStep(context.Background(), authorization, intent, resources, target, createdRecords(authorization, intent, "test-iap-firewall"))
	if err != nil || result.Resources[0].Outcome != NetworkResourceAbsent {
		t.Fatalf("absent compensation error = %v result = %#v", err, result)
	}
	assertNoCreate(t, fake.calls)

	// No records: nothing is observed or deleted.
	client, fake = testNetworkClient(t)
	result, err = client.CompensateStep(context.Background(), authorization, intent, resources, target, nil)
	if err != nil || len(result.Resources) != 0 || len(fake.calls) != 0 {
		t.Fatalf("empty compensation error = %v result = %#v", err, result)
	}
}

func TestNetworkClientRefusesToDeleteWhatItCannotProveItCreated(t *testing.T) {
	intent := networkIntent(bootstrap.IntentFirewall)
	target := networkTarget(t)
	authorization := networkAuthorization(intent, target.Preflight)
	resources := networkStepResources(intent.Kind)
	iap := presentFirewall("test-iap-firewall")
	runDescription, err := isolation.RunFirewallDescription(strings.Repeat("c", 64))
	if err != nil {
		t.Fatalf("RunFirewallDescription() error = %v", err)
	}
	drifted := map[string]string{
		"widened source":           strings.Replace(iap, "35.235.240.0/20", "0.0.0.0/0", 1),
		"foreign description":      strings.Replace(iap, networkOwnershipDescription(goldenNetworkResources()["test-iap-firewall"]), "created by hand", 1),
		"run lifetime description": strings.Replace(iap, networkOwnershipDescription(goldenNetworkResources()["test-iap-firewall"]), runDescription, 1),
		"empty description":        strings.Replace(iap, networkOwnershipDescription(goldenNetworkResources()["test-iap-firewall"]), "", 1),
		"other network":            strings.Replace(iap, "networks/ctrldb-test-vpc", "networks/default", 1),
	}
	for name, output := range drifted {
		client, fake := testNetworkClient(t, ok(output))
		_, err := client.CompensateStep(context.Background(), authorization, intent, resources, target, createdRecords(authorization, intent, "test-iap-firewall"))
		assertNetworkFailure(t, name, err, NetworkFailureDrift, domain.MutationNotOccurred)
		assertNoCreate(t, fake.calls)
	}

	// Creation records which do not name this operation, step, attempt, or
	// exact provider identity are refused before any process.
	type recordMutation struct {
		name   string
		kind   NetworkFailureKind
		mutate func(*NetworkCreatedResource)
	}
	tests := []recordMutation{
		{name: "other operation", kind: NetworkFailureAuthorization, mutate: func(record *NetworkCreatedResource) { record.OperationID = "op-20260906-0002" }},
		{name: "other step", kind: NetworkFailureAuthorization, mutate: func(record *NetworkCreatedResource) { record.StepID = "t3-nat" }},
		{name: "zero attempt", kind: NetworkFailureAuthorization, mutate: func(record *NetworkCreatedResource) { record.Attempt = 0 }},
		{name: "future attempt", kind: NetworkFailureAuthorization, mutate: func(record *NetworkCreatedResource) { record.Attempt = 2 }},
		{name: "unknown resource", kind: NetworkFailureTarget, mutate: func(record *NetworkCreatedResource) { record.ResourceID = "test-subnet" }},
		{name: "resource of another step", kind: NetworkFailureTarget, mutate: func(record *NetworkCreatedResource) {
			golden := goldenNetworkResources()["test-network"]
			record.ResourceID, record.Kind, record.Name, record.Location, record.ProviderID = golden.ID, golden.Kind, golden.Name, golden.Location, golden.ProviderID
		}},
		{name: "renamed", kind: NetworkFailureTarget, mutate: func(record *NetworkCreatedResource) { record.Name = "default-allow-ssh" }},
		{name: "cross-project", kind: NetworkFailureTarget, mutate: func(record *NetworkCreatedResource) { record.Project = "foreign-project" }},
		{name: "provider id", kind: NetworkFailureTarget, mutate: func(record *NetworkCreatedResource) {
			record.ProviderID = "projects/example-project/global/firewalls/default-allow-ssh"
		}},
		{name: "wrong kind", kind: NetworkFailureTarget, mutate: func(record *NetworkCreatedResource) { record.Kind = bootstrap.ResourceNetwork }},
	}
	for _, test := range tests {
		records := createdRecords(authorization, intent, "test-iap-firewall")
		test.mutate(&records[0])
		client, fake := testNetworkClient(t, ok(iap), ok(""), ok("[]"))
		_, err := client.CompensateStep(context.Background(), authorization, intent, resources, target, records)
		assertNetworkFailure(t, test.name, err, test.kind, domain.MutationNotOccurred)
		if len(fake.calls) != 0 {
			t.Fatalf("%s reached a process", test.name)
		}
	}
	duplicate := createdRecords(authorization, intent, "test-iap-firewall", "test-iap-firewall")
	client, fake := testNetworkClient(t, ok(iap))
	_, err = client.CompensateStep(context.Background(), authorization, intent, resources, target, duplicate)
	assertNetworkFailure(t, "duplicate record", err, NetworkFailureTarget, domain.MutationNotOccurred)
	if len(fake.calls) != 0 {
		t.Fatal("duplicate record reached a process")
	}

	// Compensation inherits every admission check of Apply.
	stale := authorization
	stale.Now = stale.ValidUntil.Add(time.Second)
	client, fake = testNetworkClient(t, ok(iap))
	_, err = client.CompensateStep(context.Background(), stale, intent, resources, target, createdRecords(authorization, intent, "test-iap-firewall"))
	assertNetworkFailure(t, "stale compensation", err, NetworkFailureAuthorization, domain.MutationNotOccurred)
	if len(fake.calls) != 0 {
		t.Fatal("stale compensation reached a process")
	}
}

func TestNetworkClientRouterCompensationNeverRemovesAnUnrecordedNAT(t *testing.T) {
	intent := networkIntent(bootstrap.IntentNAT)
	target := networkTarget(t)
	authorization := networkAuthorization(intent, target.Preflight)
	resources := networkStepResources(intent.Kind)
	routerWithNAT := strings.Replace(presentRouter, `"network"`, `"nats":[{"name":"ctrldb-test-nat"}],"network"`, 1)

	client, fake := testNetworkClient(t, ok(routerWithNAT), ok(presentNAT))
	_, err := client.CompensateStep(context.Background(), authorization, intent, resources, target, createdRecords(authorization, intent, "test-router"))
	assertNetworkFailure(t, "router with unrecorded nat", err, NetworkFailureDrift, domain.MutationNotOccurred)
	assertNoCreate(t, fake.calls)

	// With both recorded, the NAT is removed first and the router only after
	// the NAT list is proven empty.
	client, fake = testNetworkClient(t, ok(presentNAT), ok(presentStatus), ok(""), ok("[]"), ok(presentRouter), ok("[]"), ok(""), ok("[]"))
	result, err := client.CompensateStep(context.Background(), authorization, intent, resources, target, createdRecords(authorization, intent, "test-router", "test-nat"))
	if err != nil || len(result.Resources) != 2 || result.Resources[0].ResourceID != "test-nat" || result.Resources[1].ResourceID != "test-router" {
		t.Fatalf("ordered compensation error = %v result = %#v", err, result)
	}
	if strings.Join(fake.calls[2], " ") != strings.Join(natDeleteArguments(commandContext{account: networkTestAccount, project: networkTestProject, region: networkTestRegion, zone: networkTestZone}, "ctrldb-test-nat", "ctrldb-test-router"), " ") {
		t.Fatalf("first delete = %q", fake.calls[2])
	}
}

func TestNetworkClientReportsMutationObservationOnCompensationFailure(t *testing.T) {
	intent := networkIntent(bootstrap.IntentNetwork)
	target := networkTarget(t)
	authorization := networkAuthorization(intent, target.Preflight)
	resources := networkStepResources(intent.Kind)
	records := createdRecords(authorization, intent, "test-network")

	client, _ := testNetworkClient(t, ok(presentNetwork), networkFakeStep{exitCode: 1, stderr: "ERROR: token=SYNTHETIC_SECRET_VALUE"})
	_, err := client.CompensateStep(context.Background(), authorization, intent, resources, target, records)
	assertNetworkFailure(t, "delete exit", err, NetworkFailureProcess, domain.MutationUnknown)

	client, _ = testNetworkClient(t, ok(presentNetwork), ok(""), ok(presentNetwork))
	_, err = client.CompensateStep(context.Background(), authorization, intent, resources, target, records)
	assertNetworkFailure(t, "present after delete", err, NetworkFailureUnverified, domain.MutationOccurred)

	client, fake := testNetworkClient(t, networkFakeStep{stdout: "[]", stderr: "WARNING: partial"})
	_, err = client.CompensateStep(context.Background(), authorization, intent, resources, target, records)
	assertNetworkFailure(t, "diagnostic", err, NetworkFailureProcess, domain.MutationNotOccurred)
	assertNoCreate(t, fake.calls)
}

func TestNetworkApplyAndVerifyNeverRenderADelete(t *testing.T) {
	for _, kind := range networkKinds {
		intent := networkIntent(kind)
		target := networkTarget(t)
		for _, script := range [][]networkFakeStep{createScript(kind), presentScript(kind)} {
			client, fake := testNetworkClient(t, script...)
			_, _ = client.ApplyStep(context.Background(), networkAuthorization(intent, target.Preflight), intent, networkStepResources(kind), target)
			for _, call := range fake.calls {
				if strings.Contains(" "+strings.Join(call, " ")+" ", " delete ") {
					t.Fatalf("%s apply rendered a delete: %q", kind, call)
				}
			}
		}
	}
}
