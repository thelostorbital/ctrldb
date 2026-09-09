// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/observation"
)

var networkKinds = []bootstrap.IntentKind{bootstrap.IntentNetwork, bootstrap.IntentSubnet, bootstrap.IntentNAT, bootstrap.IntentFirewall}

func TestNewNetworkClientSealsGcloudExactlyLikeReadClient(t *testing.T) {
	base := NetworkClientOptions{GcloudPath: readHelperExecutable(t), SearchPath: "/usr/bin:/bin", Home: t.TempDir(),
		CloudSDKConfig: t.TempDir(), Locale: "C.UTF-8", CommandTimeout: time.Second, Clock: fixedClock}
	if _, err := NewNetworkClient(base); err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}
	invalid := []func(*NetworkClientOptions){
		func(value *NetworkClientOptions) { value.CommandTimeout = 0 },
		func(value *NetworkClientOptions) { value.CommandTimeout = networkStepTimeout + time.Second },
		func(value *NetworkClientOptions) { value.Locale = "" },
		func(value *NetworkClientOptions) { value.Clock = nil },
		func(value *NetworkClientOptions) { value.GcloudPath = "" },
		func(value *NetworkClientOptions) { value.GcloudPath = "gcloud" },
		func(value *NetworkClientOptions) { value.GcloudPath = filepath.Join(t.TempDir(), "not-gcloud") },
	}
	for index, mutate := range invalid {
		options := base
		mutate(&options)
		_, err := NewNetworkClient(options)
		assertNetworkFailure(t, "options", err, NetworkFailureInvalid, domain.MutationNotOccurred)
		_ = index
	}
	var client *NetworkClient
	_, err := client.ApplyStep(context.Background(), NetworkMutationAuthorization{}, bootstrap.StepIntent{}, nil, NetworkTarget{})
	assertNetworkFailure(t, "nil client", err, NetworkFailureInvalid, domain.MutationNotOccurred)
}

func TestNetworkClientExposesNoPlainNameOrArgvSurface(t *testing.T) {
	clientType := reflect.TypeOf(&NetworkClient{})
	for index := 0; index < clientType.NumMethod(); index++ {
		method := clientType.Method(index)
		for parameter := 1; parameter < method.Type.NumIn(); parameter++ {
			kind := method.Type.In(parameter).Kind()
			if kind == reflect.String || kind == reflect.Slice && method.Type.In(parameter).Elem().Kind() == reflect.String {
				t.Fatalf("exported method %s accepts a plain string or argv parameter", method.Name)
			}
		}
	}
	for _, field := range reflect.VisibleFields(reflect.TypeOf(NetworkClientOptions{})) {
		if field.Type.Kind() == reflect.Interface || field.Type.Kind() == reflect.Slice {
			t.Fatalf("option %s could inject a runner or argv", field.Name)
		}
	}
}

func TestNetworkClientAppliesEachStepWithByteExactArgv(t *testing.T) {
	for _, kind := range networkKinds {
		t.Run(string(kind), func(t *testing.T) {
			intent := networkIntent(kind)
			target := networkTarget(t)
			client, fake := testNetworkClient(t, createScript(kind)...)
			result, err := client.ApplyStep(context.Background(), networkAuthorization(intent, target.Preflight), intent, networkStepResources(kind), target)
			if err != nil {
				t.Fatalf("ApplyStep() error = %v", err)
			}
			if got, want := encodeCalls(t, fake.calls), readGoldenArgv(t, intent.StepID); got != want {
				t.Fatalf("argv differs from fixture:\n got: %s\nwant: %s", got, want)
			}
			assertClosedCommandShape(t, fake.calls, kind)
			if result.StepID != intent.StepID || result.Kind != kind || result.Attempt != 1 || result.OperationID != "op-20260906-0001" ||
				len(result.Resources) != len(intent.ResourceIDs) || len(result.Created) != len(intent.ResourceIDs) {
				t.Fatalf("result = %#v", result)
			}
			for index, resource := range result.Resources {
				golden := goldenNetworkResources()[intent.ResourceIDs[index]]
				if resource.Outcome != NetworkResourceCreated || resource.ResourceID != golden.ID || resource.ProviderID != golden.ProviderID ||
					resource.DesiredStateFingerprint != golden.DesiredStateFingerprint || resource.Project != networkTestProject {
					t.Fatalf("resource result = %#v", resource)
				}
				created := result.Created[index]
				if created.OperationID != "op-20260906-0001" || created.StepID != intent.StepID || created.Attempt != 1 ||
					created.ResourceID != golden.ID || created.ProviderID != golden.ProviderID || created.Location != golden.Location {
					t.Fatalf("created record = %#v", created)
				}
			}
			if strings.Contains(encodeCalls(t, fake.calls), "SYNTHETIC") || reflect.DeepEqual(result, NetworkStepResult{}) {
				t.Fatal("result is empty")
			}
		})
	}
}

func assertClosedCommandShape(t *testing.T, calls [][]string, kind bootstrap.IntentKind) {
	t.Helper()
	regional := kind == bootstrap.IntentSubnet || kind == bootstrap.IntentNAT
	for _, call := range calls {
		joined := " " + strings.Join(call, " ") + " "
		for _, forbidden := range []string{"--async", "--impersonate-service-account", "--configuration", " delete ", " update ", " ssh ", "--limit", "--page-size"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("command admitted forbidden token %q: %s", forbidden, joined)
			}
		}
		for _, required := range []string{"--account=" + networkTestAccount, "--project=" + networkTestProject, "--quiet", "--verbosity=error"} {
			if !strings.Contains(joined, " "+required+" ") {
				t.Fatalf("command lacks %q: %s", required, joined)
			}
		}
		if regional && !strings.Contains(joined, "--region="+networkTestRegion) && !strings.Contains(joined, "--regions="+networkTestRegion) {
			t.Fatalf("regional command lacks explicit region: %s", joined)
		}
		if call[0] != "compute" {
			t.Fatalf("command outside compute: %s", joined)
		}
	}
}

func TestNetworkClientConvergesWithoutMutationWhenStateAlreadyMatches(t *testing.T) {
	for _, kind := range networkKinds {
		intent := networkIntent(kind)
		target := networkTarget(t)
		for _, verifyOnly := range []bool{false, true} {
			client, fake := testNetworkClient(t, presentScript(kind)...)
			apply := client.ApplyStep
			if verifyOnly {
				apply = client.VerifyStep
			}
			authorization := networkAuthorization(intent, target.Preflight)
			authorization.Attempt = 2
			result, err := apply(context.Background(), authorization, intent, networkStepResources(kind), target)
			if err != nil {
				t.Fatalf("%s converge error = %v", kind, err)
			}
			assertNoCreate(t, fake.calls)
			if len(result.Created) != 0 || len(result.Resources) != len(intent.ResourceIDs) || result.Attempt != 2 {
				t.Fatalf("%s result = %#v", kind, result)
			}
			for _, resource := range result.Resources {
				if resource.Outcome != NetworkResourceAlreadyPresent {
					t.Fatalf("%s outcome = %q", kind, resource.Outcome)
				}
			}
		}
	}
}

func TestNetworkClientVerifyStepNeverCreates(t *testing.T) {
	intent := networkIntent(bootstrap.IntentNetwork)
	target := networkTarget(t)
	client, fake := testNetworkClient(t, ok("[]"))
	_, err := client.VerifyStep(context.Background(), networkAuthorization(intent, target.Preflight), intent, networkStepResources(intent.Kind), target)
	assertNetworkFailure(t, "verify absent", err, NetworkFailureDrift, domain.MutationNotOccurred)
	assertNoCreate(t, fake.calls)
	if len(fake.calls) != 1 {
		t.Fatalf("calls = %d", len(fake.calls))
	}
}

func TestNetworkClientRefusesDriftBeforeAnyMutation(t *testing.T) {
	iap := presentFirewall("test-iap-firewall")
	internal := presentFirewall("test-internal-firewall")
	tests := []struct {
		name   string
		kind   bootstrap.IntentKind
		script []networkFakeStep
	}{
		{name: "auto-mode network", kind: bootstrap.IntentNetwork, script: []networkFakeStep{ok(strings.Replace(presentNetwork, `"autoCreateSubnetworks":false`, `"autoCreateSubnetworks":true`, 1))}},
		{name: "legacy network", kind: bootstrap.IntentNetwork, script: []networkFakeStep{ok(strings.Replace(presentNetwork, `"autoCreateSubnetworks":false`, `"autoCreateSubnetworks":false,"IPv4Range":"10.240.0.0/16"`, 1))}},
		{name: "network without mode", kind: bootstrap.IntentNetwork, script: []networkFakeStep{ok(strings.Replace(presentNetwork, `,"autoCreateSubnetworks":false`, ``, 1))}},
		{name: "subnet range", kind: bootstrap.IntentSubnet, script: []networkFakeStep{ok(strings.Replace(presentSubnet, "10.40.0.0/24", "10.40.0.0/25", 1))}},
		{name: "subnet without private access", kind: bootstrap.IntentSubnet, script: []networkFakeStep{ok(strings.Replace(presentSubnet, `"privateIpGoogleAccess":true`, `"privateIpGoogleAccess":false`, 1))}},
		{name: "subnet on another network", kind: bootstrap.IntentSubnet, script: []networkFakeStep{ok(strings.Replace(presentSubnet, "networks/ctrldb-test-vpc", "networks/default", 1))}},
		{name: "subnet secondary range", kind: bootstrap.IntentSubnet, script: []networkFakeStep{ok(strings.Replace(presentSubnet, `"purpose":"PRIVATE"`, `"purpose":"PRIVATE","secondaryIpRanges":[{"ipCidrRange":"10.41.0.0/24"}]`, 1))}},
		{name: "subnet dual stack", kind: bootstrap.IntentSubnet, script: []networkFakeStep{ok(strings.Replace(presentSubnet, "IPV4_ONLY", "IPV4_IPV6", 1))}},
		{name: "subnet public range", kind: bootstrap.IntentSubnet, script: []networkFakeStep{ok(strings.Replace(presentSubnet, "10.40.0.0/24", "203.0.113.0/24", 1))}},
		{name: "router on another network", kind: bootstrap.IntentNAT, script: []networkFakeStep{ok(strings.Replace(presentRouter, "networks/ctrldb-test-vpc", "networks/default", 1))}},
		{name: "router with foreign nat", kind: bootstrap.IntentNAT, script: []networkFakeStep{ok(strings.Replace(presentRouter, `"network"`, `"nats":[{"name":"other-nat"}],"network"`, 1))}},
		{name: "manual nat", kind: bootstrap.IntentNAT, script: []networkFakeStep{ok(presentRouter), ok(strings.Replace(presentNAT, "AUTO_ONLY", "MANUAL_ONLY", 1))}},
		{name: "nat with addresses", kind: bootstrap.IntentNAT, script: []networkFakeStep{ok(presentRouter), ok(strings.Replace(presentNAT, `"type"`, `"natIps":["`+computeBase+`regions/us-central1/addresses/x"],"type"`, 1))}},
		{name: "private nat", kind: bootstrap.IntentNAT, script: []networkFakeStep{ok(presentRouter), ok(strings.Replace(presentNAT, "PUBLIC", "PRIVATE", 1))}},
		{name: "nat partial ranges", kind: bootstrap.IntentNAT, script: []networkFakeStep{ok(presentRouter), ok(strings.Replace(presentNAT, "ALL_SUBNETWORKS_ALL_IP_RANGES", "LIST_OF_SUBNETWORKS", 1))}},
		{name: "foreign nat on router", kind: bootstrap.IntentNAT, script: []networkFakeStep{ok(presentRouter), ok(strings.Replace(presentNAT, "ctrldb-test-nat", "other-nat", 1))}},
		{name: "nat not operational", kind: bootstrap.IntentNAT, script: []networkFakeStep{ok(presentRouter), ok(presentNAT), ok(strings.Replace(presentStatus, `"minExtraNatIpsNeeded":0`, `"minExtraNatIpsNeeded":1`, 1))}},
		{name: "status names other nat", kind: bootstrap.IntentNAT, script: []networkFakeStep{ok(presentRouter), ok(presentNAT), ok(strings.Replace(presentStatus, `"name":"ctrldb-test-nat"`, `"name":"other-nat"`, 1))}},
		{name: "status on other network", kind: bootstrap.IntentNAT, script: []networkFakeStep{ok(presentRouter), ok(presentNAT), ok(strings.Replace(presentStatus, "networks/ctrldb-test-vpc", "networks/default", 1))}},
		{name: "internet-wide ssh", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, "35.235.240.0/20", "0.0.0.0/0", 1))}},
		{name: "wider iap range", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, "35.235.240.0/20", "35.235.240.0/19", 1))}},
		{name: "extra source range", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, `["35.235.240.0/20"]`, `["35.235.240.0/20","203.0.113.0/24"]`, 1))}},
		{name: "production target tag", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, `"targetTags":["ctrldb-test-node"]`, `"targetTags":["ctrldb-test-node","mongodb-prod"]`, 1))}},
		{name: "non-test target tag", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, `"targetTags":["ctrldb-test-node"]`, `"targetTags":["mongodb-prod"]`, 1))}},
		{name: "mongodb from non-test tag", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(iap), ok(strings.Replace(internal, `"sourceTags":["ctrldb-test-node"]`, `"sourceTags":["mongodb-prod"]`, 1))}},
		{name: "mongodb from cidr", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(iap), ok(strings.Replace(internal, `"sourceTags":["ctrldb-test-node"]`, `"sourceRanges":["10.40.0.0/24"]`, 1))}},
		{name: "mongodb from tag and cidr", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(iap), ok(strings.Replace(internal, `"sourceTags":["ctrldb-test-node"]`, `"sourceTags":["ctrldb-test-node"],"sourceRanges":["10.40.0.0/24"]`, 1))}},
		{name: "wrong port", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(iap), ok(strings.Replace(internal, `"27017"`, `"27018"`, 1))}},
		{name: "port range", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(iap), ok(strings.Replace(internal, `"27017"`, `"27017-27019"`, 1))}},
		{name: "all protocols", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, `"allowed":[{"IPProtocol":"tcp","ports":["22"]}]`, `"allowed":[{"IPProtocol":"all"}]`, 1))}},
		{name: "second protocol", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, `"allowed":[{"IPProtocol":"tcp","ports":["22"]}]`, `"allowed":[{"IPProtocol":"tcp","ports":["22"]},{"IPProtocol":"udp","ports":["22"]}]`, 1))}},
		{name: "denied tuple", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, `"logConfig"`, `"denied":[{"IPProtocol":"tcp","ports":["23"]}],"logConfig"`, 1))}},
		{name: "egress", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, "INGRESS", "EGRESS", 1))}},
		{name: "disabled", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, `"disabled":false`, `"disabled":true`, 1))}},
		{name: "priority", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, `"priority":1000`, `"priority":900`, 1))}},
		{name: "missing priority", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, `"priority":1000,`, ``, 1))}},
		{name: "logging", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, `"enable":false`, `"enable":true`, 1))}},
		{name: "service account target", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, `"logConfig"`, `"targetServiceAccounts":["x@example-project.iam.gserviceaccount.com"],"logConfig"`, 1))}},
		{name: "destination range", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, `"logConfig"`, `"destinationRanges":["10.40.0.0/24"],"logConfig"`, 1))}},
		{name: "ownership description", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, "fingerprint=6c4e", "fingerprint=0000", 1))}},
		{name: "firewall on another network", kind: bootstrap.IntentFirewall, script: []networkFakeStep{ok(strings.Replace(iap, "networks/ctrldb-test-vpc", "networks/default", 1))}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := networkIntent(test.kind)
			target := networkTarget(t)
			client, fake := testNetworkClient(t, test.script...)
			result, err := client.ApplyStep(context.Background(), networkAuthorization(intent, target.Preflight), intent, networkStepResources(test.kind), target)
			assertNetworkFailure(t, test.name, err, NetworkFailureDrift, domain.MutationNotOccurred)
			assertNoCreate(t, fake.calls)
			if len(fake.calls) != len(test.script) || len(result.Created) != 0 {
				t.Fatalf("calls = %d, created = %d", len(fake.calls), len(result.Created))
			}
		})
	}
}

func TestNetworkClientFailsClosedBeforeAnyProcess(t *testing.T) {
	type mutation struct {
		name          string
		kind          NetworkFailureKind
		authorization func(*NetworkMutationAuthorization)
		intent        func(*bootstrap.StepIntent)
		resources     func([]bootstrap.DesiredResource) []bootstrap.DesiredResource
		target        func(*testing.T, *NetworkTarget)
	}
	stalePreflight := func(t *testing.T, target *NetworkTarget) {
		t.Helper()
		target.Preflight = networkPreflight(t, []observation.SubnetRange{{Name: "other", Project: networkTestProject, Region: networkTestRegion, CIDR: "10.50.0.0/24", ProviderID: computeBase + "regions/us-central1/subnetworks/other"}})
	}
	tests := []mutation{
		{name: "missing plan digest", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.PlanDocumentSHA256 = "" }},
		{name: "uppercase plan hash", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.PlanV1Hash = strings.Repeat("A", 64) }},
		{name: "short plan hash", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.PlanV1Hash = strings.Repeat("a", 63) }},
		{name: "binding mismatch", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.EnvelopeBindingSHA256 = strings.Repeat("9", 64) }},
		{name: "step mismatch", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.StepID = "t2-subnet" }},
		{name: "missing operation", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.OperationID = "" }},
		{name: "operation with control character", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.OperationID = "op\n1" }},
		{name: "zero attempt", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.Attempt = 0 }},
		{name: "attempt beyond retry", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.Attempt = 4 }},
		{name: "zero claim generation", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.ClaimGeneration = 0 }},
		{name: "operator identity", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.ExecutingIdentity = domain.IdentityOperator }},
		{name: "unknown identity", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.ExecutingIdentity = "root" }},
		{name: "observation revision", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.ObservationRevision = strings.Repeat("3", 64) }},
		{name: "observed at", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.ObservedAt = value.ObservedAt.Add(time.Second) }},
		{name: "valid until", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.ValidUntil = value.ValidUntil.Add(time.Hour) }},
		{name: "zero now", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.Now = time.Time{} }},
		{name: "now before observation", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.Now = value.ObservedAt.Add(-time.Second) }},
		{name: "now after validity", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.Now = value.ValidUntil }},
		{name: "non-utc now", kind: NetworkFailureAuthorization, authorization: func(value *NetworkMutationAuthorization) { value.Now = value.Now.In(time.FixedZone("x", 3600)) }},
		{name: "stale preflight", kind: NetworkFailureAuthorization, target: stalePreflight},
		{name: "foreign intent kind", kind: NetworkFailureIntent, intent: func(value *bootstrap.StepIntent) { value.Kind = bootstrap.IntentIdentities }},
		{name: "storage intent kind", kind: NetworkFailureIntent, intent: func(value *bootstrap.StepIntent) {
			value.Kind = bootstrap.IntentControlBucket
			value.StepID = "k2-control-bucket"
		}},
		{name: "kind step mismatch", kind: NetworkFailureIntent, intent: func(value *bootstrap.StepIntent) { value.StepID = "t2-subnet" }},
		{name: "extra resource id", kind: NetworkFailureIntent, intent: func(value *bootstrap.StepIntent) { value.ResourceIDs = append(value.ResourceIDs, "test-subnet") }},
		{name: "intent identity", kind: NetworkFailureIntent, intent: func(value *bootstrap.StepIntent) { value.ExecutingIdentity = domain.IdentityTestOperator }},
		{name: "intent timeout", kind: NetworkFailureIntent, intent: func(value *bootstrap.StepIntent) { value.TimeoutSeconds = 61 }},
		{name: "intent retry", kind: NetworkFailureIntent, intent: func(value *bootstrap.StepIntent) { value.Retry = domain.RetryPolicy{} }},
		{name: "intent ponr", kind: NetworkFailureIntent, intent: func(value *bootstrap.StepIntent) { value.PointOfNoReturn = bootstrap.PONRAuditRetentionLock }},
		{name: "intent transition", kind: NetworkFailureIntent, intent: func(value *bootstrap.StepIntent) { value.Transition = &bootstrap.HarnessTransition{} }},
		{name: "no resources", kind: NetworkFailureTarget, resources: func([]bootstrap.DesiredResource) []bootstrap.DesiredResource { return nil }},
		{name: "extra resource", kind: NetworkFailureTarget, resources: func(values []bootstrap.DesiredResource) []bootstrap.DesiredResource {
			return append(values, goldenNetworkResources()["test-subnet"])
		}},
		{name: "cross-project resource", kind: NetworkFailureTarget, resources: func(values []bootstrap.DesiredResource) []bootstrap.DesiredResource {
			values[0].Project = "foreign-project"
			return values
		}},
		{name: "cross-project provider id", kind: NetworkFailureTarget, resources: func(values []bootstrap.DesiredResource) []bootstrap.DesiredResource {
			values[0].ProviderID = strings.Replace(values[0].ProviderID, "example-project", "foreign-project", 1)
			return values
		}},
		{name: "renamed resource", kind: NetworkFailureTarget, resources: func(values []bootstrap.DesiredResource) []bootstrap.DesiredResource {
			values[0].Name = "ctrldb-test-vpc2"
			return values
		}},
		{name: "production name", kind: NetworkFailureTarget, resources: func(values []bootstrap.DesiredResource) []bootstrap.DesiredResource {
			values[0].Name = "default"
			values[0].ProviderID = "projects/example-project/global/networks/default"
			return values
		}},
		{name: "disposable permanence", kind: NetworkFailureTarget, resources: func(values []bootstrap.DesiredResource) []bootstrap.DesiredResource {
			values[0].Permanence = bootstrap.DisposableRun
			return values
		}},
		{name: "fingerprint mismatch", kind: NetworkFailureTarget, resources: func(values []bootstrap.DesiredResource) []bootstrap.DesiredResource {
			values[0].DesiredStateFingerprint = strings.Repeat("0", 64)
			return values
		}},
		{name: "wrong kind", kind: NetworkFailureTarget, resources: func(values []bootstrap.DesiredResource) []bootstrap.DesiredResource {
			values[0].Kind = bootstrap.ResourceFirewall
			return values
		}},
		{name: "cross-region location", kind: NetworkFailureTarget, resources: func(values []bootstrap.DesiredResource) []bootstrap.DesiredResource {
			values[0].Location = "us-east1"
			return values
		}},
		{name: "invalid account", kind: NetworkFailureTarget, target: func(_ *testing.T, target *NetworkTarget) { target.Account = "not-an-account" }},
		{name: "preflight account", kind: NetworkFailureTarget, target: func(_ *testing.T, target *NetworkTarget) { target.Account = "other@example.invalid" }},
		{name: "empty configuration", kind: NetworkFailureTarget, target: func(_ *testing.T, target *NetworkTarget) { target.Configuration = config.HarnessConfiguration{} }},
		{name: "empty preflight", kind: NetworkFailureTarget, target: func(_ *testing.T, target *NetworkTarget) { target.Preflight = observation.HarnessPreflight{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := networkIntent(bootstrap.IntentNetwork)
			target := networkTarget(t)
			if test.target != nil {
				test.target(t, &target)
			}
			if test.intent != nil {
				test.intent(&intent)
			}
			resources := networkStepResources(bootstrap.IntentNetwork)
			if test.resources != nil {
				resources = test.resources(resources)
			}
			authorization := networkAuthorization(networkIntent(bootstrap.IntentNetwork), networkTarget(t).Preflight)
			if test.authorization != nil {
				test.authorization(&authorization)
			}
			client, fake := testNetworkClient(t, createScript(bootstrap.IntentNetwork)...)
			_, err := client.ApplyStep(context.Background(), authorization, intent, resources, target)
			assertNetworkFailure(t, test.name, err, test.kind, domain.MutationNotOccurred)
			if len(fake.calls) != 0 {
				t.Fatalf("%s ran %d commands before failing closed", test.name, len(fake.calls))
			}
		})
	}
}

func TestNetworkClientRejectsCrossRegionAndCrossProjectConfigurationWithoutProcess(t *testing.T) {
	intent := networkIntent(bootstrap.IntentSubnet)
	target := networkTarget(t)
	resources := networkStepResources(bootstrap.IntentSubnet)
	resources[0].Location = "us-east1"
	resources[0].ProviderID = "projects/example-project/regions/us-east1/subnetworks/ctrldb-test-subnet"
	client, fake := testNetworkClient(t, createScript(bootstrap.IntentSubnet)...)
	_, err := client.ApplyStep(context.Background(), networkAuthorization(intent, target.Preflight), intent, resources, target)
	assertNetworkFailure(t, "cross-region subnet", err, NetworkFailureTarget, domain.MutationNotOccurred)
	if len(fake.calls) != 0 {
		t.Fatal("cross-region subnet reached a process")
	}
}

func TestNetworkClientReportsMutationObservationOnPartialFailure(t *testing.T) {
	intent := networkIntent(bootstrap.IntentNAT)
	target := networkTarget(t)
	resources := networkStepResources(bootstrap.IntentNAT)
	authorization := networkAuthorization(intent, target.Preflight)

	client, fake := testNetworkClient(t, ok("[]"), networkFakeStep{exitCode: 1, stderr: "ERROR: token=SYNTHETIC_SECRET_VALUE"})
	result, err := client.ApplyStep(context.Background(), authorization, intent, resources, target)
	assertNetworkFailure(t, "create exit", err, NetworkFailureProcess, domain.MutationUnknown)
	if strings.Contains(err.Error(), "SYNTHETIC") || len(result.Created) != 0 || len(fake.calls) != 2 {
		t.Fatalf("create failure result = %#v, err = %v", result, err)
	}

	client, fake = testNetworkClient(t, ok("[]"), ok(""), ok("[]"))
	result, err = client.ApplyStep(context.Background(), authorization, intent, resources, target)
	assertNetworkFailure(t, "absent after create", err, NetworkFailureUnverified, domain.MutationOccurred)
	if len(result.Created) != 1 || result.Created[0].ResourceID != "test-router" || len(fake.calls) != 3 {
		t.Fatalf("unverified result = %#v", result)
	}

	client, fake = testNetworkClient(t, ok("[]"), ok(""), ok(strings.Replace(presentRouter, "networks/ctrldb-test-vpc", "networks/default", 1)))
	result, err = client.ApplyStep(context.Background(), authorization, intent, resources, target)
	assertNetworkFailure(t, "drift after create", err, NetworkFailureUnverified, domain.MutationOccurred)
	if len(result.Created) != 1 || len(fake.calls) != 3 {
		t.Fatalf("post-create drift result = %#v", result)
	}

	client, fake = testNetworkClient(t, ok("[]"), ok(""), ok(presentRouter), ok("[]"), networkFakeStep{err: errors.New("timeout")})
	result, err = client.ApplyStep(context.Background(), authorization, intent, resources, target)
	assertNetworkFailure(t, "second create", err, NetworkFailureProcess, domain.MutationUnknown)
	if len(result.Created) != 1 || result.Created[0].ResourceID != "test-router" || result.Created[0].OperationID != authorization.OperationID || len(fake.calls) != 5 {
		t.Fatalf("partial result = %#v", result)
	}

	client, fake = testNetworkClient(t, ok("[]"), ok(""), ok(presentRouter), ok("[]"), ok(""), ok(presentNAT), ok(strings.Replace(presentStatus, `"minExtraNatIpsNeeded":0`, `"minExtraNatIpsNeeded":2`, 1)))
	result, err = client.ApplyStep(context.Background(), authorization, intent, resources, target)
	assertNetworkFailure(t, "nat not operational after create", err, NetworkFailureUnverified, domain.MutationOccurred)
	if len(result.Created) != 2 || len(fake.calls) != 7 {
		t.Fatalf("nat status result = %#v", result)
	}

	client, fake = testNetworkClient(t, networkFakeStep{stdout: "[]", stderr: "WARNING: partial"})
	result, err = client.ApplyStep(context.Background(), authorization, intent, resources, target)
	assertNetworkFailure(t, "diagnostic on observe", err, NetworkFailureProcess, domain.MutationNotOccurred)
	if len(result.Created) != 0 || len(fake.calls) != 1 {
		t.Fatalf("diagnostic result = %#v", result)
	}
}

func TestNetworkClientRunsThroughTheSealedProcessBoundary(t *testing.T) {
	executable := readHelperExecutable(t)
	sdkConfig := filepath.Join(t.TempDir(), "valid")
	if err := os.MkdirAll(sdkConfig, 0o700); err != nil {
		t.Fatalf("create SDK config fixture: %v", err)
	}
	client, err := NewNetworkClient(NetworkClientOptions{GcloudPath: executable, SearchPath: "/usr/bin:/bin", Home: t.TempDir(),
		CloudSDKConfig: sdkConfig, Locale: "C.UTF-8", CommandTimeout: 5 * time.Second, Clock: fixedClock})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}
	intent := networkIntent(bootstrap.IntentNetwork)
	target := networkTarget(t)
	// The shared helper answers the exact-name network read with its canned
	// M1-03 fixture, which carries no subnet-mode field. The sealed path must
	// therefore report drift after exactly one real process and render no
	// create command.
	result, err := client.ApplyStep(context.Background(), networkAuthorization(intent, target.Preflight), intent, networkStepResources(intent.Kind), target)
	assertNetworkFailure(t, "helper", err, NetworkFailureDrift, domain.MutationNotOccurred)
	if len(result.Created) != 0 {
		t.Fatalf("helper result = %#v", result)
	}
	commands, readErr := os.ReadFile(filepath.Join(sdkConfig, "commands.log"))
	if readErr != nil {
		t.Fatalf("read command log: %v", readErr)
	}
	lines := strings.Split(strings.TrimSpace(string(commands)), "\n")
	want := []string{
		"compute networks list --filter=name=ctrldb-test-vpc " + networkFormat + " --account=operator@example.invalid --project=example-project --quiet --verbosity=error",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("helper commands = %q, want %q", lines, want)
	}
}

func TestNetworkClientHonoursStepTimeoutAndCancellation(t *testing.T) {
	intent := networkIntent(bootstrap.IntentNetwork)
	target := networkTarget(t)
	client, fake := testNetworkClient(t, createScript(bootstrap.IntentNetwork)...)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fake.script = []networkFakeStep{{err: context.Canceled}}
	_, err := client.ApplyStep(ctx, networkAuthorization(intent, target.Preflight), intent, networkStepResources(intent.Kind), target)
	assertNetworkFailure(t, "canceled", err, NetworkFailureProcess, domain.MutationNotOccurred)
	assertNoCreate(t, fake.calls)
}
