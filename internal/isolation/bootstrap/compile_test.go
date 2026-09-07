// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/observation"
)

func TestCompileProducesCompleteWFTestPlan(t *testing.T) {
	t.Parallel()

	compiled := mustCompile(t, validCompileRequest(t))
	wantSteps := []string{
		"k1-audit-bootstrap", "k2-control-bucket", "k3-bucket-iam", "k4-seed-control", "k5-lock-round-trip",
		"t1-network", "t2-subnet", "t3-nat", "t4-firewall", "t5-identities", "t6-control-prefix",
		"t7-nightly-wipe", "t8-isolation-gate",
	}
	intents := compiled.Intents()
	if len(intents) != len(wantSteps) {
		t.Fatalf("len(Intents()) = %d; want %d", len(intents), len(wantSteps))
	}
	for index, want := range wantSteps {
		if intents[index].StepID != want {
			t.Errorf("Intents()[%d].StepID = %q; want %q", index, intents[index].StepID, want)
		}
		if intents[index].ExecutingIdentity != domain.IdentityHuman || intents[index].TimeoutSeconds <= 0 ||
			len(intents[index].Preconditions) == 0 || len(intents[index].Verification) == 0 ||
			intents[index].Compensation == "" {
			t.Errorf("Intents()[%d] lacks required execution metadata: %#v", index, intents[index])
		}
	}
	last := intents[len(intents)-1]
	if last.Kind != IntentIsolationGate || last.Transition == nil ||
		last.Transition.FromBootstrapPhase != "pending" || last.Transition.FromTestUsability != "unusable" ||
		last.Transition.ToBootstrapPhase != "open" || last.Transition.ToTestUsability != "usable" {
		t.Fatalf("T8 transition = %#v; want pending/unusable to open/usable", last.Transition)
	}
	steps := compiled.ExecutionContract().Steps()
	if steps[len(steps)-1].Effect != domain.StepEffectRead {
		t.Errorf("T8 effect = %q; want read", steps[len(steps)-1].Effect)
	}
	for index := 0; index < len(steps)-1; index++ {
		if steps[index].Effect != domain.StepEffectMutation {
			t.Errorf("step %q effect = %q; want mutation", steps[index].ID, steps[index].Effect)
		}
	}

	desired := compiled.DesiredState()
	if desired.NamePrefix != "ctrldb-test-" || desired.Project != testProject || desired.Region != testRegion || desired.Zone != testZone {
		t.Fatalf("DesiredState() lost explicit provider or ownership choices: %#v", desired)
	}
	for _, resource := range compiled.DesiredResources() {
		if resource.Permanence != PermanentSingleton {
			t.Errorf("resource %q permanence = %q; want permanent singleton", resource.ID, resource.Permanence)
		}
	}
	if got := compiled.CleanupCapabilities(); !slices.Equal(got, isolation.InitialCleanupCapabilities()) {
		t.Fatalf("CleanupCapabilities() = %v; want %v", got, isolation.InitialCleanupCapabilities())
	}
	if compiled.Plan().PointOfNoReturn != "k1-audit-bootstrap" || compiled.Risks().ExpectedDowntimeSeconds != 0 ||
		compiled.Risks().ProductionExposure != "none" {
		t.Fatal("compiled review surface lost the retention boundary or safety summary")
	}
	if compiled.Plan().PointOfNoReturnTrigger != domain.PointOfNoReturnMutationObserved {
		t.Fatalf("point-of-no-return trigger = %q; want mutation-observed", compiled.Plan().PointOfNoReturnTrigger)
	}

	encoded := mustCanonical(t, compiled)
	parsed, err := ParseCompiledPlan(encoded)
	if err != nil {
		t.Fatalf("ParseCompiledPlan() unexpected error: %v", err)
	}
	if !bytes.Equal(encoded, mustCanonical(t, parsed)) || parsed.DocumentHash() != compiled.DocumentHash() {
		t.Fatal("canonical round trip changed bytes or document hash")
	}
}

func TestRequiredAPIsAreClosedCanonicalAndDetached(t *testing.T) {
	t.Parallel()

	want := []string{
		"artifactregistry.googleapis.com", "cloudresourcemanager.googleapis.com", "cloudscheduler.googleapis.com",
		"compute.googleapis.com", "iam.googleapis.com", "iamcredentials.googleapis.com", "run.googleapis.com",
		"secretmanager.googleapis.com", "serviceusage.googleapis.com", "storage.googleapis.com",
	}
	if got := RequiredAPIs(); !slices.Equal(got, want) {
		t.Fatalf("RequiredAPIs() = %v; want %v", got, want)
	}
	got := RequiredAPIs()
	got[0] = "tampered.googleapis.com"
	if RequiredAPIs()[0] != want[0] {
		t.Fatal("RequiredAPIs() exposed mutable package state")
	}
}

func TestCompileIsStableAcrossEquivalentObservationOrdering(t *testing.T) {
	t.Parallel()

	request := validCompileRequest(t)
	seed := validPreflightSeed(testProject, testRegion, testZone, nil, nil, nil)
	slices.Reverse(seed.Schemas)
	slices.Reverse(seed.APIs)
	second, err := observation.NewHarnessPreflight(seed)
	if err != nil {
		t.Fatalf("NewHarnessPreflight(reordered) unexpected error: %v", err)
	}
	if second.Revision() != request.Preflight.Revision() {
		t.Fatal("semantically identical reordered observation changed its content revision")
	}
	request.Preflight = second
	first := mustCompile(t, validCompileRequest(t))
	reordered := mustCompile(t, request)
	if !bytes.Equal(mustCanonical(t, first), mustCanonical(t, reordered)) || first.DocumentHash() != reordered.DocumentHash() {
		t.Fatal("equivalent reordered observation changed canonical plan bytes")
	}
}

func TestCompileBindsObservationWindowWithoutPerturbingContentRevision(t *testing.T) {
	t.Parallel()

	firstRequest := validCompileRequest(t)
	seed := validPreflightSeed(testProject, testRegion, testZone, nil, nil, nil)
	seed.ObservedAt = seed.ObservedAt.Add(15 * time.Second)
	seed.ValidUntil = seed.ValidUntil.Add(15 * time.Second)
	second, err := observation.NewHarnessPreflight(seed)
	if err != nil {
		t.Fatalf("NewHarnessPreflight(shifted window) unexpected error: %v", err)
	}
	if second.Revision() != firstRequest.Preflight.Revision() {
		t.Fatal("observation timestamps perturbed the content-only revision")
	}
	secondRequest := firstRequest
	secondRequest.Preflight = second
	first := mustCompile(t, firstRequest)
	shifted := mustCompile(t, secondRequest)
	if first.DocumentHash() == shifted.DocumentHash() || bytes.Equal(mustCanonical(t, first), mustCanonical(t, shifted)) {
		t.Fatal("freshness window was not bound into the compiled artifact")
	}
}

func TestCompileRejectsStaleOrMismatchedInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*CompileRequest)
		want   error
	}{
		{name: "stale observation", mutate: func(value *CompileRequest) {
			value.CreatedAt = testNow.Add(4 * time.Minute)
			value.ExpiresAt = value.CreatedAt.Add(31 * time.Minute)
		}, want: ErrPlanBlocked},
		{name: "manifest project", mutate: func(value *CompileRequest) {
			value.Preflight = validPreflight(t, "other-project", testRegion, testZone, nil, nil, nil)
		}, want: ErrPlanBlocked},
		{name: "manifest region", mutate: func(value *CompileRequest) {
			value.Preflight = validPreflight(t, testProject, "us-east1", "us-east1-b", nil, nil, nil)
		}, want: ErrPlanBlocked},
		{name: "missing configuration", mutate: func(value *CompileRequest) { value.Configuration = zeroHarnessConfiguration() }, want: ErrInvalidCompileRequest},
		{name: "missing preflight", mutate: func(value *CompileRequest) { value.Preflight = observation.HarnessPreflight{} }, want: ErrPlanBlocked},
		{name: "policy mismatch", mutate: func(value *CompileRequest) { value.ApprovedPolicyHash = repeatedHex("c") }, want: ErrPlanBlocked},
		{name: "short validity", mutate: func(value *CompileRequest) { value.ExpiresAt = value.CreatedAt.Add(29 * time.Minute) }, want: ErrInvalidCompileRequest},
		{name: "non UTC creation", mutate: func(value *CompileRequest) { value.CreatedAt = value.CreatedAt.In(time.FixedZone("offset", 3600)) }, want: ErrInvalidCompileRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validCompileRequest(t)
			test.mutate(&request)
			_, err := Compile(request)
			if !errors.Is(err, test.want) {
				t.Fatalf("Compile() error = %v; want %v", err, test.want)
			}
		})
	}
}

func TestCompileRejectsProviderSafetyFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		resources []observation.Resource
		subnets   []observation.SubnetRange
		firewalls []observation.FirewallRule
		disable   string
	}{
		{name: "bucket collision", resources: []observation.Resource{{Kind: observation.ResourceBucket, Name: "example-project-ctrldb-audit", Project: testProject, Location: "us", ProviderID: provider(testProject, "global", string(observation.ResourceBucket), "example-project-ctrldb-audit")}}},
		{name: "CIDR overlap", subnets: []observation.SubnetRange{{Name: "existing", Project: testProject, Region: testRegion, CIDR: "10.40.0.128/25", ProviderID: provider(testProject, "regions", testRegion, "subnetworks", "existing")}}},
		{name: "public MongoDB", firewalls: []observation.FirewallRule{{
			Name: "public-db", Project: testProject,
			ProviderID: provider(testProject, "global", "firewalls", "public-db"),
			Direction:  "INGRESS", SourceRanges: []string{"0.0.0.0/0"},
			Allowed: []observation.Protocol{{Name: "tcp", Ports: []string{"27017"}}},
		}}},
		{name: "disabled API", disable: "compute.googleapis.com"},
		{name: "unknown API", disable: "absent:compute.googleapis.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := validPreflightSeed(testProject, testRegion, testZone, test.resources, test.subnets, test.firewalls)
			for index := range seed.APIs {
				if seed.APIs[index].Name == test.disable {
					seed.APIs[index].State = observation.APIDisabled
				}
			}
			if strings.HasPrefix(test.disable, "absent:") {
				service := strings.TrimPrefix(test.disable, "absent:")
				seed.APIs = slices.DeleteFunc(seed.APIs, func(value observation.APIService) bool { return value.Name == service })
			}
			preflight, err := observation.NewHarnessPreflight(seed)
			if err != nil {
				t.Fatalf("NewHarnessPreflight() unexpected error: %v", err)
			}
			request := validCompileRequest(t)
			request.Preflight = preflight
			_, err = Compile(request)
			if !errors.Is(err, ErrPlanBlocked) {
				t.Fatalf("Compile() error = %v; want ErrPlanBlocked", err)
			}
		})
	}
}

func TestCompileAcceptsAdjacentCIDRBoundary(t *testing.T) {
	t.Parallel()

	adjacent := observation.SubnetRange{
		Name: "adjacent", Project: testProject, Region: testRegion, CIDR: "10.40.1.0/24",
		ProviderID: provider(testProject, "regions", testRegion, "subnetworks", "adjacent"),
	}
	request := validCompileRequest(t)
	request.Preflight = validPreflight(t, testProject, testRegion, testZone, nil, []observation.SubnetRange{adjacent}, nil)
	if _, err := Compile(request); err != nil {
		t.Fatalf("Compile(adjacent CIDR) unexpected error: %v", err)
	}
}

func TestCompileComparesCompleteCollisionIdentity(t *testing.T) {
	t.Parallel()

	otherScope := observation.Resource{
		Kind: observation.ResourceRunJob, Name: "ctrldb-test-wipe", Project: testProject, Location: "us-east1",
		ProviderID: provider(testProject, "regions", "us-east1", string(observation.ResourceRunJob), "ctrldb-test-wipe"),
	}
	request := validCompileRequest(t)
	request.Preflight = validPreflight(t, testProject, testRegion, testZone, []observation.Resource{otherScope}, nil, nil)
	if _, err := Compile(request); err != nil {
		t.Fatalf("Compile(other-scope same name) unexpected error: %v", err)
	}

	exact := otherScope
	exact.Location = testRegion
	exact.ProviderID = provider(testProject, "regions", testRegion, string(observation.ResourceRunJob), exact.Name)
	request.Preflight = validPreflight(t, testProject, testRegion, testZone, []observation.Resource{exact}, nil, nil)
	if _, err := Compile(request); !errors.Is(err, ErrPlanBlocked) {
		t.Fatalf("Compile(exact collision) error = %v; want ErrPlanBlocked", err)
	}
}

func TestCompileRejectsUnresolvedOrAmbiguousPricing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*CompileRequest)
	}{
		{name: "unobserved machine", mutate: func(value *CompileRequest) { value.Pricing.MachineType = "n2-standard-2" }},
		{name: "numeric mismatch", mutate: func(value *CompileRequest) { value.Pricing.GuestCPUs++ }},
		{name: "over cost cap", mutate: func(value *CompileRequest) { value.Pricing.EstimatedRunMicros = 25_000_001 }},
		{name: "float precision overflow", mutate: func(value *CompileRequest) { value.Pricing.EstimatedRunMicros = maximumExactMicros + 1 }},
		{name: "negative cost", mutate: func(value *CompileRequest) { value.Pricing.EstimatedRunMicros = -1 }},
		{name: "future price table", mutate: func(value *CompileRequest) { value.Pricing.PriceTableDate = "2026-09-08" }},
		{name: "stale price table", mutate: func(value *CompileRequest) { value.Pricing.PriceTableDate = "2026-08-01" }},
		{name: "expired pricing", mutate: func(value *CompileRequest) { value.Pricing.ValidUntil = value.CreatedAt }},
		{name: "unknown schema", mutate: func(value *CompileRequest) { value.Pricing.Schema = "pricing/v2" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validCompileRequest(t)
			test.mutate(&request)
			if _, err := Compile(request); err == nil {
				t.Fatal("Compile() succeeded; want fail-closed error")
			}
		})
	}
}

func TestCompileRejectsDeprecatedMachineObservation(t *testing.T) {
	t.Parallel()

	seed := validPreflightSeed(testProject, testRegion, testZone, nil, nil, nil)
	seed.MachineTypes[0].Deprecated = true
	preflight, err := observation.NewHarnessPreflight(seed)
	if err != nil {
		t.Fatalf("NewHarnessPreflight(deprecated machine) unexpected error: %v", err)
	}
	request := validCompileRequest(t)
	request.Preflight = preflight
	if _, err := Compile(request); !errors.Is(err, ErrPlanBlocked) {
		t.Fatalf("Compile(deprecated machine) error = %v; want ErrPlanBlocked", err)
	}
}

func TestCompileAcceptsExactIntegerCostBoundary(t *testing.T) {
	t.Parallel()

	request := validCompileRequest(t)
	request.Pricing.EstimatedRunMicros = 25_000_000
	compiled := mustCompile(t, request)
	if compiled.Limits().EstimatedCostMicros != compiled.Limits().MaximumCostMicros {
		t.Fatal("exact micro-USD cap boundary was not preserved")
	}
}

func TestInvalidProvenanceCannotReachCompiler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*observation.Seed)
	}{
		{name: "partial schemas", mutate: func(value *observation.Seed) { value.Schemas = value.Schemas[1:] }},
		{name: "unsupported schema", mutate: func(value *observation.Seed) { value.Schemas[0] = "gcloud-560/unsupported-v1" }},
		{name: "wrong-zone machine", mutate: func(value *observation.Seed) { value.MachineTypes[0].Zone = "us-central1-b" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := validPreflightSeed(testProject, testRegion, testZone, nil, nil, nil)
			test.mutate(&seed)
			if _, err := observation.NewHarnessPreflight(seed); !errors.Is(err, observation.ErrInvalidObservation) {
				t.Fatalf("NewHarnessPreflight() error = %v; want ErrInvalidObservation", err)
			}
		})
	}
}

func TestCompiledPlanGettersAreDetached(t *testing.T) {
	t.Parallel()

	compiled := mustCompile(t, validCompileRequest(t))
	original := mustCanonical(t, compiled)
	desired := compiled.DesiredState()
	desired.Labels["managed-by"] = "tampered"
	intents := compiled.Intents()
	intents[0].Dependencies = append(intents[0].Dependencies, "tampered")
	intents[len(intents)-1].Transition.ToBootstrapPhase = "tampered"
	capabilities := compiled.CleanupCapabilities()
	capabilities[0] = isolation.CleanupCapability("tampered")
	plan := compiled.Plan()
	plan.Steps[0].ID = "tampered"
	if !bytes.Equal(original, mustCanonical(t, compiled)) {
		t.Fatal("detached getter mutation changed compiled plan")
	}
}

func zeroHarnessConfiguration() config.HarnessConfiguration { return config.HarnessConfiguration{} }

func TestStepRegistryHasNoRepresentableTestRunOrUnrelatedIntent(t *testing.T) {
	t.Parallel()

	compiled := mustCompile(t, validCompileRequest(t))
	allowed := []IntentKind{
		IntentAuditBootstrap, IntentControlBucket, IntentBucketIAM, IntentSeedControl, IntentLockRoundTrip,
		IntentNetwork, IntentSubnet, IntentNAT, IntentFirewall, IntentIdentities, IntentControlPrefix,
		IntentNightlyWipe, IntentIsolationGate,
	}
	for _, intent := range compiled.Intents() {
		if !slices.Contains(allowed, intent.Kind) {
			t.Fatalf("compiled pre-T8 intent %q is outside WF-TEST-01", intent.Kind)
		}
	}
	if !reflect.DeepEqual(compiled.CleanupCapabilities(), []isolation.CleanupCapability{
		isolation.CleanupComputeDisks, isolation.CleanupComputeFirewalls, isolation.CleanupComputeInstances,
	}) {
		t.Fatal("compiled cleanup capability set is not the closed initial set")
	}
}
