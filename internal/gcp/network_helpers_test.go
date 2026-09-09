// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/observation"
	"github.com/thelostorbital/ctrldb/internal/redact"
	"github.com/thelostorbital/ctrldb/internal/runner"
)

const (
	networkTestAccount = "operator@example.invalid"
	networkTestProject = "example-project"
	networkTestRegion  = "us-central1"
	networkTestZone    = "us-central1-a"
	networkTestBinding = "d31f90cdb0354b17c102e948ef5b8ec579f97ff876ce03334714b146a719af7d"
	computeBase        = "https://www.googleapis.com/compute/v1/projects/example-project/"
)

// goldenNetworkResources are the exact desired resources the M1-04 compiler
// emits for the shared fixture manifest (example-project, us-central1,
// 10.40.0.0/24). The fingerprints were captured from bootstrap.Compile and
// pin the adapter's descriptor mirror to the compiler.
func goldenNetworkResources() map[string]bootstrap.DesiredResource {
	network := "projects/example-project/global/networks/ctrldb-test-vpc"
	router := "projects/example-project/regions/us-central1/routers/ctrldb-test-router"
	golden := func(id string, kind bootstrap.ResourceKind, name, location, providerID, parent, fingerprint string) bootstrap.DesiredResource {
		return bootstrap.DesiredResource{ID: id, Kind: kind, Name: name, Project: networkTestProject, Location: location,
			ProviderID: providerID, ParentProviderID: parent, Permanence: bootstrap.PermanentSingleton, DesiredStateFingerprint: fingerprint}
	}
	return map[string]bootstrap.DesiredResource{
		"test-network": golden("test-network", bootstrap.ResourceNetwork, "ctrldb-test-vpc", "global", network, "",
			"72655d84df09ba0f76adab7cd6d06c34c3b7a64b3849cb2716c9a6f2678ba26a"),
		"test-subnet": golden("test-subnet", bootstrap.ResourceSubnetwork, "ctrldb-test-subnet", networkTestRegion,
			"projects/example-project/regions/us-central1/subnetworks/ctrldb-test-subnet", network,
			"40a97fdd0f4e9f1252c800128e86f86105fdf649298d57b26c415f995e7c4d3c"),
		"test-router": golden("test-router", bootstrap.ResourceRouter, "ctrldb-test-router", networkTestRegion, router, network,
			"904ea6c085482e038ac2667f4e8cbcde1be532148d6f51719ee3dac1a320ede4"),
		"test-nat": golden("test-nat", bootstrap.ResourceNAT, "ctrldb-test-nat", networkTestRegion, router+"/nats/ctrldb-test-nat", router,
			"5147b853a5dbb2bf15edc023ac928cb4ecea6b4ac7a20208fdda74255386f08c"),
		"test-iap-firewall": golden("test-iap-firewall", bootstrap.ResourceFirewall, "ctrldb-test-iap-ssh", "global",
			"projects/example-project/global/firewalls/ctrldb-test-iap-ssh", network,
			"6c4eb5096ad2b4368afce138710ef7a9f766b4b715b14dbce4529fc4130964e1"),
		"test-internal-firewall": golden("test-internal-firewall", bootstrap.ResourceFirewall, "ctrldb-test-internal", "global",
			"projects/example-project/global/firewalls/ctrldb-test-internal", network,
			"b65581decc34e5d37b4f7a6d01e3ce7f2ae97a8ea68cc968aded6de1cf4a8183"),
	}
}

func networkStepResources(kind bootstrap.IntentKind) []bootstrap.DesiredResource {
	golden := goldenNetworkResources()
	ids := networkIntentSteps[kind].resources
	result := make([]bootstrap.DesiredResource, 0, len(ids))
	for _, id := range ids {
		result = append(result, golden[id])
	}
	return result
}

func networkIntent(kind bootstrap.IntentKind) bootstrap.StepIntent {
	definition := networkIntentSteps[kind]
	return bootstrap.StepIntent{
		StepID: definition.stepID, Kind: kind, EnvelopeBindingSHA256: networkTestBinding, ExecutingIdentity: domain.IdentityHuman,
		ResourceIDs: append([]string(nil), definition.resources...), Dependencies: []string{"k5-lock-round-trip"},
		Preconditions: []string{"fresh-observation"}, Verification: []string{"exact"},
		Retry:          domain.RetryPolicy{MaxAttempts: 3, InitialBackoffSeconds: 5, MaxBackoffSeconds: 20},
		TimeoutSeconds: 60, CancelSafe: true, Compensation: "delete only recorded resources", PointOfNoReturn: bootstrap.PONRReversible,
	}
}

func networkPreflight(t *testing.T, subnets []observation.SubnetRange) observation.HarnessPreflight {
	t.Helper()
	required := bootstrap.RequiredAPIs()
	services := make([]observation.APIService, len(required))
	for index, service := range required {
		services[index] = observation.APIService{Name: service, State: observation.APIEnabled}
	}
	observedAt := fixedClock().Add(-time.Minute)
	preflight, err := observation.NewHarnessPreflight(observation.Seed{
		Account: networkTestAccount, Project: networkTestProject, Region: networkTestRegion, Zone: networkTestZone,
		GcloudVersion: observation.SupportedGcloudVersion, CompletenessPolicy: observation.GcloudCompletenessPolicy,
		ObservedAt: observedAt, ValidUntil: observedAt.Add(5 * time.Minute), Schemas: observation.RequiredSchemas(),
		Regions: []observation.Region{{Name: networkTestRegion, Availability: observation.AvailabilityUp, ProviderID: "projects/example-project/regions/us-central1"}},
		Zones:   []observation.Zone{{Name: networkTestZone, Region: networkTestRegion, Availability: observation.AvailabilityUp, ProviderID: "projects/example-project/zones/us-central1-a"}},
		MachineTypes: []observation.MachineType{{Name: "e2-medium", Zone: networkTestZone, GuestCPUs: 2, MemoryMiB: 4096,
			ProviderID: "projects/example-project/zones/us-central1-a/machineTypes/e2-medium"}},
		SubnetRanges: subnets, APIs: services, Exhaustive: true,
	})
	if err != nil {
		t.Fatalf("observation.NewHarnessPreflight() error = %v", err)
	}
	return preflight
}

// networkFixture caches the immutable configuration and preflight; every
// getter returns detached values, so sharing them across tests is safe.
var networkFixture struct {
	once          sync.Once
	configuration config.HarnessConfiguration
	preflight     observation.HarnessPreflight
}

func networkTarget(t *testing.T) NetworkTarget {
	t.Helper()
	networkFixture.once.Do(func() {
		networkFixture.configuration = validHarnessConfiguration(t)
		networkFixture.preflight = networkPreflight(t, nil)
	})
	return NetworkTarget{Account: networkTestAccount, Configuration: networkFixture.configuration, Preflight: networkFixture.preflight}
}

func networkAuthorization(intent bootstrap.StepIntent, preflight observation.HarnessPreflight) NetworkMutationAuthorization {
	return NetworkMutationAuthorization{
		PlanDocumentSHA256: strings.Repeat("1", 64), PlanV1Hash: strings.Repeat("2", 64), EnvelopeBindingSHA256: intent.EnvelopeBindingSHA256,
		OperationID: "op-20260906-0001", StepID: intent.StepID, Attempt: 1, ClaimGeneration: 1, ExecutingIdentity: domain.IdentityHuman,
		ObservationRevision: preflight.Revision(), ObservedAt: preflight.ObservedAt(), ValidUntil: preflight.ValidUntil(), Now: fixedClock(),
	}
}

type networkFakeStep struct {
	stdout   string
	stderr   string
	exitCode int
	err      error
}

// networkFake is a package-owned runner double. Production code can only
// obtain the sealed process boundary; this double is reachable solely through
// the unexported client field from tests in this package.
type networkFake struct {
	script []networkFakeStep
	calls  [][]string
}

func (fake *networkFake) Run(_ context.Context, request runner.Request) (runner.Result, error) {
	fake.calls = append(fake.calls, append([]string(nil), request.Arguments...))
	if len(fake.script) == 0 {
		return runner.Result{}, errors.New("unexpected command")
	}
	step := fake.script[0]
	fake.script = fake.script[1:]
	if step.err != nil {
		return runner.Result{ExitCode: -1}, step.err
	}
	return runner.Result{ExitCode: step.exitCode, Stdout: []byte(step.stdout), Stderr: redact.Sanitize(step.stderr)}, nil
}

func testNetworkClient(t *testing.T, script ...networkFakeStep) (*NetworkClient, *networkFake) {
	t.Helper()
	client, err := NewNetworkClient(NetworkClientOptions{
		GcloudPath: readHelperExecutable(t), SearchPath: "/usr/bin:/bin", Home: t.TempDir(), CloudSDKConfig: t.TempDir(),
		Locale: "C.UTF-8", CommandTimeout: 5 * time.Second, Clock: fixedClock,
	})
	if err != nil {
		t.Fatalf("NewNetworkClient() error = %v", err)
	}
	fake := &networkFake{script: script}
	client.boundary = fake
	return client, fake
}

func ok(stdout string) networkFakeStep { return networkFakeStep{stdout: stdout} }

// Present-state fixtures equal to the desired state.
const (
	presentNetwork = `[{"name":"ctrldb-test-vpc","selfLink":"` + computeBase + `global/networks/ctrldb-test-vpc","autoCreateSubnetworks":false}]`
	presentSubnet  = `[{"name":"ctrldb-test-subnet","selfLink":"` + computeBase + `regions/us-central1/subnetworks/ctrldb-test-subnet","region":"` + computeBase + `regions/us-central1","network":"` + computeBase + `global/networks/ctrldb-test-vpc","ipCidrRange":"10.40.0.0/24","privateIpGoogleAccess":true,"purpose":"PRIVATE","stackType":"IPV4_ONLY"}]`
	presentRouter  = `[{"name":"ctrldb-test-router","selfLink":"` + computeBase + `regions/us-central1/routers/ctrldb-test-router","region":"` + computeBase + `regions/us-central1","network":"` + computeBase + `global/networks/ctrldb-test-vpc"}]`
	presentNAT     = `[{"name":"ctrldb-test-nat","natIpAllocateOption":"AUTO_ONLY","sourceSubnetworkIpRangesToNat":"ALL_SUBNETWORKS_ALL_IP_RANGES","type":"PUBLIC"}]`
	presentStatus  = `{"result":{"network":"` + computeBase + `global/networks/ctrldb-test-vpc","natStatus":[{"name":"ctrldb-test-nat","minExtraNatIpsNeeded":0}]}}`
)

func presentFirewall(id string) string {
	golden := goldenNetworkResources()[id]
	description := networkOwnershipDescription(golden)
	source := `"sourceRanges":["35.235.240.0/20"]`
	port := "22"
	if id == "test-internal-firewall" {
		source = `"sourceTags":["ctrldb-test-node"]`
		port = "27017"
	}
	return `[{"name":"` + golden.Name + `","selfLink":"` + computeBase + `global/firewalls/` + golden.Name + `","network":"` + computeBase +
		`global/networks/ctrldb-test-vpc","direction":"INGRESS","disabled":false,"priority":1000,"description":"` + description + `",` + source +
		`,"targetTags":["ctrldb-test-node"],"allowed":[{"IPProtocol":"tcp","ports":["` + port + `"]}],"logConfig":{"enable":false}}]`
}

func presentObservations(kind bootstrap.IntentKind) [][]networkFakeStep {
	switch kind {
	case bootstrap.IntentNetwork:
		return [][]networkFakeStep{{ok(presentNetwork)}}
	case bootstrap.IntentSubnet:
		return [][]networkFakeStep{{ok(presentSubnet)}}
	case bootstrap.IntentNAT:
		return [][]networkFakeStep{{ok(presentRouter)}, {ok(presentNAT), ok(presentStatus)}}
	default:
		return [][]networkFakeStep{{ok(presentFirewall("test-iap-firewall"))}, {ok(presentFirewall("test-internal-firewall"))}}
	}
}

// createScript is observe(absent) -> create -> observe(present) per resource.
func createScript(kind bootstrap.IntentKind) []networkFakeStep {
	var script []networkFakeStep
	for _, present := range presentObservations(kind) {
		script = append(script, ok("[]"), ok(""))
		script = append(script, present...)
	}
	return script
}

func presentScript(kind bootstrap.IntentKind) []networkFakeStep {
	var script []networkFakeStep
	for _, present := range presentObservations(kind) {
		script = append(script, present...)
	}
	return script
}

func assertNetworkFailure(t *testing.T, name string, err error, kind NetworkFailureKind, mutation domain.MutationObservation) {
	t.Helper()
	var failure *NetworkError
	if !errors.As(err, &failure) || failure.Kind() != kind || failure.Mutation() != mutation || !errors.Is(err, ErrNetworkRejected) {
		t.Fatalf("%s error = %#v, want kind %q mutation %q", name, err, kind, mutation)
	}
	if !failure.Class().Valid() || strings.Contains(err.Error(), "SYNTHETIC") {
		t.Fatalf("%s error class = %q (%v)", name, failure.Class(), err)
	}
	if (failure.Class() == domain.RetryFailureTransient) != (kind == NetworkFailureProcess || kind == NetworkFailureUnverified) {
		t.Fatalf("%s class = %q for kind %q", name, failure.Class(), kind)
	}
}

func assertNoCreate(t *testing.T, calls [][]string) {
	t.Helper()
	for _, call := range calls {
		for _, argument := range call {
			if argument == "create" || argument == "delete" || argument == "update" {
				t.Fatalf("mutation command rendered: %q", call)
			}
		}
	}
}

func encodeCalls(t *testing.T, calls [][]string) string {
	t.Helper()
	var builder strings.Builder
	for _, call := range calls {
		encoded, err := json.Marshal(call)
		if err != nil {
			t.Fatalf("json.Marshal(argv) error = %v", err)
		}
		builder.Write(encoded)
		builder.WriteString("\n")
	}
	return builder.String()
}

func readGoldenArgv(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "network-argv", name+".jsonl"))
	if err != nil {
		t.Fatalf("read golden argv: %v", err)
	}
	return string(data)
}
