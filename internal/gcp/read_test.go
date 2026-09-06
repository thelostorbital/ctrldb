// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/observation"
)

func TestMain(m *testing.M) {
	processHelper := false
	for _, argument := range os.Args[1:] {
		if strings.HasPrefix(argument, "-test.") {
			processHelper = true
			break
		}
	}
	if filepath.Base(os.Args[0]) == "gcloud" && len(os.Args) > 1 && !processHelper {
		runReadHelper()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestReadClientObservesCompleteDeterministicHarnessPreflight(t *testing.T) {
	client, sdkConfig := testReadClient(t, "valid", 5*time.Second)
	request := validHarnessReadRequest(t)
	first, err := client.ObserveHarness(context.Background(), request)
	if err != nil {
		t.Fatalf("ObserveHarness() error = %v", err)
	}
	second, err := client.ObserveHarness(context.Background(), request)
	if err != nil {
		t.Fatalf("second ObserveHarness() error = %v", err)
	}

	if !first.Exhaustive() || first.Account() != request.Account || first.Project() != request.Configuration.Project() ||
		first.Region() != request.Configuration.Region() || first.Zone() != request.Configuration.Zone() ||
		first.GcloudVersion() != observation.SupportedGcloudVersion {
		t.Fatalf("preflight context = %#v", first)
	}
	if first.CompletenessPolicy() != observation.GcloudCompletenessPolicy {
		t.Fatalf("completeness policy = %q", first.CompletenessPolicy())
	}
	if first.Revision() != second.Revision() {
		t.Fatalf("deterministic revision changed: %s != %s", first.Revision(), second.Revision())
	}
	if got := first.APIState("compute.googleapis.com"); got != observation.APIEnabled {
		t.Fatalf("compute API = %q", got)
	}
	if got := first.APIState("iam.googleapis.com"); got != observation.APIDisabled {
		t.Fatalf("IAM API = %q", got)
	}
	if got := first.APIState("unrequested.googleapis.com"); got != observation.APIUnknown {
		t.Fatalf("unrequested API = %q", got)
	}
	if got, ingressErr := first.PublicMongoDBIngressAt(first.ObservedAt()); ingressErr != nil || !slices.Equal(got, []string{"public-mongodb"}) {
		t.Fatalf("public MongoDB rules = %v", got)
	}
	serviceAccountFound := false
	for _, resource := range first.Resources() {
		if resource.Kind == observation.ResourceServiceAccount && resource.ImmutableID == "123456789012345678901" {
			serviceAccountFound = true
		}
	}
	if !serviceAccountFound {
		t.Fatal("service-account immutable identity was not preserved")
	}
	collisions := map[observation.ResourceKind]string{
		observation.ResourceNetwork:        "ctrldb-test-vpc",
		observation.ResourceSubnetwork:     "ctrldb-test-subnet",
		observation.ResourceRouter:         "ctrldb-test-router",
		observation.ResourceNAT:            "ctrldb-test-nat",
		observation.ResourceFirewall:       "ctrldb-test-iap-ssh",
		observation.ResourceInstance:       "ctrldb-test-run-node",
		observation.ResourceDisk:           "ctrldb-test-run-data",
		observation.ResourceSnapshot:       "ctrldb-test-run-snapshot",
		observation.ResourceAddress:        "ctrldb-test-run-address",
		observation.ResourceResourcePolicy: "ctrldb-test-run-policy",
		observation.ResourceServiceAccount: "ctrldb-test-operator@example-project.iam.gserviceaccount.com",
		observation.ResourceCustomRole:     "ctrldbTestOperator",
		observation.ResourceBucket:         "example-project-ctrldb-state",
		observation.ResourceSecret:         "ctrldb-test-run-secret",
		observation.ResourceRunJob:         "ctrldb-test-wipe",
		observation.ResourceSchedulerJob:   "ctrldb-test-wipe-schedule",
	}
	for kind, name := range collisions {
		if !first.HasCollision(kind, name) {
			t.Errorf("missing %s collision for %q", kind, name)
		}
	}
	overlap, err := first.CIDROverlapsAt(request.Configuration.CIDR(), first.ObservedAt())
	if err != nil || !overlap {
		t.Fatalf("CIDROverlaps() = %v, %v", overlap, err)
	}

	commands, err := os.ReadFile(filepath.Join(sdkConfig, "commands.log"))
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	assertReadOnlyCommands(t, string(commands), request)
}

func TestReadClientRejectsInvalidContextAndOptions(t *testing.T) {
	configuration := validHarnessConfiguration(t)
	client, _ := testReadClient(t, "valid", 5*time.Second)
	tests := []HarnessReadRequest{
		{Account: "", Configuration: configuration, RequiredAPIs: []string{"compute.googleapis.com"}},
		{Account: "not-an-account", Configuration: configuration, RequiredAPIs: []string{"compute.googleapis.com"}},
		{Account: "operator@example.invalid", Configuration: configuration},
		{Account: "operator@example.invalid", Configuration: configuration, RequiredAPIs: []string{"bad service"}},
		{Account: "operator@example.invalid", Configuration: configuration, RequiredAPIs: []string{"compute.googleapis.com", "compute.googleapis.com"}},
	}
	for index, request := range tests {
		_, err := client.ObserveHarness(context.Background(), request)
		assertReadFailure(t, fmt.Sprintf("request-%d", index), err, ReadFailureInvalid)
	}

	executable := readHelperExecutable(t)
	base := ReadClientOptions{GcloudPath: executable, SearchPath: "/usr/bin:/bin", Home: t.TempDir(), CloudSDKConfig: t.TempDir(), Locale: "C.UTF-8", CommandTimeout: time.Second, EvidenceTTL: time.Minute, Clock: fixedClock}
	invalid := []func(*ReadClientOptions){
		func(value *ReadClientOptions) { value.CommandTimeout = 0 },
		func(value *ReadClientOptions) { value.CommandTimeout = readTimeout + time.Second },
		func(value *ReadClientOptions) { value.EvidenceTTL = 0 },
		func(value *ReadClientOptions) { value.EvidenceTTL = observation.MaxEvidenceLifetime + time.Second },
		func(value *ReadClientOptions) { value.Locale = "" },
		func(value *ReadClientOptions) { value.Clock = nil },
	}
	for index, mutate := range invalid {
		options := base
		mutate(&options)
		_, err := NewReadClient(options)
		assertReadFailure(t, fmt.Sprintf("options-%d", index), err, ReadFailureInvalid)
	}
}

func TestReadClientFailsClosedOnHostileProviderOutput(t *testing.T) {
	tests := []struct {
		scenario string
		kind     ReadFailureKind
	}{
		{scenario: "unsupported-version", kind: ReadFailureUnsupported},
		{scenario: "malformed", kind: ReadFailureSchema},
		{scenario: "trailing", kind: ReadFailureSchema},
		{scenario: "duplicate-field", kind: ReadFailureSchema},
		{scenario: "unknown-field", kind: ReadFailureSchema},
		{scenario: "duplicate-identity", kind: ReadFailureSchema},
		{scenario: "cross-project", kind: ReadFailureSchema},
		{scenario: "cross-account", kind: ReadFailureIdentity},
		{scenario: "ambient-impersonation", kind: ReadFailureIdentity},
		{scenario: "configuration-project-mismatch", kind: ReadFailureIdentity},
		{scenario: "cross-location", kind: ReadFailureSchema},
		{scenario: "cross-location-project", kind: ReadFailureSchema},
		{scenario: "unknown-api-state", kind: ReadFailureSchema},
		{scenario: "malformed-api-name", kind: ReadFailureSchema},
		{scenario: "missing-page", kind: ReadFailureProcess},
		{scenario: "partial-success-diagnostic", kind: ReadFailureProcess},
		{scenario: "oversized", kind: ReadFailureProcess},
		{scenario: "nonzero-secret", kind: ReadFailureProcess},
	}
	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			client, _ := testReadClient(t, test.scenario, 5*time.Second)
			_, err := client.ObserveHarness(context.Background(), validHarnessReadRequest(t))
			assertReadFailure(t, test.scenario, err, test.kind)
			if err != nil && strings.Contains(err.Error(), "SYNTHETIC_SECRET_VALUE") {
				t.Fatal("provider error exposed stderr")
			}
		})
	}
}

func TestReadClientPropagatesTimeoutAndCancellationAsSanitizedProcessFailures(t *testing.T) {
	client, _ := testReadClient(t, "timeout", 20*time.Millisecond)
	_, err := client.ObserveHarness(context.Background(), validHarnessReadRequest(t))
	assertReadFailure(t, "timeout", err, ReadFailureProcess)

	client, _ = testReadClient(t, "valid", time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = client.ObserveHarness(ctx, validHarnessReadRequest(t))
	assertReadFailure(t, "cancel", err, ReadFailureProcess)
}

func TestStrictJSONRejectsTopLevelAndNestedAmbiguity(t *testing.T) {
	var target []regionWire
	invalid := [][]byte{
		[]byte(``), []byte(`null`), []byte(`[] {}`), []byte(`[ {"name":"a","name":"b"} ]`),
		[]byte(`[ {"name":"a","Name":"b"} ]`),
		[]byte(`[ {"name":"a","nested":{"x":1,"x":2}} ]`),
		[]byte(`[ {"name":"a","unknown":true} ]`),
		{'[', '{', '"', 'n', 'a', 'm', 'e', '"', ':', '"', 0xff, '"', '}', ']'},
	}
	for index, input := range invalid {
		if err := decodeStrictJSON(input, &target); !errors.Is(err, errInvalidJSON) {
			t.Fatalf("input %d error = %v", index, err)
		}
	}
}

func testReadClient(t *testing.T, scenario string, timeout time.Duration) (*ReadClient, string) {
	t.Helper()
	executable := readHelperExecutable(t)
	sdkConfig := filepath.Join(t.TempDir(), scenario)
	if err := os.MkdirAll(sdkConfig, 0o700); err != nil {
		t.Fatalf("create SDK config fixture: %v", err)
	}
	client, err := NewReadClient(ReadClientOptions{
		GcloudPath: executable, SearchPath: "/usr/bin:/bin", Home: t.TempDir(), CloudSDKConfig: sdkConfig,
		Locale: "C.UTF-8", CommandTimeout: timeout, EvidenceTTL: time.Minute, Clock: fixedClock,
	})
	if err != nil {
		t.Fatalf("NewReadClient() error = %v", err)
	}
	return client, sdkConfig
}

func readHelperExecutable(t *testing.T) string {
	t.Helper()
	current, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	executable := filepath.Join(t.TempDir(), "gcloud")
	if err := os.Link(current, executable); err != nil {
		t.Fatalf("create gcloud helper: %v", err)
	}
	return executable
}

func validHarnessReadRequest(t *testing.T) HarnessReadRequest {
	t.Helper()
	return HarnessReadRequest{Account: "operator@example.invalid", Configuration: validHarnessConfiguration(t), RequiredAPIs: []string{"iam.googleapis.com", "compute.googleapis.com"}}
}

func validHarnessConfiguration(t *testing.T) config.HarnessConfiguration {
	t.Helper()
	fixture, err := os.ReadFile("../config/testdata/manifest-v1alpha1.yaml")
	if err != nil {
		t.Fatalf("read manifest fixture: %v", err)
	}
	manifest := strings.Replace(string(fixture), "  name: staging\n  class: staging", "  name: disposable-test\n  class: disposable", 1)
	manifest = strings.Replace(manifest, "    serviceAccount: ctrldb-host@example-project.iam.gserviceaccount.com", "    serviceAccount: ctrldb-test-vm@example-project.iam.gserviceaccount.com", 1)
	manifest = strings.Replace(manifest, "    schedulerJob: ctrldb-reconcile\n    runJob: ctrldb-reconcile\n    serviceAccount: ctrldb-reconciler@example-project.iam.gserviceaccount.com", "    schedulerJob: ctrldb-test-wipe-schedule\n    runJob: ctrldb-test-wipe\n    serviceAccount: ctrldb-test-wipe@example-project.iam.gserviceaccount.com", 1)
	testIsolation := strings.Join([]string{
		"  testIsolation:",
		"    namePrefix: ctrldb-test-",
		"    labels: {managed-by: ctrldb, environment: disposable, purpose: test}",
		"    operatorServiceAccount: ctrldb-test-operator@example-project.iam.gserviceaccount.com",
		"    destructiveServiceAccount: ctrldb-test-destructive@example-project.iam.gserviceaccount.com",
		"    network: {vpc: ctrldb-test-vpc, subnet: ctrldb-test-subnet, cidr: 10.40.0.0/24, nat: ctrldb-test-nat}",
		"    ciPrincipal: principalSet://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/example-pool/attribute.repository/example-org/ctrldb",
		"    caps: {maxMachineType: e2-medium, maxDiskGiB: 100, maxInstances: 3, maxLifetime: 8h, maxEstimatedUSDPerRun: 25}",
		"    monitoringTests: manual-only",
		"",
	}, "\n")
	manifest = strings.Replace(manifest, "spec:\n", "spec:\n"+testIsolation, 1)
	document, err := config.DecodeManifest([]byte(manifest))
	if err != nil {
		t.Fatalf("DecodeManifest() error = %v", err)
	}
	configuration, err := config.HarnessConfigurationFromManifest(document)
	if err != nil {
		t.Fatalf("HarnessConfigurationFromManifest() error = %v", err)
	}
	return configuration
}

func fixedClock() time.Time { return time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC) }

func assertReadFailure(t *testing.T, name string, err error, kind ReadFailureKind) {
	t.Helper()
	var failure *ReadError
	if !errors.As(err, &failure) || failure.Kind() != kind {
		t.Fatalf("%s error = %#v, want kind %q", name, err, kind)
	}
}

func assertReadOnlyCommands(t *testing.T, log string, request HarnessReadRequest) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(log), "\n")
	if len(lines) != len(observation.RequiredSchemas())*2 { // the test performs two complete observations
		t.Fatalf("command count = %d, want %d", len(lines), len(observation.RequiredSchemas())*2)
	}
	for _, line := range lines {
		for _, forbidden := range []string{" create ", " update ", " delete ", " enable ", " disable ", " execute ", "jobs execute", " ssh ", "auth login", "print-access-token", "--async", "--limit", "--page-size", "--configuration", "--impersonate-service-account"} {
			if strings.Contains(" "+line+" ", forbidden) {
				t.Fatalf("command admitted forbidden token %q: %s", forbidden, line)
			}
		}
		if strings.HasPrefix(line, "version ") || line == "version --format=json" {
			continue
		}
		if !strings.Contains(line, "--account="+request.Account) || !strings.Contains(line, "--project="+request.Configuration.Project()) {
			t.Fatalf("command lacks explicit identity/project: %s", line)
		}
		if strings.HasPrefix(line, "auth list ") && !strings.Contains(line, "--filter=account="+request.Account) {
			t.Fatalf("auth command lacks the exact account filter: %s", line)
		}
	}
}

func runReadHelper() {
	scenario := filepath.Base(os.Getenv("CLOUDSDK_CONFIG"))
	args := os.Args[1:]
	logPath := filepath.Join(os.Getenv("CLOUDSDK_CONFIG"), "commands.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err == nil {
		_, _ = fmt.Fprintln(log, strings.Join(args, " "))
		_ = log.Close()
	}
	key := commandKey(args)
	if scenario == "timeout" && key == "version" {
		time.Sleep(time.Second)
	}
	if scenario == "nonzero-secret" && key == "version" {
		_, _ = io.WriteString(os.Stderr, "token=SYNTHETIC_SECRET_VALUE")
		os.Exit(17)
	}
	if scenario == "oversized" && key == "version" {
		_, _ = io.WriteString(os.Stdout, strings.Repeat("x", int(readStdoutLimit)+1))
		return
	}
	if scenario == "missing-page" && key == "compute regions list" {
		os.Exit(18)
	}
	if scenario == "partial-success-diagnostic" && key == "compute instances list" {
		_, _ = io.WriteString(os.Stderr, "Some requests did not succeed")
	}
	output := helperOutput(key)
	if scenario == "unsupported-version" && key == "version" {
		output = `{"Google Cloud SDK":"561.0.0"}`
	}
	if scenario == "malformed" && key == "compute regions list" {
		output = `[`
	}
	if scenario == "trailing" && key == "compute regions list" {
		output += `{}`
	}
	if scenario == "duplicate-field" && key == "compute regions list" {
		output = `[ {"name":"us-central1","name":"other","status":"UP","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1"} ]`
	}
	if scenario == "unknown-field" && key == "compute regions list" {
		output = `[ {"name":"us-central1","status":"UP","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1","unexpected":true} ]`
	}
	if scenario == "duplicate-identity" && key == "compute regions list" {
		output = `[{"name":"us-central1","status":"UP","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1"},{"name":"us-central1","status":"UP","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1-copy"}]`
	}
	if scenario == "cross-project" && key == "compute regions list" {
		output = `[ {"name":"us-central1","status":"UP","selfLink":"https://compute.googleapis.com/compute/v1/projects/foreign-project/regions/us-central1"} ]`
	}
	if scenario == "cross-account" && key == "auth list" {
		output = `[{"account":"other@example.invalid"}]`
	}
	if scenario == "ambient-impersonation" && key == "config list" {
		output = `{"auth":{"impersonate_service_account":"impersonated@example-project.iam.gserviceaccount.com"},"core":{"account":"operator@example.invalid","project":"example-project"}}`
	}
	if scenario == "configuration-project-mismatch" && key == "config list" {
		output = `{"core":{"account":"operator@example.invalid","project":"foreign-project"}}`
	}
	if scenario == "cross-location" && key == "compute machine-types list" {
		output = `[ {"name":"e2-medium","zone":"https://compute.googleapis.com/compute/v1/projects/example-project/zones/us-east1-b","guestCpus":2,"memoryMb":4096,"isSharedCpu":false,"selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/zones/us-east1-b/machineTypes/e2-medium"} ]`
	}
	if scenario == "cross-location-project" && key == "compute machine-types list" {
		output = `[ {"name":"e2-medium","zone":"https://compute.googleapis.com/compute/v1/projects/foreign-project/zones/us-central1-a","guestCpus":2,"memoryMb":4096,"isSharedCpu":false,"selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/zones/us-central1-a/machineTypes/e2-medium"} ]`
	}
	if scenario == "unknown-api-state" && key == "services list" {
		output = `[{"config":{"name":"compute.googleapis.com"},"state":"STATE_UNSPECIFIED"}]`
	}
	if scenario == "malformed-api-name" && key == "services list" {
		output = `[{"config":{"name":"Compute.googleapis.com"},"state":"ENABLED"}]`
	}
	_, _ = io.WriteString(os.Stdout, output)
}

func commandKey(args []string) string {
	plain := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") {
			continue
		}
		plain = append(plain, arg)
	}
	candidates := []string{"compute machine-types list", "compute networks subnets list", "compute firewall-rules list", "compute resource-policies list", "iam service-accounts list", "storage buckets list", "run jobs list", "scheduler jobs list", "compute regions list", "compute zones list", "compute networks list", "compute routers list", "compute instances list", "compute disks list", "compute snapshots list", "compute addresses list", "iam roles list", "secrets list", "services list", "auth list", "config list", "projects describe", "version"}
	joined := strings.Join(plain, " ")
	for _, candidate := range candidates {
		if strings.HasPrefix(joined, candidate) {
			return candidate
		}
	}
	return "unknown"
}

func helperOutput(key string) string {
	switch key {
	case "version":
		return `{"Google Cloud SDK":"560.0.0","core":"2026.03.09"}`
	case "auth list":
		return `[{"account":"operator@example.invalid"}]`
	case "config list":
		return `{"core":{"account":"operator@example.invalid","project":"example-project"}}`
	case "projects describe":
		return `{"projectId":"example-project","projectNumber":"123456789","lifecycleState":"ACTIVE"}`
	case "compute regions list":
		return `[{"name":"us-central1","status":"UP","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1"},{"name":"us-east1","status":"UP","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-east1"}]`
	case "compute zones list":
		return `[{"name":"us-central1-a","region":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1","status":"UP","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/zones/us-central1-a"},{"name":"us-east1-b","region":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-east1","status":"DOWN","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/zones/us-east1-b"}]`
	case "compute machine-types list":
		return `[{"name":"e2-medium","zone":"https://compute.googleapis.com/compute/v1/projects/example-project/zones/us-central1-a","guestCpus":2,"memoryMb":4096,"isSharedCpu":false,"selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/zones/us-central1-a/machineTypes/e2-medium"}]`
	case "compute networks list":
		return `[{"name":"ctrldb-test-vpc","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/global/networks/ctrldb-test-vpc"}]`
	case "compute networks subnets list":
		return `[{"name":"ctrldb-test-subnet","region":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1","ipCidrRange":"10.40.0.0/25","secondaryIpRanges":[{"ipCidrRange":"10.41.0.0/24"}],"selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1/subnetworks/ctrldb-test-subnet"}]`
	case "compute routers list":
		return `[{"name":"ctrldb-test-router","region":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1","nats":[{"name":"ctrldb-test-nat"}],"selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1/routers/ctrldb-test-router"}]`
	case "compute firewall-rules list":
		return `[{"name":"public-mongodb","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/global/firewalls/public-mongodb","direction":"INGRESS","disabled":false,"sourceRanges":["0.0.0.0/0"],"allowed":[{"IPProtocol":"tcp","ports":["27017"]}]},{"name":"ctrldb-test-iap-ssh","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/global/firewalls/ctrldb-test-iap-ssh","direction":"INGRESS","disabled":false,"sourceRanges":["35.235.240.0/20"],"allowed":[{"IPProtocol":"tcp","ports":["22"]}]}]`
	case "compute instances list":
		return `[{"name":"ctrldb-test-run-node","zone":"https://compute.googleapis.com/compute/v1/projects/example-project/zones/us-central1-a","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/zones/us-central1-a/instances/ctrldb-test-run-node"}]`
	case "compute disks list":
		return `[{"name":"ctrldb-test-run-data","zone":"https://compute.googleapis.com/compute/v1/projects/example-project/zones/us-central1-a","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/zones/us-central1-a/disks/ctrldb-test-run-data"}]`
	case "compute snapshots list":
		return `[{"name":"ctrldb-test-run-snapshot","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/global/snapshots/ctrldb-test-run-snapshot"}]`
	case "compute addresses list":
		return `[{"name":"ctrldb-test-run-address","region":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1/addresses/ctrldb-test-run-address"}]`
	case "compute resource-policies list":
		return `[{"name":"ctrldb-test-run-policy","region":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1","selfLink":"https://compute.googleapis.com/compute/v1/projects/example-project/regions/us-central1/resourcePolicies/ctrldb-test-run-policy"}]`
	case "iam service-accounts list":
		return `[{"email":"ctrldb-test-operator@example-project.iam.gserviceaccount.com","projectId":"example-project","uniqueId":"123456789012345678901"}]`
	case "iam roles list":
		return `[{"name":"projects/example-project/roles/ctrldbTestOperator","deleted":false}]`
	case "storage buckets list":
		return `[{"name":"example-project-ctrldb-state","location":"US-CENTRAL1"}]`
	case "secrets list":
		return `[{"name":"projects/example-project/secrets/ctrldb-test-run-secret"}]`
	case "run jobs list":
		return `[{"metadata":{"name":"ctrldb-test-wipe"}}]`
	case "scheduler jobs list":
		return `[{"name":"projects/example-project/locations/us-central1/jobs/ctrldb-test-wipe-schedule"}]`
	case "services list":
		return `[{"config":{"name":"compute.googleapis.com"},"state":"ENABLED"}]`
	default:
		return `[]`
	}
}
