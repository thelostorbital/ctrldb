// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/observation"
	"github.com/thelostorbital/ctrldb/internal/runner"
)

const (
	readTimeout     = 30 * time.Second
	readStdoutLimit = 8 << 20
	readStderrLimit = 64 << 10
)

var (
	ErrReadRejected = errors.New("gcp read request rejected")
	accountPattern  = regexp.MustCompile(`^[^[:space:]@]+@[^[:space:]@]+$`)
	servicePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]*\.googleapis\.com$`)
)

type ReadFailureKind string

const (
	ReadFailureInvalid     ReadFailureKind = "invalid"
	ReadFailureProcess     ReadFailureKind = "process"
	ReadFailureSchema      ReadFailureKind = "schema"
	ReadFailureIdentity    ReadFailureKind = "identity"
	ReadFailureUnsupported ReadFailureKind = "unsupported"
)

type ReadError struct {
	kind   ReadFailureKind
	source string
}

func (failure *ReadError) Error() string {
	if failure == nil || failure.source == "" {
		return "gcp read failed"
	}
	return "gcp read failed: " + failure.source
}

func (failure *ReadError) Unwrap() error { return ErrReadRejected }
func (failure *ReadError) Kind() ReadFailureKind {
	if failure == nil {
		return ""
	}
	return failure.kind
}

type ReadClientOptions struct {
	GcloudPath     string
	SearchPath     string
	Home           string
	CloudSDKConfig string
	Locale         string
	CommandTimeout time.Duration
	EvidenceTTL    time.Duration
	Clock          func() time.Time
}

// ReadClient exposes only the closed M1-03 observation operation. It has no
// generic command or mutation method.
type ReadClient struct {
	boundary       *processBoundary
	executable     string
	environment    []runner.EnvironmentVariable
	evidenceTTL    time.Duration
	commandTimeout time.Duration
	clock          func() time.Time
}

func NewReadClient(options ReadClientOptions) (*ReadClient, error) {
	if options.CommandTimeout <= 0 || options.CommandTimeout > readTimeout ||
		options.EvidenceTTL <= 0 || options.EvidenceTTL > observation.MaxEvidenceLifetime || options.Clock == nil {
		return nil, &ReadError{kind: ReadFailureInvalid, source: "client options"}
	}
	if options.Locale != "C.UTF-8" && options.Locale != "en_US.UTF-8" {
		return nil, &ReadError{kind: ReadFailureInvalid, source: "client options"}
	}
	environment := []runner.EnvironmentVariable{
		{Name: "PATH", Value: options.SearchPath},
		{Name: "HOME", Value: options.Home},
		{Name: "CLOUDSDK_CONFIG", Value: options.CloudSDKConfig},
		{Name: "CLOUDSDK_CORE_DISABLE_PROMPTS", Value: "1"},
		{Name: "CLOUDSDK_CORE_DISABLE_USAGE_REPORTING", Value: "1"},
		{Name: "NO_COLOR", Value: "1"},
		{Name: "LC_ALL", Value: options.Locale},
	}
	boundary, err := newProcessBoundary(options.GcloudPath, environment)
	if err != nil {
		return nil, &ReadError{kind: ReadFailureInvalid, source: "process boundary"}
	}
	return &ReadClient{
		boundary: boundary, executable: options.GcloudPath,
		environment: append([]runner.EnvironmentVariable(nil), environment...),
		evidenceTTL: options.EvidenceTTL, commandTimeout: options.CommandTimeout, clock: options.Clock,
	}, nil
}

type HarnessReadRequest struct {
	Account       string
	Configuration config.HarnessConfiguration
	RequiredAPIs  []string
}

// ObserveHarness runs the complete, fixed, read-only WF-TEST-01 preflight.
// Any missing or failed source prevents construction of exhaustive evidence.
func (client *ReadClient) ObserveHarness(ctx context.Context, request HarnessReadRequest) (observation.HarnessPreflight, error) {
	if client == nil || ctx == nil || !accountPattern.MatchString(request.Account) {
		return observation.HarnessPreflight{}, &ReadError{kind: ReadFailureInvalid, source: "read context"}
	}
	configuration := request.Configuration
	if configuration.Project() == "" || configuration.Region() == "" || configuration.Zone() == "" {
		return observation.HarnessPreflight{}, &ReadError{kind: ReadFailureInvalid, source: "read context"}
	}
	requiredAPIs, err := validateRequiredAPIs(request.RequiredAPIs)
	if err != nil {
		return observation.HarnessPreflight{}, err
	}
	observedAt := client.clock().UTC()
	if observedAt.IsZero() {
		return observation.HarnessPreflight{}, &ReadError{kind: ReadFailureInvalid, source: "observation clock"}
	}

	common := commandContext{account: request.Account, project: configuration.Project(), region: configuration.Region(), zone: configuration.Zone()}
	versionOutput, err := client.run(ctx, schemaVersion, []string{"version", "--format=json"})
	if err != nil {
		return observation.HarnessPreflight{}, err
	}
	version, err := parseVersion(versionOutput)
	if err != nil || version != observation.SupportedGcloudVersion {
		return observation.HarnessPreflight{}, &ReadError{kind: ReadFailureUnsupported, source: schemaVersion}
	}

	authOutput, err := client.run(ctx, schemaAuth, authArguments(common))
	if err != nil {
		return observation.HarnessPreflight{}, err
	}
	if err := verifyAuth(authOutput, request.Account); err != nil {
		return observation.HarnessPreflight{}, &ReadError{kind: ReadFailureIdentity, source: schemaAuth}
	}
	configurationOutput, err := client.run(ctx, schemaConfiguration, configurationArguments(common))
	if err != nil {
		return observation.HarnessPreflight{}, err
	}
	if err := verifyConfiguration(configurationOutput, request.Account, configuration.Project()); err != nil {
		return observation.HarnessPreflight{}, &ReadError{kind: ReadFailureIdentity, source: schemaConfiguration}
	}
	projectOutput, err := client.run(ctx, schemaProject, projectArguments(common))
	if err != nil {
		return observation.HarnessPreflight{}, err
	}
	if err := verifyProject(projectOutput, configuration.Project()); err != nil {
		return observation.HarnessPreflight{}, &ReadError{kind: ReadFailureIdentity, source: schemaProject}
	}

	regions, err := client.readRegions(ctx, common)
	if err != nil {
		return observation.HarnessPreflight{}, err
	}
	zones, err := client.readZones(ctx, common)
	if err != nil {
		return observation.HarnessPreflight{}, err
	}
	machines, err := client.readMachineTypes(ctx, common)
	if err != nil {
		return observation.HarnessPreflight{}, err
	}
	subnets, subnetResources, err := client.readSubnets(ctx, common)
	if err != nil {
		return observation.HarnessPreflight{}, err
	}
	resources := append([]observation.Resource(nil), subnetResources...)
	firewalls, firewallResources, err := client.readFirewalls(ctx, common)
	if err != nil {
		return observation.HarnessPreflight{}, err
	}
	resources = append(resources, firewallResources...)

	resourceReaders := []func(context.Context, commandContext) ([]observation.Resource, error){
		client.readNetworks, client.readRouters, client.readInstances, client.readDisks,
		client.readSnapshots, client.readAddresses, client.readResourcePolicies,
		client.readServiceAccounts, client.readRoles, client.readBuckets, client.readSecrets,
		client.readRunJobs, client.readSchedulerJobs,
	}
	for _, read := range resourceReaders {
		items, readErr := read(ctx, common)
		if readErr != nil {
			return observation.HarnessPreflight{}, readErr
		}
		resources = append(resources, items...)
	}
	apis, err := client.readAPIs(ctx, common, requiredAPIs)
	if err != nil {
		return observation.HarnessPreflight{}, err
	}

	preflight, err := observation.NewHarnessPreflight(observation.Seed{
		Account: request.Account, Project: configuration.Project(), Region: configuration.Region(), Zone: configuration.Zone(),
		GcloudVersion: version, CompletenessPolicy: observation.GcloudCompletenessPolicy,
		ObservedAt: observedAt, ValidUntil: observedAt.Add(client.evidenceTTL),
		Schemas: observation.RequiredSchemas(), Regions: regions, Zones: zones, MachineTypes: machines,
		SubnetRanges: subnets, Resources: resources, APIs: apis, Firewalls: firewalls, Exhaustive: true,
	})
	if err != nil {
		return observation.HarnessPreflight{}, &ReadError{kind: ReadFailureSchema, source: "normalized preflight"}
	}
	return preflight, nil
}

func (client *ReadClient) run(ctx context.Context, source string, arguments []string) ([]byte, error) {
	result, err := client.boundary.Run(ctx, runner.Request{
		Executable: client.executable, Arguments: append([]string(nil), arguments...),
		Environment: append([]runner.EnvironmentVariable(nil), client.environment...),
		Timeout:     client.commandTimeout, StdoutLimitBytes: readStdoutLimit, StderrLimitBytes: readStderrLimit,
	})
	if err != nil {
		return nil, &ReadError{kind: ReadFailureProcess, source: source}
	}
	if result.Stderr.String() != "" {
		return nil, &ReadError{kind: ReadFailureProcess, source: source}
	}
	return append([]byte(nil), result.Stdout...), nil
}

type commandContext struct{ account, project, region, zone string }

func globalArguments(ctx commandContext, group ...string) []string {
	args := append([]string(nil), group...)
	return append(args, "--account="+ctx.account, "--project="+ctx.project, "--quiet", "--verbosity=error")
}

func validateRequiredAPIs(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, &ReadError{kind: ReadFailureInvalid, source: "required APIs"}
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index, value := range result {
		if !servicePattern.MatchString(value) || (index > 0 && value == result[index-1]) {
			return nil, &ReadError{kind: ReadFailureInvalid, source: "required APIs"}
		}
	}
	return result, nil
}

func sourceError(source string, err error) error {
	if err == nil {
		return nil
	}
	return &ReadError{kind: ReadFailureSchema, source: source}
}

func normalizeComputeLocation(value, project, collection string) (string, bool) {
	parts := strings.Split(strings.TrimSuffix(value, "/"), "/")
	if len(parts) < 4 {
		return "", false
	}
	name := parts[len(parts)-1]
	projectScopes := 0
	for index, part := range parts {
		if part != "projects" {
			continue
		}
		if index+3 >= len(parts) || parts[index+1] != project || parts[index+2] != collection || parts[index+3] != name || index+4 != len(parts) {
			return "", false
		}
		projectScopes++
	}
	return name, projectScopes == 1
}

func normalizedProviderID(project string, kind observation.ResourceKind, location, name string) string {
	return fmt.Sprintf("projects/%s/%s/%s/%s", project, location, kind, name)
}
