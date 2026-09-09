// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/observation"
	"github.com/thelostorbital/ctrldb/internal/runner"
)

// M1-06 network adapter. It translates one authorized typed WF-TEST-01
// T1-T4 intent into fixed synchronous gcloud templates behind the sealed
// process boundary. It never accepts a plain resource name, an argv, a
// runner, or an ambient project/account/region.
const (
	// networkStepTimeout bounds one T1-T4 step. It equals the WF-TEST-01 row
	// timeout, so a compiled intent can never lengthen it.
	networkStepTimeout = 60 * time.Second
	// networkOwnershipSchema is the D-157 versioned ownership description
	// prefix written to provider kinds which support a description.
	networkOwnershipSchema = "ctrldb-ownership/v1"
	networkTestNodeTag     = "ctrldb-test-node"
	networkSSHPort         = 22
	networkMongoDBPort     = 27017
)

var (
	ErrNetworkRejected   = errors.New("gcp network mutation rejected")
	networkHexPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	networkNamePattern   = regexp.MustCompile(`^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	networkRegionPattern = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+$`)
	networkOpIDPattern   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$`)
)

// NetworkFailureKind classifies a refusal or failure without exposing
// provider output.
type NetworkFailureKind string

const (
	NetworkFailureInvalid       NetworkFailureKind = "invalid"
	NetworkFailureAuthorization NetworkFailureKind = "authorization"
	NetworkFailureIntent        NetworkFailureKind = "intent"
	NetworkFailureTarget        NetworkFailureKind = "target"
	NetworkFailureProcess       NetworkFailureKind = "process"
	NetworkFailureSchema        NetworkFailureKind = "schema"
	NetworkFailureDrift         NetworkFailureKind = "drift"
	NetworkFailureUnverified    NetworkFailureKind = "unverified"
)

// NetworkError is the only error type returned by the adapter. Mutation
// reports whether a provider mutation is known to have happened before the
// failure so the gateway can pause, retry, or compensate correctly.
type NetworkError struct {
	kind     NetworkFailureKind
	source   string
	mutation domain.MutationObservation
}

func (failure *NetworkError) Error() string {
	if failure == nil || failure.source == "" {
		return "gcp network mutation failed"
	}
	return "gcp network mutation failed: " + failure.source
}

func (failure *NetworkError) Unwrap() error { return ErrNetworkRejected }

func (failure *NetworkError) Kind() NetworkFailureKind {
	if failure == nil {
		return ""
	}
	return failure.kind
}

// Class maps the failure onto the domain retry classification: refusals and
// hostile output are validation failures, provider process failures are
// transient, drift is a stale fingerprint, and an unverified post-create state
// is transient because the idempotent observe-then-create loop converges.
func (failure *NetworkError) Class() domain.RetryFailureClass {
	switch failure.Kind() {
	case NetworkFailureProcess, NetworkFailureUnverified:
		return domain.RetryFailureTransient
	case NetworkFailureDrift:
		return domain.RetryFailureStaleFingerprint
	default:
		return domain.RetryFailureValidation
	}
}

func (failure *NetworkError) Mutation() domain.MutationObservation {
	if failure == nil || failure.mutation == "" {
		return domain.MutationNotOccurred
	}
	return failure.mutation
}

func networkError(kind NetworkFailureKind, source string) error {
	return &NetworkError{kind: kind, source: source, mutation: domain.MutationNotOccurred}
}

func networkMutationError(kind NetworkFailureKind, source string, mutation domain.MutationObservation) error {
	return &NetworkError{kind: kind, source: source, mutation: mutation}
}

// NetworkClientOptions mirrors ReadClientOptions. Evidence freshness comes
// from the authorization, not from a client-level TTL.
type NetworkClientOptions struct {
	GcloudPath     string
	SearchPath     string
	Home           string
	CloudSDKConfig string
	Locale         string
	CommandTimeout time.Duration
	Clock          func() time.Time
}

// NetworkClient exposes only the closed T1-T4 apply and verify operations.
type NetworkClient struct {
	boundary       runner.Runner
	executable     string
	environment    []runner.EnvironmentVariable
	commandTimeout time.Duration
	clock          func() time.Time
}

// NewNetworkClient seals one validated absolute gcloud executable and the
// explicit minimal SDK environment exactly like NewReadClient.
func NewNetworkClient(options NetworkClientOptions) (*NetworkClient, error) {
	if options.CommandTimeout <= 0 || options.CommandTimeout > networkStepTimeout || options.Clock == nil {
		return nil, networkError(NetworkFailureInvalid, "client options")
	}
	if options.Locale != "C.UTF-8" && options.Locale != "en_US.UTF-8" {
		return nil, networkError(NetworkFailureInvalid, "client options")
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
		return nil, networkError(NetworkFailureInvalid, "process boundary")
	}
	return &NetworkClient{
		boundary: boundary, executable: options.GcloudPath,
		environment:    append([]runner.EnvironmentVariable(nil), environment...),
		commandTimeout: options.CommandTimeout, clock: options.Clock,
	}, nil
}

// NetworkMutationAuthorization carries the uniform M-1 mutation claim. The
// central gateway maps one durable claim onto every adapter; this adapter only
// validates the value against the intent, the fresh observation, and the
// current time.
type NetworkMutationAuthorization struct {
	PlanDocumentSHA256    string
	PlanV1Hash            string
	EnvelopeBindingSHA256 string
	OperationID           string
	StepID                string
	Attempt               uint32
	ClaimGeneration       uint64
	ExecutingIdentity     domain.ExecutionIdentity
	ObservationRevision   string
	ObservedAt            time.Time
	ValidUntil            time.Time
	Now                   time.Time
}

// NetworkTarget binds the explicit account, the immutable validated harness
// configuration, and the fresh exact preflight the authorization refers to.
type NetworkTarget struct {
	Account       string
	Configuration config.HarnessConfiguration
	Preflight     observation.HarnessPreflight
}

// NetworkResourceOutcome is the closed per-resource result.
type NetworkResourceOutcome string

const (
	NetworkResourceAlreadyPresent NetworkResourceOutcome = "already-present"
	NetworkResourceCreated        NetworkResourceOutcome = "created"
	NetworkResourceDeleted        NetworkResourceOutcome = "deleted"
	NetworkResourceAbsent         NetworkResourceOutcome = "absent"
)

// NetworkResourceResult is a typed, provider-output-free result for one
// desired resource.
type NetworkResourceResult struct {
	ResourceID              string
	Kind                    bootstrap.ResourceKind
	Name                    string
	Project                 string
	Location                string
	ProviderID              string
	Outcome                 NetworkResourceOutcome
	DesiredStateFingerprint string
}

// NetworkCreatedResource records one resource created by exactly this
// operation, step, and attempt. Only such records can ever authorize a
// compensating delete.
type NetworkCreatedResource struct {
	OperationID string
	StepID      string
	Attempt     uint32
	ResourceID  string
	Kind        bootstrap.ResourceKind
	Name        string
	Project     string
	Location    string
	ProviderID  string
}

// NetworkStepResult is the typed result of one T1-T4 apply or verify. On a
// partial failure the returned value still lists every resource created
// before the failure so the gateway can persist the compensation record.
type NetworkStepResult struct {
	OperationID string
	StepID      string
	Attempt     uint32
	Kind        bootstrap.IntentKind
	Resources   []NetworkResourceResult
	Created     []NetworkCreatedResource
}

// ApplyStep observes, creates when exactly absent, and re-observes each
// desired resource of one authorized T1-T4 intent in order. An existing
// resource must equal the desired fingerprint exactly; otherwise nothing is
// mutated.
func (client *NetworkClient) ApplyStep(
	ctx context.Context,
	authorization NetworkMutationAuthorization,
	intent bootstrap.StepIntent,
	resources []bootstrap.DesiredResource,
	target NetworkTarget,
) (NetworkStepResult, error) {
	return client.execute(ctx, authorization, intent, resources, target, true)
}

// VerifyStep performs only the observation half of ApplyStep. It never
// renders a create command; an absent or drifted resource is an error.
func (client *NetworkClient) VerifyStep(
	ctx context.Context,
	authorization NetworkMutationAuthorization,
	intent bootstrap.StepIntent,
	resources []bootstrap.DesiredResource,
	target NetworkTarget,
) (NetworkStepResult, error) {
	return client.execute(ctx, authorization, intent, resources, target, false)
}

func (client *NetworkClient) execute(
	ctx context.Context,
	authorization NetworkMutationAuthorization,
	intent bootstrap.StepIntent,
	resources []bootstrap.DesiredResource,
	target NetworkTarget,
	mutate bool,
) (NetworkStepResult, error) {
	if client == nil || client.boundary == nil || ctx == nil {
		return NetworkStepResult{}, networkError(NetworkFailureInvalid, "client context")
	}
	plan, err := client.admit(authorization, intent, resources, target)
	if err != nil {
		return NetworkStepResult{}, err
	}
	if mutate {
		for _, expected := range plan {
			if expected.resource.Kind == bootstrap.ResourceSubnetwork {
				if err := rejectSubnetOverlap(target.Preflight, expected, authorization.Now); err != nil {
					return NetworkStepResult{}, err
				}
			}
		}
	}
	stepContext, cancel := context.WithTimeout(ctx, stepTimeout(intent))
	defer cancel()

	result := NetworkStepResult{OperationID: authorization.OperationID, StepID: intent.StepID, Attempt: authorization.Attempt, Kind: intent.Kind}
	for _, expected := range plan {
		outcome, applyErr := client.applyResource(stepContext, expected, mutate, func() error {
			return client.validateNetworkAuthorization(authorization, intent, target.Preflight)
		})
		if outcome.Outcome == NetworkResourceCreated {
			result.Created = append(result.Created, NetworkCreatedResource{
				OperationID: authorization.OperationID, StepID: intent.StepID, Attempt: authorization.Attempt,
				ResourceID: expected.resource.ID, Kind: expected.resource.Kind, Name: expected.resource.Name,
				Project: expected.resource.Project, Location: expected.resource.Location, ProviderID: expected.resource.ProviderID,
			})
		}
		if applyErr != nil {
			if len(result.Created) != 0 {
				var failure *NetworkError
				if errors.As(applyErr, &failure) && failure.Mutation() == domain.MutationNotOccurred {
					applyErr = networkMutationError(failure.kind, failure.source, domain.MutationOccurred)
				}
			}
			return result, applyErr
		}
		result.Resources = append(result.Resources, outcome)
	}
	return result, nil
}

// applyResource is the describe-before-create loop for one resource.
func (client *NetworkClient) applyResource(
	ctx context.Context,
	expected expectedNetworkResource,
	mutate bool,
	authorizeMutation func() error,
) (NetworkResourceResult, error) {
	result := NetworkResourceResult{
		ResourceID: expected.resource.ID, Kind: expected.resource.Kind, Name: expected.resource.Name,
		Project: expected.resource.Project, Location: expected.resource.Location, ProviderID: expected.resource.ProviderID,
		DesiredStateFingerprint: expected.resource.DesiredStateFingerprint,
	}
	present, err := client.observe(ctx, expected)
	if err != nil {
		return NetworkResourceResult{}, err
	}
	if present {
		result.Outcome = NetworkResourceAlreadyPresent
		return result, nil
	}
	if !mutate {
		return NetworkResourceResult{}, networkError(NetworkFailureDrift, expected.resource.ID+" is absent")
	}
	if err := authorizeMutation(); err != nil {
		return NetworkResourceResult{}, err
	}
	if err := client.create(ctx, expected); err != nil {
		return NetworkResourceResult{}, err
	}
	result.Outcome = NetworkResourceCreated
	present, err = client.observe(ctx, expected)
	if err != nil {
		var failure *NetworkError
		if errors.As(err, &failure) {
			return result, networkMutationError(NetworkFailureUnverified, failure.source, domain.MutationOccurred)
		}
		return result, networkMutationError(NetworkFailureUnverified, expected.resource.ID, domain.MutationOccurred)
	}
	if !present {
		return result, networkMutationError(NetworkFailureUnverified, expected.resource.ID+" absent after create", domain.MutationOccurred)
	}
	return result, nil
}

// observe runs the exact-name read for one resource and reports exact
// presence. A present resource which differs from the desired state is drift.
func (client *NetworkClient) observe(ctx context.Context, expected expectedNetworkResource) (bool, error) {
	data, err := client.run(ctx, expected.observeArguments(), expected.resource.ID+" observe")
	if err != nil {
		return false, err
	}
	present, err := expected.parseObservation(data)
	if err != nil {
		return false, err
	}
	if !present {
		return false, nil
	}
	if expected.resource.Kind == bootstrap.ResourceNAT {
		statusData, statusErr := client.run(ctx, expected.statusArguments(), expected.resource.ID+" status")
		if statusErr != nil {
			return false, statusErr
		}
		if err := expected.parseNATStatus(statusData); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (client *NetworkClient) create(ctx context.Context, expected expectedNetworkResource) error {
	_, err := client.run(ctx, expected.createArguments(), expected.resource.ID+" create")
	if err == nil {
		return nil
	}
	var failure *NetworkError
	if errors.As(err, &failure) {
		return networkMutationError(failure.kind, failure.source, domain.MutationUnknown)
	}
	return networkMutationError(NetworkFailureProcess, expected.resource.ID+" create", domain.MutationUnknown)
}

func (client *NetworkClient) run(ctx context.Context, arguments []string, source string) ([]byte, error) {
	result, err := client.boundary.Run(ctx, runner.Request{
		Executable: client.executable, Arguments: append([]string(nil), arguments...),
		Environment: append([]runner.EnvironmentVariable(nil), client.environment...),
		Timeout:     client.commandTimeout, StdoutLimitBytes: readStdoutLimit, StderrLimitBytes: readStderrLimit,
	})
	if err != nil || result.ExitCode != 0 || result.Stderr.String() != "" {
		return nil, networkError(NetworkFailureProcess, source)
	}
	return append([]byte(nil), result.Stdout...), nil
}

// admit fails closed on any missing, stale, mismatched, or cross-project
// value before a process can run, then returns the closed expected resource
// set derived only from the validated configuration.
func (client *NetworkClient) admit(
	authorization NetworkMutationAuthorization,
	intent bootstrap.StepIntent,
	resources []bootstrap.DesiredResource,
	target NetworkTarget,
) ([]expectedNetworkResource, error) {
	if err := validateNetworkTarget(target); err != nil {
		return nil, err
	}
	if err := validateNetworkIntent(intent); err != nil {
		return nil, err
	}
	if err := client.validateNetworkAuthorization(authorization, intent, target.Preflight); err != nil {
		return nil, err
	}
	return expectedNetworkResources(intent, resources, target)
}

func validateNetworkTarget(target NetworkTarget) error {
	configuration := target.Configuration
	if !accountPattern.MatchString(target.Account) || configuration.Project() == "" || configuration.Zone() == "" ||
		!networkNamePattern.MatchString(configuration.Project()) || !networkRegionPattern.MatchString(configuration.Region()) {
		return networkError(NetworkFailureTarget, "harness configuration")
	}
	if configuration.NamePrefix() != config.TestResourcePrefix {
		return networkError(NetworkFailureTarget, "harness prefix")
	}
	preflight := target.Preflight
	if !preflight.Exhaustive() || preflight.Account() != target.Account || preflight.Project() != configuration.Project() ||
		preflight.Region() != configuration.Region() || preflight.Zone() != configuration.Zone() ||
		preflight.GcloudVersion() != observation.SupportedGcloudVersion {
		return networkError(NetworkFailureTarget, "preflight binding")
	}
	return nil
}

var networkIntentSteps = map[bootstrap.IntentKind]struct {
	stepID    string
	resources []string
}{
	bootstrap.IntentNetwork:  {stepID: "t1-network", resources: []string{"test-network"}},
	bootstrap.IntentSubnet:   {stepID: "t2-subnet", resources: []string{"test-subnet"}},
	bootstrap.IntentNAT:      {stepID: "t3-nat", resources: []string{"test-router", "test-nat"}},
	bootstrap.IntentFirewall: {stepID: "t4-firewall", resources: []string{"test-iap-firewall", "test-internal-firewall"}},
}

func validateNetworkIntent(intent bootstrap.StepIntent) error {
	definition, ok := networkIntentSteps[intent.Kind]
	if !ok {
		return networkError(NetworkFailureIntent, "intent kind")
	}
	if intent.StepID != definition.stepID || !equalStrings(intent.ResourceIDs, definition.resources) {
		return networkError(NetworkFailureIntent, "intent step")
	}
	if !networkHexPattern.MatchString(intent.EnvelopeBindingSHA256) || intent.ExecutingIdentity != domain.IdentityHuman {
		return networkError(NetworkFailureIntent, "intent binding")
	}
	if !intent.Retry.Valid() || intent.TimeoutSeconds <= 0 || time.Duration(intent.TimeoutSeconds)*time.Second > networkStepTimeout {
		return networkError(NetworkFailureIntent, "intent bounds")
	}
	if intent.PointOfNoReturn != bootstrap.PONRReversible || intent.Transition != nil || !intent.CancelSafe {
		return networkError(NetworkFailureIntent, "intent classification")
	}
	return nil
}

func (client *NetworkClient) validateNetworkAuthorization(
	authorization NetworkMutationAuthorization,
	intent bootstrap.StepIntent,
	preflight observation.HarnessPreflight,
) error {
	for _, digest := range []string{authorization.PlanDocumentSHA256, authorization.PlanV1Hash, authorization.EnvelopeBindingSHA256, authorization.ObservationRevision} {
		if !networkHexPattern.MatchString(digest) {
			return networkError(NetworkFailureAuthorization, "authorization digest")
		}
	}
	if authorization.EnvelopeBindingSHA256 != intent.EnvelopeBindingSHA256 || authorization.StepID != intent.StepID {
		return networkError(NetworkFailureAuthorization, "authorization step binding")
	}
	if !networkOpIDPattern.MatchString(authorization.OperationID) || authorization.ClaimGeneration < 1 ||
		authorization.Attempt < 1 || authorization.Attempt > intent.Retry.MaxAttempts {
		return networkError(NetworkFailureAuthorization, "authorization claim")
	}
	if !authorization.ExecutingIdentity.Valid() || authorization.ExecutingIdentity != intent.ExecutingIdentity {
		return networkError(NetworkFailureAuthorization, "authorization identity")
	}
	if authorization.ObservationRevision != preflight.Revision() ||
		!authorization.ObservedAt.Equal(preflight.ObservedAt()) || !authorization.ValidUntil.Equal(preflight.ValidUntil()) {
		return networkError(NetworkFailureAuthorization, "authorization observation")
	}
	if !utcInstant(authorization.Now) || !preflight.FreshAt(authorization.Now) {
		return networkError(NetworkFailureAuthorization, "authorization freshness")
	}
	clock := client.clock().UTC()
	if clock.Before(authorization.Now) || !preflight.FreshAt(clock) {
		return networkError(NetworkFailureAuthorization, "authorization clock")
	}
	return nil
}

func stepTimeout(intent bootstrap.StepIntent) time.Duration {
	return time.Duration(intent.TimeoutSeconds) * time.Second
}

func utcInstant(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

// networkFirewallSpec is the closed desired shape of one permanent T4 rule.
type networkFirewallSpec struct {
	name        string
	network     string
	sourceRange string
	sourceTag   string
	targetTags  []string
	port        int
	description string
}

func iapFirewallSpec(vpc, description string) networkFirewallSpec {
	return networkFirewallSpec{name: isolation.TestIAPSSHFirewallName, network: vpc, sourceRange: isolation.IAPTCPSourceCIDR,
		targetTags: []string{networkTestNodeTag}, port: networkSSHPort, description: description}
}

func internalFirewallSpec(vpc, description string) networkFirewallSpec {
	return networkFirewallSpec{name: isolation.TestInternalFirewallName, network: vpc, sourceTag: networkTestNodeTag,
		targetTags: []string{networkTestNodeTag}, port: networkMongoDBPort, description: description}
}
