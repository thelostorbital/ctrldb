// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"errors"
	"regexp"
	"slices"
	"time"
)

const (
	TestVPCName              = "ctrldb-test-vpc"
	IAPTCPSourceCIDR         = "35.235.240.0/20"
	FirewallPortSSH   uint16 = 22
	FirewallPortMongo uint16 = 27017
	FirewallPriority         = uint32(1000)
	// TestHarnessRevocationWorkflowID is the only workflow allowed to revoke
	// or tear down run-scoped TEST-ISO exposure.
	TestHarnessRevocationWorkflowID = "WF-TEST-01"
	iapSSHFirewallRuleSuffix        = "iap-ssh"
	mongoFirewallRuleSuffix         = "internal"
	testNodeTagPrefix               = "ctrldb-test-n-"
	firewallDescriptionPrefix       = "ctrldb:test-isolation:lifetime-sha256="
	firewallDescriptionSuffix       = ";revoke=" + TestHarnessRevocationWorkflowID
)

var (
	// ErrUnsafeFirewall marks a rule whose network, purpose, protocol, source,
	// port, or tag shape could expose a non-test resource.
	ErrUnsafeFirewall          = errors.New("unsafe isolation firewall rule")
	testTagPattern             = regexp.MustCompile(`^ctrldb-test-[a-z0-9](?:[a-z0-9-]{0,49}[a-z0-9])?$`)
	runLifetimeRecordIDPattern = regexp.MustCompile(`^lifetime-[0-9a-f]{16}$`)
)

// FirewallPurpose selects one of the two firewall shapes admitted by the
// test-isolation harness.
type FirewallPurpose string

const (
	FirewallPurposeIAPSSH        FirewallPurpose = "iap-ssh"
	FirewallPurposeInternalMongo FirewallPurpose = "internal-mongodb"
)

// FirewallDirection is the closed Compute Engine firewall direction admitted
// by TEST-ISO.
type FirewallDirection string

const FirewallDirectionIngress FirewallDirection = "INGRESS"

// FirewallIPProtocol is the closed IP protocol admitted by TEST-ISO.
type FirewallIPProtocol string

const FirewallIPProtocolTCP FirewallIPProtocol = "tcp"

// FirewallTrafficRule is one explicit Compute Engine allowed or denied tuple.
// TEST-ISO admits exactly one TCP allowed tuple and no denied tuples.
type FirewallTrafficRule struct {
	IPProtocol FirewallIPProtocol
	Ports      []uint16
}

// FirewallLogMetadata is the closed metadata mode of a Compute Engine
// firewall log configuration. TEST-ISO health/admin rules admit only none.
type FirewallLogMetadata string

const FirewallLogMetadataNone FirewallLogMetadata = ""

// FirewallLogConfig is the explicit provider log configuration. D-066 keeps
// logging disabled, with no metadata mode, for these health/admin rules.
type FirewallLogConfig struct {
	Enabled  bool
	Metadata FirewallLogMetadata
}

// FirewallRule is the normalized, complete input for one admitted Compute v1
// firewalls.insert request. Every security-relevant provider default is
// represented and validated. Output-only provider fields are intentionally
// absent; provider-specific adapters are outside this package.
type FirewallRule struct {
	Identity                    ResourceIdentity
	Description                 string
	Network                     ResourceIdentity
	RunID                       string
	Purpose                     FirewallPurpose
	Enabled                     bool
	Priority                    uint32
	Direction                   FirewallDirection
	Allowed                     []FirewallTrafficRule
	Denied                      []FirewallTrafficRule
	DestinationCIDRs            []string
	SourceCIDRs                 []string
	SourceTags                  []string
	SourceServiceAccounts       []string
	TargetTags                  []string
	TargetServiceAccounts       []string
	LogConfig                   FirewallLogConfig
	ResourceManagerTags         map[string]string
	LifetimeContractFingerprint string
}

// FirewallObservationState is the exhaustive discovered state of one desired
// run-scoped firewall rule.
type FirewallObservationState string

const (
	FirewallObservationAbsent  FirewallObservationState = "absent"
	FirewallObservationPresent FirewallObservationState = "present"
)

// FirewallObservation binds one desired identity to either confirmed absence
// or the complete normalized provider state observed at the proof boundary.
// PresentRule must be nil for absence and complete for presence.
type FirewallObservation struct {
	Identity    ResourceIdentity
	State       FirewallObservationState
	PresentRule *FirewallRule
}

// RunLifetimeContract is the single durable lifetime record for one
// disposable test run. RecordID and RecordGeneration identify the immutable
// object version that must exist before provider mutation. Plan and OperationID
// prevent a reused run ID from adopting an earlier run's exposure while still
// allowing later steps and retries of that same operation to use the rule.
//
// A future provider adapter must persist the canonical description derived
// from the resulting fingerprint in both run-scoped firewall rules, then parse
// and observe that exact description when rediscovering either rule. The
// fingerprint binds every field in this contract. The WF-TEST-01 teardown and
// nightly-cleanup adapter consumes the durable record and removes each rule no
// later than ExpiresAt. This pure package performs no provider or durable-record
// I/O.
type RunLifetimeContract struct {
	RunID                string
	Plan                 PlanIdentity
	OperationID          string
	RecordID             string
	RecordGeneration     uint64
	CreatedAt            time.Time
	ExpiresAt            time.Time
	RevocationWorkflowID string
}

// FirewallValidationContext supplies the independently sourced values used to
// validate a run-level lifetime record. Full mutation gates construct it from
// trusted policy, the immutable plan, the durable operation, and their own
// boundary clock; it is not serialized into each firewall rule.
type FirewallValidationContext struct {
	RunID           string
	Plan            PlanIdentity
	Operation       OperationBinding
	PlannedLifetime time.Duration
	RunLimits       RunLimits
	RunLifetime     RunLifetimeContract
	Now             time.Time
}

// RunLifetimeContractFingerprint returns the canonical identity a future
// adapter persists in, and parses back from, both run-scoped rule descriptions.
// Time and policy bounds are evaluated separately at each independent mutation
// boundary; this function performs no provider or durable-record I/O.
func RunLifetimeContractFingerprint(contract RunLifetimeContract) (string, error) {
	if err := ValidateRunID(contract.RunID); err != nil {
		return "", err
	}
	if !planIDPattern.MatchString(contract.Plan.ID) || !isSHA256Fingerprint(contract.Plan.Hash) {
		return "", guardError(ErrInvalidGuardInput, "runLifetime.plan", "must identify a canonical immutable plan")
	}
	if !operationIDPattern.MatchString(contract.OperationID) {
		return "", guardError(ErrInvalidGuardInput, "runLifetime.operationID", "must identify one durable operation")
	}
	if !runLifetimeRecordIDPattern.MatchString(contract.RecordID) || contract.RecordGeneration == 0 {
		return "", guardError(ErrInvalidGuardInput, "runLifetime.record", "must identify one immutable durable record generation")
	}
	if contract.CreatedAt.IsZero() || contract.ExpiresAt.IsZero() {
		return "", guardError(ErrInvalidGuardInput, "runLifetime.timestamps", "must be complete")
	}
	for _, value := range []time.Time{contract.CreatedAt, contract.ExpiresAt} {
		if _, offset := value.Zone(); offset != 0 {
			return "", guardError(ErrInvalidGuardInput, "runLifetime.timestamps", "must use UTC")
		}
	}
	if contract.RevocationWorkflowID != TestHarnessRevocationWorkflowID {
		return "", guardError(ErrUnsafeFirewall, "runLifetime.revocationWorkflowID", "must use the TEST-ISO teardown workflow")
	}
	return canonicalJSONFingerprint(contract)
}

// RunFirewallDescription returns the only bounded Compute firewall description
// accepted for a lifetime contract fingerprint. A future adapter must send and
// rediscover this value verbatim; it must not synthesize its own metadata.
func RunFirewallDescription(lifetimeFingerprint string) (string, error) {
	if !isSHA256Fingerprint(lifetimeFingerprint) {
		return "", guardError(ErrInvalidGuardInput, "runLifetime.fingerprint", "must be a SHA-256 fingerprint")
	}
	return firewallDescriptionPrefix + lifetimeFingerprint + firewallDescriptionSuffix, nil
}

func validateRunLifetimeContract(
	contract RunLifetimeContract,
	runID string,
	plan PlanIdentity,
	operation OperationBinding,
	plannedLifetime time.Duration,
	limits RunLimits,
	now time.Time,
) (string, error) {
	fingerprint, err := RunLifetimeContractFingerprint(contract)
	if err != nil {
		return "", err
	}
	if contract.RunID != runID {
		return "", guardError(ErrUnsafeFirewall, "runLifetime.runID", "does not match the owning run")
	}
	if contract.Plan != plan {
		return "", guardError(ErrUnsafeFirewall, "runLifetime.plan", "does not match the immutable test plan")
	}
	if err := validateOperationBinding(operation); err != nil {
		return "", err
	}
	if contract.OperationID != operation.OperationID {
		return "", guardError(ErrUnsafeFirewall, "runLifetime.operationID", "does not match the durable operation")
	}
	if now.IsZero() {
		return "", guardError(ErrInvalidGuardInput, "now", "must not be zero")
	}
	if plannedLifetime <= 0 || limits.MaxLifetime <= 0 {
		return "", guardError(ErrInvalidGuardInput, "runLifetime", "requires positive trusted lifetime bounds")
	}
	if contract.CreatedAt.After(now) {
		return "", guardError(ErrStaleProof, "runLifetime.createdAt", "must not be after the mutation-boundary time")
	}
	if !now.Before(contract.ExpiresAt) {
		return "", guardError(ErrStaleProof, "runLifetime.expiresAt", "must be strictly after the mutation-boundary time")
	}
	duration := contract.ExpiresAt.Sub(contract.CreatedAt)
	if duration <= 0 {
		return "", guardError(ErrStaleProof, "runLifetime.expiresAt", "must be strictly after record creation")
	}
	if duration > plannedLifetime || duration > limits.MaxLifetime {
		return "", guardError(ErrCapacityExceeded, "runLifetime.expiresAt", "exceeds the planned or configured run lifetime")
	}
	return fingerprint, nil
}

// ValidateFirewallRules requires exactly one IAP SSH rule and one internal
// MongoDB rule, plus one exhaustive provider observation for each identity.
// Only confirmed-absent rules may be selected as insert targets; exact-present
// rules are converged, while any different or ambiguous state fails closed.
func ValidateFirewallRules(rules []FirewallRule, observations []FirewallObservation, productionCIDRs []string, targets []MutationTarget, context FirewallValidationContext) error {
	lifetimeFingerprint, err := validateRunLifetimeContract(
		context.RunLifetime,
		context.RunID,
		context.Plan,
		context.Operation,
		context.PlannedLifetime,
		context.RunLimits,
		context.Now,
	)
	if err != nil {
		return err
	}
	if len(rules) != 2 {
		return guardError(ErrUnsafeFirewall, "firewallRules", "must contain both required purpose proofs")
	}
	if len(observations) != len(rules) {
		return guardError(ErrUnsafeFirewall, "firewallObservations", "must contain one exhaustive observation per required rule")
	}
	selected, err := SelectRunMutationTargets(context.RunID, targets)
	if err != nil {
		return err
	}
	targetKeys := make(map[string]struct{}, len(selected))
	for _, target := range selected {
		if target.Identity.Service == ComputeServiceName && target.Identity.Kind == ComputeFirewallKind {
			targetKeys[target.Identity.CanonicalKey] = struct{}{}
		}
	}
	if len(targetKeys) != len(selected) {
		return guardError(ErrUnsafeFirewall, "targets", "contains an unproved non-firewall mutation")
	}
	seen := make(map[FirewallPurpose]struct{}, len(rules))
	rulesByKey := make(map[string]FirewallRule, len(rules))
	for index, rule := range rules {
		path := indexedField("firewallRules", index)
		if _, exists := seen[rule.Purpose]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier firewall purpose")
		}
		seen[rule.Purpose] = struct{}{}
		if err := validateFirewallRule(rule, productionCIDRs, context.RunID, lifetimeFingerprint); err != nil {
			return guardError(err, path, "failed its purpose proof")
		}
		if _, exists := rulesByKey[rule.Identity.CanonicalKey]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier firewall identity")
		}
		rulesByKey[rule.Identity.CanonicalKey] = normalizeFirewallRule(rule)
	}
	if _, ok := seen[FirewallPurposeIAPSSH]; !ok {
		return guardError(ErrUnsafeFirewall, "firewallRules", "is missing the IAP SSH purpose")
	}
	if _, ok := seen[FirewallPurposeInternalMongo]; !ok {
		return guardError(ErrUnsafeFirewall, "firewallRules", "is missing the internal MongoDB purpose")
	}

	absent := make(map[string]struct{}, len(rules))
	observed := make(map[string]struct{}, len(observations))
	for index, observation := range observations {
		path := indexedField("firewallObservations", index)
		if err := validateResourceIdentity(observation.Identity); err != nil {
			return guardError(err, path+".identity", "must identify one desired firewall")
		}
		desired, exists := rulesByKey[observation.Identity.CanonicalKey]
		if !exists || observation.Identity != desired.Identity {
			return guardError(ErrUnsafeFirewall, path, "does not identify a required firewall")
		}
		if _, duplicate := observed[observation.Identity.CanonicalKey]; duplicate {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier firewall observation")
		}
		observed[observation.Identity.CanonicalKey] = struct{}{}
		switch observation.State {
		case FirewallObservationAbsent:
			if observation.PresentRule != nil {
				return guardError(ErrInvalidGuardInput, path, "is ambiguous between absent and present")
			}
			absent[observation.Identity.CanonicalKey] = struct{}{}
		case FirewallObservationPresent:
			if observation.PresentRule == nil {
				return guardError(ErrInvalidGuardInput, path, "must include complete present provider state")
			}
			if err := validateFirewallRule(*observation.PresentRule, productionCIDRs, context.RunID, lifetimeFingerprint); err != nil {
				return guardError(err, path+".presentRule", "is not a safe complete provider state")
			}
			if !equalFirewallRule(*observation.PresentRule, desired) {
				return guardError(ErrProofMismatch, path+".presentRule", "differs from the desired normalized provider state")
			}
		default:
			return guardError(ErrInvalidGuardInput, path+".state", "must be absent or present")
		}
	}
	if len(observed) != len(rulesByKey) || len(targetKeys) != len(absent) {
		return guardError(ErrUnsafeFirewall, "firewallObservations", "does not exhaustively match desired rules and insert targets")
	}
	for key := range absent {
		if _, exists := targetKeys[key]; !exists {
			return guardError(ErrUnsafeFirewall, "targets", "must select every and only confirmed-absent firewall")
		}
	}
	return nil
}

// ValidateFirewallRule validates the exact shape allowed for its declared
// purpose. Errors identify only structural fields and never discovered values.
func ValidateFirewallRule(rule FirewallRule, productionCIDRs []string, context FirewallValidationContext) error {
	lifetimeFingerprint, err := validateRunLifetimeContract(
		context.RunLifetime,
		context.RunID,
		context.Plan,
		context.Operation,
		context.PlannedLifetime,
		context.RunLimits,
		context.Now,
	)
	if err != nil {
		return err
	}
	return validateFirewallRule(rule, productionCIDRs, context.RunID, lifetimeFingerprint)
}

func validateFirewallRule(rule FirewallRule, productionCIDRs []string, runID string, lifetimeFingerprint string) error {
	rule = normalizeFirewallRule(rule)
	if err := ValidateRunID(runID); err != nil {
		return err
	}
	if !isSHA256Fingerprint(lifetimeFingerprint) {
		return guardError(ErrInvalidGuardInput, "runLifetime.fingerprint", "must be a SHA-256 fingerprint")
	}
	if rule.RunID != runID {
		return guardError(ErrUnsafeFirewall, "runID", "does not match the owning run")
	}
	expectedDescription, err := RunFirewallDescription(lifetimeFingerprint)
	if err != nil {
		return err
	}
	if rule.Description != expectedDescription {
		return guardError(ErrUnsafeFirewall, "description", "does not bind the exact run lifetime contract")
	}
	if !rule.Enabled {
		return guardError(ErrUnsafeFirewall, "enabled", "must be enabled")
	}
	if err := validateResourceIdentity(rule.Identity); err != nil {
		return guardError(ErrUnsafeFirewall, "identity", "must be a complete canonical firewall identity")
	}
	if err := validateResourceIdentity(rule.Network); err != nil {
		return guardError(ErrUnsafeFirewall, "network", "must be a complete canonical network identity")
	}
	if rule.Identity.Service != ComputeServiceName || rule.Identity.Kind != ComputeFirewallKind || rule.Identity.Scope != ResourceScopeGlobal ||
		rule.Network.Service != ComputeServiceName || rule.Network.Kind != ComputeNetworkKind || rule.Network.Scope != ResourceScopeGlobal ||
		rule.Network.Name != TestVPCName || rule.Identity.Project != rule.Network.Project {
		return guardError(ErrUnsafeFirewall, "identity", "must bind a global Compute firewall to the explicit test VPC project")
	}
	if rule.Priority != FirewallPriority {
		return guardError(ErrUnsafeFirewall, "priority", "must use the fixed TEST-ISO priority")
	}
	if rule.Direction != FirewallDirectionIngress {
		return guardError(ErrUnsafeFirewall, "direction", "must be ingress")
	}
	if len(rule.Allowed) != 1 || len(rule.Denied) != 0 || rule.Allowed[0].IPProtocol != FirewallIPProtocolTCP || len(rule.Allowed[0].Ports) != 1 {
		return guardError(ErrUnsafeFirewall, "allow", "must contain one purpose-specific TCP port")
	}
	if len(rule.DestinationCIDRs) != 0 || len(rule.SourceServiceAccounts) != 0 || len(rule.TargetServiceAccounts) != 0 {
		return guardError(ErrUnsafeFirewall, "selectors", "contains a selector outside the admitted TEST-ISO shape")
	}
	if rule.LogConfig.Enabled || rule.LogConfig.Metadata != FirewallLogMetadataNone {
		return guardError(ErrUnsafeFirewall, "logConfig", "must be disabled without metadata")
	}
	if len(rule.ResourceManagerTags) != 0 {
		return guardError(ErrUnsafeFirewall, "resourceManagerTags", "must be empty")
	}
	if err := validateTestTags("targetTags", rule.TargetTags, true); err != nil {
		return err
	}
	if err := validateProductionCIDRs(productionCIDRs); err != nil {
		return err
	}
	for index, source := range rule.SourceCIDRs {
		prefix, err := parseCanonicalIPv4Prefix(source)
		if err != nil {
			return guardError(ErrInvalidGuardInput, indexedField("sourceCIDRs", index), "must be a canonical IPv4 prefix")
		}
		for productionIndex, value := range productionCIDRs {
			production, _ := parseCanonicalIPv4Prefix(value)
			if prefixesOverlap(prefix, production) {
				return guardError(ErrNetworkOverlap, indexedField("productionCIDRs", productionIndex), "overlaps a firewall source")
			}
		}
	}

	switch rule.Purpose {
	case FirewallPurposeIAPSSH:
		expectedName, _ := RunFirewallRuleName(runID, FirewallPurposeIAPSSH)
		expectedTag, _ := RunNodeTag(lifetimeFingerprint)
		if rule.Identity.Name != expectedName || rule.Allowed[0].Ports[0] != FirewallPortSSH || len(rule.SourceTags) != 0 ||
			len(rule.SourceCIDRs) != 1 || rule.SourceCIDRs[0] != IAPTCPSourceCIDR ||
			!slices.Equal(rule.TargetTags, []string{expectedTag}) || rule.LifetimeContractFingerprint != lifetimeFingerprint {
			return guardError(ErrUnsafeFirewall, "shape", "does not match the IAP SSH purpose")
		}
	case FirewallPurposeInternalMongo:
		expectedName, _ := RunFirewallRuleName(runID, FirewallPurposeInternalMongo)
		expectedTag, _ := RunNodeTag(lifetimeFingerprint)
		if rule.Identity.Name != expectedName || rule.Allowed[0].Ports[0] != FirewallPortMongo || len(rule.SourceCIDRs) != 0 ||
			rule.LifetimeContractFingerprint != lifetimeFingerprint {
			return guardError(ErrUnsafeFirewall, "shape", "does not match the internal MongoDB purpose")
		}
		if err := validateTestTags("sourceTags", rule.SourceTags, true); err != nil {
			return err
		}
		if !slices.Equal(rule.SourceTags, []string{expectedTag}) || !slices.Equal(rule.TargetTags, []string{expectedTag}) {
			return guardError(ErrUnsafeFirewall, "shape", "does not match the internal MongoDB purpose")
		}
	default:
		return guardError(ErrUnsafeFirewall, "purpose", "is not recognized")
	}

	return nil
}

// RunFirewallRuleName derives the only firewall rule name accepted for a
// purpose and run, preventing one run's rule from selecting another run.
func RunFirewallRuleName(runID string, purpose FirewallPurpose) (string, error) {
	prefix, err := RunResourcePrefix(runID)
	if err != nil {
		return "", err
	}
	switch purpose {
	case FirewallPurposeIAPSSH:
		return prefix + iapSSHFirewallRuleSuffix, nil
	case FirewallPurposeInternalMongo:
		return prefix + mongoFirewallRuleSuffix, nil
	default:
		return "", guardError(ErrUnsafeFirewall, "purpose", "is not recognized")
	}
}

// RunNodeTag derives the only node tag admitted for one immutable run lifetime.
// Future complete VM intents must consume this exact tag; M-0 intentionally
// does not infer or authorize any VM request.
func RunNodeTag(lifetimeFingerprint string) (string, error) {
	if !isSHA256Fingerprint(lifetimeFingerprint) {
		return "", guardError(ErrInvalidGuardInput, "runLifetime.fingerprint", "must be a SHA-256 fingerprint")
	}
	// The fixed prefix plus 49 hex characters is exactly the provider's 63-byte
	// maximum and retains 196 bits of the immutable lifetime identity.
	return testNodeTagPrefix + lifetimeFingerprint[:49], nil
}

// ValidateFirewallTags is retained as the shared tag-shape primitive. Full
// mutation gates must use ValidateFirewallRule so port and source purpose are
// proved as well.
func ValidateFirewallTags(sourceTags, targetTags []string) error {
	if err := validateTestTags("sourceTags", sourceTags, false); err != nil {
		return err
	}
	return validateTestTags("targetTags", targetTags, true)
}

func validateTestTags(path string, tags []string, required bool) error {
	if required && len(tags) == 0 {
		return guardError(ErrInvalidGuardInput, path, "must not be empty")
	}
	seen := make(map[string]struct{}, len(tags))
	for index, tag := range tags {
		itemPath := indexedField(path, index)
		if !testTagPattern.MatchString(tag) {
			return guardError(ErrUnsafeTarget, itemPath, "must use the reserved test namespace")
		}
		if _, exists := seen[tag]; exists {
			return guardError(ErrInvalidGuardInput, itemPath, "duplicates an earlier tag")
		}
		seen[tag] = struct{}{}
	}
	return nil
}

func validateProductionCIDRs(values []string) error {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		path := indexedField("productionCIDRs", index)
		if _, err := parseCanonicalIPv4Prefix(value); err != nil {
			return guardError(ErrInvalidGuardInput, path, "must be a canonical IPv4 prefix")
		}
		if _, exists := seen[value]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier production CIDR")
		}
		seen[value] = struct{}{}
	}
	return nil
}
