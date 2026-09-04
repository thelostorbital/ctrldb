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
	TestVPCName                = "ctrldb-test-vpc"
	IAPTCPSourceCIDR           = "35.235.240.0/20"
	FirewallProtocolTCP        = "tcp"
	FirewallPortSSH     uint16 = 22
	FirewallPortMongo   uint16 = 27017
	// TestHarnessRevocationWorkflowID is the only workflow allowed to revoke
	// or tear down run-scoped TEST-ISO exposure.
	TestHarnessRevocationWorkflowID = "WF-TEST-01"
	iapSSHFirewallRuleSuffix        = "iap-ssh"
	mongoFirewallRuleSuffix         = "internal"
	testNodeTagSuffix               = "node"
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

// FirewallRule is the normalized, local input used to prove a proposed test
// firewall rule. Identity and Network are complete explicit provider
// identities; provider-specific adapters are outside this package.
type FirewallRule struct {
	Identity                    ResourceIdentity
	Network                     ResourceIdentity
	RunID                       string
	Purpose                     FirewallPurpose
	Protocol                    string
	Ports                       []uint16
	SourceCIDRs                 []string
	SourceTags                  []string
	TargetTags                  []string
	LifetimeContractFingerprint string
}

// RunLifetimeContract is the single durable lifetime record for one
// disposable test run. RecordID and RecordGeneration identify the immutable
// object version that must exist before provider mutation. Plan and OperationID
// prevent a reused run ID from adopting an earlier run's exposure while still
// allowing later steps and retries of that same operation to use the rule.
//
// A future provider adapter writes the canonical run, plan, operation, record
// identity, generation, expiry, revocation workflow, and resulting fingerprint
// into the IAP firewall description. WF-TEST-01 teardown and its nightly cleanup
// path consume that metadata and remove the rule no later than ExpiresAt.
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
// adapter persists in the IAP rule description. Time and policy bounds are
// evaluated separately at each independent mutation boundary.
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

// ValidateFirewallRules requires exactly one IAP SSH rule and exactly one
// internal MongoDB rule, binds both rule identities to the exact selected
// mutation targets, and rejects any source range overlapping a CIDR discovered
// for production.
func ValidateFirewallRules(rules []FirewallRule, productionCIDRs []string, targets []MutationTarget, context FirewallValidationContext) error {
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
	if len(targetKeys) != len(rules) {
		return guardError(ErrUnsafeFirewall, "targets", "must contain exactly the two proved firewall mutations")
	}
	seen := make(map[FirewallPurpose]struct{}, len(rules))
	for index, rule := range rules {
		path := indexedField("firewallRules", index)
		if _, exists := seen[rule.Purpose]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier firewall purpose")
		}
		seen[rule.Purpose] = struct{}{}
		if err := validateFirewallRule(rule, productionCIDRs, context.RunID, lifetimeFingerprint); err != nil {
			return guardError(err, path, "failed its purpose proof")
		}
		if _, exists := targetKeys[rule.Identity.CanonicalKey]; !exists {
			return guardError(ErrUnsafeFirewall, path, "is not one of the selected exact mutation targets")
		}
	}
	if _, ok := seen[FirewallPurposeIAPSSH]; !ok {
		return guardError(ErrUnsafeFirewall, "firewallRules", "is missing the IAP SSH purpose")
	}
	if _, ok := seen[FirewallPurposeInternalMongo]; !ok {
		return guardError(ErrUnsafeFirewall, "firewallRules", "is missing the internal MongoDB purpose")
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
	if err := ValidateRunID(runID); err != nil {
		return err
	}
	if !isSHA256Fingerprint(lifetimeFingerprint) {
		return guardError(ErrInvalidGuardInput, "runLifetime.fingerprint", "must be a SHA-256 fingerprint")
	}
	if rule.RunID != runID {
		return guardError(ErrUnsafeFirewall, "runID", "does not match the owning run")
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
	if rule.Protocol != FirewallProtocolTCP || len(rule.Ports) != 1 {
		return guardError(ErrUnsafeFirewall, "allow", "must contain one purpose-specific TCP port")
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
		expectedTag, _ := RunNodeTag(runID)
		if rule.Identity.Name != expectedName || rule.Ports[0] != FirewallPortSSH || len(rule.SourceTags) != 0 ||
			len(rule.SourceCIDRs) != 1 || rule.SourceCIDRs[0] != IAPTCPSourceCIDR ||
			!slices.Equal(rule.TargetTags, []string{expectedTag}) || rule.LifetimeContractFingerprint != lifetimeFingerprint {
			return guardError(ErrUnsafeFirewall, "shape", "does not match the IAP SSH purpose")
		}
	case FirewallPurposeInternalMongo:
		expectedName, _ := RunFirewallRuleName(runID, FirewallPurposeInternalMongo)
		expectedTag, _ := RunNodeTag(runID)
		if rule.Identity.Name != expectedName || rule.Ports[0] != FirewallPortMongo || len(rule.SourceCIDRs) != 0 ||
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

// RunNodeTag derives the only node tag admitted for one run.
func RunNodeTag(runID string) (string, error) {
	prefix, err := RunResourcePrefix(runID)
	if err != nil {
		return "", err
	}
	return prefix + testNodeTagSuffix, nil
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
