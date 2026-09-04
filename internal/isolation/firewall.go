// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"errors"
	"regexp"
	"slices"
)

const (
	TestVPCName                     = "ctrldb-test-vpc"
	IAPTCPSourceCIDR                = "35.235.240.0/20"
	FirewallProtocolTCP             = "tcp"
	FirewallPortSSH          uint16 = 22
	FirewallPortMongo        uint16 = 27017
	iapSSHFirewallRuleSuffix        = "iap-ssh"
	mongoFirewallRuleSuffix         = "internal"
	testNodeTagSuffix               = "node"
)

var (
	// ErrUnsafeFirewall marks a rule whose network, purpose, protocol, source,
	// port, or tag shape could expose a non-test resource.
	ErrUnsafeFirewall = errors.New("unsafe isolation firewall rule")
	testTagPattern    = regexp.MustCompile(`^ctrldb-test-[a-z0-9](?:[a-z0-9-]{0,49}[a-z0-9])?$`)
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
	Identity    ResourceIdentity
	Network     ResourceIdentity
	RunID       string
	Purpose     FirewallPurpose
	Protocol    string
	Ports       []uint16
	SourceCIDRs []string
	SourceTags  []string
	TargetTags  []string
}

// ValidateFirewallRules requires exactly one IAP SSH rule and exactly one
// internal MongoDB rule, binds both rule identities to the exact selected
// mutation targets, and rejects any source range overlapping a CIDR discovered
// for production.
func ValidateFirewallRules(rules []FirewallRule, productionCIDRs []string, runID string, targets []MutationTarget) error {
	if len(rules) != 2 {
		return guardError(ErrUnsafeFirewall, "firewallRules", "must contain both required purpose proofs")
	}
	selected, err := SelectRunMutationTargets(runID, targets)
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
		if err := ValidateFirewallRule(rule, productionCIDRs, runID); err != nil {
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
func ValidateFirewallRule(rule FirewallRule, productionCIDRs []string, runID string) error {
	if err := ValidateRunID(runID); err != nil {
		return err
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
			!slices.Equal(rule.TargetTags, []string{expectedTag}) {
			return guardError(ErrUnsafeFirewall, "shape", "does not match the IAP SSH purpose")
		}
	case FirewallPurposeInternalMongo:
		expectedName, _ := RunFirewallRuleName(runID, FirewallPurposeInternalMongo)
		expectedTag, _ := RunNodeTag(runID)
		if rule.Identity.Name != expectedName || rule.Ports[0] != FirewallPortMongo || len(rule.SourceCIDRs) != 0 {
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
