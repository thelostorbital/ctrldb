// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"errors"
	"regexp"
	"slices"
)

const (
	TestVPCName                   = "ctrldb-test-vpc"
	IAPTCPSourceCIDR              = "35.235.240.0/20"
	IAPSSHFirewallRuleName        = "ctrldb-test-iap-ssh"
	MongoFirewallRuleName         = "ctrldb-test-internal"
	TestNodeTag                   = "ctrldb-test-node"
	FirewallProtocolTCP           = "tcp"
	FirewallPortSSH        uint16 = 22
	FirewallPortMongo      uint16 = 27017
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
// firewall rule. Provider-specific adapters are outside this package.
type FirewallRule struct {
	Name        string
	Network     string
	Purpose     FirewallPurpose
	Protocol    string
	Ports       []uint16
	SourceCIDRs []string
	SourceTags  []string
	TargetTags  []string
}

// ValidateFirewallRules requires exactly one IAP SSH rule and exactly one
// internal MongoDB rule, and rejects any source range overlapping a CIDR
// discovered for production.
func ValidateFirewallRules(rules []FirewallRule, productionCIDRs []string) error {
	if len(rules) != 2 {
		return guardError(ErrUnsafeFirewall, "firewallRules", "must contain both required purpose proofs")
	}
	seen := make(map[FirewallPurpose]struct{}, len(rules))
	for index, rule := range rules {
		path := indexedField("firewallRules", index)
		if _, exists := seen[rule.Purpose]; exists {
			return guardError(ErrInvalidGuardInput, path, "duplicates an earlier firewall purpose")
		}
		seen[rule.Purpose] = struct{}{}
		if err := ValidateFirewallRule(rule, productionCIDRs); err != nil {
			return guardError(err, path, "failed its purpose proof")
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
func ValidateFirewallRule(rule FirewallRule, productionCIDRs []string) error {
	if rule.Network != TestVPCName {
		return guardError(ErrUnsafeFirewall, "network", "must be the dedicated test VPC")
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
		if rule.Name != IAPSSHFirewallRuleName || rule.Ports[0] != FirewallPortSSH || len(rule.SourceTags) != 0 ||
			len(rule.SourceCIDRs) != 1 || rule.SourceCIDRs[0] != IAPTCPSourceCIDR ||
			!slices.Equal(rule.TargetTags, []string{TestNodeTag}) {
			return guardError(ErrUnsafeFirewall, "shape", "does not match the IAP SSH purpose")
		}
	case FirewallPurposeInternalMongo:
		if rule.Name != MongoFirewallRuleName || rule.Ports[0] != FirewallPortMongo || len(rule.SourceCIDRs) != 0 {
			return guardError(ErrUnsafeFirewall, "shape", "does not match the internal MongoDB purpose")
		}
		if err := validateTestTags("sourceTags", rule.SourceTags, true); err != nil {
			return err
		}
		if !slices.Equal(rule.SourceTags, []string{TestNodeTag}) || !slices.Equal(rule.TargetTags, []string{TestNodeTag}) {
			return guardError(ErrUnsafeFirewall, "shape", "does not match the internal MongoDB purpose")
		}
	default:
		return guardError(ErrUnsafeFirewall, "purpose", "is not recognized")
	}

	return nil
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
