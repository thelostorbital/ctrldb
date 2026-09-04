// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/isolation"
)

func TestTESTISO04FirewallPurposeShapesAreExact(t *testing.T) {
	t.Parallel()

	rules := validFirewallRules()
	if err := isolation.ValidateFirewallRules(rules, []string{"10.80.0.0/16"}, "run1", firewallTargets("run1")); err != nil {
		t.Fatalf("ValidateFirewallRules() unexpected error: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*isolation.FirewallRule)
	}{
		{name: "wrong network", mutate: func(rule *isolation.FirewallRule) {
			rule.Network = testResourceIdentity("production-vpc", isolation.ComputeNetworkKind, isolation.ResourceScopeGlobal, "global")
		}},
		{name: "cross-project network", mutate: func(rule *isolation.FirewallRule) {
			rule.Network.Project = "another-test-project"
			rule.Network.CanonicalKey = mustCanonicalTargetKey(rule.Network)
		}},
		{name: "malformed rule identity", mutate: func(rule *isolation.FirewallRule) { rule.Identity.Project = "" }},
		{name: "unknown purpose", mutate: func(rule *isolation.FirewallRule) { rule.Purpose = "other" }},
		{name: "wrong protocol", mutate: func(rule *isolation.FirewallRule) { rule.Protocol = "udp" }},
		{name: "extra port", mutate: func(rule *isolation.FirewallRule) { rule.Ports = append(rule.Ports, 443) }},
		{name: "production target tag", mutate: func(rule *isolation.FirewallRule) { rule.TargetTags = []string{"production-db"} }},
		{name: "IAP source tag", mutate: func(rule *isolation.FirewallRule) { rule.SourceTags = []string{"ctrldb-test-node"} }},
		{name: "IAP wrong CIDR", mutate: func(rule *isolation.FirewallRule) { rule.SourceCIDRs = []string{"192.0.2.0/24"} }},
		{name: "IAP wrong port", mutate: func(rule *isolation.FirewallRule) { rule.Ports = []uint16{2222} }},
		{name: "IAP wrong name", mutate: func(rule *isolation.FirewallRule) {
			rule.Identity = testResourceIdentity("ctrldb-test-run1-other", isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global")
		}},
		{name: "cross-run owner", mutate: func(rule *isolation.FirewallRule) { rule.RunID = "run2" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rule := cloneFirewallRule(rules[0])
			test.mutate(&rule)
			if err := isolation.ValidateFirewallRule(rule, []string{"10.80.0.0/16"}, "run1"); err == nil {
				t.Fatal("ValidateFirewallRule() accepted an invalid IAP SSH shape")
			}
		})
	}
}

func TestTESTISO04InternalMongoDBRuleRequiresMatchingTestTags(t *testing.T) {
	t.Parallel()

	valid := validFirewallRules()[1]
	run2Tag, _ := isolation.RunNodeTag("run2")
	tests := []struct {
		name   string
		mutate func(*isolation.FirewallRule)
		kind   error
	}{
		{name: "wrong port", mutate: func(rule *isolation.FirewallRule) { rule.Ports = []uint16{22} }, kind: isolation.ErrUnsafeFirewall},
		{name: "CIDR source", mutate: func(rule *isolation.FirewallRule) { rule.SourceCIDRs = []string{"10.20.0.0/24"} }, kind: isolation.ErrUnsafeFirewall},
		{name: "missing source tag", mutate: func(rule *isolation.FirewallRule) { rule.SourceTags = nil }, kind: isolation.ErrInvalidGuardInput},
		{name: "different source tag", mutate: func(rule *isolation.FirewallRule) { rule.SourceTags = []string{"ctrldb-test-client"} }, kind: isolation.ErrUnsafeFirewall},
		{name: "other run source tag", mutate: func(rule *isolation.FirewallRule) { rule.SourceTags = []string{run2Tag} }, kind: isolation.ErrUnsafeFirewall},
		{name: "other run target tag", mutate: func(rule *isolation.FirewallRule) { rule.TargetTags = []string{run2Tag} }, kind: isolation.ErrUnsafeFirewall},
		{name: "production source tag", mutate: func(rule *isolation.FirewallRule) { rule.SourceTags = []string{"production-client"} }, kind: isolation.ErrUnsafeTarget},
		{name: "duplicate target tag", mutate: func(rule *isolation.FirewallRule) { rule.TargetTags = []string{"ctrldb-test-node", "ctrldb-test-node"} }, kind: isolation.ErrInvalidGuardInput},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rule := cloneFirewallRule(valid)
			test.mutate(&rule)
			if err := isolation.ValidateFirewallRule(rule, []string{"10.80.0.0/16"}, "run1"); !errors.Is(err, test.kind) {
				t.Fatalf("ValidateFirewallRule() error = %v; want %v", err, test.kind)
			}
		})
	}
}

func TestFirewallRuleIdentityMustBeAnExactSelectedMutationTarget(t *testing.T) {
	t.Parallel()

	rules := validFirewallRules()
	targets := firewallTargets("run1")
	if err := isolation.ValidateFirewallRules(rules, []string{"10.80.0.0/16"}, "run1", targets[:1]); !errors.Is(err, isolation.ErrUnsafeFirewall) {
		t.Fatalf("ValidateFirewallRules(missing exact target) error = %v; want ErrUnsafeFirewall", err)
	}

	crossProject := cloneFirewallRule(rules[0])
	crossProject.Identity.Project = "another-test-project"
	crossProject.Identity.CanonicalKey = mustCanonicalTargetKey(crossProject.Identity)
	crossProject.Network.Project = "another-test-project"
	crossProject.Network.CanonicalKey = mustCanonicalTargetKey(crossProject.Network)
	if err := isolation.ValidateFirewallRules([]isolation.FirewallRule{crossProject, rules[1]}, []string{"10.80.0.0/16"}, "run1", targets); !errors.Is(err, isolation.ErrUnsafeFirewall) {
		t.Fatalf("ValidateFirewallRules(cross-project identity) error = %v; want ErrUnsafeFirewall", err)
	}
}

func TestFirewallRulesDeriveDisjointOwnershipForConcurrentRuns(t *testing.T) {
	t.Parallel()

	run1 := firewallRulesForRun("run1")
	run2 := firewallRulesForRun("run2")
	if run1[1].SourceTags[0] == run2[1].SourceTags[0] || run1[1].TargetTags[0] == run2[1].TargetTags[0] ||
		run1[1].Identity.Name == run2[1].Identity.Name {
		t.Fatal("concurrent runs share MongoDB firewall ownership or tags")
	}
	if err := isolation.ValidateFirewallRules(run2, []string{"10.80.0.0/16"}, "run2", firewallTargets("run2")); err != nil {
		t.Fatalf("ValidateFirewallRules(second run) unexpected error: %v", err)
	}
}

func TestTESTISO08FirewallProofRejectsProductionCIDROverlapAndMalformedDiscovery(t *testing.T) {
	t.Parallel()

	rule := validFirewallRules()[0]
	rule.SourceCIDRs = []string{"10.80.1.0/24"}
	if err := isolation.ValidateFirewallRule(rule, []string{"10.80.0.0/16"}, "run1"); !errors.Is(err, isolation.ErrNetworkOverlap) {
		t.Fatalf("ValidateFirewallRule(overlap) error = %v; want ErrNetworkOverlap", err)
	}
	if err := isolation.ValidateFirewallRule(validFirewallRules()[0], []string{"not-a-cidr"}, "run1"); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateFirewallRule(malformed discovery) error = %v; want ErrInvalidGuardInput", err)
	}
	if err := isolation.ValidateFirewallRules([]isolation.FirewallRule{validFirewallRules()[0], validFirewallRules()[0]}, []string{"10.80.0.0/16"}, "run1", firewallTargets("run1")); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateFirewallRules(duplicate purpose) error = %v; want ErrInvalidGuardInput", err)
	}
}

func TestFirewallErrorsDoNotExposeDiscoveredValues(t *testing.T) {
	t.Parallel()

	const marker = "sensitive-production-cidr"
	err := isolation.ValidateFirewallRule(validFirewallRules()[0], []string{marker}, "run1")
	if !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateFirewallRule() error = %v; want ErrInvalidGuardInput", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("firewall error exposed a discovered value")
	}
}

func validFirewallRules() []isolation.FirewallRule {
	return firewallRulesForRun("run1")
}

func firewallRulesForRun(runID string) []isolation.FirewallRule {
	iapName, _ := isolation.RunFirewallRuleName(runID, isolation.FirewallPurposeIAPSSH)
	mongoName, _ := isolation.RunFirewallRuleName(runID, isolation.FirewallPurposeInternalMongo)
	nodeTag, _ := isolation.RunNodeTag(runID)
	network := testResourceIdentity(isolation.TestVPCName, isolation.ComputeNetworkKind, isolation.ResourceScopeGlobal, "global")
	return []isolation.FirewallRule{
		{
			Identity: testResourceIdentity(iapName, isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global"), Network: network, RunID: runID,
			Purpose: isolation.FirewallPurposeIAPSSH, Protocol: isolation.FirewallProtocolTCP,
			Ports: []uint16{isolation.FirewallPortSSH}, SourceCIDRs: []string{isolation.IAPTCPSourceCIDR},
			TargetTags: []string{nodeTag},
		},
		{
			Identity: testResourceIdentity(mongoName, isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global"), Network: network, RunID: runID,
			Purpose: isolation.FirewallPurposeInternalMongo, Protocol: isolation.FirewallProtocolTCP,
			Ports: []uint16{isolation.FirewallPortMongo}, SourceTags: []string{nodeTag},
			TargetTags: []string{nodeTag},
		},
	}
}

func firewallTargets(runID string) []isolation.MutationTarget {
	rules := firewallRulesForRun(runID)
	return []isolation.MutationTarget{
		testTargetWithIdentity(rules[0].Identity, runID),
		testTargetWithIdentity(rules[1].Identity, runID),
	}
}

func cloneFirewallRule(rule isolation.FirewallRule) isolation.FirewallRule {
	rule.Ports = append([]uint16(nil), rule.Ports...)
	rule.SourceCIDRs = append([]string(nil), rule.SourceCIDRs...)
	rule.SourceTags = append([]string(nil), rule.SourceTags...)
	rule.TargetTags = append([]string(nil), rule.TargetTags...)
	return rule
}
