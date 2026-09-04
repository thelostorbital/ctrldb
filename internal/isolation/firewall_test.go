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
	if err := isolation.ValidateFirewallRules(rules, []string{"10.80.0.0/16"}); err != nil {
		t.Fatalf("ValidateFirewallRules() unexpected error: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*isolation.FirewallRule)
	}{
		{name: "wrong network", mutate: func(rule *isolation.FirewallRule) { rule.Network = "production-vpc" }},
		{name: "unknown purpose", mutate: func(rule *isolation.FirewallRule) { rule.Purpose = "other" }},
		{name: "wrong protocol", mutate: func(rule *isolation.FirewallRule) { rule.Protocol = "udp" }},
		{name: "extra port", mutate: func(rule *isolation.FirewallRule) { rule.Ports = append(rule.Ports, 443) }},
		{name: "production target tag", mutate: func(rule *isolation.FirewallRule) { rule.TargetTags = []string{"production-db"} }},
		{name: "IAP source tag", mutate: func(rule *isolation.FirewallRule) { rule.SourceTags = []string{"ctrldb-test-node"} }},
		{name: "IAP wrong CIDR", mutate: func(rule *isolation.FirewallRule) { rule.SourceCIDRs = []string{"192.0.2.0/24"} }},
		{name: "IAP wrong port", mutate: func(rule *isolation.FirewallRule) { rule.Ports = []uint16{2222} }},
		{name: "IAP wrong name", mutate: func(rule *isolation.FirewallRule) { rule.Name = "ctrldb-test-other" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rule := cloneFirewallRule(rules[0])
			test.mutate(&rule)
			if err := isolation.ValidateFirewallRule(rule, []string{"10.80.0.0/16"}); err == nil {
				t.Fatal("ValidateFirewallRule() accepted an invalid IAP SSH shape")
			}
		})
	}
}

func TestTESTISO04InternalMongoDBRuleRequiresMatchingTestTags(t *testing.T) {
	t.Parallel()

	valid := validFirewallRules()[1]
	tests := []struct {
		name   string
		mutate func(*isolation.FirewallRule)
		kind   error
	}{
		{name: "wrong port", mutate: func(rule *isolation.FirewallRule) { rule.Ports = []uint16{22} }, kind: isolation.ErrUnsafeFirewall},
		{name: "CIDR source", mutate: func(rule *isolation.FirewallRule) { rule.SourceCIDRs = []string{"10.20.0.0/24"} }, kind: isolation.ErrUnsafeFirewall},
		{name: "missing source tag", mutate: func(rule *isolation.FirewallRule) { rule.SourceTags = nil }, kind: isolation.ErrInvalidGuardInput},
		{name: "different source tag", mutate: func(rule *isolation.FirewallRule) { rule.SourceTags = []string{"ctrldb-test-client"} }, kind: isolation.ErrUnsafeFirewall},
		{name: "production source tag", mutate: func(rule *isolation.FirewallRule) { rule.SourceTags = []string{"production-client"} }, kind: isolation.ErrUnsafeTarget},
		{name: "duplicate target tag", mutate: func(rule *isolation.FirewallRule) { rule.TargetTags = []string{"ctrldb-test-node", "ctrldb-test-node"} }, kind: isolation.ErrInvalidGuardInput},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rule := cloneFirewallRule(valid)
			test.mutate(&rule)
			if err := isolation.ValidateFirewallRule(rule, []string{"10.80.0.0/16"}); !errors.Is(err, test.kind) {
				t.Fatalf("ValidateFirewallRule() error = %v; want %v", err, test.kind)
			}
		})
	}
}

func TestTESTISO08FirewallProofRejectsProductionCIDROverlapAndMalformedDiscovery(t *testing.T) {
	t.Parallel()

	rule := validFirewallRules()[0]
	rule.SourceCIDRs = []string{"10.80.1.0/24"}
	if err := isolation.ValidateFirewallRule(rule, []string{"10.80.0.0/16"}); !errors.Is(err, isolation.ErrNetworkOverlap) {
		t.Fatalf("ValidateFirewallRule(overlap) error = %v; want ErrNetworkOverlap", err)
	}
	if err := isolation.ValidateFirewallRule(validFirewallRules()[0], []string{"not-a-cidr"}); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateFirewallRule(malformed discovery) error = %v; want ErrInvalidGuardInput", err)
	}
	if err := isolation.ValidateFirewallRules([]isolation.FirewallRule{validFirewallRules()[0], validFirewallRules()[0]}, []string{"10.80.0.0/16"}); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateFirewallRules(duplicate purpose) error = %v; want ErrInvalidGuardInput", err)
	}
}

func TestFirewallErrorsDoNotExposeDiscoveredValues(t *testing.T) {
	t.Parallel()

	const marker = "sensitive-production-cidr"
	err := isolation.ValidateFirewallRule(validFirewallRules()[0], []string{marker})
	if !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateFirewallRule() error = %v; want ErrInvalidGuardInput", err)
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("firewall error exposed a discovered value")
	}
}

func validFirewallRules() []isolation.FirewallRule {
	return []isolation.FirewallRule{
		{
			Name: isolation.IAPSSHFirewallRuleName, Network: isolation.TestVPCName,
			Purpose: isolation.FirewallPurposeIAPSSH, Protocol: isolation.FirewallProtocolTCP,
			Ports: []uint16{isolation.FirewallPortSSH}, SourceCIDRs: []string{isolation.IAPTCPSourceCIDR},
			TargetTags: []string{"ctrldb-test-node"},
		},
		{
			Name: isolation.MongoFirewallRuleName, Network: isolation.TestVPCName,
			Purpose: isolation.FirewallPurposeInternalMongo, Protocol: isolation.FirewallProtocolTCP,
			Ports: []uint16{isolation.FirewallPortMongo}, SourceTags: []string{"ctrldb-test-node"},
			TargetTags: []string{"ctrldb-test-node"},
		},
	}
}

func cloneFirewallRule(rule isolation.FirewallRule) isolation.FirewallRule {
	rule.Ports = append([]uint16(nil), rule.Ports...)
	rule.SourceCIDRs = append([]string(nil), rule.SourceCIDRs...)
	rule.SourceTags = append([]string(nil), rule.SourceTags...)
	rule.TargetTags = append([]string(nil), rule.TargetTags...)
	return rule
}
