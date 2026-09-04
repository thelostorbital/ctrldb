// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/isolation"
)

func TestTESTISO04FirewallPurposeShapesAreExact(t *testing.T) {
	t.Parallel()

	rules := validFirewallRules()
	if err := isolation.ValidateFirewallRules(rules, []string{"10.80.0.0/16"}, firewallTargets("run1"), validFirewallValidationContext("run1")); err != nil {
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
		{name: "disabled", mutate: func(rule *isolation.FirewallRule) { rule.Enabled = false }},
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
			if err := isolation.ValidateFirewallRule(rule, []string{"10.80.0.0/16"}, validFirewallValidationContext("run1")); err == nil {
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
		{name: "disabled", mutate: func(rule *isolation.FirewallRule) { rule.Enabled = false }, kind: isolation.ErrUnsafeFirewall},
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
			if err := isolation.ValidateFirewallRule(rule, []string{"10.80.0.0/16"}, validFirewallValidationContext("run1")); !errors.Is(err, test.kind) {
				t.Fatalf("ValidateFirewallRule() error = %v; want %v", err, test.kind)
			}
		})
	}
}

func TestFirewallRuleIdentityMustBeAnExactSelectedMutationTarget(t *testing.T) {
	t.Parallel()

	rules := validFirewallRules()
	targets := firewallTargets("run1")
	if err := isolation.ValidateFirewallRules(rules, []string{"10.80.0.0/16"}, targets[:1], validFirewallValidationContext("run1")); !errors.Is(err, isolation.ErrUnsafeFirewall) {
		t.Fatalf("ValidateFirewallRules(missing exact target) error = %v; want ErrUnsafeFirewall", err)
	}

	crossProject := cloneFirewallRule(rules[0])
	crossProject.Identity.Project = "another-test-project"
	crossProject.Identity.CanonicalKey = mustCanonicalTargetKey(crossProject.Identity)
	crossProject.Network.Project = "another-test-project"
	crossProject.Network.CanonicalKey = mustCanonicalTargetKey(crossProject.Network)
	if err := isolation.ValidateFirewallRules([]isolation.FirewallRule{crossProject, rules[1]}, []string{"10.80.0.0/16"}, targets, validFirewallValidationContext("run1")); !errors.Is(err, isolation.ErrUnsafeFirewall) {
		t.Fatalf("ValidateFirewallRules(cross-project identity) error = %v; want ErrUnsafeFirewall", err)
	}
}

func TestFirewallRulesRequireExactRunLifetimeFingerprint(t *testing.T) {
	t.Parallel()

	rules := validFirewallRules()
	missing := cloneFirewallRule(rules[0])
	missing.LifetimeContractFingerprint = ""
	if err := isolation.ValidateFirewallRule(missing, []string{"10.80.0.0/16"}, validFirewallValidationContext("run1")); !errors.Is(err, isolation.ErrUnsafeFirewall) {
		t.Fatalf("ValidateFirewallRule(missing lifetime) error = %v; want ErrUnsafeFirewall", err)
	}

	staleContract := validRunLifetimeContract("run1")
	staleContract.RecordGeneration++
	staleContext := validFirewallValidationContext("run1")
	staleContext.RunLifetime = staleContract
	if err := isolation.ValidateFirewallRule(rules[0], []string{"10.80.0.0/16"}, staleContext); !errors.Is(err, isolation.ErrUnsafeFirewall) {
		t.Fatalf("ValidateFirewallRule(stale lifetime) error = %v; want ErrUnsafeFirewall", err)
	}

	reusedRunRules := []isolation.FirewallRule{cloneFirewallRule(rules[0]), cloneFirewallRule(rules[1])}
	updatedContract := validRunLifetimeContract("run1")
	updatedContract.RecordGeneration++
	updatedFingerprint, err := isolation.RunLifetimeContractFingerprint(updatedContract)
	if err != nil {
		t.Fatalf("RunLifetimeContractFingerprint(updated record) unexpected error: %v", err)
	}
	reusedRunRules[0].LifetimeContractFingerprint = updatedFingerprint
	updatedContext := validFirewallValidationContext("run1")
	updatedContext.RunLifetime = updatedContract
	if err := isolation.ValidateFirewallRules(reusedRunRules, []string{"10.80.0.0/16"}, firewallTargets("run1"), updatedContext); !errors.Is(err, isolation.ErrUnsafeFirewall) {
		t.Fatalf("ValidateFirewallRules(stale internal rule after reused run) error = %v; want ErrUnsafeFirewall", err)
	}
}

func TestStandaloneFirewallValidationRejectsMalformedMutationAttempt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*isolation.FirewallValidationContext)
	}{
		{name: "missing step", mutate: func(value *isolation.FirewallValidationContext) { value.Operation.StepID = "" }},
		{name: "zero attempt", mutate: func(value *isolation.FirewallValidationContext) { value.Operation.Attempt = 0 }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			context := validFirewallValidationContext("run1")
			test.mutate(&context)
			if err := isolation.ValidateFirewallRule(validFirewallRules()[0], []string{"10.80.0.0/16"}, context); !errors.Is(err, isolation.ErrInvalidGuardInput) {
				t.Fatalf("ValidateFirewallRule() error = %v; want ErrInvalidGuardInput", err)
			}
		})
	}
}

func TestRunLifetimeContractFingerprintRejectsIncompleteMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*isolation.RunLifetimeContract)
		kind   error
	}{
		{name: "missing record", mutate: func(value *isolation.RunLifetimeContract) { value.RecordID = "" }, kind: isolation.ErrInvalidGuardInput},
		{name: "missing generation", mutate: func(value *isolation.RunLifetimeContract) { value.RecordGeneration = 0 }, kind: isolation.ErrInvalidGuardInput},
		{name: "non-UTC expiry", mutate: func(value *isolation.RunLifetimeContract) {
			value.ExpiresAt = value.ExpiresAt.In(time.FixedZone("offset", 60))
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "non-UTC creation", mutate: func(value *isolation.RunLifetimeContract) {
			value.CreatedAt = value.CreatedAt.In(time.FixedZone("offset", 60))
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "wrong revocation workflow", mutate: func(value *isolation.RunLifetimeContract) {
			value.RevocationWorkflowID = "WF-ACC-03"
		}, kind: isolation.ErrUnsafeFirewall},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := validRunLifetimeContract("run1")
			test.mutate(&value)
			if _, err := isolation.RunLifetimeContractFingerprint(value); !errors.Is(err, test.kind) {
				t.Fatalf("RunLifetimeContractFingerprint() error = %v; want %v", err, test.kind)
			}
		})
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
	if err := isolation.ValidateFirewallRules(run2, []string{"10.80.0.0/16"}, firewallTargets("run2"), validFirewallValidationContext("run2")); err != nil {
		t.Fatalf("ValidateFirewallRules(second run) unexpected error: %v", err)
	}
}

func TestTESTISO08FirewallProofRejectsProductionCIDROverlapAndMalformedDiscovery(t *testing.T) {
	t.Parallel()

	rule := validFirewallRules()[0]
	rule.SourceCIDRs = []string{"10.80.1.0/24"}
	if err := isolation.ValidateFirewallRule(rule, []string{"10.80.0.0/16"}, validFirewallValidationContext("run1")); !errors.Is(err, isolation.ErrNetworkOverlap) {
		t.Fatalf("ValidateFirewallRule(overlap) error = %v; want ErrNetworkOverlap", err)
	}
	if err := isolation.ValidateFirewallRule(validFirewallRules()[0], []string{"not-a-cidr"}, validFirewallValidationContext("run1")); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateFirewallRule(malformed discovery) error = %v; want ErrInvalidGuardInput", err)
	}
	if err := isolation.ValidateFirewallRules([]isolation.FirewallRule{validFirewallRules()[0], validFirewallRules()[0]}, []string{"10.80.0.0/16"}, firewallTargets("run1"), validFirewallValidationContext("run1")); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("ValidateFirewallRules(duplicate purpose) error = %v; want ErrInvalidGuardInput", err)
	}
}

func TestFirewallErrorsDoNotExposeDiscoveredValues(t *testing.T) {
	t.Parallel()

	const marker = "sensitive-production-cidr"
	err := isolation.ValidateFirewallRule(validFirewallRules()[0], []string{marker}, validFirewallValidationContext("run1"))
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
			Purpose: isolation.FirewallPurposeIAPSSH, Enabled: true, Protocol: isolation.FirewallProtocolTCP,
			Ports: []uint16{isolation.FirewallPortSSH}, SourceCIDRs: []string{isolation.IAPTCPSourceCIDR},
			TargetTags: []string{nodeTag}, LifetimeContractFingerprint: validLifetimeFingerprint(runID),
		},
		{
			Identity: testResourceIdentity(mongoName, isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global"), Network: network, RunID: runID,
			Purpose: isolation.FirewallPurposeInternalMongo, Enabled: true, Protocol: isolation.FirewallProtocolTCP,
			Ports: []uint16{isolation.FirewallPortMongo}, SourceTags: []string{nodeTag},
			TargetTags: []string{nodeTag}, LifetimeContractFingerprint: validLifetimeFingerprint(runID),
		},
	}
}

func validRunLifetimeContract(runID string) isolation.RunLifetimeContract {
	return isolation.RunLifetimeContract{
		RunID:       runID,
		Plan:        isolation.PlanIdentity{ID: "plan-0123456789abcdef", Hash: strings.Repeat("a", 64)},
		OperationID: "op-0123456789abcdef",
		RecordID:    "lifetime-0123456789abcdef", RecordGeneration: 1,
		CreatedAt:            time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC),
		ExpiresAt:            time.Date(2026, 9, 4, 11, 0, 0, 0, time.UTC),
		RevocationWorkflowID: isolation.TestHarnessRevocationWorkflowID,
	}
}

func validLifetimeFingerprint(runID string) string {
	fingerprint, err := isolation.RunLifetimeContractFingerprint(validRunLifetimeContract(runID))
	if err != nil {
		panic(err)
	}
	return fingerprint
}

func validFirewallValidationContext(runID string) isolation.FirewallValidationContext {
	contract := validRunLifetimeContract(runID)
	return isolation.FirewallValidationContext{
		RunID: runID, Plan: contract.Plan,
		Operation: isolation.OperationBinding{
			OperationID: contract.OperationID, StepID: "create-test-resources", Attempt: 1,
		},
		PlannedLifetime: time.Hour, RunLimits: defaultLimits(),
		RunLifetime: contract, Now: authorizationNow(),
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
