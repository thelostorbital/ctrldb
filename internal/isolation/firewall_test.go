// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation_test

import (
	"errors"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/isolation"
)

func TestTESTISO04FirewallPurposeShapesAreExact(t *testing.T) {
	t.Parallel()

	rules := validFirewallRules()
	if err := isolation.ValidateFirewallRules(rules, absentFirewallObservations(rules), []string{"10.80.0.0/16"}, firewallTargets("run1"), validFirewallValidationContext("run1")); err != nil {
		t.Fatalf("ValidateFirewallRules() unexpected error: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*isolation.FirewallRule)
	}{
		{name: "missing description", mutate: func(rule *isolation.FirewallRule) { rule.Description = "" }},
		{name: "wrong description", mutate: func(rule *isolation.FirewallRule) { rule.Description = "unbound test rule" }},
		{name: "missing network", mutate: func(rule *isolation.FirewallRule) { rule.Network = isolation.ResourceIdentity{} }},
		{name: "default network", mutate: func(rule *isolation.FirewallRule) {
			rule.Network = testResourceIdentity("default", isolation.ComputeNetworkKind, isolation.ResourceScopeGlobal, "global")
		}},
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
		{name: "missing priority", mutate: func(rule *isolation.FirewallRule) { rule.Priority = 0 }},
		{name: "wrong priority", mutate: func(rule *isolation.FirewallRule) { rule.Priority = 900 }},
		{name: "missing direction", mutate: func(rule *isolation.FirewallRule) { rule.Direction = "" }},
		{name: "egress", mutate: func(rule *isolation.FirewallRule) { rule.Direction = "EGRESS" }},
		{name: "missing allow", mutate: func(rule *isolation.FirewallRule) { rule.Allowed = nil }},
		{name: "deny action", mutate: func(rule *isolation.FirewallRule) {
			rule.Denied = []isolation.FirewallTrafficRule{{IPProtocol: isolation.FirewallIPProtocolTCP, Ports: []uint16{22}}}
		}},
		{name: "wrong protocol", mutate: func(rule *isolation.FirewallRule) { rule.Allowed[0].IPProtocol = "udp" }},
		{name: "extra allow tuple", mutate: func(rule *isolation.FirewallRule) {
			rule.Allowed = append(rule.Allowed, isolation.FirewallTrafficRule{IPProtocol: isolation.FirewallIPProtocolTCP, Ports: []uint16{443}})
		}},
		{name: "extra port", mutate: func(rule *isolation.FirewallRule) { rule.Allowed[0].Ports = append(rule.Allowed[0].Ports, 443) }},
		{name: "destination selector", mutate: func(rule *isolation.FirewallRule) { rule.DestinationCIDRs = []string{"10.20.0.0/24"} }},
		{name: "source service account", mutate: func(rule *isolation.FirewallRule) {
			rule.SourceServiceAccounts = []string{"source@example-test-project.iam.gserviceaccount.com"}
		}},
		{name: "target service account", mutate: func(rule *isolation.FirewallRule) {
			rule.TargetServiceAccounts = []string{"target@example-test-project.iam.gserviceaccount.com"}
		}},
		{name: "logging enabled", mutate: func(rule *isolation.FirewallRule) { rule.LogConfig.Enabled = true }},
		{name: "logging metadata", mutate: func(rule *isolation.FirewallRule) { rule.LogConfig.Metadata = "INCLUDE_ALL_METADATA" }},
		{name: "resource manager tag", mutate: func(rule *isolation.FirewallRule) {
			rule.ResourceManagerTags = map[string]string{"tagKeys/123": "tagValues/456"}
		}},
		{name: "production target tag", mutate: func(rule *isolation.FirewallRule) { rule.TargetTags = []string{"production-db"} }},
		{name: "IAP source tag", mutate: func(rule *isolation.FirewallRule) { rule.SourceTags = []string{"ctrldb-test-node"} }},
		{name: "IAP wrong CIDR", mutate: func(rule *isolation.FirewallRule) { rule.SourceCIDRs = []string{"192.0.2.0/24"} }},
		{name: "IAP wrong port", mutate: func(rule *isolation.FirewallRule) { rule.Allowed[0].Ports = []uint16{2222} }},
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
	run2Tag, _ := isolation.RunNodeTag(validLifetimeFingerprint("run2"))
	tests := []struct {
		name   string
		mutate func(*isolation.FirewallRule)
		kind   error
	}{
		{name: "wrong port", mutate: func(rule *isolation.FirewallRule) { rule.Allowed[0].Ports = []uint16{22} }, kind: isolation.ErrUnsafeFirewall},
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
	if err := isolation.ValidateFirewallRules(rules, absentFirewallObservations(rules), []string{"10.80.0.0/16"}, targets[:1], validFirewallValidationContext("run1")); !errors.Is(err, isolation.ErrUnsafeFirewall) {
		t.Fatalf("ValidateFirewallRules(missing exact target) error = %v; want ErrUnsafeFirewall", err)
	}

	crossProject := cloneFirewallRule(rules[0])
	crossProject.Identity.Project = "another-test-project"
	crossProject.Identity.CanonicalKey = mustCanonicalTargetKey(crossProject.Identity)
	crossProject.Network.Project = "another-test-project"
	crossProject.Network.CanonicalKey = mustCanonicalTargetKey(crossProject.Network)
	changedRules := []isolation.FirewallRule{crossProject, rules[1]}
	if err := isolation.ValidateFirewallRules(changedRules, absentFirewallObservations(changedRules), []string{"10.80.0.0/16"}, targets, validFirewallValidationContext("run1")); !errors.Is(err, isolation.ErrUnsafeFirewall) {
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
	reusedRunRules[0].Description, err = isolation.RunFirewallDescription(updatedFingerprint)
	if err != nil {
		t.Fatalf("RunFirewallDescription(updated record) unexpected error: %v", err)
	}
	updatedContext := validFirewallValidationContext("run1")
	updatedContext.RunLifetime = updatedContract
	if err := isolation.ValidateFirewallRules(reusedRunRules, absentFirewallObservations(reusedRunRules), []string{"10.80.0.0/16"}, firewallTargets("run1"), updatedContext); !errors.Is(err, isolation.ErrUnsafeFirewall) {
		t.Fatalf("ValidateFirewallRules(stale internal rule after reused run) error = %v; want ErrUnsafeFirewall", err)
	}
}

func TestFirewallObservationsAreExhaustiveAndFailClosed(t *testing.T) {
	t.Parallel()

	rules := validFirewallRules()
	targets := firewallTargets("run1")
	validPresent := presentFirewallObservations(rules)
	unknown := validPresent[1]
	unknown.Identity = testResourceIdentity("ctrldb-test-run1-unknown", isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global")
	tests := []struct {
		name         string
		observations []isolation.FirewallObservation
		targets      []isolation.MutationTarget
		kind         error
	}{
		{name: "missing observation", observations: validPresent[:1], targets: nil, kind: isolation.ErrUnsafeFirewall},
		{name: "duplicate observation", observations: []isolation.FirewallObservation{validPresent[0], validPresent[0]}, targets: nil, kind: isolation.ErrInvalidGuardInput},
		{name: "unknown identity", observations: []isolation.FirewallObservation{validPresent[0], unknown}, targets: nil, kind: isolation.ErrUnsafeFirewall},
		{name: "unknown state", observations: []isolation.FirewallObservation{validPresent[0], {Identity: rules[1].Identity, State: "unknown"}}, targets: nil, kind: isolation.ErrInvalidGuardInput},
		{name: "present without state", observations: []isolation.FirewallObservation{validPresent[0], {Identity: rules[1].Identity, State: isolation.FirewallObservationPresent}}, targets: nil, kind: isolation.ErrInvalidGuardInput},
		{name: "ambiguous absent", observations: []isolation.FirewallObservation{{Identity: rules[0].Identity, State: isolation.FirewallObservationAbsent, PresentRule: &rules[0]}, validPresent[1]}, targets: targets[:1], kind: isolation.ErrInvalidGuardInput},
		{name: "missing absent target", observations: absentFirewallObservations(rules), targets: targets[:1], kind: isolation.ErrUnsafeFirewall},
		{name: "present selected for insert", observations: validPresent, targets: targets, kind: isolation.ErrUnsafeFirewall},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := isolation.ValidateFirewallRules(rules, test.observations, []string{"10.80.0.0/16"}, test.targets, validFirewallValidationContext("run1")); !errors.Is(err, test.kind) {
				t.Fatalf("ValidateFirewallRules() error = %v; want %v", err, test.kind)
			}
		})
	}

	drifted := presentFirewallObservations(rules)
	drifted[0].PresentRule.Priority--
	if err := isolation.ValidateFirewallRules(rules, drifted, []string{"10.80.0.0/16"}, nil, validFirewallValidationContext("run1")); !errors.Is(err, isolation.ErrUnsafeFirewall) && !errors.Is(err, isolation.ErrProofMismatch) {
		t.Fatalf("ValidateFirewallRules(drifted present rule) error = %v; want fail-closed firewall/proof error", err)
	}
}

func TestRunNodeTagBindsImmutableLifetimeGeneration(t *testing.T) {
	t.Parallel()

	first := validRunLifetimeContract("run1")
	firstFingerprint, _ := isolation.RunLifetimeContractFingerprint(first)
	firstTag, err := isolation.RunNodeTag(firstFingerprint)
	if err != nil {
		t.Fatalf("RunNodeTag() unexpected error: %v", err)
	}
	if len(firstTag) != 63 || isolation.ValidateFirewallTags([]string{firstTag}, []string{firstTag}) != nil {
		t.Fatal("RunNodeTag() did not produce a provider-valid bounded tag")
	}
	stableTag, _ := isolation.RunNodeTag(firstFingerprint)
	if stableTag != firstTag {
		t.Fatal("RunNodeTag() changed for the same immutable lifetime")
	}
	reused := first
	reused.RecordGeneration++
	reusedFingerprint, _ := isolation.RunLifetimeContractFingerprint(reused)
	reusedTag, _ := isolation.RunNodeTag(reusedFingerprint)
	if reusedTag == firstTag {
		t.Fatal("RunNodeTag() reused a tag after immutable lifetime generation changed")
	}
	if _, err := isolation.RunNodeTag(""); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("RunNodeTag(invalid fingerprint) error = %v; want ErrInvalidGuardInput", err)
	}
}

func TestRunFirewallDescriptionIsCanonicalAndBounded(t *testing.T) {
	t.Parallel()

	fingerprint := validLifetimeFingerprint("run1")
	description, err := isolation.RunFirewallDescription(fingerprint)
	if err != nil {
		t.Fatalf("RunFirewallDescription() unexpected error: %v", err)
	}
	if description != validFirewallRules()[0].Description || len(description) > 256 {
		t.Fatalf("RunFirewallDescription() returned a non-canonical or overlong description")
	}
	if _, err := isolation.RunFirewallDescription(""); !errors.Is(err, isolation.ErrInvalidGuardInput) {
		t.Fatalf("RunFirewallDescription(missing fingerprint) error = %v; want ErrInvalidGuardInput", err)
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

func TestStandaloneFirewallValidationBindsLifetimeCreationToObservation(t *testing.T) {
	t.Parallel()

	valid := validFirewallValidationContext("run1")
	if !valid.RunLifetime.CreatedAt.Equal(valid.ObservedAt) {
		t.Fatal("fixture does not exercise the inclusive creation/observation boundary")
	}
	if err := isolation.ValidateFirewallRule(validFirewallRules()[0], []string{"10.80.0.0/16"}, valid); err != nil {
		t.Fatalf("ValidateFirewallRule(created at observation) unexpected error: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*isolation.FirewallValidationContext)
		kind   error
	}{
		{name: "missing observation", mutate: func(value *isolation.FirewallValidationContext) { value.ObservedAt = time.Time{} }, kind: isolation.ErrInvalidGuardInput},
		{name: "non UTC observation", mutate: func(value *isolation.FirewallValidationContext) {
			value.ObservedAt = value.ObservedAt.In(time.FixedZone("offset", 60))
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "future observation", mutate: func(value *isolation.FirewallValidationContext) {
			value.ObservedAt = value.Now.Add(time.Nanosecond)
		}, kind: isolation.ErrStaleProof},
		{name: "record created after observation", mutate: func(value *isolation.FirewallValidationContext) {
			value.RunLifetime.CreatedAt = value.ObservedAt.Add(time.Nanosecond)
		}, kind: isolation.ErrStaleProof},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			context := validFirewallValidationContext("run1")
			test.mutate(&context)
			if err := isolation.ValidateFirewallRule(validFirewallRules()[0], []string{"10.80.0.0/16"}, context); !errors.Is(err, test.kind) {
				t.Fatalf("ValidateFirewallRule() error = %v; want %v", err, test.kind)
			}
		})
	}
}

func TestStandaloneFirewallValidationRequiresRemainingMutationWindow(t *testing.T) {
	t.Parallel()

	valid := validFirewallValidationContext("run1")
	valid.Now = valid.RunLifetime.ExpiresAt.Add(-valid.FirewallMutationWindow)
	if err := isolation.ValidateFirewallRule(validFirewallRules()[0], []string{"10.80.0.0/16"}, valid); err != nil {
		t.Fatalf("ValidateFirewallRule(exact remaining window) unexpected error: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*isolation.FirewallValidationContext)
		kind   error
	}{
		{name: "one nanosecond short", mutate: func(value *isolation.FirewallValidationContext) {
			value.Now = value.RunLifetime.ExpiresAt.Add(-value.FirewallMutationWindow).Add(time.Nanosecond)
		}, kind: isolation.ErrStaleProof},
		{name: "zero window", mutate: func(value *isolation.FirewallValidationContext) {
			value.FirewallMutationWindow = 0
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "over planned lifetime", mutate: func(value *isolation.FirewallValidationContext) {
			value.FirewallMutationWindow = value.PlannedLifetime + time.Nanosecond
		}, kind: isolation.ErrInvalidGuardInput},
		{name: "over policy maximum", mutate: func(value *isolation.FirewallValidationContext) {
			value.PlannedLifetime = value.RunLimits.MaxLifetime + time.Hour
			value.FirewallMutationWindow = value.RunLimits.MaxLifetime + time.Nanosecond
		}, kind: isolation.ErrInvalidGuardInput},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			context := validFirewallValidationContext("run1")
			test.mutate(&context)
			if err := isolation.ValidateFirewallRule(validFirewallRules()[0], []string{"10.80.0.0/16"}, context); !errors.Is(err, test.kind) {
				t.Fatalf("ValidateFirewallRule() error = %v; want %v", err, test.kind)
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
	if err := isolation.ValidateFirewallRules(run2, absentFirewallObservations(run2), []string{"10.80.0.0/16"}, firewallTargets("run2"), validFirewallValidationContext("run2")); err != nil {
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
	duplicate := []isolation.FirewallRule{validFirewallRules()[0], validFirewallRules()[0]}
	if err := isolation.ValidateFirewallRules(duplicate, absentFirewallObservations(duplicate), []string{"10.80.0.0/16"}, firewallTargets("run1"), validFirewallValidationContext("run1")); !errors.Is(err, isolation.ErrInvalidGuardInput) {
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
	nodeTag, _ := isolation.RunNodeTag(validLifetimeFingerprint(runID))
	network := testResourceIdentity(isolation.TestVPCName, isolation.ComputeNetworkKind, isolation.ResourceScopeGlobal, "global")
	description, _ := isolation.RunFirewallDescription(validLifetimeFingerprint(runID))
	return []isolation.FirewallRule{
		{
			Identity:    testResourceIdentity(iapName, isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global"),
			Description: description, Network: network, RunID: runID, Purpose: isolation.FirewallPurposeIAPSSH, Enabled: true,
			Priority: isolation.FirewallPriority, Direction: isolation.FirewallDirectionIngress,
			Allowed:     []isolation.FirewallTrafficRule{{IPProtocol: isolation.FirewallIPProtocolTCP, Ports: []uint16{isolation.FirewallPortSSH}}},
			SourceCIDRs: []string{isolation.IAPTCPSourceCIDR}, TargetTags: []string{nodeTag},
			ResourceManagerTags: map[string]string{}, LifetimeContractFingerprint: validLifetimeFingerprint(runID),
		},
		{
			Identity:    testResourceIdentity(mongoName, isolation.ComputeFirewallKind, isolation.ResourceScopeGlobal, "global"),
			Description: description, Network: network, RunID: runID, Purpose: isolation.FirewallPurposeInternalMongo, Enabled: true,
			Priority: isolation.FirewallPriority, Direction: isolation.FirewallDirectionIngress,
			Allowed:    []isolation.FirewallTrafficRule{{IPProtocol: isolation.FirewallIPProtocolTCP, Ports: []uint16{isolation.FirewallPortMongo}}},
			SourceTags: []string{nodeTag}, TargetTags: []string{nodeTag}, ResourceManagerTags: map[string]string{},
			LifetimeContractFingerprint: validLifetimeFingerprint(runID),
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
		PlannedLifetime: time.Hour, RunLimits: defaultLimits(), FirewallMutationWindow: time.Minute,
		RunLifetime: contract, ObservedAt: contract.CreatedAt, Now: authorizationNow(),
	}
}

func firewallTargets(runID string) []isolation.MutationTarget {
	rules := firewallRulesForRun(runID)
	return []isolation.MutationTarget{
		testTargetWithIdentity(rules[0].Identity, runID),
		testTargetWithIdentity(rules[1].Identity, runID),
	}
}

func absentFirewallObservations(rules []isolation.FirewallRule) []isolation.FirewallObservation {
	observations := make([]isolation.FirewallObservation, len(rules))
	for index, rule := range rules {
		observations[index] = isolation.FirewallObservation{Identity: rule.Identity, State: isolation.FirewallObservationAbsent}
	}
	return observations
}

func presentFirewallObservations(rules []isolation.FirewallRule) []isolation.FirewallObservation {
	observations := make([]isolation.FirewallObservation, len(rules))
	for index, rule := range rules {
		present := cloneFirewallRule(rule)
		observations[index] = isolation.FirewallObservation{Identity: rule.Identity, State: isolation.FirewallObservationPresent, PresentRule: &present}
	}
	return observations
}

func cloneFirewallRule(rule isolation.FirewallRule) isolation.FirewallRule {
	rule.Allowed = cloneFirewallTrafficRules(rule.Allowed)
	rule.Denied = cloneFirewallTrafficRules(rule.Denied)
	rule.DestinationCIDRs = append([]string(nil), rule.DestinationCIDRs...)
	rule.SourceCIDRs = append([]string(nil), rule.SourceCIDRs...)
	rule.SourceTags = append([]string(nil), rule.SourceTags...)
	rule.SourceServiceAccounts = append([]string(nil), rule.SourceServiceAccounts...)
	rule.TargetTags = append([]string(nil), rule.TargetTags...)
	rule.TargetServiceAccounts = append([]string(nil), rule.TargetServiceAccounts...)
	rule.ResourceManagerTags = maps.Clone(rule.ResourceManagerTags)
	return rule
}

func cloneFirewallTrafficRules(rules []isolation.FirewallTrafficRule) []isolation.FirewallTrafficRule {
	cloned := make([]isolation.FirewallTrafficRule, len(rules))
	for index, rule := range rules {
		rule.Ports = append([]uint16(nil), rule.Ports...)
		cloned[index] = rule
	}
	return cloned
}
