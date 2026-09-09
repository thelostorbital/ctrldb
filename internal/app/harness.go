// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
)

const (
	harnessEnvironmentClass = "disposable"
	rollbackStepPrefix      = "rollback-"
)

// HarnessFingerprints derives the closed HarnessStateV1 resource fingerprints
// from the approved plan's desired-state fingerprints. Every value is a
// SHA-256 over canonical JSON of the exact desired resources it binds.
func HarnessFingerprints(plan bootstrap.CompiledPlan) (isolation.HarnessResourceFingerprints, error) {
	byID := make(map[string]bootstrap.DesiredResource)
	for _, resource := range plan.DesiredResources() {
		byID[resource.ID] = resource
	}
	group := func(ids ...string) (string, error) {
		selected := make([]bootstrap.DesiredResource, 0, len(ids))
		for _, id := range ids {
			resource, ok := byID[id]
			if !ok || resource.DesiredStateFingerprint == "" {
				return "", denied("desired resource " + id + " missing from the approved plan")
			}
			selected = append(selected, resource)
		}
		return hashJSON(selected)
	}
	network, err := group("test-network", "test-subnet", "test-router", "test-nat", "test-iap-firewall", "test-internal-firewall")
	if err != nil {
		return isolation.HarnessResourceFingerprints{}, err
	}
	roles, err := group("test-operator-role", "test-destructive-role")
	if err != nil {
		return isolation.HarnessResourceFingerprints{}, err
	}
	accounts, err := group("test-operator-sa", "test-destructive-sa", "test-vm-sa", "test-wipe-sa")
	if err != nil {
		return isolation.HarnessResourceFingerprints{}, err
	}
	wipe, err := group("test-wipe-job")
	if err != nil {
		return isolation.HarnessResourceFingerprints{}, err
	}
	scheduler, err := group("test-wipe-scheduler")
	if err != nil {
		return isolation.HarnessResourceFingerprints{}, err
	}
	digest := strings.TrimPrefix(plan.DesiredState().ImageDigest, "sha256:")
	if len(digest) != sha256.Size*2 {
		return isolation.HarnessResourceFingerprints{}, denied("image digest is not a sha256 value")
	}
	return isolation.HarnessResourceFingerprints{
		Network: network, RoleBindings: roles, ServiceAccounts: accounts,
		WipeJob: wipe, Scheduler: scheduler, Image: digest,
	}, nil
}

// bootstrapStepIDs returns the sorted canonical step set the pending state
// admits. Rollback admits the same identifiers because recorded compensation
// is addressed by the step it compensates.
func bootstrapStepIDs(plan bootstrap.CompiledPlan) []string {
	intents := plan.Intents()
	ids := make([]string, len(intents))
	for index, intent := range intents {
		ids[index] = intent.StepID
	}
	sort.Strings(ids)
	return ids
}

// HarnessSeed builds the pending HarnessStateV1 seed from the approved plan,
// the durable envelope, and the approval window. Nothing is sourced from a
// previously stored state.
func HarnessSeed(plan bootstrap.CompiledPlan, operationID string, envelope EnvelopeRecord, approval ApprovalProof) (isolation.HarnessStateSeed, error) {
	fingerprints, err := HarnessFingerprints(plan)
	if err != nil {
		return isolation.HarnessStateSeed{}, err
	}
	reviewed := plan.Plan()
	steps := bootstrapStepIDs(plan)
	return isolation.HarnessStateSeed{
		ProjectID: reviewed.ProjectID, Environment: reviewed.Environment, EnvironmentClass: harnessEnvironmentClass,
		ManifestHash: plan.Binding().ManifestHash,
		ApprovedPlan: isolation.PlanIdentity{ID: reviewed.PlanID, Hash: reviewed.PlanHash},
		OperationID:  operationID, BootstrapEnvelopeHash: envelope.Hash, ControlRecordGeneration: envelope.Generation,
		Resources: fingerprints, CleanupCapabilities: plan.CleanupCapabilities(),
		BootstrapSteps: steps, RollbackSteps: append([]string(nil), steps...),
		ApprovedAt: approval.ApprovedAt, ApprovalValidUntil: approval.ValidUntil,
	}, nil
}

// harnessExpectation is the trusted admission binding for the pending phase.
func harnessExpectation(seed isolation.HarnessStateSeed) isolation.HarnessStateExpectation {
	return isolation.HarnessStateExpectation{
		ProjectID: seed.ProjectID, Environment: seed.Environment, EnvironmentClass: seed.EnvironmentClass,
		ManifestHash: seed.ManifestHash, ApprovedPlan: seed.ApprovedPlan, OperationID: seed.OperationID,
		BootstrapEnvelopeHash: seed.BootstrapEnvelopeHash, ControlRecordGeneration: seed.ControlRecordGeneration,
		Resources: seed.Resources, CleanupCapabilities: append([]isolation.CleanupCapability(nil), seed.CleanupCapabilities...),
		BootstrapSteps: append([]string(nil), seed.BootstrapSteps...), RollbackSteps: append([]string(nil), seed.RollbackSteps...),
		ApprovedAt: seed.ApprovedAt, ApprovalValidUntil: seed.ApprovalValidUntil,
		BootstrapPhase: isolation.BootstrapPhasePending, TestUsability: isolation.TestUsabilityUnusable,
	}
}

func hashJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", denied("canonical encoding failed")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func utcNow(clock func() time.Time) time.Time {
	return clock().UTC().Truncate(time.Second)
}
