// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	LockRecordSchemaV1     = "ctrldb.ctrlboard.dev/lock/v1"
	AdoptionRecordSchemaV1 = "ctrldb.ctrlboard.dev/adoption/v1"
	ApprovedPolicySchemaV1 = "ctrldb.ctrlboard.dev/approved-policy/v1"
	CostCeilingSchemaV1    = "ctrldb.ctrlboard.dev/cost-ceiling/v1"

	// LockStateReleased is the seeded lock state (ARCHITECTURE lock protocol).
	LockStateReleased = "released"
	// LockStateHeld is the acquired lock state.
	LockStateHeld = "held"

	maxSeedObjectBytes = 64 << 10
)

// ErrApprovedPolicyMismatch is returned when an existing approved-policy seed
// binds a different manifest hash; WF-ENV-02 owns that change.
var ErrApprovedPolicyMismatch = errors.New("existing approved policy does not match the manifest hash; use WF-ENV-02")

// LockRecordV1 is the `locks/<env>.json` object. A released record carries no
// holder; hostname and pid are recorded only while held.
type LockRecordV1 struct {
	Schema                  string      `json:"schema"`
	Environment             string      `json:"environment"`
	WorkflowID              string      `json:"workflowId,omitempty"`
	OperationID             string      `json:"operationId,omitempty"`
	PlanID                  string      `json:"planId,omitempty"`
	Holder                  *LockHolder `json:"holder,omitempty"`
	AcquiredAt              *time.Time  `json:"acquiredAt,omitempty"`
	HeartbeatAt             *time.Time  `json:"heartbeatAt,omitempty"`
	LeaseUntil              *time.Time  `json:"leaseUntil,omitempty"`
	ExcludesHostAutomations bool        `json:"excludesHostAutomations"`
	State                   string      `json:"state"`
	Readers                 []string    `json:"readers"`
	CLIVersion              string      `json:"cliVersion,omitempty"`
}

// LockHolder identifies the holding process.
type LockHolder struct {
	Account      string `json:"account"`
	Impersonated string `json:"impersonated,omitempty"`
	Hostname     string `json:"hostname"`
	PID          int64  `json:"pid"`
}

// AdoptionRecordV1 is the `adoption/<env>.json` seed: the permanent control
// resources this bootstrap created, keyed by plan resource ID.
type AdoptionRecordV1 struct {
	Schema      string                     `json:"schema"`
	Environment string                     `json:"environment"`
	Project     string                     `json:"project"`
	OperationID string                     `json:"operationId"`
	PlanID      string                     `json:"planId"`
	AdoptedAt   time.Time                  `json:"adoptedAt"`
	Resources   map[string]AdoptedResource `json:"resources"`
}

// AdoptedResource is one fingerprinted permanent resource.
type AdoptedResource struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	ProviderID  string `json:"providerId"`
	Fingerprint string `json:"fingerprint"`
}

// ApprovedPolicyV1 is `policy/<env>/manifest-approved.json` (D-115).
type ApprovedPolicyV1 struct {
	Schema     string `json:"schema"`
	SHA256     string `json:"sha256"`
	ApprovedBy string `json:"approvedBy"`
	PlanID     string `json:"planId"`
}

// CostCeilingV1 is `policy/<env>/cost-ceiling.json` (D-102).
type CostCeilingV1 struct {
	Schema             string `json:"schema"`
	Environment        string `json:"environment"`
	CeilingMicros      int64  `json:"ceilingMicros"`
	EstimatedRunMicros int64  `json:"estimatedRunMicros"`
	Currency           string `json:"currency"`
	ApprovedBy         string `json:"approvedBy"`
	PlanID             string `json:"planId"`
}

// SeedObject is one exact K4 create-only object.
type SeedObject struct {
	Name    ControlObjectName
	Content []byte
}

// SeedObjects renders the exact K4 seed identities and contents from the
// envelope. Nothing is derived from ambient configuration.
func SeedObjects(envelope BootstrapEnvelopeV1) ([]SeedObject, error) {
	if envelope.hash == "" {
		return nil, invalidEnvelope("unsealed")
	}
	environment := envelope.Environment()
	plan := envelope.Plan()
	lockName, err := LockObjectName(environment)
	if err != nil {
		return nil, err
	}
	adoptionName, err := AdoptionObjectName(environment)
	if err != nil {
		return nil, err
	}
	policyName, err := ApprovedPolicyObjectName(environment)
	if err != nil {
		return nil, err
	}
	ceilingName, err := CostCeilingObjectName(environment)
	if err != nil {
		return nil, err
	}
	adopted := make(map[string]AdoptedResource)
	for _, resource := range plan.DesiredResources() {
		if resource.ID == "audit-bucket" || resource.ID == "control-bucket" {
			adopted[resource.ID] = AdoptedResource{Kind: string(resource.Kind), Name: resource.Name, ProviderID: resource.ProviderID, Fingerprint: resource.DesiredStateFingerprint}
		}
	}
	if len(adopted) != 2 {
		return nil, invalidEnvelope("permanent bucket resources")
	}
	values := []struct {
		name  ControlObjectName
		value any
	}{
		{lockName, LockRecordV1{Schema: LockRecordSchemaV1, Environment: environment, State: LockStateReleased, Readers: []string{}}},
		{adoptionName, AdoptionRecordV1{Schema: AdoptionRecordSchemaV1, Environment: environment, Project: envelope.Project(),
			OperationID: envelope.OperationID(), PlanID: envelope.PlanID(), AdoptedAt: envelope.SealedAt(), Resources: adopted}},
		{policyName, ApprovedPolicyV1{Schema: ApprovedPolicySchemaV1, SHA256: plan.Binding().ManifestHash, ApprovedBy: envelope.Account(), PlanID: envelope.PlanID()}},
		{ceilingName, CostCeilingV1{Schema: CostCeilingSchemaV1, Environment: environment, CeilingMicros: plan.Limits().MaximumCostMicros,
			EstimatedRunMicros: plan.Limits().EstimatedCostMicros, Currency: "USD", ApprovedBy: envelope.Account(), PlanID: envelope.PlanID()}},
	}
	result := make([]SeedObject, len(values))
	for index, item := range values {
		encoded, err := json.Marshal(item.value)
		if err != nil {
			return nil, invalidEnvelope("seed encoding")
		}
		result[index] = SeedObject{Name: item.name, Content: encoded}
	}
	return result, nil
}

// SeedOutcome records what K4 did for one object.
type SeedOutcome struct {
	Name        ControlObjectName
	Descriptor  ObjectDescriptor
	Preexisting bool
}

// SeedControlStore creates every seed with a create-only precondition. An
// existing object is read and preserved byte-for-byte; only an approved-policy
// object bound to a different manifest hash blocks.
func SeedControlStore(ctx context.Context, store ControlStore, envelope BootstrapEnvelopeV1) ([]SeedOutcome, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidStoreRequest)
	}
	seeds, err := SeedObjects(envelope)
	if err != nil {
		return nil, err
	}
	policyName, err := ApprovedPolicyObjectName(envelope.Environment())
	if err != nil {
		return nil, err
	}
	outcomes := make([]SeedOutcome, 0, len(seeds))
	for _, seed := range seeds {
		descriptor, err := store.Create(ctx, seed.Name, seed.Content)
		if err == nil {
			outcomes = append(outcomes, SeedOutcome{Name: seed.Name, Descriptor: descriptor})
			continue
		}
		if !errors.Is(err, ErrPreconditionFailed) {
			return nil, err
		}
		existing, err := store.Read(ctx, seed.Name)
		if err != nil {
			return nil, err
		}
		if seed.Name == policyName {
			if err := checkApprovedPolicy(existing.Content, envelope.Plan().Binding().ManifestHash); err != nil {
				return nil, err
			}
		}
		outcomes = append(outcomes, SeedOutcome{Name: seed.Name, Descriptor: existing.Descriptor, Preexisting: true})
	}
	return outcomes, nil
}

func checkApprovedPolicy(content []byte, manifestHash string) error {
	if len(content) == 0 || len(content) > maxSeedObjectBytes {
		return ErrApprovedPolicyMismatch
	}
	var policy ApprovedPolicyV1
	if err := json.Unmarshal(content, &policy); err != nil || policy.Schema != ApprovedPolicySchemaV1 || policy.SHA256 != manifestHash {
		return ErrApprovedPolicyMismatch
	}
	return nil
}
