// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
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

// ErrSeedIncompatible is returned when an existing seed object is malformed
// or semantically incompatible with the envelope; it is preserved, never
// overwritten, and the operation blocks.
var ErrSeedIncompatible = errors.New("existing control seed object is incompatible with the approved bootstrap")

// SeedControlStore first reads every seed location and validates each
// existing object strictly; only when no conflict exists does it create the
// absent seeds with a create-only precondition. Existing objects are preserved
// byte-for-byte. An approved-policy object bound to a different manifest hash
// blocks toward WF-ENV-02.
func SeedControlStore(ctx context.Context, store ControlStore, envelope BootstrapEnvelopeV1) ([]SeedOutcome, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidStoreRequest)
	}
	seeds, err := SeedObjects(envelope)
	if err != nil {
		return nil, err
	}
	existing := make([]*StoredObject, len(seeds))
	for index, seed := range seeds {
		object, err := store.Read(ctx, seed.Name)
		if err != nil {
			if errors.Is(err, ErrObjectNotFound) {
				continue
			}
			return nil, err
		}
		if err := validateExistingSeed(seed, object.Content, envelope); err != nil {
			return nil, err
		}
		existing[index] = &object
	}
	outcomes := make([]SeedOutcome, 0, len(seeds))
	for index, seed := range seeds {
		if existing[index] != nil {
			outcomes = append(outcomes, SeedOutcome{Name: seed.Name, Descriptor: existing[index].Descriptor, Preexisting: true})
			continue
		}
		descriptor, err := store.Create(ctx, seed.Name, seed.Content)
		if err == nil {
			outcomes = append(outcomes, SeedOutcome{Name: seed.Name, Descriptor: descriptor})
			continue
		}
		if !errors.Is(err, ErrPreconditionFailed) {
			return nil, err
		}
		// Lost a create race after the preflight: re-read and validate.
		object, err := store.Read(ctx, seed.Name)
		if err != nil {
			return nil, err
		}
		if err := validateExistingSeed(seed, object.Content, envelope); err != nil {
			return nil, err
		}
		outcomes = append(outcomes, SeedOutcome{Name: seed.Name, Descriptor: object.Descriptor, Preexisting: true})
	}
	return outcomes, nil
}

func validateExistingSeed(seed SeedObject, content []byte, envelope BootstrapEnvelopeV1) error {
	if bytes.Equal(content, seed.Content) {
		return nil
	}
	if len(content) == 0 || len(content) > maxSeedObjectBytes {
		return fmt.Errorf("%w: %s size", ErrSeedIncompatible, seed.Name)
	}
	if err := rejectDuplicateKeys(content); err != nil {
		return fmt.Errorf("%w: %s is ambiguous", ErrSeedIncompatible, seed.Name)
	}
	environment := envelope.Environment()
	plan := envelope.Plan()
	switch {
	case strings.HasPrefix(seed.Name.value, "locks/"):
		var lock LockRecordV1
		if err := decodeStrictSeed(content, &lock); err != nil || lock.Schema != LockRecordSchemaV1 || lock.Environment != environment ||
			(lock.State != LockStateReleased && lock.State != LockStateHeld) {
			return fmt.Errorf("%w: %s", ErrSeedIncompatible, seed.Name)
		}
	case strings.HasPrefix(seed.Name.value, "adoption/"):
		var adoption AdoptionRecordV1
		if err := decodeStrictSeed(content, &adoption); err != nil || adoption.Schema != AdoptionRecordSchemaV1 ||
			adoption.Environment != environment || adoption.Project != envelope.Project() ||
			!operationIDPattern.MatchString(adoption.OperationID) || !planIDPattern.MatchString(adoption.PlanID) || !validUTC(adoption.AdoptedAt) {
			return fmt.Errorf("%w: %s", ErrSeedIncompatible, seed.Name)
		}
		var expected AdoptionRecordV1
		_ = json.Unmarshal(seed.Content, &expected)
		if !equalCanonicalValue(adoption.Resources, expected.Resources) {
			return fmt.Errorf("%w: %s records different permanent resources", ErrSeedIncompatible, seed.Name)
		}
	case strings.HasSuffix(seed.Name.value, "/manifest-approved.json"):
		var policy ApprovedPolicyV1
		if err := decodeStrictSeed(content, &policy); err != nil || policy.Schema != ApprovedPolicySchemaV1 ||
			!planIDPattern.MatchString(policy.PlanID) || policy.ApprovedBy == "" {
			return fmt.Errorf("%w: %s", ErrSeedIncompatible, seed.Name)
		}
		if policy.SHA256 != plan.Binding().ManifestHash {
			return ErrApprovedPolicyMismatch
		}
	case strings.HasSuffix(seed.Name.value, "/cost-ceiling.json"):
		var ceiling CostCeilingV1
		if err := decodeStrictSeed(content, &ceiling); err != nil || ceiling.Schema != CostCeilingSchemaV1 || ceiling.Environment != environment ||
			ceiling.Currency != "USD" || !planIDPattern.MatchString(ceiling.PlanID) {
			return fmt.Errorf("%w: %s", ErrSeedIncompatible, seed.Name)
		}
		if ceiling.CeilingMicros != plan.Limits().MaximumCostMicros {
			return fmt.Errorf("%w: %s", ErrApprovedPolicyMismatch, seed.Name)
		}
	default:
		return fmt.Errorf("%w: %s", ErrSeedIncompatible, seed.Name)
	}
	return nil
}

func decodeStrictSeed(content []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// SeedObjectNames returns the closed K4 seed object names for environment.
// It returns nil for an invalid environment.
func SeedObjectNames(environment string) []string {
	lock, err := LockObjectName(environment)
	if err != nil {
		return nil
	}
	adoption, _ := AdoptionObjectName(environment)
	policy, _ := ApprovedPolicyObjectName(environment)
	ceiling, _ := CostCeilingObjectName(environment)
	return []string{lock.String(), adoption.String(), policy.String(), ceiling.String()}
}
