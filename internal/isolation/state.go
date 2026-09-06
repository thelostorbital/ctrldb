// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"time"
)

const (
	HarnessStateSchemaV1  = "ctrldb.ctrlboard.dev/harness-state/v1"
	WFTestWorkflowID      = "WF-TEST-01"
	MaxT8EvidenceLifetime = time.Hour
)

var (
	ErrInvalidHarnessState  = errors.New("invalid test harness state")
	ErrHarnessStateMismatch = errors.New("test harness state mismatch")
	ErrHarnessStateStale    = errors.New("stale test harness state")
)

type BootstrapPhase string

const (
	BootstrapPhasePending BootstrapPhase = "pending"
	BootstrapPhaseOpen    BootstrapPhase = "open"
)

type TestUsability string

const (
	TestUsabilityUnusable TestUsability = "unusable"
	TestUsabilityUsable   TestUsability = "usable"
)

// HarnessResourceFingerprints binds the complete permanent harness topology,
// identity policy, wipe runtime, schedule, and immutable image.
type HarnessResourceFingerprints struct {
	Network         string `json:"network"`
	RoleBindings    string `json:"roleBindings"`
	ServiceAccounts string `json:"serviceAccounts"`
	WipeJob         string `json:"wipeJob"`
	Scheduler       string `json:"scheduler"`
	Image           string `json:"image"`
}

// HarnessStateSeed contains the complete approved bootstrap binding. All
// values must come from the immutable plan/envelope or a complete observation.
type HarnessStateSeed struct {
	ProjectID               string
	Environment             string
	EnvironmentClass        string
	ManifestHash            string
	ApprovedPlan            PlanIdentity
	OperationID             string
	BootstrapEnvelopeHash   string
	ControlRecordGeneration uint64
	Resources               HarnessResourceFingerprints
	CleanupCapabilities     []CleanupCapability
	BootstrapSteps          []string
	RollbackSteps           []string
	ApprovedAt              time.Time
	ApprovalValidUntil      time.Time
}

type harnessStatePayloadV1 struct {
	ProjectID                string                      `json:"projectId"`
	Environment              string                      `json:"environment"`
	EnvironmentClass         string                      `json:"environmentClass"`
	ManifestHash             string                      `json:"manifestHash"`
	ApprovedPlan             PlanIdentity                `json:"approvedPlan"`
	OperationID              string                      `json:"operationId"`
	BootstrapEnvelopeHash    string                      `json:"bootstrapEnvelopeHash"`
	ControlRecordGeneration  uint64                      `json:"controlRecordGeneration"`
	Resources                HarnessResourceFingerprints `json:"resources"`
	CleanupCapabilities      []CleanupCapability         `json:"cleanupCapabilities"`
	BootstrapSteps           []string                    `json:"bootstrapSteps"`
	RollbackSteps            []string                    `json:"rollbackSteps"`
	ApprovedAt               time.Time                   `json:"approvedAt"`
	ApprovalValidUntil       time.Time                   `json:"approvalValidUntil"`
	BootstrapPhase           BootstrapPhase              `json:"bootstrapPhase"`
	BootstrapOpenedAt        *time.Time                  `json:"bootstrapOpenedAt,omitempty"`
	TestUsability            TestUsability               `json:"testUsability"`
	T8ObservationRevision    string                      `json:"t8ObservationRevision,omitempty"`
	T8ObservedAt             *time.Time                  `json:"t8ObservedAt,omitempty"`
	T8ValidUntil             *time.Time                  `json:"t8ValidUntil,omitempty"`
	DriftObservationRevision string                      `json:"driftObservationRevision,omitempty"`
	DriftDetectedAt          *time.Time                  `json:"driftDetectedAt,omitempty"`
}

type harnessStateWireV1 struct {
	SchemaVersion   string                `json:"schemaVersion"`
	State           harnessStatePayloadV1 `json:"state"`
	IntegritySHA256 string                `json:"integritySha256"`
}

// HarnessStateV1 is immutable and integrity-checked. Its only phase transition
// is Pending -> Open; drift can only change test usability. Authenticity and
// concurrency are supplied by the later generation-preconditioned store.
type HarnessStateV1 struct {
	payload   harnessStatePayloadV1
	integrity string
}

// NewPendingHarnessStateV1 seals the approved bootstrap envelope before any
// cloud mutation. T8 evidence is intentionally absent and tests are unusable.
func NewPendingHarnessStateV1(seed HarnessStateSeed) (HarnessStateV1, error) {
	payload := harnessStatePayloadV1{
		ProjectID: seed.ProjectID, Environment: seed.Environment, EnvironmentClass: seed.EnvironmentClass,
		ManifestHash: seed.ManifestHash,
		ApprovedPlan: seed.ApprovedPlan, OperationID: seed.OperationID,
		BootstrapEnvelopeHash:   seed.BootstrapEnvelopeHash,
		ControlRecordGeneration: seed.ControlRecordGeneration, Resources: seed.Resources,
		CleanupCapabilities: append([]CleanupCapability(nil), seed.CleanupCapabilities...),
		BootstrapSteps:      append([]string(nil), seed.BootstrapSteps...),
		RollbackSteps:       append([]string(nil), seed.RollbackSteps...),
		ApprovedAt:          seed.ApprovedAt, ApprovalValidUntil: seed.ApprovalValidUntil,
		BootstrapPhase: BootstrapPhasePending, TestUsability: TestUsabilityUnusable,
	}
	return sealHarnessState(payload)
}

// T8Evidence is one complete, fresh TEST-ISO result set.
type T8Evidence struct {
	Revision   string
	ObservedAt time.Time
	ValidUntil time.Time
}

// OpenAfterT8 performs the one-way bootstrap transition after a complete T8
// success. It cannot reopen or extend an already-open state.
func (state HarnessStateV1) OpenAfterT8(evidence T8Evidence, now time.Time) (HarnessStateV1, error) {
	if err := state.validate(); err != nil {
		return HarnessStateV1{}, err
	}
	if state.payload.BootstrapPhase != BootstrapPhasePending {
		return HarnessStateV1{}, guardError(ErrHarnessStateMismatch, "bootstrapPhase", "is already open")
	}
	if err := validateT8Evidence(evidence); err != nil {
		return HarnessStateV1{}, err
	}
	if !isFreshAt(evidence.ObservedAt, evidence.ValidUntil, now) {
		return HarnessStateV1{}, guardError(ErrHarnessStateStale, "now", "does not fall within the fresh T8 evidence window")
	}
	if now.Before(state.payload.ApprovedAt) || !now.Before(state.payload.ApprovalValidUntil) ||
		evidence.ObservedAt.Before(state.payload.ApprovedAt) || !evidence.ObservedAt.Before(state.payload.ApprovalValidUntil) {
		return HarnessStateV1{}, guardError(ErrHarnessStateStale, "t8ObservedAt", "is outside the approved bootstrap window")
	}
	payload := cloneHarnessPayload(state.payload)
	payload.BootstrapPhase = BootstrapPhaseOpen
	payload.BootstrapOpenedAt = timePointer(now)
	payload.TestUsability = TestUsabilityUsable
	payload.T8ObservationRevision = evidence.Revision
	payload.T8ObservedAt = timePointer(evidence.ObservedAt)
	payload.T8ValidUntil = timePointer(evidence.ValidUntil)
	return sealHarnessState(payload)
}

// HarnessDriftEvidence records the exact observation which invalidated the
// last usable T8 result.
type HarnessDriftEvidence struct {
	Revision   string
	DetectedAt time.Time
}

// MarkTestsUnusable records drift without returning the harness to the global
// pending phase. Repair and a strictly newer T8 can restore usability.
func (state HarnessStateV1) MarkTestsUnusable(drift HarnessDriftEvidence) (HarnessStateV1, error) {
	if err := state.validate(); err != nil {
		return HarnessStateV1{}, err
	}
	if state.payload.BootstrapPhase != BootstrapPhaseOpen {
		return HarnessStateV1{}, guardError(ErrHarnessStateMismatch, "bootstrapPhase", "is not open")
	}
	if !isSHA256Fingerprint(drift.Revision) || drift.DetectedAt.IsZero() || state.payload.T8ObservedAt == nil ||
		!drift.DetectedAt.After(*state.payload.T8ObservedAt) {
		return HarnessStateV1{}, guardError(ErrInvalidHarnessState, "drift", "must bind a complete observation strictly newer than T8")
	}
	if _, offset := drift.DetectedAt.Zone(); offset != 0 {
		return HarnessStateV1{}, guardError(ErrInvalidHarnessState, "drift.detectedAt", "must use UTC")
	}
	if state.payload.TestUsability == TestUsabilityUnusable {
		if state.payload.DriftDetectedAt == nil {
			return HarnessStateV1{}, guardError(ErrInvalidHarnessState, "drift", "current unusable state has no drift boundary")
		}
		if drift.Revision == state.payload.DriftObservationRevision && drift.DetectedAt.Equal(*state.payload.DriftDetectedAt) {
			return state, nil
		}
		if !drift.DetectedAt.After(*state.payload.DriftDetectedAt) {
			return HarnessStateV1{}, guardError(ErrHarnessStateStale, "drift.detectedAt", "does not advance the current drift boundary")
		}
	}
	payload := cloneHarnessPayload(state.payload)
	payload.TestUsability = TestUsabilityUnusable
	payload.DriftObservationRevision = drift.Revision
	payload.DriftDetectedAt = timePointer(drift.DetectedAt)
	return sealHarnessState(payload)
}

// RestoreTestsUsable accepts a new complete T8 while preserving Open. It does
// not change the original approved bootstrap binding.
func (state HarnessStateV1) RestoreTestsUsable(evidence T8Evidence, now time.Time) (HarnessStateV1, error) {
	if err := state.validate(); err != nil {
		return HarnessStateV1{}, err
	}
	if state.payload.BootstrapPhase != BootstrapPhaseOpen {
		return HarnessStateV1{}, guardError(ErrHarnessStateMismatch, "bootstrapPhase", "is not open")
	}
	if err := validateT8Evidence(evidence); err != nil {
		return HarnessStateV1{}, err
	}
	if !isFreshAt(evidence.ObservedAt, evidence.ValidUntil, now) {
		return HarnessStateV1{}, guardError(ErrHarnessStateStale, "now", "does not fall within the replacement T8 evidence window")
	}
	if state.payload.TestUsability != TestUsabilityUnusable || state.payload.DriftDetectedAt == nil ||
		!evidence.ObservedAt.After(*state.payload.DriftDetectedAt) {
		return HarnessStateV1{}, guardError(ErrHarnessStateStale, "t8ObservedAt", "is not strictly newer than the drift observation")
	}
	payload := cloneHarnessPayload(state.payload)
	payload.TestUsability = TestUsabilityUsable
	payload.T8ObservationRevision = evidence.Revision
	payload.T8ObservedAt = timePointer(evidence.ObservedAt)
	payload.T8ValidUntil = timePointer(evidence.ValidUntil)
	payload.DriftObservationRevision = ""
	payload.DriftDetectedAt = nil
	return sealHarnessState(payload)
}

// RenewT8 replaces expiring evidence for an unchanged open harness. Renewal
// cannot repair recorded drift; that requires RestoreTestsUsable.
func (state HarnessStateV1) RenewT8(evidence T8Evidence, now time.Time) (HarnessStateV1, error) {
	if err := state.validate(); err != nil {
		return HarnessStateV1{}, err
	}
	if state.payload.BootstrapPhase != BootstrapPhaseOpen || state.payload.TestUsability != TestUsabilityUsable ||
		state.payload.T8ObservedAt == nil {
		return HarnessStateV1{}, guardError(ErrHarnessStateMismatch, "testUsability", "is not an unchanged usable harness")
	}
	if err := validateT8Evidence(evidence); err != nil {
		return HarnessStateV1{}, err
	}
	if !isFreshAt(evidence.ObservedAt, evidence.ValidUntil, now) ||
		!evidence.ObservedAt.After(*state.payload.T8ObservedAt) {
		return HarnessStateV1{}, guardError(ErrHarnessStateStale, "t8ObservedAt", "is not a fresh strictly newer T8 observation")
	}
	payload := cloneHarnessPayload(state.payload)
	payload.T8ObservationRevision = evidence.Revision
	payload.T8ObservedAt = timePointer(evidence.ObservedAt)
	payload.T8ValidUntil = timePointer(evidence.ValidUntil)
	return sealHarnessState(payload)
}

// ParseHarnessStateV1 strictly decodes one canonical state object and verifies
// its embedded integrity hash. Unknown fields and trailing data fail closed.
func ParseHarnessStateV1(input []byte) (HarnessStateV1, error) {
	var wire harnessStateWireV1
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return HarnessStateV1{}, guardError(ErrInvalidHarnessState, "document", "is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return HarnessStateV1{}, guardError(ErrInvalidHarnessState, "document", "contains trailing data")
	}
	if wire.SchemaVersion != HarnessStateSchemaV1 || !isSHA256Fingerprint(wire.IntegritySHA256) {
		return HarnessStateV1{}, guardError(ErrInvalidHarnessState, "document", "has an unsupported schema or integrity value")
	}
	state := HarnessStateV1{payload: cloneHarnessPayload(wire.State), integrity: wire.IntegritySHA256}
	if err := state.validate(); err != nil {
		return HarnessStateV1{}, err
	}
	want, err := harnessPayloadFingerprint(state.payload)
	if err != nil || want != state.integrity {
		return HarnessStateV1{}, guardError(ErrInvalidHarnessState, "integritySha256", "does not match the canonical state")
	}
	canonical, err := state.CanonicalJSON()
	if err != nil || !bytes.Equal(canonical, input) {
		return HarnessStateV1{}, guardError(ErrInvalidHarnessState, "document", "is not canonical JSON")
	}
	return state, nil
}

// CanonicalJSON returns a detached deterministic encoding suitable for a
// generation-preconditioned durable store.
func (state HarnessStateV1) CanonicalJSON() ([]byte, error) {
	if err := state.validate(); err != nil {
		return nil, err
	}
	wire := harnessStateWireV1{SchemaVersion: HarnessStateSchemaV1, State: cloneHarnessPayload(state.payload), IntegritySHA256: state.integrity}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, guardError(ErrInvalidHarnessState, "document", "could not be encoded")
	}
	return encoded, nil
}

func sealHarnessState(payload harnessStatePayloadV1) (HarnessStateV1, error) {
	payload = cloneHarnessPayload(payload)
	state := HarnessStateV1{payload: payload}
	if err := state.validatePayload(); err != nil {
		return HarnessStateV1{}, err
	}
	fingerprint, err := harnessPayloadFingerprint(payload)
	if err != nil {
		return HarnessStateV1{}, err
	}
	state.integrity = fingerprint
	return state, nil
}

func (state HarnessStateV1) validate() error {
	if err := state.validatePayload(); err != nil {
		return err
	}
	want, err := harnessPayloadFingerprint(state.payload)
	if err != nil || want != state.integrity {
		return guardError(ErrInvalidHarnessState, "integritySha256", "does not match the canonical state")
	}
	return nil
}

func (state HarnessStateV1) validatePayload() error {
	payload := state.payload
	if !projectIDPattern.MatchString(payload.ProjectID) || !environmentNamePattern.MatchString(payload.Environment) ||
		payload.EnvironmentClass != "disposable" || !isSHA256Fingerprint(payload.ManifestHash) ||
		!planIDPattern.MatchString(payload.ApprovedPlan.ID) || !isSHA256Fingerprint(payload.ApprovedPlan.Hash) ||
		!operationIDPattern.MatchString(payload.OperationID) || !isSHA256Fingerprint(payload.BootstrapEnvelopeHash) ||
		payload.ControlRecordGeneration == 0 {
		return guardError(ErrInvalidHarnessState, "binding", "is incomplete or malformed")
	}
	for _, fingerprint := range []string{
		payload.Resources.Network, payload.Resources.RoleBindings, payload.Resources.ServiceAccounts,
		payload.Resources.WipeJob, payload.Resources.Scheduler, payload.Resources.Image,
	} {
		if !isSHA256Fingerprint(fingerprint) {
			return guardError(ErrInvalidHarnessState, "resources", "contains an invalid fingerprint")
		}
	}
	if err := ValidateCleanupCapabilities(payload.CleanupCapabilities); err != nil {
		return fmt.Errorf("%w: cleanup capabilities are not exact", ErrInvalidHarnessState)
	}
	if err := validateStepSet("bootstrapSteps", payload.BootstrapSteps); err != nil {
		return err
	}
	if err := validateStepSet("rollbackSteps", payload.RollbackSteps); err != nil {
		return err
	}
	if err := validateUTCWindow(payload.ApprovedAt, payload.ApprovalValidUntil, 0); err != nil {
		return guardError(ErrInvalidHarnessState, "approval", "does not contain a valid UTC window")
	}
	switch payload.BootstrapPhase {
	case BootstrapPhasePending:
		if payload.TestUsability != TestUsabilityUnusable || payload.T8ObservationRevision != "" ||
			payload.BootstrapOpenedAt != nil || payload.T8ObservedAt != nil || payload.T8ValidUntil != nil || payload.DriftObservationRevision != "" ||
			payload.DriftDetectedAt != nil {
			return guardError(ErrInvalidHarnessState, "bootstrapPhase", "pending state cannot contain usable T8 evidence")
		}
	case BootstrapPhaseOpen:
		if payload.TestUsability != TestUsabilityUsable && payload.TestUsability != TestUsabilityUnusable {
			return guardError(ErrInvalidHarnessState, "testUsability", "is unknown")
		}
		if payload.T8ObservedAt == nil || payload.T8ValidUntil == nil ||
			validateT8Evidence(T8Evidence{payload.T8ObservationRevision, *payload.T8ObservedAt, *payload.T8ValidUntil}) != nil {
			return guardError(ErrInvalidHarnessState, "t8", "does not contain complete evidence")
		}
		if payload.BootstrapOpenedAt == nil || payload.BootstrapOpenedAt.Before(payload.ApprovedAt) ||
			!payload.BootstrapOpenedAt.Before(payload.ApprovalValidUntil) {
			return guardError(ErrInvalidHarnessState, "bootstrapOpenedAt", "falls outside the approved bootstrap window")
		}
		if _, offset := payload.BootstrapOpenedAt.Zone(); offset != 0 {
			return guardError(ErrInvalidHarnessState, "bootstrapOpenedAt", "must use UTC")
		}
		if payload.TestUsability == TestUsabilityUsable {
			if payload.DriftObservationRevision != "" || payload.DriftDetectedAt != nil {
				return guardError(ErrInvalidHarnessState, "drift", "usable state cannot retain a drift boundary")
			}
		} else if !isSHA256Fingerprint(payload.DriftObservationRevision) || payload.DriftDetectedAt == nil ||
			!payload.DriftDetectedAt.After(*payload.T8ObservedAt) {
			return guardError(ErrInvalidHarnessState, "drift", "unusable state requires a drift observation strictly newer than T8")
		} else if _, offset := payload.DriftDetectedAt.Zone(); offset != 0 {
			return guardError(ErrInvalidHarnessState, "drift.detectedAt", "must use UTC")
		}
	default:
		return guardError(ErrInvalidHarnessState, "bootstrapPhase", "is unknown")
	}
	return nil
}

func validateStepSet(path string, values []string) error {
	if len(values) == 0 {
		return guardError(ErrInvalidHarnessState, path, "must not be empty")
	}
	if !sort.StringsAreSorted(values) {
		return guardError(ErrInvalidHarnessState, path, "must be canonical and sorted")
	}
	for index, value := range values {
		if !canonicalIDPattern.MatchString(value) || (index > 0 && value == values[index-1]) {
			return guardError(ErrInvalidHarnessState, indexedField(path, index), "is invalid or duplicated")
		}
	}
	return nil
}

func validateT8Evidence(evidence T8Evidence) error {
	if !isSHA256Fingerprint(evidence.Revision) || validateUTCWindow(evidence.ObservedAt, evidence.ValidUntil, MaxT8EvidenceLifetime) != nil {
		return guardError(ErrHarnessStateStale, "t8", "must be a complete bounded UTC observation")
	}
	return nil
}

func validateUTCWindow(start, end time.Time, maximum time.Duration) error {
	if start.IsZero() || end.IsZero() || !end.After(start) {
		return ErrInvalidHarnessState
	}
	for _, value := range []time.Time{start, end} {
		_, offset := value.Zone()
		if offset != 0 {
			return ErrInvalidHarnessState
		}
	}
	if maximum > 0 && end.Sub(start) > maximum {
		return ErrHarnessStateStale
	}
	return nil
}

func isFreshAt(observedAt, validUntil, now time.Time) bool {
	if now.IsZero() {
		return false
	}
	if _, offset := now.Zone(); offset != 0 {
		return false
	}
	return !now.Before(observedAt) && now.Before(validUntil)
}

func harnessPayloadFingerprint(payload harnessStatePayloadV1) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", guardError(ErrInvalidHarnessState, "state", "could not be fingerprinted")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func cloneHarnessPayload(payload harnessStatePayloadV1) harnessStatePayloadV1 {
	payload.CleanupCapabilities = append([]CleanupCapability(nil), payload.CleanupCapabilities...)
	payload.BootstrapSteps = append([]string(nil), payload.BootstrapSteps...)
	payload.RollbackSteps = append([]string(nil), payload.RollbackSteps...)
	if payload.T8ObservedAt != nil {
		payload.T8ObservedAt = timePointer(*payload.T8ObservedAt)
	}
	if payload.BootstrapOpenedAt != nil {
		payload.BootstrapOpenedAt = timePointer(*payload.BootstrapOpenedAt)
	}
	if payload.T8ValidUntil != nil {
		payload.T8ValidUntil = timePointer(*payload.T8ValidUntil)
	}
	if payload.DriftDetectedAt != nil {
		payload.DriftDetectedAt = timePointer(*payload.DriftDetectedAt)
	}
	return payload
}

func timePointer(value time.Time) *time.Time { return &value }

func containsStep(values []string, step string) bool {
	_, found := slices.BinarySearch(values, step)
	return found
}

func (state HarnessStateV1) ProjectID() string          { return state.payload.ProjectID }
func (state HarnessStateV1) Environment() string        { return state.payload.Environment }
func (state HarnessStateV1) EnvironmentClass() string   { return state.payload.EnvironmentClass }
func (state HarnessStateV1) ManifestHash() string       { return state.payload.ManifestHash }
func (state HarnessStateV1) ApprovedPlan() PlanIdentity { return state.payload.ApprovedPlan }
func (state HarnessStateV1) OperationID() string        { return state.payload.OperationID }
func (state HarnessStateV1) BootstrapEnvelopeHash() string {
	return state.payload.BootstrapEnvelopeHash
}
func (state HarnessStateV1) ControlRecordGeneration() uint64 {
	return state.payload.ControlRecordGeneration
}
func (state HarnessStateV1) Resources() HarnessResourceFingerprints { return state.payload.Resources }
func (state HarnessStateV1) CleanupCapabilities() []CleanupCapability {
	return append([]CleanupCapability(nil), state.payload.CleanupCapabilities...)
}
func (state HarnessStateV1) BootstrapPhase() BootstrapPhase { return state.payload.BootstrapPhase }
func (state HarnessStateV1) TestUsability() TestUsability   { return state.payload.TestUsability }
func (state HarnessStateV1) T8ObservationRevision() string {
	return state.payload.T8ObservationRevision
}
func (state HarnessStateV1) T8ValidUntil() (time.Time, bool) {
	if state.payload.T8ValidUntil == nil {
		return time.Time{}, false
	}
	return *state.payload.T8ValidUntil, true
}
func (state HarnessStateV1) IntegritySHA256() string { return state.integrity }
