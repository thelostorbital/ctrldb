// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package control implements the D-158 control/audit storage bootstrap: the
// local BootstrapEnvelopeV1 handoff, the typed durable control and audit
// stores, and the resumable first-bootstrap engine. It performs no provider
// I/O itself; provider access arrives through narrow typed ports.
package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/workflow"
)

const (
	// BootstrapEnvelopeSchemaV1 identifies the sealed local-to-audit handoff.
	BootstrapEnvelopeSchemaV1 = "ctrldb.ctrlboard.dev/bootstrap-envelope/v1"
	// ApprovalProofSchemaV1 identifies the plan-bound approval record.
	ApprovalProofSchemaV1 = "ctrldb.ctrlboard.dev/approval-proof/v1"
	// ExpectationAbsent is the only admissible pre-bootstrap observation: every
	// desired provider identity was observed absent by the exact preflight.
	ExpectationAbsent = "absent"
	// MaxEnvelopeBytes bounds any envelope read from disk or a bucket.
	MaxEnvelopeBytes = 8 << 20
)

var (
	// ErrInvalidEnvelope is returned for a malformed, tampered, noncanonical,
	// or cross-binding-inconsistent envelope.
	ErrInvalidEnvelope = errors.New("invalid bootstrap envelope")
	// ErrInvalidApprovalProof is returned when an approval does not bind the
	// exact compiled plan.
	ErrInvalidApprovalProof = errors.New("invalid approval proof")

	sha256Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	operationIDPattern = regexp.MustCompile(`^op-[0-9a-f]{16}$`)
	planIDPattern      = regexp.MustCompile(`^plan-[0-9a-f]{16}$`)
	environmentPattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	canonicalIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

// ApprovalProofV1 records the AP-3 approval of one exact compiled plan. It is
// bound to both the compiled document hash and the PlanV1 hash so that no
// semantic change can retain the approval.
type ApprovalProofV1 struct {
	Schema             string               `json:"schema"`
	WorkflowID         string               `json:"workflowId"`
	PlanID             string               `json:"planId"`
	PlanDocumentSHA256 string               `json:"planDocumentSha256"`
	PlanV1Hash         string               `json:"planV1Hash"`
	ApprovalClass      domain.ApprovalClass `json:"approvalClass"`
	ApprovedBy         string               `json:"approvedBy"`
	ApprovedAt         time.Time            `json:"approvedAt"`
	ValidUntil         time.Time            `json:"validUntil"`
	ProofSHA256        string               `json:"proofSha256"`
}

// NewApprovalProof seals an approval for plan. The caller supplies only the
// approving account and UTC window; every binding value comes from the plan.
func NewApprovalProof(plan bootstrap.CompiledPlan, approvedBy string, approvedAt, validUntil time.Time) (ApprovalProofV1, error) {
	sealed := plan.Plan()
	proof := ApprovalProofV1{
		Schema: ApprovalProofSchemaV1, WorkflowID: sealed.WorkflowID, PlanID: sealed.PlanID,
		PlanDocumentSHA256: plan.DocumentHash(), PlanV1Hash: sealed.PlanHash, ApprovalClass: sealed.ApprovalClass,
		ApprovedBy: approvedBy, ApprovedAt: approvedAt, ValidUntil: validUntil,
	}
	digest, err := hashJSON(proof)
	if err != nil {
		return ApprovalProofV1{}, invalidApproval("encoding")
	}
	proof.ProofSHA256 = digest
	if err := validateApprovalProof(proof, plan); err != nil {
		return ApprovalProofV1{}, err
	}
	return proof, nil
}

func validateApprovalProof(proof ApprovalProofV1, plan bootstrap.CompiledPlan) error {
	sealed := plan.Plan()
	if proof.Schema != ApprovalProofSchemaV1 || proof.WorkflowID != sealed.WorkflowID || proof.PlanID != sealed.PlanID ||
		proof.PlanDocumentSHA256 != plan.DocumentHash() || proof.PlanV1Hash != sealed.PlanHash ||
		proof.ApprovalClass != sealed.ApprovalClass || proof.ApprovalClass != domain.ApprovalSecuritySensitive ||
		proof.ApprovedBy == "" || proof.ApprovedBy != sealed.Principal {
		return invalidApproval("plan binding")
	}
	if !validUTC(proof.ApprovedAt) || !validUTC(proof.ValidUntil) || !proof.ApprovedAt.Before(proof.ValidUntil) ||
		proof.ApprovedAt.Before(sealed.CreatedAt) || proof.ValidUntil.After(sealed.ExpiresAt) {
		return invalidApproval("approval window")
	}
	copy := proof
	copy.ProofSHA256 = ""
	digest, err := hashJSON(copy)
	if err != nil || digest != proof.ProofSHA256 {
		return invalidApproval("integrity")
	}
	return nil
}

// ExpectedObservationV1 is one complete pre-bootstrap expectation. The first
// bootstrap is admissible only when every desired identity was absent.
type ExpectedObservationV1 struct {
	ResourceID              string                 `json:"resourceId"`
	Kind                    bootstrap.ResourceKind `json:"kind"`
	Name                    string                 `json:"name"`
	Project                 string                 `json:"project"`
	Location                string                 `json:"location"`
	ProviderID              string                 `json:"providerId"`
	Expectation             string                 `json:"expectation"`
	DesiredStateFingerprint string                 `json:"desiredStateFingerprint"`
}

type envelopePayloadV1 struct {
	WorkflowID             string                  `json:"workflowId"`
	OperationID            string                  `json:"operationId"`
	Environment            string                  `json:"environment"`
	Project                string                  `json:"project"`
	Account                string                  `json:"account"`
	PlanID                 string                  `json:"planId"`
	PlanDocumentSHA256     string                  `json:"planDocumentSha256"`
	PlanV1Hash             string                  `json:"planV1Hash"`
	EnvelopeBindingSHA256  string                  `json:"envelopeBindingSha256"`
	ContractHash           string                  `json:"contractHash"`
	Plan                   json.RawMessage         `json:"plan"`
	Approval               ApprovalProofV1         `json:"approval"`
	ObservationRevision    string                  `json:"observationRevision"`
	ExpectedObservations   []ExpectedObservationV1 `json:"expectedObservations"`
	AuditBucket            string                  `json:"auditBucket"`
	AuditBucketLocation    string                  `json:"auditBucketLocation"`
	ControlBucket          string                  `json:"controlBucket"`
	FirstJournalObjectName string                  `json:"firstJournalObjectName"`
	FirstJournalEntry      json.RawMessage         `json:"firstJournalEntry"`
	SealedAt               time.Time               `json:"sealedAt"`
}

type envelopeWireV1 struct {
	SchemaVersion  string            `json:"schemaVersion"`
	Envelope       envelopePayloadV1 `json:"envelope"`
	EnvelopeSHA256 string            `json:"envelopeSha256"`
}

// EnvelopeSeed contains the caller-owned inputs for sealing. Everything else
// in the envelope is derived from the immutable compiled plan.
type EnvelopeSeed struct {
	Plan              bootstrap.CompiledPlan
	OperationID       string
	Approval          ApprovalProofV1
	FirstJournalEntry domain.JournalEntry
	SealedAt          time.Time
}

// BootstrapEnvelopeV1 is immutable. It carries no credential, token, or
// provider output: every field is typed and derived from the compiled plan,
// the approval proof, or the closed journal schema.
type BootstrapEnvelopeV1 struct {
	payload envelopePayloadV1
	hash    string
	plan    bootstrap.CompiledPlan
	entry   domain.JournalEntry
}

// SealBootstrapEnvelope validates every cross-binding and seals the envelope.
func SealBootstrapEnvelope(seed EnvelopeSeed) (BootstrapEnvelopeV1, error) {
	planJSON, err := seed.Plan.CanonicalJSON()
	if err != nil {
		return BootstrapEnvelopeV1{}, invalidEnvelope("compiled plan")
	}
	entryJSON, err := workflow.EncodeJournalEntry(seed.FirstJournalEntry)
	if err != nil {
		return BootstrapEnvelopeV1{}, invalidEnvelope("first journal entry")
	}
	sealed := seed.Plan.Plan()
	desired := seed.Plan.DesiredState()
	journalName, err := JournalEntryObjectName(sealed.Environment, seed.FirstJournalEntry)
	if err != nil {
		return BootstrapEnvelopeV1{}, invalidEnvelope("first journal object name")
	}
	payload := envelopePayloadV1{
		WorkflowID: sealed.WorkflowID, OperationID: seed.OperationID, Environment: sealed.Environment,
		Project: sealed.ProjectID, Account: sealed.Principal, PlanID: sealed.PlanID,
		PlanDocumentSHA256: seed.Plan.DocumentHash(), PlanV1Hash: sealed.PlanHash,
		EnvelopeBindingSHA256: seed.Plan.Binding().BindingSHA256, ContractHash: seed.Plan.ExecutionContract().Digest(),
		Plan: planJSON, Approval: seed.Approval, ObservationRevision: seed.Plan.Binding().ObservationRevision,
		ExpectedObservations: expectedObservations(seed.Plan), AuditBucket: desired.AuditBucket,
		AuditBucketLocation: desired.Region, ControlBucket: desired.ControlBucket,
		FirstJournalObjectName: journalName.String(), FirstJournalEntry: entryJSON, SealedAt: seed.SealedAt,
	}
	envelope := BootstrapEnvelopeV1{payload: payload, plan: seed.Plan, entry: seed.FirstJournalEntry}
	if err := envelope.validate(); err != nil {
		return BootstrapEnvelopeV1{}, err
	}
	envelope.hash, err = hashJSON(payload)
	if err != nil {
		return BootstrapEnvelopeV1{}, invalidEnvelope("hash")
	}
	return envelope, nil
}

func expectedObservations(plan bootstrap.CompiledPlan) []ExpectedObservationV1 {
	resources := plan.DesiredResources()
	result := make([]ExpectedObservationV1, len(resources))
	for index, resource := range resources {
		result[index] = ExpectedObservationV1{
			ResourceID: resource.ID, Kind: resource.Kind, Name: resource.Name, Project: resource.Project,
			Location: resource.Location, ProviderID: resource.ProviderID, Expectation: ExpectationAbsent,
			DesiredStateFingerprint: resource.DesiredStateFingerprint,
		}
	}
	return result
}

func (envelope BootstrapEnvelopeV1) validate() error {
	payload := envelope.payload
	sealed := envelope.plan.Plan()
	desired := envelope.plan.DesiredState()
	if payload.WorkflowID != bootstrap.WorkflowID || sealed.WorkflowID != bootstrap.WorkflowID ||
		!operationIDPattern.MatchString(payload.OperationID) || !environmentPattern.MatchString(payload.Environment) ||
		payload.Environment != sealed.Environment || payload.Project != sealed.ProjectID || payload.Account != sealed.Principal ||
		!planIDPattern.MatchString(payload.PlanID) || payload.PlanID != sealed.PlanID ||
		payload.PlanDocumentSHA256 != envelope.plan.DocumentHash() || payload.PlanV1Hash != sealed.PlanHash ||
		payload.EnvelopeBindingSHA256 != envelope.plan.Binding().BindingSHA256 ||
		payload.ContractHash != envelope.plan.ExecutionContract().Digest() ||
		payload.ObservationRevision != envelope.plan.Binding().ObservationRevision {
		return invalidEnvelope("plan binding")
	}
	if payload.AuditBucket != desired.AuditBucket || payload.ControlBucket != desired.ControlBucket ||
		payload.AuditBucketLocation != desired.Region || payload.AuditBucket == payload.ControlBucket ||
		payload.AuditBucket == "" || payload.ControlBucket == "" || payload.AuditBucketLocation == "" {
		return invalidEnvelope("bucket identities")
	}
	if !equalCanonicalValue(payload.ExpectedObservations, expectedObservations(envelope.plan)) {
		return invalidEnvelope("expected observations")
	}
	if err := validateApprovalProof(payload.Approval, envelope.plan); err != nil {
		return err
	}
	if !validUTC(payload.SealedAt) || payload.SealedAt.Before(sealed.CreatedAt) || !payload.SealedAt.Before(sealed.ExpiresAt) ||
		payload.SealedAt.Before(payload.Approval.ApprovedAt) || !payload.SealedAt.Before(payload.Approval.ValidUntil) {
		return invalidEnvelope("seal time")
	}
	entry := envelope.entry
	if entry.OperationID != payload.OperationID || entry.PlanID != payload.PlanID || entry.ContractHash != payload.ContractHash ||
		entry.Sequence != 1 || entry.Kind != domain.JournalEntryTransition || entry.OperationState != domain.OperationDiscover ||
		entry.RecordedAt.Before(sealed.CreatedAt) || entry.RecordedAt.After(payload.SealedAt) {
		return invalidEnvelope("first journal entry binding")
	}
	journalName, err := JournalEntryObjectName(payload.Environment, entry)
	if err != nil || journalName.String() != payload.FirstJournalObjectName {
		return invalidEnvelope("first journal object name")
	}
	return nil
}

// ParseBootstrapEnvelope accepts only the canonical encoding. Duplicate,
// unknown, null, or trailing fields, a hash mismatch, or any cross-binding
// failure rejects the document.
func ParseBootstrapEnvelope(encoded []byte) (BootstrapEnvelopeV1, error) {
	if len(encoded) == 0 || len(encoded) > MaxEnvelopeBytes || !json.Valid(encoded) {
		return BootstrapEnvelopeV1{}, invalidEnvelope("document")
	}
	if err := rejectDuplicateKeys(encoded); err != nil {
		return BootstrapEnvelopeV1{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire envelopeWireV1
	if err := decoder.Decode(&wire); err != nil {
		return BootstrapEnvelopeV1{}, invalidEnvelope("document schema")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return BootstrapEnvelopeV1{}, invalidEnvelope("trailing data")
	}
	if wire.SchemaVersion != BootstrapEnvelopeSchemaV1 || !sha256Pattern.MatchString(wire.EnvelopeSHA256) {
		return BootstrapEnvelopeV1{}, invalidEnvelope("schema or hash")
	}
	digest, err := hashJSON(wire.Envelope)
	if err != nil || digest != wire.EnvelopeSHA256 {
		return BootstrapEnvelopeV1{}, invalidEnvelope("integrity")
	}
	plan, err := bootstrap.ParseCompiledPlan(wire.Envelope.Plan)
	if err != nil {
		return BootstrapEnvelopeV1{}, invalidEnvelope("embedded plan")
	}
	entry, err := workflow.DecodeJournalEntry(wire.Envelope.FirstJournalEntry)
	if err != nil {
		return BootstrapEnvelopeV1{}, invalidEnvelope("embedded journal entry")
	}
	envelope := BootstrapEnvelopeV1{payload: wire.Envelope, hash: wire.EnvelopeSHA256, plan: plan, entry: entry}
	if err := envelope.validate(); err != nil {
		return BootstrapEnvelopeV1{}, err
	}
	canonical, err := envelope.CanonicalJSON()
	if err != nil || !bytes.Equal(canonical, encoded) {
		return BootstrapEnvelopeV1{}, invalidEnvelope("noncanonical encoding")
	}
	return envelope, nil
}

// CanonicalJSON returns the compact hash-bound encoding.
func (envelope BootstrapEnvelopeV1) CanonicalJSON() ([]byte, error) {
	if envelope.hash == "" {
		return nil, invalidEnvelope("unsealed")
	}
	if err := envelope.validate(); err != nil {
		return nil, err
	}
	digest, err := hashJSON(envelope.payload)
	if err != nil || digest != envelope.hash {
		return nil, invalidEnvelope("integrity")
	}
	return json.Marshal(envelopeWireV1{SchemaVersion: BootstrapEnvelopeSchemaV1, Envelope: envelope.payload, EnvelopeSHA256: envelope.hash})
}

// SHA256 returns the envelope hash which every retry must reproduce exactly.
func (envelope BootstrapEnvelopeV1) SHA256() string { return envelope.hash }

func (envelope BootstrapEnvelopeV1) OperationID() string { return envelope.payload.OperationID }
func (envelope BootstrapEnvelopeV1) Environment() string { return envelope.payload.Environment }
func (envelope BootstrapEnvelopeV1) Project() string     { return envelope.payload.Project }
func (envelope BootstrapEnvelopeV1) Account() string     { return envelope.payload.Account }
func (envelope BootstrapEnvelopeV1) PlanID() string      { return envelope.payload.PlanID }
func (envelope BootstrapEnvelopeV1) PlanDocumentSHA256() string {
	return envelope.payload.PlanDocumentSHA256
}
func (envelope BootstrapEnvelopeV1) PlanV1Hash() string { return envelope.payload.PlanV1Hash }
func (envelope BootstrapEnvelopeV1) EnvelopeBindingSHA256() string {
	return envelope.payload.EnvelopeBindingSHA256
}
func (envelope BootstrapEnvelopeV1) ContractHash() string      { return envelope.payload.ContractHash }
func (envelope BootstrapEnvelopeV1) Approval() ApprovalProofV1 { return envelope.payload.Approval }
func (envelope BootstrapEnvelopeV1) ObservationRevision() string {
	return envelope.payload.ObservationRevision
}
func (envelope BootstrapEnvelopeV1) AuditBucket() string { return envelope.payload.AuditBucket }
func (envelope BootstrapEnvelopeV1) AuditBucketLocation() string {
	return envelope.payload.AuditBucketLocation
}
func (envelope BootstrapEnvelopeV1) ControlBucket() string        { return envelope.payload.ControlBucket }
func (envelope BootstrapEnvelopeV1) SealedAt() time.Time          { return envelope.payload.SealedAt }
func (envelope BootstrapEnvelopeV1) Plan() bootstrap.CompiledPlan { return envelope.plan }
func (envelope BootstrapEnvelopeV1) FirstJournalEntry() domain.JournalEntry {
	return envelope.entry
}
func (envelope BootstrapEnvelopeV1) ExpectedObservations() []ExpectedObservationV1 {
	return append([]ExpectedObservationV1(nil), envelope.payload.ExpectedObservations...)
}

// FirstJournalObjectName returns the audit object name of the first entry.
func (envelope BootstrapEnvelopeV1) FirstJournalObjectName() AuditObjectName {
	return AuditObjectName{value: envelope.payload.FirstJournalObjectName}
}

// FirstJournalEntryJSON returns the exact bytes uploaded create-only.
func (envelope BootstrapEnvelopeV1) FirstJournalEntryJSON() []byte {
	return append([]byte(nil), envelope.payload.FirstJournalEntry...)
}

func rejectDuplicateKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := consumeUniqueValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return invalidEnvelope("trailing data")
	}
	return nil
}

func consumeUniqueValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil || token == nil {
		return invalidEnvelope("malformed or null JSON")
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return invalidEnvelope("object key")
			}
			if _, exists := seen[key]; exists {
				return invalidEnvelope("duplicate field")
			}
			seen[key] = struct{}{}
			if err := consumeUniqueValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
	case '[':
		for decoder.More() {
			if err := consumeUniqueValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
	default:
		return invalidEnvelope("JSON delimiter")
	}
	if err != nil {
		return invalidEnvelope("malformed JSON")
	}
	return nil
}

func hashJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func equalCanonicalValue(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func validUTC(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

func invalidEnvelope(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidEnvelope, field)
}

func invalidApproval(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidApprovalProof, field)
}
