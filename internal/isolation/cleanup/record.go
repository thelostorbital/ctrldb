// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/redact"
)

const (
	WipeRecordSchemaV1     = "ctrldb.ctrlboard.dev/test-wipe/v1"
	DeletionRecordSchemaV1 = "ctrldb.ctrlboard.dev/test-wipe-deletion/v1"
)

var ErrInvalidWipeRecord = errors.New("invalid test wipe record")

// DeletionStatus is the closed lifecycle of one recorded deletion.
type DeletionStatus string

const (
	DeletionIssued  DeletionStatus = "issued"
	DeletionDeleted DeletionStatus = "deleted"
	DeletionFailed  DeletionStatus = "failed"
)

// PlannedDeletionV1 is the durable, seal-free projection of one deletion.
type PlannedDeletionV1 struct {
	Sequence   int                         `json:"sequence"`
	Capability isolation.CleanupCapability `json:"capability"`
	Project    string                      `json:"project"`
	Location   string                      `json:"location"`
	Name       string                      `json:"name"`
	RunID      string                      `json:"runId"`
	CreatedAt  time.Time                   `json:"createdAt"`
	ExpiredAt  time.Time                   `json:"expiredAt"`
	KeepDisks  bool                        `json:"keepDisks"`
	Attempt    uint32                      `json:"attempt"`
}

// RecordedResourceV1 is one non-deleted resource the wipe accounted for.
type RecordedResourceV1 struct {
	Capability isolation.CleanupCapability `json:"capability,omitempty"`
	Project    string                      `json:"project"`
	Location   string                      `json:"location"`
	Name       string                      `json:"name"`
	Reason     string                      `json:"reason,omitempty"`
	ExpiresAt  *time.Time                  `json:"expiresAt,omitempty"`
	BlockedBy  []string                    `json:"blockedBy,omitempty"`
}

// WipeRecordV1 is the canonical `test/wipe/<date>.json` document written
// before any deletion is issued. It contains no credentials, provider output,
// or free text.
type WipeRecordV1 struct {
	SchemaVersion          string               `json:"schemaVersion"`
	Mode                   string               `json:"mode"`
	ProjectID              string               `json:"projectId"`
	RunNumber              uint64               `json:"runNumber"`
	HarnessIntegritySHA256 string               `json:"harnessIntegritySha256"`
	BootstrapPhase         string               `json:"bootstrapPhase"`
	TestUsability          string               `json:"testUsability"`
	Disposition            Disposition          `json:"disposition"`
	InventoryRevision      string               `json:"inventoryRevision"`
	PlannedAt              time.Time            `json:"plannedAt"`
	MaxLifetimeSeconds     int64                `json:"maxLifetimeSeconds"`
	IgnoredForeign         int                  `json:"ignoredForeign"`
	Deletions              []PlannedDeletionV1  `json:"deletions"`
	Retained               []RecordedResourceV1 `json:"retained"`
	Deferred               []RecordedResourceV1 `json:"deferred"`
	Protected              []RecordedResourceV1 `json:"protected"`
	IntegritySHA256        string               `json:"integritySha256"`
}

// DeletionRecordV1 is written immediately before a deletion is issued and
// again with its outcome. The pre-issue record makes a crash between record
// and provider call visible to the next run.
type DeletionRecordV1 struct {
	SchemaVersion   string            `json:"schemaVersion"`
	PlanIntegrity   string            `json:"planIntegritySha256"`
	Deletion        PlannedDeletionV1 `json:"deletion"`
	Status          DeletionStatus    `json:"status"`
	IssuedAt        time.Time         `json:"issuedAt"`
	CompletedAt     *time.Time        `json:"completedAt,omitempty"`
	Failure         redact.Text       `json:"failure"`
	IntegritySHA256 string            `json:"integritySha256"`
}

// Record returns the canonical durable record for a sealed plan.
func (plan WipePlan) Record() (WipeRecordV1, error) {
	if !plan.Sealed() {
		return WipeRecordV1{}, inputError("plan", "is not a sealed wipe plan")
	}
	record := planRecord(plan)
	fingerprint, err := canonicalFingerprint(record)
	if err != nil {
		return WipeRecordV1{}, err
	}
	record.IntegritySHA256 = fingerprint
	return record, nil
}

// CanonicalJSON returns the deterministic encoding of a complete record.
func (record WipeRecordV1) CanonicalJSON() ([]byte, error) {
	if record.SchemaVersion != WipeRecordSchemaV1 || !sha256Pattern.MatchString(record.IntegritySHA256) {
		return nil, ErrInvalidWipeRecord
	}
	check := record
	check.IntegritySHA256 = ""
	fingerprint, err := canonicalFingerprint(check)
	if err != nil || fingerprint != record.IntegritySHA256 {
		return nil, ErrInvalidWipeRecord
	}
	return json.Marshal(record)
}

// ParseWipeRecordV1 strictly decodes one canonical record and verifies its
// integrity. Unknown fields, trailing data, and tampering fail closed.
func ParseWipeRecordV1(input []byte) (WipeRecordV1, error) {
	var record WipeRecordV1
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return WipeRecordV1{}, ErrInvalidWipeRecord
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return WipeRecordV1{}, ErrInvalidWipeRecord
	}
	canonical, err := record.CanonicalJSON()
	if err != nil || !bytes.Equal(canonical, input) {
		return WipeRecordV1{}, ErrInvalidWipeRecord
	}
	return record, nil
}

func planRecord(plan WipePlan) WipeRecordV1 {
	selection := plan.Selection
	record := WipeRecordV1{
		SchemaVersion: WipeRecordSchemaV1, Mode: plan.Mode, ProjectID: plan.ProjectID, RunNumber: plan.RunNumber,
		HarnessIntegritySHA256: plan.HarnessIntegritySHA256, BootstrapPhase: string(plan.BootstrapPhase),
		TestUsability: string(plan.TestUsability), Disposition: plan.Disposition,
		InventoryRevision: selection.InventoryRevision, PlannedAt: selection.Now,
		MaxLifetimeSeconds: int64(selection.MaxLifetime / time.Second), IgnoredForeign: selection.Ignored,
		Deletions: make([]PlannedDeletionV1, 0, len(selection.Deletions)),
		Retained:  make([]RecordedResourceV1, 0, len(selection.Retained)),
		Deferred:  make([]RecordedResourceV1, 0, len(selection.Deferred)),
		Protected: make([]RecordedResourceV1, 0, len(selection.Protected)),
	}
	for _, deletion := range selection.Deletions {
		record.Deletions = append(record.Deletions, plannedDeletion(deletion))
	}
	for _, retained := range selection.Retained {
		expires := retained.ExpiresAt
		record.Retained = append(record.Retained, RecordedResourceV1{
			Capability: retained.Capability, Project: retained.Identity.Project, Location: retained.Identity.Location,
			Name: retained.Identity.Name, Reason: "not expired", ExpiresAt: &expires,
		})
	}
	for _, deferred := range selection.Deferred {
		record.Deferred = append(record.Deferred, RecordedResourceV1{
			Capability: isolation.CleanupComputeDisks, Project: deferred.Identity.Project, Location: deferred.Identity.Location,
			Name: deferred.Identity.Name, Reason: deferred.Reason, BlockedBy: append([]string(nil), deferred.BlockedBy...),
		})
	}
	for _, protected := range selection.Protected {
		record.Protected = append(record.Protected, RecordedResourceV1{
			Project: protected.Identity.Project, Location: protected.Identity.Location,
			Name: protected.Identity.Name, Reason: "permanent harness singleton",
		})
	}
	return record
}

func plannedDeletion(deletion Deletion) PlannedDeletionV1 {
	return PlannedDeletionV1{
		Sequence: deletion.Sequence, Capability: deletion.Capability, Project: deletion.Identity.Project,
		Location: deletion.Identity.Location, Name: deletion.Identity.Name, RunID: deletion.RunID,
		CreatedAt: deletion.CreatedAt, ExpiredAt: deletion.ExpiredAt, KeepDisks: deletion.KeepDisks, Attempt: deletion.Attempt,
	}
}

func sealDeletionRecord(record DeletionRecordV1) (DeletionRecordV1, error) {
	record.SchemaVersion = DeletionRecordSchemaV1
	record.IntegritySHA256 = ""
	fingerprint, err := canonicalFingerprint(record)
	if err != nil {
		return DeletionRecordV1{}, err
	}
	record.IntegritySHA256 = fingerprint
	return record, nil
}

func canonicalFingerprint(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", inputError("record", "could not be encoded canonically")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
