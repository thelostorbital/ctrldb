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
	"path/filepath"
	"strings"
	"time"
)

const (
	// HandoffRecordSchemaV1 identifies one local D-158 progress record.
	HandoffRecordSchemaV1 = "ctrldb.ctrlboard.dev/bootstrap-handoff-record/v1"
	// AuditRetentionSeconds is the D-111 Bucket Lock retention (365 days).
	AuditRetentionSeconds int64 = 365 * 24 * 60 * 60
	// AuditArchiveAfterDays is the D-088 class transition with no delete rule.
	AuditArchiveAfterDays int64 = 365
	// AuditStorageClass is the mandated default class.
	AuditStorageClass = "STANDARD"
	// PublicAccessPreventionEnforced is the only admissible PAP value.
	PublicAccessPreventionEnforced = "enforced"

	maxHandoffRecordBytes = 64 << 10
)

var (
	// ErrBucketNameConflict is the explicit create-time precondition failure:
	// the global bucket namespace already holds the name. It is never a claim
	// about absence.
	ErrBucketNameConflict = errors.New("bucket-conflict-guarded precondition failed: audit bucket name is taken in the global namespace")
	// ErrPartialBootstrapBlocked is returned when an unrecorded or conflicting
	// partial audit bucket must be recovered explicitly.
	ErrPartialBootstrapBlocked = errors.New("partial audit bootstrap blocked for explicit recovery")
	// ErrHandoffOutOfOrder is returned when a caller asks for K1b before K1a
	// is durably verified.
	ErrHandoffOutOfOrder = errors.New("audit handoff phase out of order")
	// ErrInvalidHandoffRecord is returned for a malformed or inconsistent local
	// progress record chain.
	ErrInvalidHandoffRecord = errors.New("invalid bootstrap handoff record")
	// ErrInvalidHandoffPort is returned when a port returns an impossible
	// observation.
	ErrInvalidHandoffPort = errors.New("audit bucket port returned an inconsistent observation")
)

// HandoffPhase is the closed, ordered D-158 boundary set.
type HandoffPhase string

const (
	PhaseEnvelopeSealed       HandoffPhase = "envelope-sealed"
	PhaseAuditBucketClaimed   HandoffPhase = "audit-bucket-create-claimed"
	PhaseAuditBucketCreated   HandoffPhase = "audit-bucket-created"
	PhaseEnvelopeUploaded     HandoffPhase = "envelope-uploaded"
	PhaseJournalUploaded      HandoffPhase = "journal-uploaded"
	PhaseLifecycleConfigured  HandoffPhase = "lifecycle-configured"
	PhaseHandoffVerified      HandoffPhase = "handoff-verified"
	PhaseRetentionConfigured  HandoffPhase = "retention-configured"
	PhaseRetentionLockClaimed HandoffPhase = "retention-lock-claimed"
	PhaseRetentionLocked      HandoffPhase = "retention-locked"
	phaseOrderUnknown                      = -1
)

var handoffPhaseOrder = [...]HandoffPhase{
	PhaseEnvelopeSealed, PhaseAuditBucketClaimed, PhaseAuditBucketCreated, PhaseEnvelopeUploaded,
	PhaseJournalUploaded, PhaseLifecycleConfigured, PhaseHandoffVerified, PhaseRetentionConfigured,
	PhaseRetentionLockClaimed, PhaseRetentionLocked,
}

func (phase HandoffPhase) order() int {
	for index, candidate := range handoffPhaseOrder {
		if candidate == phase {
			return index
		}
	}
	return phaseOrderUnknown
}

// BucketIdentity is the exact desired bucket identity from the approved plan.
type BucketIdentity struct {
	Name     string `json:"name"`
	Project  string `json:"project"`
	Location string `json:"location"`
}

// BucketState is a complete typed bucket observation. A port must fill every
// field from machine-readable provider output; it never infers a default.
type BucketState struct {
	Identity                 BucketIdentity
	UniformBucketLevelAccess bool
	PublicAccessPrevention   string
	StorageClass             string
	Versioning               bool
	RetentionSeconds         int64
	RetentionLocked          bool
	LifecycleArchiveAfterDay int64
	LifecycleDeleteRule      bool
	Metageneration           int64
	TimeCreated              time.Time
}

// AuditBucketPort is the narrow provider surface the handoff needs. It has no
// delete, list, or IAM method. A conforming implementation performs exactly
// the named mutation and nothing else. LockRetention must re-observe the
// bucket immediately before the irreversible call and refuse to lock when the
// metageneration differs from expectedMetageneration (gcloud offers no
// server-side precondition for this update).
type AuditBucketPort interface {
	DescribeBucket(ctx context.Context, name string) (BucketState, bool, error)
	CreateAuditBucket(ctx context.Context, identity BucketIdentity) error
	ConfigureArchiveLifecycle(ctx context.Context, identity BucketIdentity) error
	UploadCreateOnly(ctx context.Context, identity BucketIdentity, object AuditObjectName, content []byte) (ObjectDescriptor, error)
	DescribeObject(ctx context.Context, identity BucketIdentity, object AuditObjectName) (ObjectDescriptor, bool, error)
	ConfigureRetention(ctx context.Context, identity BucketIdentity, seconds int64) error
	ReadObject(ctx context.Context, identity BucketIdentity, object AuditObjectName) ([]byte, ObjectDescriptor, bool, error)
	LockRetention(ctx context.Context, identity BucketIdentity, expectedMetageneration int64) error
}

// HandoffRecordV1 is one append-only local progress record.
type HandoffRecordV1 struct {
	Schema         string            `json:"schema"`
	OperationID    string            `json:"operationId"`
	EnvelopeSHA256 string            `json:"envelopeSha256"`
	Sequence       uint64            `json:"sequence"`
	Phase          HandoffPhase      `json:"phase"`
	RecordedAt     time.Time         `json:"recordedAt"`
	Bucket         BucketIdentity    `json:"bucket"`
	Envelope       *ObjectDescriptor `json:"envelope,omitempty"`
	Journal        *ObjectDescriptor `json:"journal,omitempty"`
	RecordSHA256   string            `json:"recordSha256"`
}

// HandoffStatus is the resumable view of an operation's D-158 progress.
type HandoffStatus struct {
	Phase           HandoffPhase
	EnvelopeSHA256  string
	Envelope        ObjectDescriptor
	Journal         ObjectDescriptor
	RetentionLocked bool
}

// AuditHandoff drives K1a/K1b deterministically from the local envelope, the
// local record chain, and fresh bucket observations.
type AuditHandoff struct {
	directory StateDirectory
	port      AuditBucketPort
	clock     func() time.Time
}

// NewAuditHandoff binds one validated state directory and one port.
func NewAuditHandoff(directory StateDirectory, port AuditBucketPort, clock func() time.Time) (*AuditHandoff, error) {
	if directory.path == "" || port == nil || clock == nil {
		return nil, fmt.Errorf("%w: handoff construction", ErrInvalidStoreRequest)
	}
	return &AuditHandoff{directory: directory, port: port, clock: clock}, nil
}

// Bootstrap performs or resumes K1a: envelope, audit bucket, create-only
// uploads, lifecycle, and verification. It never locks retention.
func (handoff *AuditHandoff) Bootstrap(ctx context.Context, envelope BootstrapEnvelopeV1) (HandoffStatus, error) {
	session, err := handoff.open(ctx, envelope)
	if err != nil {
		return HandoffStatus{}, err
	}
	if session.reached(PhaseHandoffVerified) {
		if _, err := session.verifyObservation(ctx); err != nil {
			return HandoffStatus{}, err
		}
		return session.status(), nil
	}
	if err := session.ensureBucket(ctx); err != nil {
		return HandoffStatus{}, err
	}
	if err := session.ensureUploads(ctx); err != nil {
		return HandoffStatus{}, err
	}
	if err := session.ensureLifecycle(ctx); err != nil {
		return HandoffStatus{}, err
	}
	if err := session.verify(ctx); err != nil {
		return HandoffStatus{}, err
	}
	return session.status(), nil
}

// LockRetention performs or resumes K1b. It re-verifies the envelope and
// journal hashes and generations before the irreversible lock and records the
// PONR only when the lock mutation is observed.
func (handoff *AuditHandoff) LockRetention(ctx context.Context, envelope BootstrapEnvelopeV1) (HandoffStatus, error) {
	session, err := handoff.open(ctx, envelope)
	if err != nil {
		return HandoffStatus{}, err
	}
	if !session.reached(PhaseHandoffVerified) {
		return HandoffStatus{}, fmt.Errorf("%w: handoff is not verified", ErrHandoffOutOfOrder)
	}
	state, err := session.verifyObservation(ctx)
	if err != nil {
		return HandoffStatus{}, err
	}
	if state.RetentionLocked {
		if state.RetentionSeconds != AuditRetentionSeconds {
			return HandoffStatus{}, fmt.Errorf("%w: foreign retention period on the locked audit bucket", ErrPartialBootstrapBlocked)
		}
		if !session.reached(PhaseRetentionLockClaimed) {
			return HandoffStatus{}, fmt.Errorf("%w: retention is locked without a local lock claim", ErrPartialBootstrapBlocked)
		}
		if !session.reached(PhaseRetentionLocked) {
			if err := session.append(PhaseRetentionLocked, nil, nil); err != nil {
				return HandoffStatus{}, err
			}
		}
		return session.status(), nil
	}
	if state.RetentionSeconds != AuditRetentionSeconds {
		if state.RetentionSeconds != 0 {
			return HandoffStatus{}, fmt.Errorf("%w: foreign retention policy", ErrPartialBootstrapBlocked)
		}
		if err := session.authorizeMutation(); err != nil {
			return HandoffStatus{}, err
		}
		if err := handoff.port.ConfigureRetention(ctx, session.identity, AuditRetentionSeconds); err != nil {
			return HandoffStatus{}, err
		}
		state, err = session.verifyObservation(ctx)
		if err != nil {
			return HandoffStatus{}, err
		}
		if state.RetentionSeconds != AuditRetentionSeconds || state.RetentionLocked {
			return HandoffStatus{}, fmt.Errorf("%w: retention did not converge", ErrInvalidHandoffPort)
		}
	}
	if !session.reached(PhaseRetentionConfigured) {
		if err := session.append(PhaseRetentionConfigured, nil, nil); err != nil {
			return HandoffStatus{}, err
		}
	}
	if !session.reached(PhaseRetentionLockClaimed) {
		if err := session.append(PhaseRetentionLockClaimed, nil, nil); err != nil {
			return HandoffStatus{}, err
		}
	}
	if err := session.authorizeMutation(); err != nil {
		return HandoffStatus{}, err
	}
	if err := handoff.port.LockRetention(ctx, session.identity, state.Metageneration); err != nil {
		return HandoffStatus{}, err
	}
	state, err = session.verifyObservation(ctx)
	if err != nil {
		return HandoffStatus{}, err
	}
	if !state.RetentionLocked || state.RetentionSeconds != AuditRetentionSeconds {
		return HandoffStatus{}, fmt.Errorf("%w: lock was not observed", ErrInvalidHandoffPort)
	}
	if err := session.append(PhaseRetentionLocked, nil, nil); err != nil {
		return HandoffStatus{}, err
	}
	return session.status(), nil
}

// Status reads the local record chain without touching the provider.
func (handoff *AuditHandoff) Status(envelope BootstrapEnvelopeV1) (HandoffStatus, error) {
	session, err := handoff.load(envelope)
	if err != nil {
		return HandoffStatus{}, err
	}
	return session.status(), nil
}

type handoffSession struct {
	handoff      *AuditHandoff
	envelope     BootstrapEnvelopeV1
	identity     BucketIdentity
	directory    string
	records      []HandoffRecordV1
	envelopeJSON []byte
	envelopeName AuditObjectName
	journalJSON  []byte
	journalName  AuditObjectName
}

func (handoff *AuditHandoff) open(ctx context.Context, envelope BootstrapEnvelopeV1) (*handoffSession, error) {
	if err := storeContext(ctx); err != nil {
		return nil, err
	}
	if err := envelope.validAt(handoff.clock().UTC()); err != nil {
		return nil, err
	}
	stored, err := EnsureBootstrapEnvelope(handoff.directory, envelope)
	if err != nil {
		return nil, err
	}
	session, err := handoff.load(stored)
	if err != nil {
		return nil, err
	}
	if !session.reached(PhaseEnvelopeSealed) {
		if err := session.append(PhaseEnvelopeSealed, nil, nil); err != nil {
			return nil, err
		}
	}
	return session, nil
}

func (handoff *AuditHandoff) load(envelope BootstrapEnvelopeV1) (*handoffSession, error) {
	envelopeJSON, err := envelope.CanonicalJSON()
	if err != nil {
		return nil, err
	}
	envelopeName, err := BootstrapEnvelopeObjectName(envelope.Environment(), envelope.OperationID())
	if err != nil {
		return nil, err
	}
	directory, err := handoff.directory.handoffPath(envelope.OperationID())
	if err != nil {
		return nil, err
	}
	session := &handoffSession{
		handoff: handoff, envelope: envelope, directory: directory,
		identity:     BucketIdentity{Name: envelope.AuditBucket(), Project: envelope.Project(), Location: envelope.AuditBucketLocation()},
		envelopeJSON: envelopeJSON, envelopeName: envelopeName,
		journalJSON: envelope.FirstJournalEntryJSON(), journalName: envelope.FirstJournalObjectName(),
	}
	records, err := readHandoffRecords(directory, envelope)
	if err != nil {
		return nil, err
	}
	session.records = records
	return session, nil
}

func (session *handoffSession) reached(phase HandoffPhase) bool {
	for _, record := range session.records {
		if record.Phase == phase {
			return true
		}
	}
	return false
}

func (session *handoffSession) latest() HandoffPhase {
	if len(session.records) == 0 {
		return ""
	}
	return session.records[len(session.records)-1].Phase
}

func (session *handoffSession) recorded(phase HandoffPhase) (HandoffRecordV1, bool) {
	for _, record := range session.records {
		if record.Phase == phase {
			return record, true
		}
	}
	return HandoffRecordV1{}, false
}

func (session *handoffSession) status() HandoffStatus {
	status := HandoffStatus{Phase: session.latest(), EnvelopeSHA256: session.envelope.SHA256(), RetentionLocked: session.reached(PhaseRetentionLocked)}
	if record, ok := session.recorded(PhaseEnvelopeUploaded); ok && record.Envelope != nil {
		status.Envelope = *record.Envelope
	}
	if record, ok := session.recorded(PhaseJournalUploaded); ok && record.Journal != nil {
		status.Journal = *record.Journal
	}
	return status
}

// authorizeMutation samples the clock at the last in-process boundary before
// a provider write. Entry-time validation is insufficient because a preceding
// observation, local record, or provider call can consume the approval window.
func (session *handoffSession) authorizeMutation() error {
	now := session.handoff.clock().UTC()
	if len(session.records) > 0 && now.Before(session.records[len(session.records)-1].RecordedAt) {
		return fmt.Errorf("%w: clock moved backwards before provider mutation", ErrInvalidHandoffRecord)
	}
	return session.envelope.validAt(now)
}

func (session *handoffSession) append(phase HandoffPhase, envelopeObject, journalObject *ObjectDescriptor) error {
	if phase.order() <= session.latest().order() && session.latest() != "" {
		return fmt.Errorf("%w: phase %s does not advance %s", ErrInvalidHandoffRecord, phase, session.latest())
	}
	now := session.handoff.clock().UTC()
	if !validUTC(now) || (len(session.records) > 0 && now.Before(session.records[len(session.records)-1].RecordedAt)) {
		return fmt.Errorf("%w: clock moved backwards; refusing to persist a non-monotonic record", ErrInvalidHandoffRecord)
	}
	record := HandoffRecordV1{
		Schema: HandoffRecordSchemaV1, OperationID: session.envelope.OperationID(), EnvelopeSHA256: session.envelope.SHA256(),
		Sequence: uint64(len(session.records) + 1), Phase: phase, RecordedAt: now, Bucket: session.identity,
		Envelope: cloneDescriptor(envelopeObject), Journal: cloneDescriptor(journalObject),
	}
	digest, err := hashJSON(record)
	if err != nil {
		return fmt.Errorf("%w: encoding", ErrInvalidHandoffRecord)
	}
	record.RecordSHA256 = digest
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("%w: encoding", ErrInvalidHandoffRecord)
	}
	if err := ensurePrivateDirectory(session.directory); err != nil {
		return err
	}
	fileName := fmt.Sprintf("%020d-%s.json", record.Sequence, phase)
	if err := writePrivateFileExclusive(filepath.Join(session.directory, fileName), encoded); err != nil {
		return err
	}
	session.records = append(session.records, record)
	return nil
}

func (session *handoffSession) ensureBucket(ctx context.Context) error {
	port := session.handoff.port
	state, exists, err := port.DescribeBucket(ctx, session.identity.Name)
	if err != nil {
		return err
	}
	if exists {
		return session.adoptExistingBucket(ctx, state)
	}
	if session.reached(PhaseAuditBucketCreated) {
		return fmt.Errorf("%w: recorded audit bucket is absent", ErrPartialBootstrapBlocked)
	}
	if !session.reached(PhaseAuditBucketClaimed) {
		if err := session.append(PhaseAuditBucketClaimed, nil, nil); err != nil {
			return err
		}
	}
	if err := session.authorizeMutation(); err != nil {
		return err
	}
	if err := port.CreateAuditBucket(ctx, session.identity); err != nil {
		return err
	}
	state, exists, err = port.DescribeBucket(ctx, session.identity.Name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: created bucket is not observable", ErrInvalidHandoffPort)
	}
	if err := session.checkPreLockState(state); err != nil {
		return err
	}
	return session.append(PhaseAuditBucketCreated, nil, nil)
}

func (session *handoffSession) adoptExistingBucket(ctx context.Context, state BucketState) error {
	if err := session.checkPreLockState(state); err != nil {
		return err
	}
	if session.reached(PhaseAuditBucketCreated) {
		return nil
	}
	// Only an operation-bound remote marker proves ownership: the bucket must
	// already hold exactly this envelope. A local create claim alone, or a
	// creation timestamp, never adopts a bucket (D-158: an unrecorded partial
	// bucket blocks for explicit recovery).
	envelopeMatches, err := session.remoteEnvelopeMatches(ctx)
	if err != nil {
		return err
	}
	if !envelopeMatches {
		return fmt.Errorf("%w: existing audit bucket has no matching envelope record", ErrPartialBootstrapBlocked)
	}
	return session.append(PhaseAuditBucketCreated, nil, nil)
}

// remoteEnvelopeMatches reports whether the bucket already holds exactly this
// envelope, compared byte for byte. A present object with different content
// is a conflict.
func (session *handoffSession) remoteEnvelopeMatches(ctx context.Context) (bool, error) {
	return session.remoteObjectMatches(ctx, session.envelopeName, session.envelopeJSON)
}

func (session *handoffSession) remoteObjectMatches(ctx context.Context, name AuditObjectName, content []byte) (bool, error) {
	remote, descriptor, exists, err := session.handoff.port.ReadObject(ctx, session.identity, name)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if !descriptor.MatchesContent(content) || !bytes.Equal(remote, content) {
		return false, fmt.Errorf("%w: audit bucket holds different content at %s", ErrPartialBootstrapBlocked, name)
	}
	return true, nil
}

func (session *handoffSession) ensureUploads(ctx context.Context) error {
	if !session.reached(PhaseEnvelopeUploaded) {
		descriptor, err := session.uploadCreateOnly(ctx, session.envelopeName, session.envelopeJSON)
		if err != nil {
			return err
		}
		if err := session.append(PhaseEnvelopeUploaded, &descriptor, nil); err != nil {
			return err
		}
	}
	if !session.reached(PhaseJournalUploaded) {
		descriptor, err := session.uploadCreateOnly(ctx, session.journalName, session.journalJSON)
		if err != nil {
			return err
		}
		if err := session.append(PhaseJournalUploaded, nil, &descriptor); err != nil {
			return err
		}
	}
	return nil
}

func (session *handoffSession) uploadCreateOnly(ctx context.Context, name AuditObjectName, content []byte) (ObjectDescriptor, error) {
	port := session.handoff.port
	if err := session.authorizeMutation(); err != nil {
		return ObjectDescriptor{}, err
	}
	descriptor, err := port.UploadCreateOnly(ctx, session.identity, name, content)
	if err == nil {
		if !descriptor.MatchesContent(content) {
			return ObjectDescriptor{}, fmt.Errorf("%w: upload descriptor mismatch", ErrInvalidHandoffPort)
		}
		return descriptor, nil
	}
	if !errors.Is(err, ErrPreconditionFailed) {
		return ObjectDescriptor{}, err
	}
	matches, matchErr := session.remoteObjectMatches(ctx, name, content)
	if matchErr != nil {
		return ObjectDescriptor{}, matchErr
	}
	if !matches {
		return ObjectDescriptor{}, fmt.Errorf("%w: %s create precondition failed but the object is not observable", ErrPartialBootstrapBlocked, name)
	}
	existing, exists, describeErr := port.DescribeObject(ctx, session.identity, name)
	if describeErr != nil {
		return ObjectDescriptor{}, describeErr
	}
	if !exists || !existing.MatchesContent(content) {
		return ObjectDescriptor{}, fmt.Errorf("%w: %s holds conflicting content", ErrPartialBootstrapBlocked, name)
	}
	return existing, nil
}

func (session *handoffSession) ensureLifecycle(ctx context.Context) error {
	if session.reached(PhaseLifecycleConfigured) {
		return nil
	}
	state, exists, err := session.handoff.port.DescribeBucket(ctx, session.identity.Name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: audit bucket vanished", ErrPartialBootstrapBlocked)
	}
	if err := session.checkPreLockState(state); err != nil {
		return err
	}
	if state.LifecycleArchiveAfterDay != AuditArchiveAfterDays {
		if err := session.authorizeMutation(); err != nil {
			return err
		}
		if err := session.handoff.port.ConfigureArchiveLifecycle(ctx, session.identity); err != nil {
			return err
		}
	}
	return session.append(PhaseLifecycleConfigured, nil, nil)
}

func (session *handoffSession) verify(ctx context.Context) error {
	if _, err := session.verifyObservation(ctx); err != nil {
		return err
	}
	return session.append(PhaseHandoffVerified, nil, nil)
}

// verifyObservation re-observes the bucket and both objects and requires exact
// hash and generation equality with the recorded uploads.
func (session *handoffSession) verifyObservation(ctx context.Context) (BucketState, error) {
	port := session.handoff.port
	state, exists, err := port.DescribeBucket(ctx, session.identity.Name)
	if err != nil {
		return BucketState{}, err
	}
	if !exists {
		return BucketState{}, fmt.Errorf("%w: audit bucket vanished", ErrPartialBootstrapBlocked)
	}
	if err := session.checkCommonState(state); err != nil {
		return BucketState{}, err
	}
	if state.LifecycleArchiveAfterDay != AuditArchiveAfterDays {
		return BucketState{}, fmt.Errorf("%w: archive lifecycle is not configured", ErrPartialBootstrapBlocked)
	}
	envelopeRecord, ok := session.recorded(PhaseEnvelopeUploaded)
	if !ok || envelopeRecord.Envelope == nil {
		return BucketState{}, fmt.Errorf("%w: envelope upload is unrecorded", ErrHandoffOutOfOrder)
	}
	journalRecord, ok := session.recorded(PhaseJournalUploaded)
	if !ok || journalRecord.Journal == nil {
		return BucketState{}, fmt.Errorf("%w: journal upload is unrecorded", ErrHandoffOutOfOrder)
	}
	if err := session.verifyObject(ctx, session.envelopeName, session.envelopeJSON, *envelopeRecord.Envelope); err != nil {
		return BucketState{}, err
	}
	if err := session.verifyObject(ctx, session.journalName, session.journalJSON, *journalRecord.Journal); err != nil {
		return BucketState{}, err
	}
	return state, nil
}

func (session *handoffSession) verifyObject(ctx context.Context, name AuditObjectName, content []byte, recorded ObjectDescriptor) error {
	observed, exists, err := session.handoff.port.DescribeObject(ctx, session.identity, name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s is absent", ErrPartialBootstrapBlocked, name)
	}
	if observed != recorded || !observed.MatchesContent(content) {
		return fmt.Errorf("%w: %s hash or generation differs from the recorded upload", ErrPartialBootstrapBlocked, name)
	}
	remote, remoteDescriptor, remoteExists, err := session.handoff.port.ReadObject(ctx, session.identity, name)
	if err != nil {
		return err
	}
	if !remoteExists || remoteDescriptor != recorded || !bytes.Equal(remote, content) {
		return fmt.Errorf("%w: %s bytes differ from the recorded upload", ErrPartialBootstrapBlocked, name)
	}
	return nil
}

func (session *handoffSession) checkPreLockState(state BucketState) error {
	if err := session.checkCommonState(state); err != nil {
		return err
	}
	if state.RetentionLocked {
		return fmt.Errorf("%w: retention is already locked before the handoff was verified", ErrPartialBootstrapBlocked)
	}
	if state.RetentionSeconds != 0 && state.RetentionSeconds != AuditRetentionSeconds {
		return fmt.Errorf("%w: foreign retention policy", ErrPartialBootstrapBlocked)
	}
	return nil
}

func (session *handoffSession) checkCommonState(state BucketState) error {
	if state.Identity != session.identity {
		return fmt.Errorf("%w: bucket identity differs from the approved audit bucket", ErrPartialBootstrapBlocked)
	}
	if !state.UniformBucketLevelAccess || state.PublicAccessPrevention != PublicAccessPreventionEnforced ||
		state.StorageClass != AuditStorageClass || !state.Versioning || state.LifecycleDeleteRule ||
		(state.LifecycleArchiveAfterDay != 0 && state.LifecycleArchiveAfterDay != AuditArchiveAfterDays) {
		return fmt.Errorf("%w: bucket state is not the exact compliant audit configuration", ErrPartialBootstrapBlocked)
	}
	return nil
}

func readHandoffRecords(directory string, envelope BootstrapEnvelopeV1) ([]HandoffRecordV1, error) {
	names, err := listStateFiles(directory)
	if err != nil {
		return nil, err
	}
	records := make([]HandoffRecordV1, 0, len(names))
	previous := phaseOrderUnknown
	for index, name := range names {
		encoded, err := readPrivateFile(filepath.Join(directory, name), maxHandoffRecordBytes)
		if err != nil {
			return nil, err
		}
		record, err := parseHandoffRecord(encoded)
		if err != nil {
			return nil, err
		}
		if record.Sequence != uint64(index+1) || record.OperationID != envelope.OperationID() ||
			record.EnvelopeSHA256 != envelope.SHA256() || record.Phase.order() <= previous ||
			name != fmt.Sprintf("%020d-%s.json", record.Sequence, record.Phase) ||
			record.Bucket != (BucketIdentity{Name: envelope.AuditBucket(), Project: envelope.Project(), Location: envelope.AuditBucketLocation()}) {
			return nil, fmt.Errorf("%w: chain is not contiguous, ordered, and bound to the envelope", ErrInvalidHandoffRecord)
		}
		if index > 0 && record.RecordedAt.Before(records[index-1].RecordedAt) {
			return nil, fmt.Errorf("%w: recordedAt moved backwards", ErrInvalidHandoffRecord)
		}
		previous = record.Phase.order()
		records = append(records, record)
	}
	return records, nil
}

func parseHandoffRecord(encoded []byte) (HandoffRecordV1, error) {
	if err := rejectDuplicateKeys(encoded); err != nil {
		return HandoffRecordV1{}, fmt.Errorf("%w: %v", ErrInvalidHandoffRecord, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record HandoffRecordV1
	if err := decoder.Decode(&record); err != nil {
		return HandoffRecordV1{}, fmt.Errorf("%w: schema", ErrInvalidHandoffRecord)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return HandoffRecordV1{}, fmt.Errorf("%w: trailing data", ErrInvalidHandoffRecord)
	}
	if record.Schema != HandoffRecordSchemaV1 || record.Phase.order() == phaseOrderUnknown || !validUTC(record.RecordedAt) ||
		!sha256Pattern.MatchString(record.RecordSHA256) || !sha256Pattern.MatchString(record.EnvelopeSHA256) ||
		!operationIDPattern.MatchString(record.OperationID) || record.Sequence == 0 ||
		(record.Phase == PhaseEnvelopeUploaded) != (record.Envelope != nil) ||
		(record.Phase == PhaseJournalUploaded) != (record.Journal != nil) ||
		(record.Envelope != nil && record.Envelope.Generation == 0) || (record.Journal != nil && record.Journal.Generation == 0) {
		return HandoffRecordV1{}, fmt.Errorf("%w: fields", ErrInvalidHandoffRecord)
	}
	copy := record
	copy.RecordSHA256 = ""
	digest, err := hashJSON(copy)
	if err != nil || digest != record.RecordSHA256 {
		return HandoffRecordV1{}, fmt.Errorf("%w: integrity", ErrInvalidHandoffRecord)
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return HandoffRecordV1{}, fmt.Errorf("%w: noncanonical", ErrInvalidHandoffRecord)
	}
	return record, nil
}

func cloneDescriptor(value *ObjectDescriptor) *ObjectDescriptor {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

// String renders a phase for diagnostics without provider values.
func (phase HandoffPhase) String() string { return strings.TrimSpace(string(phase)) }
