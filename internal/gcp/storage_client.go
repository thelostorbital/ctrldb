// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/control"
	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/redact"
	"github.com/thelostorbital/ctrldb/internal/runner"
)

const (
	storageStepTimeout  = 2 * time.Minute
	storageStdoutLimit  = 8 << 20
	storageStderrLimit  = 64 << 10
	storageContentType  = "application/json"
	storageWorkFileMode = os.FileMode(0o600)
	// storageClockSkew bounds how far the gateway's Now may drift from the
	// trusted clock before a session is treated as retained/stale.
	storageClockSkew = 2 * time.Minute

	// Exact desired bucket settings (ARCHITECTURE "Control-plane storage").
	controlSoftDeleteSeconds int64 = 30 * 24 * 60 * 60
	auditLifecycleDocument         = `{"rule":[{"action":{"type":"SetStorageClass","storageClass":"ARCHIVE"},"condition":{"age":365}}]}`
)

var (
	// ErrStorageRejected is the sentinel for every storage adapter refusal.
	ErrStorageRejected = errors.New("gcp storage request rejected")

	storageSHA256Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	storageOperationIDPattern = regexp.MustCompile(`^op-[0-9a-f]{16}$`)
	storageBucketNamePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$`)
	storageObjectNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$`)
)

// StorageFailureKind classifies an adapter failure without provider text.
type StorageFailureKind string

const (
	StorageFailureInvalid      StorageFailureKind = "invalid"
	StorageFailureUnauthorized StorageFailureKind = "unauthorized"
	StorageFailureProcess      StorageFailureKind = "process"
	StorageFailureSchema       StorageFailureKind = "schema"
	StorageFailureIdentity     StorageFailureKind = "identity"
	StorageFailurePrecondition StorageFailureKind = "precondition"
	StorageFailureConflict     StorageFailureKind = "bucket-name-conflict"
)

// StorageError carries a closed failure kind, the operation source, and the
// sanitized provider diagnostics. Precondition and conflict failures unwrap to
// the control package sentinels so the handoff engine can act on them.
type StorageError struct {
	kind        StorageFailureKind
	source      string
	diagnostics redact.Text
}

func (failure *StorageError) Error() string {
	if failure == nil {
		return "gcp storage failed"
	}
	return fmt.Sprintf("gcp storage %s failed (%s)", failure.source, failure.kind)
}

func (failure *StorageError) Kind() StorageFailureKind {
	if failure == nil {
		return ""
	}
	return failure.kind
}

// Diagnostics returns the sanitized provider stderr for the human operator.
func (failure *StorageError) Diagnostics() redact.Text {
	if failure == nil {
		return redact.Sanitize("")
	}
	return failure.diagnostics
}

func (failure *StorageError) Unwrap() []error {
	result := []error{ErrStorageRejected}
	if failure == nil {
		return result
	}
	switch failure.kind {
	case StorageFailurePrecondition:
		result = append(result, control.ErrPreconditionFailed)
	case StorageFailureConflict:
		result = append(result, control.ErrBucketNameConflict)
	}
	return result
}

func storageError(kind StorageFailureKind, source string) *StorageError {
	return &StorageError{kind: kind, source: source, diagnostics: redact.Sanitize("")}
}

// StorageClientOptions mirrors ReadClientOptions plus an owner-private work
// directory for the transient upload and lifecycle files gcloud requires.
type StorageClientOptions struct {
	GcloudPath     string
	SearchPath     string
	Home           string
	CloudSDKConfig string
	Locale         string
	CommandTimeout time.Duration
	WorkDirectory  string
	Clock          func() time.Time
}

// StorageClient seals the process boundary. It exposes no method that takes a
// bare bucket name or argv; every operation is reached through Authorize.
type StorageClient struct {
	boundary       runner.Runner
	executable     string
	environment    []runner.EnvironmentVariable
	commandTimeout time.Duration
	workDirectory  string
	clock          func() time.Time
}

// NewStorageClient validates the options and seals gcloud exactly like
// NewReadClient.
func NewStorageClient(options StorageClientOptions) (*StorageClient, error) {
	if options.CommandTimeout <= 0 || options.CommandTimeout > storageStepTimeout || options.Clock == nil {
		return nil, storageError(StorageFailureInvalid, "client options")
	}
	if options.Locale != "C.UTF-8" && options.Locale != "en_US.UTF-8" {
		return nil, storageError(StorageFailureInvalid, "client options")
	}
	if err := validateWorkDirectory(options.WorkDirectory); err != nil {
		return nil, err
	}
	environment := []runner.EnvironmentVariable{
		{Name: "PATH", Value: options.SearchPath},
		{Name: "HOME", Value: options.Home},
		{Name: "CLOUDSDK_CONFIG", Value: options.CloudSDKConfig},
		{Name: "CLOUDSDK_CORE_DISABLE_PROMPTS", Value: "1"},
		{Name: "CLOUDSDK_CORE_DISABLE_USAGE_REPORTING", Value: "1"},
		{Name: "NO_COLOR", Value: "1"},
		{Name: "LC_ALL", Value: options.Locale},
	}
	boundary, err := newProcessBoundary(options.GcloudPath, environment)
	if err != nil {
		return nil, storageError(StorageFailureInvalid, "process boundary")
	}
	return &StorageClient{
		boundary: boundary, executable: options.GcloudPath,
		environment:    append([]runner.EnvironmentVariable(nil), environment...),
		commandTimeout: options.CommandTimeout, workDirectory: options.WorkDirectory, clock: options.Clock,
	}, nil
}

func validateWorkDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return storageError(StorageFailureInvalid, "work directory")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return storageError(StorageFailureInvalid, "work directory")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return storageError(StorageFailureInvalid, "work directory")
	}
	return nil
}

// StorageMutationAuthorization is the uniform per-step authorization issued by
// the central gateway (board fields). The adapter validates it; it never
// issues one.
type StorageMutationAuthorization struct {
	PlanDocumentSHA256    string
	PlanV1Hash            string
	EnvelopeBindingSHA256 string
	OperationID           string
	StepID                string
	Attempt               uint32
	ClaimGeneration       uint64
	ExecutingIdentity     domain.ExecutionIdentity
	ObservationRevision   string
	ObservedAt            time.Time
	ValidUntil            time.Time
	Now                   time.Time
}

// StorageTarget binds the explicit account and the immutable validated
// harness configuration the buckets belong to.
type StorageTarget struct {
	Account       string
	Configuration config.HarnessConfiguration
}

var storageStepKinds = map[string]bootstrap.IntentKind{
	"k1-audit-bootstrap": bootstrap.IntentAuditBootstrap,
	"k1-retention-lock":  bootstrap.IntentAuditRetention,
	"k2-control-bucket":  bootstrap.IntentControlBucket,
	"k3-bucket-iam":      bootstrap.IntentBucketIAM,
	"k4-seed-control":    bootstrap.IntentSeedControl,
	"k5-lock-round-trip": bootstrap.IntentLockRoundTrip,
}

type storageOperation string

const (
	opDescribeBucket   storageOperation = "buckets list"
	opCreateAudit      storageOperation = "buckets create audit"
	opCreateControl    storageOperation = "buckets create control"
	opEnableVersioning storageOperation = "buckets update versioning"
	opLifecycle        storageOperation = "buckets update lifecycle"
	opRetention        storageOperation = "buckets update retention"
	opLockRetention    storageOperation = "buckets update lock-retention"
	opUploadCreateOnly storageOperation = "cp if-generation-match=0"
	opUploadCAS        storageOperation = "cp if-generation-match"
	opDescribeObject   storageOperation = "objects list"
	opReadObject       storageOperation = "cat"
	opGetIAM           storageOperation = "buckets get-iam-policy"
	opAddBinding       storageOperation = "buckets add-iam-policy-binding"
	opRemoveBinding    storageOperation = "buckets remove-iam-policy-binding"
)

// admittedOperations is the closed per-intent operation set. Nothing renders a
// delete verb.
var admittedOperations = map[bootstrap.IntentKind]map[storageOperation]struct{}{
	bootstrap.IntentAuditBootstrap: set(opDescribeBucket, opCreateAudit, opEnableVersioning, opLifecycle, opUploadCreateOnly, opDescribeObject, opReadObject),
	bootstrap.IntentAuditRetention: set(opDescribeBucket, opDescribeObject, opReadObject, opRetention, opLockRetention),
	bootstrap.IntentControlBucket:  set(opDescribeBucket, opCreateControl, opEnableVersioning),
	bootstrap.IntentBucketIAM:      set(opDescribeBucket, opGetIAM, opAddBinding, opRemoveBinding),
	bootstrap.IntentSeedControl:    set(opDescribeBucket, opUploadCreateOnly, opDescribeObject, opReadObject),
	bootstrap.IntentLockRoundTrip:  set(opDescribeObject, opReadObject, opUploadCAS),
}

func set(values ...storageOperation) map[storageOperation]struct{} {
	result := make(map[storageOperation]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

// StorageSession is one authorized step. It implements control.AuditBucketPort
// for the K1 intents and exposes the typed K2-K5 operations. Every method
// re-checks that the bucket is one of the step's approved resources and that
// the intent kind admits the operation.
type StorageSession struct {
	client        *StorageClient
	authorization StorageMutationAuthorization
	kind          bootstrap.IntentKind
	account       string
	project       string
	location      string
	buckets       map[string]bootstrap.DesiredResource
	auditBucket   string
	controlBucket string
	// policy is the exact rendered K3 binding set; IAM changes outside it
	// are refused.
	policy map[control.BucketBinding]struct{}
	// objects is the closed object-name set a K4/K5 session may touch.
	objects map[string]struct{}
}

var (
	_ control.AuditBucketPort = (*StorageSession)(nil)
	_ control.StorageStepPort = (*StorageSession)(nil)
)

// Authorize validates the authorization, the intent, and the step's desired
// resources, and binds them into a session. Missing, stale, mismatched-kind,
// mismatched-identity, or cross-project values fail before any process runs.
func (client *StorageClient) Authorize(
	authorization StorageMutationAuthorization,
	intent bootstrap.StepIntent,
	resources []bootstrap.DesiredResource,
	target StorageTarget,
) (*StorageSession, error) {
	if client == nil || client.boundary == nil {
		return nil, storageError(StorageFailureInvalid, "client")
	}
	kind, known := storageStepKinds[intent.StepID]
	if !known || kind != intent.Kind {
		return nil, storageError(StorageFailureUnauthorized, "intent kind")
	}
	if err := validateStorageAuthorization(authorization, intent); err != nil {
		return nil, err
	}
	configuration := target.Configuration
	if !accountPattern.MatchString(target.Account) || configuration.Project() == "" || configuration.Region() == "" ||
		configuration.AuditBucket() == "" || configuration.ControlBucket() == "" || configuration.AuditBucket() == configuration.ControlBucket() {
		return nil, storageError(StorageFailureIdentity, "target")
	}
	buckets, err := validateStorageResources(intent, resources, configuration)
	if err != nil {
		return nil, err
	}
	session := &StorageSession{
		client: client, authorization: authorization, kind: kind, account: target.Account,
		project: configuration.Project(), location: configuration.Region(), buckets: buckets,
		auditBucket: configuration.AuditBucket(), controlBucket: configuration.ControlBucket(),
		policy: map[control.BucketBinding]struct{}{}, objects: map[string]struct{}{},
	}
	if err := session.bindStepTargets(configuration); err != nil {
		return nil, err
	}
	// The trusted clock, not the caller's Now, decides freshness now and
	// again before every mutation.
	if err := session.fresh(); err != nil {
		return nil, err
	}
	return session, nil
}

// bindStepTargets closes the K3 policy set and the K4/K5 object-name set from
// the validated configuration, never from caller input.
func (session *StorageSession) bindStepTargets(configuration config.HarnessConfiguration) error {
	switch session.kind {
	case bootstrap.IntentBucketIAM:
		desired := bootstrap.HarnessDesiredState{
			AuditBucket: configuration.AuditBucket(), ControlBucket: configuration.ControlBucket(),
			OperatorPrincipal: configuration.OperatorPrincipal(), DestructivePrincipal: configuration.DestructivePrincipal(),
			VMPrincipal: configuration.VMPrincipal(), WipePrincipal: configuration.WipeServiceAccount(),
		}
		policy, err := control.RenderBucketPolicy("k3-bucket-iam", desired)
		if err != nil {
			return storageError(StorageFailureUnauthorized, "rendered policy")
		}
		for _, binding := range policy.Bindings {
			session.policy[binding] = struct{}{}
		}
	case bootstrap.IntentSeedControl:
		environment := configuration.Environment()
		for _, name := range control.SeedObjectNames(environment) {
			session.objects[name] = struct{}{}
		}
		if len(session.objects) == 0 {
			return storageError(StorageFailureUnauthorized, "seed object names")
		}
	case bootstrap.IntentLockRoundTrip:
		lock, err := control.LockObjectName(configuration.Environment())
		if err != nil {
			return storageError(StorageFailureUnauthorized, "lock object name")
		}
		session.objects[lock.String()] = struct{}{}
	}
	return nil
}

// fresh revalidates the authorization window against the trusted clock. It
// runs at Authorize and immediately before every state-changing call, so a
// retained session cannot outlive its window.
func (session *StorageSession) fresh() error {
	now := session.client.clock().UTC()
	authorization := session.authorization
	if now.IsZero() || now.Before(authorization.ObservedAt) || !now.Before(authorization.ValidUntil) ||
		authorization.Now.After(now.Add(storageClockSkew)) || now.Sub(authorization.Now) > storageClockSkew {
		return storageError(StorageFailureUnauthorized, "authorization is stale at the trusted clock")
	}
	return nil
}

func validateStorageAuthorization(authorization StorageMutationAuthorization, intent bootstrap.StepIntent) error {
	if !storageSHA256Pattern.MatchString(authorization.PlanDocumentSHA256) || !storageSHA256Pattern.MatchString(authorization.PlanV1Hash) ||
		!storageSHA256Pattern.MatchString(authorization.EnvelopeBindingSHA256) || !storageSHA256Pattern.MatchString(authorization.ObservationRevision) ||
		!storageOperationIDPattern.MatchString(authorization.OperationID) {
		return storageError(StorageFailureUnauthorized, "authorization binding")
	}
	if authorization.EnvelopeBindingSHA256 != intent.EnvelopeBindingSHA256 || authorization.StepID != intent.StepID {
		return storageError(StorageFailureUnauthorized, "authorization step binding")
	}
	if authorization.Attempt == 0 || int64(authorization.Attempt) > int64(intent.Retry.MaxAttempts) || authorization.ClaimGeneration == 0 {
		return storageError(StorageFailureUnauthorized, "authorization claim")
	}
	if !authorization.ExecutingIdentity.Valid() || authorization.ExecutingIdentity != intent.ExecutingIdentity ||
		authorization.ExecutingIdentity != domain.IdentityHuman {
		return storageError(StorageFailureIdentity, "executing identity")
	}
	for _, value := range []time.Time{authorization.ObservedAt, authorization.ValidUntil, authorization.Now} {
		if value.IsZero() {
			return storageError(StorageFailureUnauthorized, "authorization window")
		}
		if _, offset := value.Zone(); offset != 0 {
			return storageError(StorageFailureUnauthorized, "authorization window")
		}
	}
	if !authorization.ObservedAt.Before(authorization.ValidUntil) || authorization.Now.Before(authorization.ObservedAt) ||
		!authorization.Now.Before(authorization.ValidUntil) {
		return storageError(StorageFailureUnauthorized, "stale authorization")
	}
	return nil
}

func validateStorageResources(intent bootstrap.StepIntent, resources []bootstrap.DesiredResource, configuration config.HarnessConfiguration) (map[string]bootstrap.DesiredResource, error) {
	if len(resources) == 0 || len(resources) != len(intent.ResourceIDs) {
		return nil, storageError(StorageFailureUnauthorized, "resource set")
	}
	expectedNames := map[string]string{"audit-bucket": configuration.AuditBucket(), "control-bucket": configuration.ControlBucket()}
	result := make(map[string]bootstrap.DesiredResource, len(resources))
	for index, resource := range resources {
		expectedName, known := expectedNames[resource.ID]
		if !known || resource.ID != intent.ResourceIDs[index] || resource.Kind != bootstrap.ResourceBucket ||
			resource.Name != expectedName || !storageBucketNamePattern.MatchString(resource.Name) ||
			resource.Project != configuration.Project() || resource.Location != configuration.Region() ||
			resource.Permanence != bootstrap.PermanentSingleton ||
			resource.ProviderID != "projects/"+configuration.Project()+"/global/"+string(bootstrap.ResourceBucket)+"/"+resource.Name ||
			!storageSHA256Pattern.MatchString(resource.DesiredStateFingerprint) {
			return nil, storageError(StorageFailureUnauthorized, "approved resource")
		}
		if _, duplicate := result[resource.Name]; duplicate {
			return nil, storageError(StorageFailureUnauthorized, "duplicate resource")
		}
		result[resource.Name] = resource
	}
	return result, nil
}

func (session *StorageSession) admit(operation storageOperation, bucket string) error {
	if session == nil || session.client == nil {
		return storageError(StorageFailureInvalid, "session")
	}
	if _, ok := admittedOperations[session.kind][operation]; !ok {
		return storageError(StorageFailureUnauthorized, string(operation))
	}
	if _, approved := session.buckets[bucket]; !approved {
		return storageError(StorageFailureUnauthorized, "bucket is not an approved desired resource")
	}
	return nil
}

// admitObject confines K4/K5 object writes and reads to the closed name set.
func (session *StorageSession) admitObject(object string) error {
	if len(session.objects) == 0 {
		return nil
	}
	if _, ok := session.objects[object]; !ok {
		return storageError(StorageFailureUnauthorized, "object is not an approved step target")
	}
	return nil
}

func (session *StorageSession) identity(identity control.BucketIdentity) error {
	if identity.Project != session.project || identity.Location != session.location || !storageBucketNamePattern.MatchString(identity.Name) {
		return storageError(StorageFailureIdentity, "bucket identity")
	}
	return nil
}

func (session *StorageSession) globals(group ...string) []string {
	args := append([]string(nil), group...)
	return append(args, "--account="+session.account, "--project="+session.project, "--quiet", "--verbosity=error")
}

func bucketURL(name string) string { return "gs://" + name }

func objectURL(bucket string, object string) string { return "gs://" + bucket + "/" + object }

var mutatingOperations = set(opCreateAudit, opCreateControl, opEnableVersioning, opLifecycle, opRetention, opLockRetention, opUploadCreateOnly, opUploadCAS, opAddBinding, opRemoveBinding)

// run executes one fixed argv template through the sealed boundary. Every
// mutating template is preceded by a trusted-clock freshness check.
func (session *StorageSession) run(ctx context.Context, source storageOperation, arguments []string) (runner.Result, error) {
	if ctx == nil {
		return runner.Result{}, storageError(StorageFailureInvalid, string(source))
	}
	if _, mutating := mutatingOperations[source]; mutating {
		if err := session.fresh(); err != nil {
			return runner.Result{}, err
		}
	}
	client := session.client
	result, err := client.boundary.Run(ctx, runner.Request{
		Executable: client.executable, Arguments: append([]string(nil), arguments...),
		Environment: append([]runner.EnvironmentVariable(nil), client.environment...),
		Timeout:     client.commandTimeout, StdoutLimitBytes: storageStdoutLimit, StderrLimitBytes: storageStderrLimit,
	})
	if err != nil {
		return result, &StorageError{kind: StorageFailureProcess, source: string(source), diagnostics: result.Stderr}
	}
	return result, nil
}

// withWorkFile writes content to an exclusive private temporary file in the
// work directory, invokes use with its path, and removes only that file.
func (session *StorageSession) withWorkFile(content []byte, use func(path string) error) error {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return storageError(StorageFailureInvalid, "work file")
	}
	path := filepath.Join(session.client.workDirectory, "ctrldb-storage-"+hex.EncodeToString(suffix)+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, storageWorkFileMode)
	if err != nil {
		return storageError(StorageFailureInvalid, "work file")
	}
	defer func() { _ = os.Remove(path) }()
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return storageError(StorageFailureInvalid, "work file")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return storageError(StorageFailureInvalid, "work file")
	}
	if err := file.Close(); err != nil {
		return storageError(StorageFailureInvalid, "work file")
	}
	return use(path)
}
