// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"strconv"

	"github.com/thelostorbital/ctrldb/internal/control"
	"github.com/thelostorbital/ctrldb/internal/redact"
)

// Fixed argument templates. Callers supply only validated identities; no
// flag or verb is caller-provided and no delete verb exists in this file.

const (
	bucketDescribeProjection = "json(name,location,metageneration,creation_time,default_storage_class,uniform_bucket_level_access,public_access_prevention,versioning_enabled,retention_period,retention_policy_is_locked,lifecycle_config,soft_delete_policy)"
	objectDescribeProjection = "json(name,bucket,generation,metageneration,size,crc32c_hash)"
	iamPolicyProjection      = "json(bindings,etag)"
)

// DescribeBucket observes one approved bucket. Absence is reported only when
// the provider explicitly answers that the bucket does not exist.
func (session *StorageSession) DescribeBucket(ctx context.Context, name string) (control.BucketState, bool, error) {
	if err := session.admit(opDescribeBucket, name); err != nil {
		return control.BucketState{}, false, err
	}
	// A filtered list answers absence with an empty JSON array, so absence is
	// never inferred from a failed describe or from provider text.
	result, err := session.run(ctx, opDescribeBucket, session.globals("storage", "buckets", "list", "--filter=name="+name, "--format="+bucketDescribeProjection))
	if err != nil {
		return control.BucketState{}, false, err
	}
	state, exists, err := parseBucketState(result.Stdout, name)
	if err != nil || !exists {
		return control.BucketState{}, false, err
	}
	return session.bindProject(state), true, nil
}

// CreateAuditBucket creates the audit bucket with UBLA, enforced PAP, STANDARD
// class, and the explicit project and location, then enables versioning.
// Describe-before-create is the caller's duty; a create refusal followed by a
// bucket that is not observable in the project is the explicit global
// bucket-name conflict precondition failure, never an absence claim.
func (session *StorageSession) CreateAuditBucket(ctx context.Context, identity control.BucketIdentity) error {
	if err := session.admit(opCreateAudit, identity.Name); err != nil {
		return err
	}
	if err := session.identity(identity); err != nil {
		return err
	}
	if identity.Name != session.auditBucket {
		return storageError(StorageFailureUnauthorized, "audit bucket identity")
	}
	arguments := session.globals("storage", "buckets", "create", bucketURL(identity.Name), "--location="+identity.Location,
		"--uniform-bucket-level-access", "--public-access-prevention", "--default-storage-class=STANDARD")
	return session.createBucket(ctx, opCreateAudit, identity, arguments, true)
}

// CreateControlBucket creates the mutable control bucket: UBLA, enforced PAP,
// STANDARD class, 30-day soft delete. Versioning is a separate EnableVersioning
// call so the executor can record the creation before converging it.
func (session *StorageSession) CreateControlBucket(ctx context.Context, identity control.BucketIdentity) error {
	if err := session.admit(opCreateControl, identity.Name); err != nil {
		return err
	}
	if err := session.identity(identity); err != nil {
		return err
	}
	if identity.Name != session.controlBucket {
		return storageError(StorageFailureUnauthorized, "control bucket identity")
	}
	arguments := session.globals("storage", "buckets", "create", bucketURL(identity.Name), "--location="+identity.Location,
		"--uniform-bucket-level-access", "--public-access-prevention", "--default-storage-class=STANDARD",
		"--soft-delete-duration="+strconv.FormatInt(controlSoftDeleteSeconds, 10)+"s")
	return session.createBucket(ctx, opCreateControl, identity, arguments, false)
}

// createBucket performs discovery inside the mutation boundary: a bucket
// already observable in the project is a positive collision and the create is
// never rendered. A refused create is reported as the process failure with
// its sanitized diagnostics; gcloud 560 exposes no machine-readable
// distinction between a global-name conflict and any other refusal, so the
// adapter never relabels a refusal as a conflict or as absence.
func (session *StorageSession) createBucket(ctx context.Context, operation storageOperation, identity control.BucketIdentity, arguments []string, versioning bool) error {
	if _, exists, err := session.DescribeBucket(ctx, identity.Name); err != nil {
		return err
	} else if exists {
		return storageError(StorageFailurePrecondition, string(operation))
	}
	if _, err := session.run(ctx, operation, arguments); err != nil {
		if _, exists, describeErr := session.DescribeBucket(ctx, identity.Name); describeErr == nil && exists {
			return &StorageError{kind: StorageFailurePrecondition, source: string(operation), diagnostics: redactDiagnostics(err)}
		}
		return err
	}
	if !versioning {
		return nil
	}
	_, err := session.run(ctx, opEnableVersioning, session.globals("storage", "buckets", "update", bucketURL(identity.Name), "--versioning"))
	return err
}

// AuthorizedStep exposes the binding this session was authorized for.
func (session *StorageSession) AuthorizedStep() (string, string, string) {
	if session == nil {
		return "", "", ""
	}
	return session.authorization.EnvelopeBindingSHA256, session.authorization.OperationID, session.authorization.StepID
}

// EnableVersioning converges versioning on an approved bucket (K2 repair).
func (session *StorageSession) EnableVersioning(ctx context.Context, identity control.BucketIdentity) error {
	if err := session.admit(opEnableVersioning, identity.Name); err != nil {
		return err
	}
	if err := session.identity(identity); err != nil {
		return err
	}
	_, err := session.run(ctx, opEnableVersioning, session.globals("storage", "buckets", "update", bucketURL(identity.Name), "--versioning"))
	return err
}

// ConfigureArchiveLifecycle sets the exact D-088 rule: SetStorageClass ARCHIVE
// after 365 days and no delete action.
func (session *StorageSession) ConfigureArchiveLifecycle(ctx context.Context, identity control.BucketIdentity) error {
	if err := session.admit(opLifecycle, identity.Name); err != nil {
		return err
	}
	if err := session.identity(identity); err != nil {
		return err
	}
	return session.withWorkFile([]byte(auditLifecycleDocument), func(path string) error {
		_, err := session.run(ctx, opLifecycle, session.globals("storage", "buckets", "update", bucketURL(identity.Name), "--lifecycle-file="+path))
		return err
	})
}

// UploadCreateOnly uploads content with if-generation-match=0 and returns the
// described object. An existing object yields the precondition failure.
func (session *StorageSession) UploadCreateOnly(ctx context.Context, identity control.BucketIdentity, object control.AuditObjectName, content []byte) (control.ObjectDescriptor, error) {
	return session.upload(ctx, opUploadCreateOnly, identity, object.String(), content, 0)
}

// UploadControlCreateOnly is UploadCreateOnly for a control-bucket object
// (K4 seeds).
func (session *StorageSession) UploadControlCreateOnly(ctx context.Context, identity control.BucketIdentity, object control.ControlObjectName, content []byte) (control.ObjectDescriptor, error) {
	return session.upload(ctx, opUploadCreateOnly, identity, object.String(), content, 0)
}

// UploadIfGenerationMatch replaces a control object only when its current
// generation equals expected (expected > 0). This is the K5 lock round-trip
// compare-and-swap primitive.
func (session *StorageSession) UploadIfGenerationMatch(ctx context.Context, identity control.BucketIdentity, object control.ControlObjectName, expected control.Generation, content []byte) (control.ObjectDescriptor, error) {
	if expected == 0 {
		return control.ObjectDescriptor{}, storageError(StorageFailureInvalid, "expected generation")
	}
	return session.upload(ctx, opUploadCAS, identity, object.String(), content, expected)
}

func (session *StorageSession) upload(ctx context.Context, operation storageOperation, identity control.BucketIdentity, object string, content []byte, expected control.Generation) (control.ObjectDescriptor, error) {
	if err := session.admit(operation, identity.Name); err != nil {
		return control.ObjectDescriptor{}, err
	}
	if err := session.identity(identity); err != nil {
		return control.ObjectDescriptor{}, err
	}
	if !storageObjectNamePattern.MatchString(object) || len(content) == 0 || len(content) > storageStdoutLimit {
		return control.ObjectDescriptor{}, storageError(StorageFailureInvalid, "object")
	}
	if err := session.admitObject(object); err != nil {
		return control.ObjectDescriptor{}, err
	}
	var descriptor control.ObjectDescriptor
	err := session.withWorkFile(content, func(path string) error {
		arguments := session.globals("storage", "cp", path, objectURL(identity.Name, object),
			"--if-generation-match="+strconv.FormatUint(uint64(expected), 10), "--content-type="+storageContentType)
		if _, err := session.run(ctx, operation, arguments); err != nil {
			observed, exists, describeErr := session.describeObject(ctx, identity, object)
			if describeErr == nil && exists && observed.Generation != expected {
				return &StorageError{kind: StorageFailurePrecondition, source: string(operation), diagnostics: redactDiagnostics(err)}
			}
			return err
		}
		observed, exists, err := session.describeObject(ctx, identity, object)
		if err != nil {
			return err
		}
		if !exists || !observed.MatchesContent(content) {
			return storageError(StorageFailureSchema, "uploaded object verification")
		}
		descriptor = observed
		return nil
	})
	return descriptor, err
}

// DescribeObject returns generation, size, and CRC32C for one audit object.
func (session *StorageSession) DescribeObject(ctx context.Context, identity control.BucketIdentity, object control.AuditObjectName) (control.ObjectDescriptor, bool, error) {
	return session.describeObject(ctx, identity, object.String())
}

// DescribeControlObject is DescribeObject for a control-bucket object.
func (session *StorageSession) DescribeControlObject(ctx context.Context, identity control.BucketIdentity, object control.ControlObjectName) (control.ObjectDescriptor, bool, error) {
	return session.describeObject(ctx, identity, object.String())
}

func (session *StorageSession) describeObject(ctx context.Context, identity control.BucketIdentity, object string) (control.ObjectDescriptor, bool, error) {
	if err := session.admit(opDescribeObject, identity.Name); err != nil {
		return control.ObjectDescriptor{}, false, err
	}
	if err := session.identity(identity); err != nil {
		return control.ObjectDescriptor{}, false, err
	}
	if !storageObjectNamePattern.MatchString(object) {
		return control.ObjectDescriptor{}, false, storageError(StorageFailureInvalid, "object")
	}
	if err := session.admitObject(object); err != nil {
		return control.ObjectDescriptor{}, false, err
	}
	// objects list on the exact URL answers absence with an empty JSON array.
	result, err := session.run(ctx, opDescribeObject, session.globals("storage", "objects", "list", objectURL(identity.Name, object), "--format="+objectDescribeProjection))
	if err != nil {
		return control.ObjectDescriptor{}, false, err
	}
	return parseObjectDescriptor(result.Stdout, identity.Name, object)
}

// ReadObject returns the exact bytes and descriptor of one audit object.
func (session *StorageSession) ReadObject(ctx context.Context, identity control.BucketIdentity, object control.AuditObjectName) ([]byte, control.ObjectDescriptor, bool, error) {
	return session.readObject(ctx, identity, object.String())
}

// ReadControlObject is ReadObject for a control-bucket object.
func (session *StorageSession) ReadControlObject(ctx context.Context, identity control.BucketIdentity, object control.ControlObjectName) ([]byte, control.ObjectDescriptor, bool, error) {
	return session.readObject(ctx, identity, object.String())
}

func (session *StorageSession) readObject(ctx context.Context, identity control.BucketIdentity, object string) ([]byte, control.ObjectDescriptor, bool, error) {
	if err := session.admit(opReadObject, identity.Name); err != nil {
		return nil, control.ObjectDescriptor{}, false, err
	}
	descriptor, exists, err := session.describeObject(ctx, identity, object)
	if err != nil || !exists {
		return nil, control.ObjectDescriptor{}, false, err
	}
	// The read is pinned to the described generation (gs://bucket/object#gen)
	// so a concurrent replacement cannot be mistaken for the described bytes.
	pinned := objectURL(identity.Name, object) + "#" + strconv.FormatUint(uint64(descriptor.Generation), 10)
	result, err := session.run(ctx, opReadObject, session.globals("storage", "cat", pinned))
	if err != nil {
		return nil, control.ObjectDescriptor{}, false, err
	}
	content := append([]byte(nil), result.Stdout...)
	if !descriptor.MatchesContent(content) {
		return nil, control.ObjectDescriptor{}, false, storageError(StorageFailureSchema, "object bytes do not match the described checksum")
	}
	return content, descriptor, true, nil
}

// ConfigureRetention sets the (still unlocked) retention period.
func (session *StorageSession) ConfigureRetention(ctx context.Context, identity control.BucketIdentity, seconds int64) error {
	if err := session.admit(opRetention, identity.Name); err != nil {
		return err
	}
	if err := session.identity(identity); err != nil {
		return err
	}
	if seconds != control.AuditRetentionSeconds || identity.Name != session.auditBucket {
		return storageError(StorageFailureUnauthorized, "retention period")
	}
	_, err := session.run(ctx, opRetention, session.globals("storage", "buckets", "update", bucketURL(identity.Name), "--retention-period="+strconv.FormatInt(seconds, 10)+"s"))
	return err
}

// LockRetention is the irreversible D-158 boundary and a separate call. gcloud
// offers no server-side precondition for it, so the bucket is re-observed
// immediately before the lock and the call is refused unless the metageneration
// still equals expectedMetageneration and the period is exactly 365 days.
func (session *StorageSession) LockRetention(ctx context.Context, identity control.BucketIdentity, expectedMetageneration int64) error {
	if err := session.admit(opLockRetention, identity.Name); err != nil {
		return err
	}
	if err := session.identity(identity); err != nil {
		return err
	}
	if identity.Name != session.auditBucket || expectedMetageneration <= 0 {
		return storageError(StorageFailureUnauthorized, "retention lock target")
	}
	state, exists, err := session.DescribeBucket(ctx, identity.Name)
	if err != nil {
		return err
	}
	if !exists || state.Identity != identity || state.RetentionSeconds != control.AuditRetentionSeconds || state.RetentionLocked ||
		state.Metageneration != expectedMetageneration {
		return storageError(StorageFailurePrecondition, string(opLockRetention))
	}
	_, err = session.run(ctx, opLockRetention, session.globals("storage", "buckets", "update", bucketURL(identity.Name), "--lock-retention-period"))
	return err
}

// GetBindings returns the bucket's current conditional bindings.
func (session *StorageSession) GetBindings(ctx context.Context, identity control.BucketIdentity) ([]control.BucketBinding, error) {
	if err := session.admit(opGetIAM, identity.Name); err != nil {
		return nil, err
	}
	if err := session.identity(identity); err != nil {
		return nil, err
	}
	result, err := session.run(ctx, opGetIAM, session.globals("storage", "buckets", "get-iam-policy", bucketURL(identity.Name), "--format="+iamPolicyProjection))
	if err != nil {
		return nil, err
	}
	return parseBucketBindings(result.Stdout, identity.Name)
}

// AddBinding adds one validated resource-scoped conditional binding.
func (session *StorageSession) AddBinding(ctx context.Context, identity control.BucketIdentity, binding control.BucketBinding) error {
	return session.changeBinding(ctx, opAddBinding, "add-iam-policy-binding", identity, binding)
}

// RemoveBinding removes one validated binding. Callers must pass only
// bindings recorded as added by this operation (control.CompensationBindings).
func (session *StorageSession) RemoveBinding(ctx context.Context, identity control.BucketIdentity, binding control.BucketBinding) error {
	return session.changeBinding(ctx, opRemoveBinding, "remove-iam-policy-binding", identity, binding)
}

func (session *StorageSession) changeBinding(ctx context.Context, operation storageOperation, verb string, identity control.BucketIdentity, binding control.BucketBinding) error {
	if err := session.admit(operation, identity.Name); err != nil {
		return err
	}
	if err := session.identity(identity); err != nil {
		return err
	}
	if binding.Bucket != identity.Name {
		return storageError(StorageFailureUnauthorized, "binding bucket")
	}
	if err := control.ValidateBucketBindingShape(binding, session.auditBucket, session.controlBucket); err != nil {
		return storageError(StorageFailureUnauthorized, "binding shape")
	}
	if _, rendered := session.policy[binding]; !rendered {
		return storageError(StorageFailureUnauthorized, "binding is not in the rendered K3 policy")
	}
	arguments := session.globals("storage", "buckets", verb, bucketURL(identity.Name), "--member="+binding.Member, "--role="+binding.Role,
		"--condition=expression="+binding.ConditionExpression+",title="+binding.ConditionTitle)
	_, err := session.run(ctx, operation, arguments)
	return err
}

func redactDiagnostics(err error) redact.Text {
	var failure *StorageError
	if errors.As(err, &failure) {
		return failure.diagnostics
	}
	return redact.Sanitize("")
}
