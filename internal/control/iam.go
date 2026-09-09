// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
)

const (
	RoleObjectUser    = "roles/storage.objectUser"
	RoleObjectViewer  = "roles/storage.objectViewer"
	RoleObjectCreator = "roles/storage.objectCreator"

	// TestPrefix is the disposable subtree that every harness identity is
	// confined to on both buckets (SECURITY §2.9, ARCHITECTURE layout).
	TestPrefix = "test/"
	// WipePrefix is where the nightly wipe writes its run records.
	WipePrefix = "test/wipe/"
)

var (
	// ErrInvalidBucketBinding is returned when a binding is not exactly
	// resource-scoped to one approved bucket and one closed prefix.
	ErrInvalidBucketBinding = errors.New("invalid bucket IAM binding")

	closedBindingRoles   = map[string]struct{}{RoleObjectUser: {}, RoleObjectViewer: {}, RoleObjectCreator: {}}
	closedBindingPrefix  = map[string]struct{}{TestPrefix: {}, WipePrefix: {}}
	serviceAccountMember = regexp.MustCompile(`^serviceAccount:[a-z][a-z0-9-]{5,29}@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
)

// BucketBinding is one conditional IAM binding on one approved bucket. The
// condition confines the grant to objects under Prefix; there is no
// bucket-wide grant and no setIamPolicy for any tool identity.
type BucketBinding struct {
	Bucket              string `json:"bucket"`
	Role                string `json:"role"`
	Member              string `json:"member"`
	Prefix              string `json:"prefix"`
	ConditionTitle      string `json:"conditionTitle"`
	ConditionExpression string `json:"conditionExpression"`
}

// BucketPolicy is the closed rendered binding set for one step plus its
// fingerprint for the harness-state RoleBindings field.
type BucketPolicy struct {
	StepID      string          `json:"stepId"`
	Bindings    []BucketBinding `json:"bindings"`
	Fingerprint string          `json:"fingerprint"`
}

// RenderBucketPolicy renders exactly the K3 (both buckets) or T6 (control
// test prefix) bindings for the approved desired state. Any other step is
// rejected; the catalog is protocol-owned and not caller-extensible.
func RenderBucketPolicy(stepID string, desired bootstrap.HarnessDesiredState) (BucketPolicy, error) {
	operator := "serviceAccount:" + desired.OperatorPrincipal
	destructive := "serviceAccount:" + desired.DestructivePrincipal
	vm := "serviceAccount:" + desired.VMPrincipal
	wipe := "serviceAccount:" + desired.WipePrincipal
	var bindings []BucketBinding
	switch stepID {
	case "k3-bucket-iam":
		bindings = []BucketBinding{
			binding(desired.AuditBucket, RoleObjectCreator, operator, TestPrefix),
			binding(desired.AuditBucket, RoleObjectViewer, operator, TestPrefix),
			binding(desired.AuditBucket, RoleObjectCreator, destructive, TestPrefix),
			binding(desired.AuditBucket, RoleObjectViewer, destructive, TestPrefix),
			binding(desired.AuditBucket, RoleObjectCreator, wipe, TestPrefix),
			binding(desired.ControlBucket, RoleObjectCreator, wipe, WipePrefix),
			binding(desired.ControlBucket, RoleObjectViewer, wipe, TestPrefix),
			binding(desired.ControlBucket, RoleObjectViewer, vm, TestPrefix),
		}
	case "t6-control-prefix":
		bindings = []BucketBinding{
			binding(desired.ControlBucket, RoleObjectUser, operator, TestPrefix),
			binding(desired.ControlBucket, RoleObjectUser, destructive, TestPrefix),
		}
	default:
		return BucketPolicy{}, fmt.Errorf("%w: step %q renders no bucket policy", ErrInvalidBucketBinding, stepID)
	}
	if desired.AuditBucket == "" || desired.ControlBucket == "" || desired.AuditBucket == desired.ControlBucket {
		return BucketPolicy{}, fmt.Errorf("%w: bucket identities", ErrInvalidBucketBinding)
	}
	for _, item := range bindings {
		if err := ValidateBucketBinding(item, desired); err != nil {
			return BucketPolicy{}, err
		}
	}
	sortBindings(bindings)
	fingerprint, err := hashJSON(bindings)
	if err != nil {
		return BucketPolicy{}, fmt.Errorf("%w: fingerprint", ErrInvalidBucketBinding)
	}
	return BucketPolicy{StepID: stepID, Bindings: bindings, Fingerprint: fingerprint}, nil
}

func binding(bucket, role, member, prefix string) BucketBinding {
	title := "ctrldb-" + strings.TrimSuffix(strings.ReplaceAll(prefix, "/", "-"), "-") + "-" + strings.TrimPrefix(role, "roles/storage.")
	expression := fmt.Sprintf(`resource.type == "storage.googleapis.com/Object" && resource.name.startsWith("projects/_/buckets/%s/objects/%s")`, bucket, prefix)
	return BucketBinding{Bucket: bucket, Role: role, Member: member, Prefix: prefix, ConditionTitle: title, ConditionExpression: expression}
}

// ValidateBucketBinding fails closed unless the binding names one approved
// bucket, one closed role, one harness service account, one closed prefix, and
// the exact resource-scoped condition for that bucket and prefix.
func ValidateBucketBinding(item BucketBinding, desired bootstrap.HarnessDesiredState) error {
	if item.Bucket == "" || (item.Bucket != desired.AuditBucket && item.Bucket != desired.ControlBucket) {
		return fmt.Errorf("%w: bucket is not an approved control-plane bucket", ErrInvalidBucketBinding)
	}
	if _, ok := closedBindingRoles[item.Role]; !ok {
		return fmt.Errorf("%w: role %q is outside the closed set", ErrInvalidBucketBinding, item.Role)
	}
	if _, ok := closedBindingPrefix[item.Prefix]; !ok {
		return fmt.Errorf("%w: prefix is outside the disposable subtree", ErrInvalidBucketBinding)
	}
	if !serviceAccountMember.MatchString(item.Member) {
		return fmt.Errorf("%w: member is not a project service account", ErrInvalidBucketBinding)
	}
	principals := map[string]struct{}{
		"serviceAccount:" + desired.OperatorPrincipal: {}, "serviceAccount:" + desired.DestructivePrincipal: {},
		"serviceAccount:" + desired.VMPrincipal: {}, "serviceAccount:" + desired.WipePrincipal: {},
	}
	if _, ok := principals[item.Member]; !ok {
		return fmt.Errorf("%w: member is not an approved harness identity", ErrInvalidBucketBinding)
	}
	expected := binding(item.Bucket, item.Role, item.Member, item.Prefix)
	if item != expected {
		return fmt.Errorf("%w: condition is not the exact resource-scoped expression", ErrInvalidBucketBinding)
	}
	return nil
}

// CompensationBindings returns the rendered bindings that were absent before
// the operation. Compensation may remove only these; preexisting grants are
// never touched.
func CompensationBindings(rendered []BucketBinding, preexisting []BucketBinding) []BucketBinding {
	existing := make(map[BucketBinding]struct{}, len(preexisting))
	for _, item := range preexisting {
		existing[item] = struct{}{}
	}
	result := make([]BucketBinding, 0, len(rendered))
	for _, item := range rendered {
		if _, present := existing[item]; !present {
			result = append(result, item)
		}
	}
	sortBindings(result)
	return result
}

func sortBindings(values []BucketBinding) {
	sort.Slice(values, func(left, right int) bool {
		a, b := values[left], values[right]
		if a.Bucket != b.Bucket {
			return a.Bucket < b.Bucket
		}
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		if a.Member != b.Member {
			return a.Member < b.Member
		}
		return a.Prefix < b.Prefix
	})
}
