// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/thelostorbital/ctrldb/internal/control"
)

// Wire projections of `gcloud storage` (560.0.0) resource JSON. Every field
// is requested explicitly through a `--format=json(...)` projection so an
// unknown key is a schema failure, never an ignored value. Omitted boolean
// and numeric keys mean "unset" in the gcloud resource model and are read as
// false / zero, which always fails the compliance comparison closed.

type bucketWireV560 struct {
	Name                     string              `json:"name"`
	Location                 string              `json:"location"`
	Metageneration           json.Number         `json:"metageneration"`
	CreationTime             string              `json:"creation_time"`
	DefaultStorageClass      string              `json:"default_storage_class"`
	UniformBucketLevelAccess *bool               `json:"uniform_bucket_level_access"`
	PublicAccessPrevention   string              `json:"public_access_prevention"`
	VersioningEnabled        *bool               `json:"versioning_enabled"`
	RetentionPeriod          json.Number         `json:"retention_period"`
	RetentionPolicyIsLocked  *bool               `json:"retention_policy_is_locked"`
	LifecycleConfig          *lifecycleWireV560  `json:"lifecycle_config"`
	SoftDeletePolicy         *softDeleteWireV560 `json:"soft_delete_policy"`
}

type lifecycleWireV560 struct {
	Rule []lifecycleRuleWireV560 `json:"rule"`
}

type lifecycleRuleWireV560 struct {
	Action    lifecycleActionWireV560    `json:"action"`
	Condition lifecycleConditionWireV560 `json:"condition"`
}

type lifecycleActionWireV560 struct {
	Type         string `json:"type"`
	StorageClass string `json:"storageClass"`
}

type lifecycleConditionWireV560 struct {
	Age json.Number `json:"age"`
}

type softDeleteWireV560 struct {
	RetentionDurationSeconds json.Number `json:"retentionDurationSeconds"`
	EffectiveTime            string      `json:"effectiveTime"`
}

type objectWireV560 struct {
	Name           string      `json:"name"`
	Bucket         string      `json:"bucket"`
	Generation     string      `json:"generation"`
	Metageneration json.Number `json:"metageneration"`
	Size           json.Number `json:"size"`
	CRC32CHash     string      `json:"crc32c_hash"`
}

type iamPolicyWireV560 struct {
	Bindings []iamBindingWireV560 `json:"bindings"`
	Etag     string               `json:"etag"`
}

type iamBindingWireV560 struct {
	Role      string                `json:"role"`
	Members   []string              `json:"members"`
	Condition *iamConditionWireV560 `json:"condition"`
}

type iamConditionWireV560 struct {
	Expression  string `json:"expression"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

const gcloudTimeLayout = "2006-01-02T15:04:05-0700"

// parseBucketState decodes a filtered `buckets list` answer: exactly one
// bucket with the expected name, or an empty array meaning absent.
func parseBucketState(data []byte, expectedName string) (control.BucketState, bool, error) {
	var items []bucketWireV560
	if err := decodeVersionJSON(data, &items); err != nil {
		return control.BucketState{}, false, storageError(StorageFailureSchema, "bucket JSON")
	}
	if len(items) == 0 {
		return control.BucketState{}, false, nil
	}
	if len(items) != 1 {
		return control.BucketState{}, false, storageError(StorageFailureSchema, "bucket list is ambiguous")
	}
	wire := items[0]
	if wire.Name != expectedName || wire.Name == "" || wire.Location == "" {
		return control.BucketState{}, false, storageError(StorageFailureSchema, "bucket identity")
	}
	state, err := bucketStateFromWire(wire)
	if err != nil {
		return control.BucketState{}, false, err
	}
	return state, true, nil
}

func bucketStateFromWire(wire bucketWireV560) (control.BucketState, error) {
	metageneration, err := numberInt64(wire.Metageneration, true)
	if err != nil || metageneration <= 0 {
		return control.BucketState{}, storageError(StorageFailureSchema, "bucket metageneration")
	}
	retention, err := numberInt64(wire.RetentionPeriod, false)
	if err != nil || retention < 0 {
		return control.BucketState{}, storageError(StorageFailureSchema, "bucket retention")
	}
	created, err := parseGcloudTime(wire.CreationTime)
	if err != nil {
		return control.BucketState{}, storageError(StorageFailureSchema, "bucket creation time")
	}
	state := control.BucketState{
		Identity:                 control.BucketIdentity{Name: wire.Name, Location: strings.ToLower(wire.Location)},
		UniformBucketLevelAccess: boolValue(wire.UniformBucketLevelAccess),
		PublicAccessPrevention:   wire.PublicAccessPrevention,
		StorageClass:             wire.DefaultStorageClass,
		Versioning:               boolValue(wire.VersioningEnabled),
		RetentionSeconds:         retention,
		RetentionLocked:          boolValue(wire.RetentionPolicyIsLocked),
		Metageneration:           metageneration,
		TimeCreated:              created,
	}
	if wire.LifecycleConfig != nil {
		for _, rule := range wire.LifecycleConfig.Rule {
			switch rule.Action.Type {
			case "SetStorageClass":
				age, err := numberInt64(rule.Condition.Age, true)
				if err != nil || rule.Action.StorageClass != "ARCHIVE" {
					return control.BucketState{}, storageError(StorageFailureSchema, "lifecycle rule")
				}
				state.LifecycleArchiveAfterDay = age
			case "Delete":
				state.LifecycleDeleteRule = true
			default:
				return control.BucketState{}, storageError(StorageFailureSchema, "lifecycle action")
			}
		}
	}
	return state, nil
}

// BucketProject cannot be read from the gcloud bucket resource; the session
// binds the project explicitly from the authorization target instead.
func (session *StorageSession) bindProject(state control.BucketState) control.BucketState {
	state.Identity.Project = session.project
	return state
}

// parseObjectDescriptor decodes an exact-URL `objects list` answer: exactly
// one object with the expected identity, or an empty array meaning absent.
// gcloud 560 emits generation as a JSON string and size as a number.
func parseObjectDescriptor(data []byte, expectedBucket, expectedName string) (control.ObjectDescriptor, bool, error) {
	var items []objectWireV560
	if err := decodeVersionJSON(data, &items); err != nil {
		return control.ObjectDescriptor{}, false, storageError(StorageFailureSchema, "object JSON")
	}
	if len(items) == 0 {
		return control.ObjectDescriptor{}, false, nil
	}
	if len(items) != 1 {
		return control.ObjectDescriptor{}, false, storageError(StorageFailureSchema, "object list is ambiguous")
	}
	wire := items[0]
	if wire.Name != expectedName || wire.Bucket != expectedBucket {
		return control.ObjectDescriptor{}, false, storageError(StorageFailureSchema, "object identity")
	}
	generation, err := strconv.ParseInt(wire.Generation, 10, 64)
	if err != nil || generation <= 0 {
		return control.ObjectDescriptor{}, false, storageError(StorageFailureSchema, "object generation")
	}
	size, err := numberInt64(wire.Size, true)
	if err != nil || size < 0 {
		return control.ObjectDescriptor{}, false, storageError(StorageFailureSchema, "object size")
	}
	crc, err := base64.StdEncoding.DecodeString(wire.CRC32CHash)
	if err != nil || len(crc) != 4 {
		return control.ObjectDescriptor{}, false, storageError(StorageFailureSchema, "object crc32c")
	}
	return control.ObjectDescriptor{Generation: control.Generation(generation), Size: size, CRC32C: binary.BigEndian.Uint32(crc)}, true, nil
}

func parseBucketBindings(data []byte, bucket string) ([]control.BucketBinding, error) {
	var wire iamPolicyWireV560
	if err := decodeVersionJSON(data, &wire); err != nil {
		return nil, storageError(StorageFailureSchema, "IAM policy JSON")
	}
	result := make([]control.BucketBinding, 0)
	for _, binding := range wire.Bindings {
		if binding.Role == "" || len(binding.Members) == 0 {
			return nil, storageError(StorageFailureSchema, "IAM binding")
		}
		title, expression := "", ""
		if binding.Condition != nil {
			title, expression = binding.Condition.Title, binding.Condition.Expression
		}
		for _, member := range binding.Members {
			result = append(result, control.BucketBinding{Bucket: bucket, Role: binding.Role, Member: member,
				Prefix: control.PrefixFromCondition(bucket, expression), ConditionTitle: title, ConditionExpression: expression})
		}
	}
	return result, nil
}

func numberInt64(value json.Number, required bool) (int64, error) {
	if value == "" {
		if required {
			return 0, errors.New("missing number")
		}
		return 0, nil
	}
	return strconv.ParseInt(string(value), 10, 64)
}

func boolValue(value *bool) bool { return value != nil && *value }

func parseGcloudTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("missing time")
	}
	parsed, err := time.Parse(gcloudTimeLayout, value)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339, value)
	}
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}
