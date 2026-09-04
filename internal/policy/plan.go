// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package policy validates plans and applies safety policy without performing I/O.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/redact"
)

var (
	// ErrInvalidPlan is returned when a plan violates its closed schema or
	// safety invariants.
	ErrInvalidPlan = errors.New("invalid plan")

	// ErrExpiredPlan is returned when a structurally valid plan has reached its
	// immutable expiry boundary.
	ErrExpiredPlan = errors.New("expired plan")
)

var (
	planIDPattern        = regexp.MustCompile(`^plan-[0-9a-f]{16}$`)
	planHashPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	workflowIDPattern    = regexp.MustCompile(`^WF-[A-Z0-9]+-[0-9]{2}$`)
	projectIDPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	environmentPattern   = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	identifierPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	resourceScopePattern = regexp.MustCompile(
		`^projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/(?:global|regions/[a-z][a-z0-9-]{0,62}|zones/[a-z][a-z0-9-]{0,62}|locations/[a-z][a-z0-9-]{0,62})$`,
	)
	permissionPattern     = regexp.MustCompile(`^[a-z][a-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*){2,}$`)
	datePattern           = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	evidenceRefPattern    = regexp.MustCompile(`^[a-z0-9][A-Za-z0-9._/-]{0,511}$`)
	serviceAccountPattern = regexp.MustCompile(
		`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`,
	)
	zeroPlanHash    = strings.Repeat("0", sha256.Size*2)
	rfc1918Networks = [...]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
)

const (
	maxRecoveryAssets  = 64
	maxExposureTargets = 64
	maxExposureSources = 64
	maxExposurePorts   = 16
)

type planJSONSchema struct {
	fields  map[string]*planJSONSchema
	element *planJSONSchema
}

var (
	planJSONScalar      = &planJSONSchema{}
	planJSONStringArray = &planJSONSchema{element: planJSONScalar}
	planJSONResource    = planJSONObject(map[string]*planJSONSchema{
		"kind": planJSONScalar, "scope": planJSONScalar, "name": planJSONScalar, "fingerprint": planJSONScalar,
	})
	planJSONRecoveryAsset = planJSONObject(map[string]*planJSONSchema{
		"kind": planJSONScalar, "resource": planJSONResource, "protects": {element: planJSONResource}, "evidenceRef": planJSONScalar,
		"verifiedAt": planJSONScalar, "restoreTo": planJSONScalar,
	})
	planJSONExposureSource = planJSONObject(map[string]*planJSONSchema{
		"kind": planJSONScalar, "value": planJSONScalar,
	})
	planJSONExposurePort = planJSONObject(map[string]*planJSONSchema{
		"protocol": planJSONScalar, "number": planJSONScalar,
	})
	planJSONRetry = planJSONObject(map[string]*planJSONSchema{
		"maxAttempts": planJSONScalar, "initialBackoffSeconds": planJSONScalar, "maxBackoffSeconds": planJSONScalar,
	})
	planJSONRoot = planJSONObject(map[string]*planJSONSchema{
		"planId": planJSONScalar, "planHash": planJSONScalar, "workflowId": planJSONScalar,
		"projectId": planJSONScalar, "environment": planJSONScalar, "environmentClass": planJSONScalar,
		"principal": planJSONScalar, "createdAt": planJSONScalar, "approvalClass": planJSONScalar,
		"expiresAt": planJSONScalar, "coolingOffSeconds": planJSONScalar, "stepUpRequired": planJSONScalar,
		"exposure": planJSONScalar, "pointOfNoReturn": planJSONScalar,
		"pointOfNoReturnTrigger": planJSONScalar,
		"exposureControls": planJSONObject(map[string]*planJSONSchema{
			"profile": planJSONScalar, "targets": {element: planJSONResource},
			"sources": {element: planJSONExposureSource}, "ports": {element: planJSONExposurePort},
			"authentication": planJSONScalar,
			"tls": planJSONObject(map[string]*planJSONSchema{
				"required": planJSONScalar, "hostnameVerification": planJSONScalar, "trust": planJSONScalar,
			}),
			"expiresAt": planJSONScalar, "reviewAt": planJSONScalar, "auditLogging": planJSONScalar,
			"revocationWorkflowId": planJSONScalar, "simulationPreconditionId": planJSONScalar,
			"internetWide": planJSONScalar, "permanentInternetWideAcknowledged": planJSONScalar,
		}),
		"identity": planJSONObject(map[string]*planJSONSchema{
			"default": planJSONScalar, "hostControlSteps": planJSONScalar,
			"deleteSteps": planJSONScalar, "bootstrapSteps": planJSONScalar,
		}),
		"policyHash": planJSONObject(map[string]*planJSONSchema{
			"local": planJSONScalar, "approved": planJSONScalar, "match": planJSONScalar,
		}),
		"intent": planJSONObject(map[string]*planJSONSchema{
			"validUntil": planJSONScalar, "windowStart": planJSONScalar,
		}),
		"resources": {element: planJSONResource},
		"preconditions": {element: planJSONObject(map[string]*planJSONSchema{
			"id": planJSONScalar, "ok": planJSONScalar, "detail": planJSONScalar,
		})},
		"permissions": {element: planJSONObject(map[string]*planJSONSchema{
			"stepId": planJSONScalar, "identity": planJSONScalar, "permission": planJSONScalar,
			"resource": planJSONResource, "granted": planJSONScalar,
		})},
		"steps": {element: planJSONObject(map[string]*planJSONSchema{
			"id": planJSONScalar, "executor": planJSONScalar, "executingIdentity": planJSONScalar,
			"commandRedacted": planJSONScalar, "idempotent": planJSONScalar, "retry": planJSONRetry,
			"cancelSafe": planJSONScalar, "timeoutSeconds": planJSONScalar, "successCondition": planJSONScalar,
			"failureBehavior": planJSONScalar, "targets": {element: planJSONResource},
		})},
		"cost": planJSONObject(map[string]*planJSONSchema{
			"runRate": planJSONObject(map[string]*planJSONSchema{
				"amountUSD": planJSONScalar, "period": planJSONScalar,
			}),
			"items": {element: planJSONObject(map[string]*planJSONSchema{
				"resource": planJSONScalar, "kind": planJSONScalar, "amountUSD": planJSONScalar,
			})},
			"incremental": planJSONObject(map[string]*planJSONSchema{
				"amountUSD": planJSONScalar, "period": planJSONScalar, "plan": planJSONScalar,
			}),
			"source": planJSONScalar, "priceTableDate": planJSONScalar, "stale": planJSONScalar,
			"assumptions": planJSONStringArray, "unpriced": planJSONStringArray,
			"budget": planJSONObject(map[string]*planJSONSchema{
				"state": planJSONScalar, "reason": planJSONScalar, "ceilingUSD": planJSONScalar,
			}),
		}),
		"downtime": planJSONObject(map[string]*planJSONSchema{
			"expectedSeconds": planJSONScalar, "kind": planJSONScalar,
		}),
		"protection": planJSONStringArray,
		"rollback": planJSONObject(map[string]*planJSONSchema{
			"boundary": planJSONScalar, "assets": {element: planJSONRecoveryAsset},
		}),
		"verification": planJSONStringArray,
	})
)

func planJSONObject(fields map[string]*planJSONSchema) *planJSONSchema {
	return &planJSONSchema{fields: fields}
}

// SealPlan structurally validates plan and returns a copy carrying the digest
// of its complete reviewable contents. The input value is never modified.
func SealPlan(plan domain.Plan) (domain.Plan, error) {
	plan = normalizePlanCollections(plan)
	plan.PlanHash = zeroPlanHash
	if err := validatePlanStructure(plan); err != nil {
		return domain.Plan{}, err
	}

	digest, err := computePlanHash(plan)
	if err != nil {
		return domain.Plan{}, err
	}
	plan.PlanHash = digest

	return plan, nil
}

// SealPlanAt returns a sealed copy whose creation and expiry boundaries are
// derived from one trusted clock reading and the configured plan validity.
func SealPlanAt(plan domain.Plan, createdAt time.Time, planValidity time.Duration) (domain.Plan, error) {
	if err := validateUTCTime("createdAt", createdAt); err != nil {
		return domain.Plan{}, err
	}
	if planValidity <= 0 {
		return domain.Plan{}, invalid("planValidity", "must be positive")
	}

	expiresAt := createdAt.Add(planValidity)
	if !expiresAt.After(createdAt) {
		return domain.Plan{}, invalid("planValidity", "overflows the expiry boundary")
	}
	plan.CreatedAt = createdAt
	plan.ExpiresAt = expiresAt

	return SealPlan(plan)
}

// ComputePlanHash returns the digest SealPlan would assign without modifying
// plan. Any existing PlanHash value is deliberately ignored.
func ComputePlanHash(plan domain.Plan) (string, error) {
	plan = normalizePlanCollections(plan)
	plan.PlanHash = zeroPlanHash
	if err := validatePlanStructure(plan); err != nil {
		return "", err
	}

	return computePlanHash(plan)
}

// VerifyPlanHash validates both the plan structure and its content digest.
func VerifyPlanHash(plan domain.Plan) error {
	if err := validatePlanStructure(plan); err != nil {
		return err
	}

	digest, err := computePlanHash(plan)
	if err != nil {
		return err
	}
	if plan.PlanHash != digest {
		return invalid("planHash", "does not match the plan contents")
	}

	return nil
}

func computePlanHash(plan domain.Plan) (string, error) {
	plan.PlanHash = ""
	encoded, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("%w: hash encoding: %v", ErrInvalidPlan, err)
	}

	digest := sha256.Sum256(encoded)

	return fmt.Sprintf("%x", digest), nil
}

// EncodePlan validates plan and serializes it as compact JSON.
func EncodePlan(plan domain.Plan) ([]byte, error) {
	if err := ValidatePlan(plan); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidPlan, err)
	}

	return encoded, nil
}

func normalizePlanCollections(plan domain.Plan) domain.Plan {
	if plan.Resources == nil {
		plan.Resources = []domain.PlanResource{}
	}
	if plan.Preconditions == nil {
		plan.Preconditions = []domain.PlanPrecondition{}
	}
	if plan.Permissions == nil {
		plan.Permissions = []domain.PlanPermission{}
	}
	if plan.Steps == nil {
		plan.Steps = []domain.PlanStep{}
	} else {
		steps := make([]domain.PlanStep, len(plan.Steps))
		copy(steps, plan.Steps)
		plan.Steps = steps
		for index := range plan.Steps {
			if plan.Steps[index].Targets == nil {
				plan.Steps[index].Targets = []domain.PlanResource{}
			}
		}
	}
	if plan.Cost.Items == nil {
		plan.Cost.Items = []domain.PlanCostItem{}
	}
	if plan.Cost.Assumptions == nil {
		plan.Cost.Assumptions = []redact.Text{}
	}
	if plan.Cost.Unpriced == nil {
		plan.Cost.Unpriced = []string{}
	}
	if plan.Protection == nil {
		plan.Protection = []redact.Text{}
	}
	if plan.Rollback.Assets == nil {
		plan.Rollback.Assets = []domain.PlanRecoveryAsset{}
	} else {
		assets := make([]domain.PlanRecoveryAsset, len(plan.Rollback.Assets))
		copy(assets, plan.Rollback.Assets)
		plan.Rollback.Assets = assets
		for index := range plan.Rollback.Assets {
			if plan.Rollback.Assets[index].Protects == nil {
				plan.Rollback.Assets[index].Protects = []domain.PlanResource{}
			}
		}
	}
	if plan.Verification == nil {
		plan.Verification = []redact.Text{}
	}
	if plan.ExposureControls != nil {
		controls := *plan.ExposureControls
		if controls.Targets == nil {
			controls.Targets = []domain.PlanResource{}
		}
		if controls.Sources == nil {
			controls.Sources = []domain.PlanExposureSource{}
		}
		if controls.Ports == nil {
			controls.Ports = []domain.PlanExposurePort{}
		}
		plan.ExposureControls = &controls
	}

	return plan
}

// DecodePlan rejects unknown fields and trailing values, then validates the
// complete plan before returning it.
func DecodePlan(encoded []byte) (domain.Plan, error) {
	if err := rejectDuplicateJSONKeys(encoded); err != nil {
		return domain.Plan{}, err
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	var plan domain.Plan
	if err := decoder.Decode(&plan); err != nil {
		return domain.Plan{}, invalid("decode", "contains an invalid typed value")
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return domain.Plan{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidPlan)
	}
	if err := validateRequiredPlanJSON(encoded); err != nil {
		return domain.Plan{}, err
	}

	if err := ValidatePlan(plan); err != nil {
		return domain.Plan{}, err
	}
	canonical, err := json.Marshal(plan)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return domain.Plan{}, invalid("decode", "must use canonical PlanV1 JSON")
	}

	return plan, nil
}

func rejectDuplicateJSONKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := consumeUniqueJSONValue(decoder, planJSONRoot); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid("decode", "trailing JSON value")
	}

	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder, schema *planJSONSchema) error {
	token, err := decoder.Token()
	if err != nil {
		return invalid("decode", "contains malformed JSON")
	}
	if token == nil {
		return invalid("decode", "null is not allowed at this schema position")
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		if schema == nil || schema.fields != nil || schema.element != nil {
			return invalid("decode", "scalar has the wrong schema type")
		}
		return nil
	}

	switch delimiter {
	case '{':
		if schema == nil || schema.fields == nil {
			return invalid("decode", "object is not allowed at this schema position")
		}
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return invalid("decode", "contains malformed JSON")
			}
			key, ok := keyToken.(string)
			if !ok {
				return invalid("decode", "object key must be a string")
			}
			childSchema, canonical := schema.fields[key]
			if !canonical {
				return invalid("decode", "object contains a noncanonical key")
			}
			if _, exists := seen[key]; exists {
				return invalid("decode", "object contains a duplicate key")
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder, childSchema); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return invalid("decode", "contains malformed JSON")
		}
	case '[':
		if schema == nil || schema.element == nil {
			return invalid("decode", "array is not allowed at this schema position")
		}
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder, schema.element); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return invalid("decode", "contains malformed JSON")
		}
	default:
		return invalid("decode", "contains an unexpected delimiter")
	}

	return nil
}

func validateRequiredPlanJSON(encoded []byte) error {
	var plan map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &plan); err != nil {
		return invalid("decode", "contains malformed JSON")
	}
	if err := requireJSONFields(plan, "plan",
		"planId", "planHash", "workflowId", "projectId", "environment", "environmentClass", "principal", "createdAt",
		"approvalClass", "expiresAt", "coolingOffSeconds", "identity", "policyHash",
		"stepUpRequired", "resources", "preconditions", "permissions", "steps", "cost",
		"downtime", "exposure", "protection", "rollback", "verification",
	); err != nil {
		return err
	}

	if err := requireNestedJSONFields(plan["identity"], "identity",
		"default", "hostControlSteps", "deleteSteps", "bootstrapSteps",
	); err != nil {
		return err
	}
	if err := requireNestedJSONFields(plan["policyHash"], "policyHash", "match"); err != nil {
		return err
	}
	if intent, exists := plan["intent"]; exists {
		if err := requireNestedJSONFields(intent, "intent", "validUntil", "windowStart"); err != nil {
			return err
		}
	}
	if _, exists := plan["pointOfNoReturn"]; exists {
		if _, triggerExists := plan["pointOfNoReturnTrigger"]; !triggerExists {
			return invalid("pointOfNoReturnTrigger", "is required with pointOfNoReturn")
		}
	}
	if err := requireJSONArrayFields(plan["resources"], "resources", "kind", "scope", "name", "fingerprint"); err != nil {
		return err
	}
	if err := requireJSONArrayFields(plan["preconditions"], "preconditions", "id", "ok", "detail"); err != nil {
		return err
	}
	if err := requireJSONArrayFields(plan["permissions"], "permissions", "stepId", "identity", "permission", "resource", "granted"); err != nil {
		return err
	}
	var permissions []map[string]json.RawMessage
	if err := json.Unmarshal(plan["permissions"], &permissions); err != nil {
		return invalid("permissions", "must be an array")
	}
	for index, permission := range permissions {
		if err := requireNestedJSONFields(permission["resource"], fmt.Sprintf("permissions[%d].resource", index),
			"kind", "scope", "name", "fingerprint",
		); err != nil {
			return err
		}
	}

	var steps []map[string]json.RawMessage
	if err := json.Unmarshal(plan["steps"], &steps); err != nil {
		return invalid("steps", "must be an array")
	}
	for index, step := range steps {
		path := fmt.Sprintf("steps[%d]", index)
		if err := requireJSONFields(step, path,
			"id", "executor", "executingIdentity", "commandRedacted", "idempotent", "retry",
			"cancelSafe", "timeoutSeconds", "successCondition", "failureBehavior", "targets",
		); err != nil {
			return err
		}
		if err := requireNestedJSONFields(step["retry"], path+".retry",
			"maxAttempts", "initialBackoffSeconds", "maxBackoffSeconds",
		); err != nil {
			return err
		}
		if err := requireJSONArrayFields(step["targets"], path+".targets", "kind", "scope", "name", "fingerprint"); err != nil {
			return err
		}
	}
	if err := validateRequiredCostJSON(plan["cost"]); err != nil {
		return err
	}
	if err := requireNestedJSONFields(plan["downtime"], "downtime", "expectedSeconds", "kind"); err != nil {
		return err
	}
	if err := requireNestedJSONFields(plan["rollback"], "rollback", "boundary", "assets"); err != nil {
		return err
	}
	var rollback map[string]json.RawMessage
	if err := json.Unmarshal(plan["rollback"], &rollback); err != nil {
		return invalid("rollback", "must be an object")
	}
	if err := validateRequiredRecoveryAssetsJSON(rollback["assets"]); err != nil {
		return err
	}
	if controls, exists := plan["exposureControls"]; exists {
		if err := validateRequiredExposureControlsJSON(controls); err != nil {
			return err
		}
	}

	return nil
}

func validateRequiredRecoveryAssetsJSON(encoded json.RawMessage) error {
	var assets []map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &assets); err != nil {
		return invalid("rollback.assets", "must be an array")
	}
	for index, asset := range assets {
		path := fmt.Sprintf("rollback.assets[%d]", index)
		if err := requireJSONFields(asset, path, "kind", "resource", "protects", "evidenceRef", "verifiedAt"); err != nil {
			return err
		}
		if err := requireNestedJSONFields(asset["resource"], path+".resource",
			"kind", "scope", "name", "fingerprint",
		); err != nil {
			return err
		}
		if err := requireJSONArrayFields(asset["protects"], path+".protects",
			"kind", "scope", "name", "fingerprint",
		); err != nil {
			return err
		}
		var kind domain.RecoveryAssetKind
		if err := json.Unmarshal(asset["kind"], &kind); err == nil && kind == domain.RecoveryAssetPBMRecoveryPoint {
			if _, exists := asset["restoreTo"]; !exists {
				return invalid(path+".restoreTo", "is required for a PBM recovery point")
			}
		}
	}

	return nil
}

func validateRequiredExposureControlsJSON(encoded json.RawMessage) error {
	var controls map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &controls); err != nil {
		return invalid("exposureControls", "must be an object")
	}
	if err := requireJSONFields(controls, "exposureControls",
		"profile", "targets", "sources", "ports", "authentication", "tls", "auditLogging",
		"revocationWorkflowId", "simulationPreconditionId", "internetWide",
		"permanentInternetWideAcknowledged",
	); err != nil {
		return err
	}
	if err := requireJSONArrayFields(controls["targets"], "exposureControls.targets",
		"kind", "scope", "name", "fingerprint",
	); err != nil {
		return err
	}
	if err := requireJSONArrayFields(controls["sources"], "exposureControls.sources", "kind", "value"); err != nil {
		return err
	}
	if err := requireJSONArrayFields(controls["ports"], "exposureControls.ports", "protocol", "number"); err != nil {
		return err
	}

	return requireNestedJSONFields(controls["tls"], "exposureControls.tls",
		"required", "hostnameVerification", "trust",
	)
}

func validateRequiredCostJSON(encoded json.RawMessage) error {
	var cost map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &cost); err != nil {
		return invalid("cost", "must be an object")
	}
	if err := requireJSONFields(cost, "cost",
		"runRate", "items", "source", "priceTableDate", "stale", "assumptions", "unpriced", "budget",
	); err != nil {
		return err
	}
	if err := requireNestedJSONFields(cost["runRate"], "cost.runRate", "amountUSD", "period"); err != nil {
		return err
	}
	if err := requireJSONArrayFields(cost["items"], "cost.items", "resource", "kind", "amountUSD"); err != nil {
		return err
	}
	if incremental, exists := cost["incremental"]; exists {
		if err := requireNestedJSONFields(incremental, "cost.incremental", "amountUSD", "period", "plan"); err != nil {
			return err
		}
	}

	return requireNestedJSONFields(cost["budget"], "cost.budget", "state")
}

func requireJSONArrayFields(encoded json.RawMessage, path string, fields ...string) error {
	var values []map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &values); err != nil {
		return invalid(path, "must be an array")
	}
	for index, value := range values {
		if err := requireJSONFields(value, fmt.Sprintf("%s[%d]", path, index), fields...); err != nil {
			return err
		}
	}

	return nil
}

func requireNestedJSONFields(encoded json.RawMessage, path string, fields ...string) error {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &value); err != nil {
		return invalid(path, "must be an object")
	}

	return requireJSONFields(value, path, fields...)
}

func requireJSONFields(value map[string]json.RawMessage, path string, fields ...string) error {
	for _, field := range fields {
		if _, exists := value[field]; !exists {
			return invalid(path+"."+field, "is required")
		}
	}

	return nil
}

// ValidatePlan checks the resource-independent PlanV1 invariants and content
// digest.
func ValidatePlan(plan domain.Plan) error {
	return VerifyPlanHash(plan)
}

func validatePlanStructure(plan domain.Plan) error {
	if err := validateCanonicalPlanCollections(plan); err != nil {
		return err
	}
	if !planIDPattern.MatchString(plan.PlanID) {
		return invalid("planId", "must match plan-<16 lowercase hex>")
	}
	if !planHashPattern.MatchString(plan.PlanHash) {
		return invalid("planHash", "must be 64 lowercase hex characters")
	}
	if !workflowIDPattern.MatchString(plan.WorkflowID) {
		return invalid("workflowId", "must match WF-<GROUP>-<NN>")
	}
	if !projectIDPattern.MatchString(plan.ProjectID) {
		return invalid("projectId", "must be a canonical project identifier")
	}
	if !environmentPattern.MatchString(plan.Environment) {
		return invalid("environment", "must be a canonical environment name")
	}
	if !plan.EnvironmentClass.Valid() {
		return invalid("environmentClass", "unknown value")
	}
	if err := validatePrincipal(plan.Principal); err != nil {
		return err
	}
	if err := validateUTCTime("createdAt", plan.CreatedAt); err != nil {
		return err
	}
	if !plan.ApprovalClass.Valid() {
		return invalid("approvalClass", "unknown value")
	}
	if err := validateUTCTime("expiresAt", plan.ExpiresAt); err != nil {
		return err
	}
	if !plan.ExpiresAt.After(plan.CreatedAt) {
		return invalid("expiresAt", "must be later than createdAt")
	}
	if plan.CoolingOffSeconds < 0 {
		return invalid("coolingOffSeconds", "must not be negative")
	}
	if plan.CoolingOffSeconds > int64(plan.ExpiresAt.Sub(plan.CreatedAt)/time.Second) {
		return invalid("coolingOffSeconds", "must fit within plan validity")
	}
	if err := validateIdentityPlan(plan.Identity); err != nil {
		return err
	}
	if err := validatePolicyHash(plan.PolicyHash); err != nil {
		return err
	}
	if plan.EnvironmentClass != domain.EnvironmentProduction && plan.StepUpRequired {
		return invalid("stepUpRequired", "must be false outside production")
	}
	if plan.EnvironmentClass == domain.EnvironmentProduction {
		if plan.ApprovalClass < domain.ApprovalDestructive && plan.StepUpRequired {
			return invalid("stepUpRequired", "requires a production AP-4 or stronger plan")
		}
	}
	if plan.Intent != nil {
		if err := validateIntent(*plan.Intent); err != nil {
			return err
		}
	}
	if err := validateResources(plan.Resources, plan.ProjectID); err != nil {
		return err
	}
	if plan.ApprovalClass != domain.ApprovalRead && len(plan.Resources) == 0 {
		return invalid("resources", "must identify at least one fingerprinted mutation target")
	}
	if err := validatePreconditions(plan.Preconditions); err != nil {
		return err
	}
	if err := validateSteps(plan.Steps, plan.PointOfNoReturn, plan.Resources); err != nil {
		return err
	}
	if plan.PointOfNoReturn == "" {
		if plan.PointOfNoReturnTrigger != "" {
			return invalid("pointOfNoReturnTrigger", "must be absent without pointOfNoReturn")
		}
	} else if !plan.PointOfNoReturnTrigger.Valid() {
		return invalid("pointOfNoReturnTrigger", "unknown value")
	}
	if err := validatePermissions(plan.Permissions, plan.ApprovalClass, plan.Steps, plan.Resources); err != nil {
		return err
	}
	if err := validateCost(plan.Cost); err != nil {
		return err
	}
	if plan.Downtime.ExpectedSeconds < 0 {
		return invalid("downtime.expectedSeconds", "must not be negative")
	}
	if plan.Downtime.Kind == "" {
		return invalid("downtime.kind", "must not be empty")
	}
	if !plan.Exposure.Valid() {
		return invalid("exposure", "unknown value")
	}
	if err := validateExposureControls(plan); err != nil {
		return err
	}
	if plan.ApprovalClass >= domain.ApprovalProtected && len(plan.Protection) == 0 {
		return invalid("protection", "must describe at least one safeguard for AP-2 or stronger")
	}
	if plan.Rollback.Boundary == "" {
		return invalid("rollback.boundary", "must not be empty; use none when unavailable")
	}
	if err := validateRecoveryAssets(plan); err != nil {
		return err
	}
	if len(plan.Verification) == 0 {
		return invalid("verification", "must contain at least one independent check")
	}

	return nil
}

func validateCanonicalPlanCollections(plan domain.Plan) error {
	if plan.Resources == nil || plan.Preconditions == nil || plan.Permissions == nil || plan.Steps == nil ||
		plan.Cost.Items == nil || plan.Cost.Assumptions == nil || plan.Cost.Unpriced == nil ||
		plan.Protection == nil || plan.Rollback.Assets == nil || plan.Verification == nil {
		return invalid("collections", "required arrays must use canonical non-null encoding")
	}
	for _, step := range plan.Steps {
		if step.Targets == nil {
			return invalid("steps.targets", "required arrays must use canonical non-null encoding")
		}
	}
	for _, asset := range plan.Rollback.Assets {
		if asset.Protects == nil {
			return invalid("rollback.assets.protects", "required arrays must use canonical non-null encoding")
		}
	}
	if plan.ExposureControls != nil && (plan.ExposureControls.Targets == nil ||
		plan.ExposureControls.Sources == nil || plan.ExposureControls.Ports == nil) {
		return invalid("exposureControls", "required arrays must use canonical non-null encoding")
	}

	return nil
}

func validateRecoveryAssets(plan domain.Plan) error {
	assets := plan.Rollback.Assets
	if len(assets) > maxRecoveryAssets {
		return invalid("rollback.assets", "exceeds the bounded asset count")
	}
	if plan.ApprovalClass == domain.ApprovalDataDestructive && len(assets) == 0 {
		return invalid("rollback.assets", "requires recovery proof for a data-destructive plan")
	}
	resources := make([]domain.PlanResource, len(assets))
	planResources := make(map[string]domain.PlanResource, len(plan.Resources))
	for _, resource := range plan.Resources {
		planResources[planResourceKey(resource)] = resource
	}
	seen := make(map[string]struct{}, len(assets))
	targetedResources := make(map[string]struct{})
	for _, step := range plan.Steps {
		for _, target := range step.Targets {
			targetedResources[planResourceKey(target)] = struct{}{}
		}
	}
	for index, asset := range assets {
		path := fmt.Sprintf("rollback.assets[%d]", index)
		if !asset.Kind.Valid() {
			return invalid(path+".kind", "unknown value")
		}
		resources[index] = asset.Resource
		key := string(asset.Kind) + "\x00" + planResourceKey(asset.Resource)
		if _, duplicate := seen[key]; duplicate {
			return invalid(path, "duplicates a recovery asset")
		}
		seen[key] = struct{}{}
		if _, targeted := targetedResources[planResourceKey(asset.Resource)]; targeted {
			return invalid(path+".resource", "must not be a target of the same plan")
		}
		if len(asset.Protects) == 0 || len(asset.Protects) > maxExposureTargets {
			return invalid(path+".protects", "must contain bounded protected plan resources")
		}
		seenProtected := make(map[string]struct{}, len(asset.Protects))
		for _, protected := range asset.Protects {
			if protected == asset.Resource {
				return invalid(path+".protects", "must not claim that a recovery asset protects itself")
			}
			protectedKey := planResourceKey(protected)
			if planned, exists := planResources[protectedKey]; !exists || protected != planned {
				return invalid(path+".protects", "must exactly match fingerprinted plan resources")
			}
			if _, duplicate := seenProtected[protectedKey]; duplicate {
				return invalid(path+".protects", "contains a duplicate protected resource")
			}
			seenProtected[protectedKey] = struct{}{}
		}
		if !safeEvidenceReference(asset.EvidenceRef) {
			return invalid(path+".evidenceRef", "must be a canonical non-secret object reference")
		}
		if err := validateUTCTime(path+".verifiedAt", asset.VerifiedAt); err != nil {
			return err
		}
		if asset.VerifiedAt.After(plan.CreatedAt) ||
			plan.CreatedAt.Sub(asset.VerifiedAt) > plan.ExpiresAt.Sub(plan.CreatedAt) {
			return invalid(path+".verifiedAt", "must be current within the plan validity interval")
		}
		switch asset.Kind {
		case domain.RecoveryAssetPBMRecoveryPoint:
			if asset.Resource.Kind != "pbm-recovery-point" || asset.RestoreTo == nil {
				return invalid(path, "PBM proof requires a recovery-point resource and restoreTo")
			}
			if err := validateUTCTime(path+".restoreTo", *asset.RestoreTo); err != nil {
				return err
			}
			if asset.RestoreTo.Before(plan.CreatedAt) || asset.RestoreTo.After(plan.ExpiresAt) {
				return invalid(path+".restoreTo", "must cover plan creation within plan validity")
			}
		case domain.RecoveryAssetSnapshot:
			if asset.Resource.Kind != "snapshot" || asset.RestoreTo != nil {
				return invalid(path, "snapshot proof requires a snapshot resource and no restoreTo")
			}
			if plan.CreatedAt.Sub(asset.VerifiedAt) > time.Hour {
				return invalid(path+".verifiedAt", "snapshot proof must be at most one hour old")
			}
		}
	}
	if err := validateResources(resources, plan.ProjectID); err != nil && len(resources) != 0 {
		return invalid("rollback.assets", "must contain unique fingerprinted resources in the plan project")
	}

	return nil
}

func safeEvidenceReference(reference string) bool {
	if !evidenceRefPattern.MatchString(reference) || strings.Contains(reference, "//") {
		return false
	}
	for _, segment := range strings.Split(reference, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}

	return true
}

func validateExposureControls(plan domain.Plan) error {
	controls := plan.ExposureControls
	if plan.Exposure == domain.ExposureNone {
		if controls != nil {
			return invalid("exposureControls", "must be absent when exposure is none")
		}
		return nil
	}
	if plan.ApprovalClass < domain.ApprovalSecuritySensitive || controls == nil {
		return invalid("exposureControls", "requires AP-3 approval and complete controls")
	}
	if !controls.Profile.Valid() || !controls.Authentication.Valid() || !controls.TLS.Trust.Valid() {
		return invalid("exposureControls", "contains an unknown closed value")
	}
	if len(controls.Targets) == 0 || len(controls.Targets) > maxExposureTargets ||
		len(controls.Sources) == 0 || len(controls.Sources) > maxExposureSources ||
		len(controls.Ports) == 0 || len(controls.Ports) > maxExposurePorts {
		return invalid("exposureControls", "requires bounded non-empty targets, sources, and ports")
	}
	planResources := make(map[string]struct{}, len(plan.Resources))
	for _, resource := range plan.Resources {
		planResources[planResourceKey(resource)] = struct{}{}
	}
	seenTargets := make(map[string]struct{}, len(controls.Targets))
	for _, target := range controls.Targets {
		key := planResourceKey(target)
		if _, exists := planResources[key]; !exists {
			return invalid("exposureControls.targets", "must exactly match fingerprinted plan resources")
		}
		if _, duplicate := seenTargets[key]; duplicate {
			return invalid("exposureControls.targets", "contains a duplicate target")
		}
		seenTargets[key] = struct{}{}
	}
	wantsInternetWide := false
	seenSources := make(map[string]struct{}, len(controls.Sources))
	for _, source := range controls.Sources {
		if !source.Kind.Valid() || !validExposureSource(source) || !sourceAllowedForExposure(plan.Exposure, source.Kind) {
			return invalid("exposureControls.sources", "contains a noncanonical source")
		}
		key := string(source.Kind) + "\x00" + source.Value
		if _, duplicate := seenSources[key]; duplicate {
			return invalid("exposureControls.sources", "contains a duplicate source")
		}
		seenSources[key] = struct{}{}
		wantsInternetWide = wantsInternetWide || source.Kind == domain.ExposureSourceCIDR && source.Value == "0.0.0.0/0"
	}
	seenPorts := make(map[domain.PlanExposurePort]struct{}, len(controls.Ports))
	for _, port := range controls.Ports {
		if port.Protocol != "tcp" || port.Number != 27017 {
			return invalid("exposureControls.ports", "only tcp/27017 is supported")
		}
		if _, duplicate := seenPorts[port]; duplicate {
			return invalid("exposureControls.ports", "contains a duplicate port")
		}
		seenPorts[port] = struct{}{}
	}
	if !validExposureAuthentication(plan.Exposure, *controls) {
		return invalid("exposureControls.authentication", "does not match the exposure path")
	}
	if plan.Exposure == domain.ExposureExternal &&
		(!controls.TLS.Required || !controls.TLS.HostnameVerification || controls.TLS.Trust != domain.ExposureTrustPublic) {
		return invalid("exposureControls.tls", "external access requires public TLS with hostname verification")
	}
	if !controls.AuditLogging || controls.RevocationWorkflowID != "WF-ACC-04" {
		return invalid("exposureControls", "requires audit logging and the kill-switch revocation workflow")
	}
	if !passedPrecondition(plan.Preconditions, controls.SimulationPreconditionID) {
		return invalid("exposureControls.simulationPreconditionId", "must reference a passed plan precondition")
	}
	if controls.InternetWide != wantsInternetWide {
		return invalid("exposureControls.internetWide", "must exactly match a 0.0.0.0/0 source")
	}
	if !controls.InternetWide && controls.Profile == domain.ExposureProfileACC08 {
		return invalid("exposureControls.profile", "ACC-08 is reserved for internet-wide exposure")
	}
	if err := validateExposureLifetime(plan, *controls); err != nil {
		return err
	}

	return nil
}

func sourceAllowedForExposure(exposure domain.ExposureDelta, kind domain.ExposureSourceKind) bool {
	switch exposure {
	case domain.ExposurePrivate:
		return kind == domain.ExposureSourcePrivateRange || kind == domain.ExposureSourceTag ||
			kind == domain.ExposureSourceServiceAccount
	case domain.ExposureTunnel:
		return kind == domain.ExposureSourceIAP || kind == domain.ExposureSourceTunnel
	case domain.ExposureExternal:
		return kind == domain.ExposureSourceCIDR
	default:
		return false
	}
}

func validExposureSource(source domain.PlanExposureSource) bool {
	switch source.Kind {
	case domain.ExposureSourceCIDR, domain.ExposureSourcePrivateRange:
		prefix, err := netip.ParsePrefix(source.Value)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
			return false
		}
		if source.Kind == domain.ExposureSourcePrivateRange {
			return whollyWithinRFC1918(prefix)
		}
		return prefix.Bits() >= 24 || source.Value == "0.0.0.0/0"
	case domain.ExposureSourceTag, domain.ExposureSourceTunnel:
		return identifierPattern.MatchString(source.Value)
	case domain.ExposureSourceServiceAccount:
		return serviceAccountPattern.MatchString(source.Value)
	case domain.ExposureSourceIAP:
		return source.Value == "35.235.240.0/20"
	default:
		return false
	}
}

func whollyWithinRFC1918(prefix netip.Prefix) bool {
	for _, privateNetwork := range rfc1918Networks {
		if prefix.Bits() >= privateNetwork.Bits() && privateNetwork.Contains(prefix.Addr()) {
			return true
		}
	}

	return false
}

func validExposureAuthentication(exposure domain.ExposureDelta, controls domain.PlanExposureControls) bool {
	if exposure == domain.ExposureTunnel {
		return controls.Authentication == domain.ExposureAuthIAP
	}
	if exposure == domain.ExposureExternal {
		return controls.Authentication == domain.ExposureAuthSCRAM ||
			controls.Authentication == domain.ExposureAuthVPN || controls.Authentication == domain.ExposureAuthOverlay
	}

	return controls.Authentication != domain.ExposureAuthIAP
}

func passedPrecondition(preconditions []domain.PlanPrecondition, identifier string) bool {
	if !identifierPattern.MatchString(identifier) {
		return false
	}
	for _, precondition := range preconditions {
		if precondition.ID == identifier {
			return precondition.OK
		}
	}

	return false
}

func validateExposureLifetime(plan domain.Plan, controls domain.PlanExposureControls) error {
	hasExpiry := controls.ExpiresAt != nil
	hasReview := controls.ReviewAt != nil
	if controls.InternetWide {
		if controls.Profile != domain.ExposureProfileACC08 || plan.ApprovalClass != domain.ApprovalDataDestructive {
			return invalid("exposureControls.internetWide", "requires ACC-08 and AP-5")
		}
		if controls.PermanentInternetWideAcknowledged {
			if hasExpiry || hasReview {
				return invalid("exposureControls", "permanent internet-wide access cannot carry a lifetime")
			}
			return nil
		}
		if !hasExpiry || hasReview {
			return invalid("exposureControls.expiresAt", "internet-wide access requires an expiry")
		}
	} else if controls.PermanentInternetWideAcknowledged || hasExpiry == hasReview {
		return invalid("exposureControls", "requires exactly one expiry or review date")
	}
	if hasExpiry {
		if err := validateUTCTime("exposureControls.expiresAt", *controls.ExpiresAt); err != nil {
			return err
		}
		if !controls.ExpiresAt.After(plan.CreatedAt) {
			return invalid("exposureControls.expiresAt", "must be after plan creation")
		}
	}
	if hasReview {
		if err := validateUTCTime("exposureControls.reviewAt", *controls.ReviewAt); err != nil {
			return err
		}
		if !controls.ReviewAt.After(plan.CreatedAt) {
			return invalid("exposureControls.reviewAt", "must be after plan creation")
		}
	}

	return nil
}

// ValidatePlanAt applies structural validation and the immutable expiry gate.
func ValidatePlanAt(plan domain.Plan, now time.Time) error {
	if err := ValidatePlan(plan); err != nil {
		return err
	}
	if now.IsZero() {
		return invalid("currentTime", "must not be zero")
	}
	if !now.Before(plan.ExpiresAt) {
		return fmt.Errorf("%w: plan %s expired at %s", ErrExpiredPlan, plan.PlanID, plan.ExpiresAt.Format(time.RFC3339))
	}

	return nil
}

func validateIdentityPlan(identity domain.IdentityPlan) error {
	want := domain.DefaultIdentityPlan()
	if identity != want {
		return invalid(
			"identity",
			"must route default/operator, host-control/provisioner, delete/destructive, and bootstrap/human",
		)
	}

	return nil
}

func validatePolicyHash(policyHash domain.PlanPolicyHash) error {
	if policyHash.Local != "" && !planHashPattern.MatchString(policyHash.Local) {
		return invalid("policyHash.local", "must be empty or 64 lowercase hex characters")
	}
	if policyHash.Approved != "" && !planHashPattern.MatchString(policyHash.Approved) {
		return invalid("policyHash.approved", "must be empty or 64 lowercase hex characters")
	}

	matches := policyHash.Local != "" && policyHash.Local == policyHash.Approved
	if policyHash.Match != matches {
		return invalid("policyHash.match", "does not agree with local and approved hashes")
	}

	return nil
}

func validateIntent(intent domain.PlanIntent) error {
	if err := validateUTCTime("intent.windowStart", intent.WindowStart); err != nil {
		return err
	}
	if err := validateUTCTime("intent.validUntil", intent.ValidUntil); err != nil {
		return err
	}
	if !intent.ValidUntil.After(intent.WindowStart) {
		return invalid("intent.validUntil", "must be later than windowStart")
	}

	return nil
}

func validateResources(resources []domain.PlanResource, projectID string) error {
	seen := make(map[string]struct{}, len(resources))
	for index, resource := range resources {
		path := fmt.Sprintf("resources[%d]", index)
		if !identifierPattern.MatchString(resource.Kind) || !identifierPattern.MatchString(resource.Name) ||
			resource.Fingerprint == "" {
			return invalid(path, "kind and name must be canonical identifiers and fingerprint must not be empty")
		}
		scopeParts := resourceScopePattern.FindStringSubmatch(resource.Scope)
		if len(scopeParts) != 2 || scopeParts[1] != projectID {
			return invalid(path+".scope", "must be a canonical scope in the plan project")
		}

		key := resource.Scope + "\x00" + resource.Kind + "\x00" + resource.Name
		if _, exists := seen[key]; exists {
			return invalid(path, "duplicate kind and name")
		}
		seen[key] = struct{}{}
	}

	return nil
}

func validatePreconditions(preconditions []domain.PlanPrecondition) error {
	seen := make(map[string]struct{}, len(preconditions))
	for index, precondition := range preconditions {
		path := fmt.Sprintf("preconditions[%d]", index)
		if !identifierPattern.MatchString(precondition.ID) {
			return invalid(path+".id", "must be a canonical identifier")
		}
		if _, exists := seen[precondition.ID]; exists {
			return invalid(path+".id", "duplicate value")
		}
		seen[precondition.ID] = struct{}{}
	}

	return nil
}

func validateSteps(steps []domain.PlanStep, pointOfNoReturn string, resources []domain.PlanResource) error {
	if len(steps) == 0 {
		return invalid("steps", "must contain at least one step")
	}

	seen := make(map[string]struct{}, len(steps))
	resourcesByKey := make(map[string]domain.PlanResource, len(resources))
	for _, resource := range resources {
		resourcesByKey[planResourceKey(resource)] = resource
	}
	coveredResources := make(map[string]struct{}, len(resources))
	for index, step := range steps {
		path := fmt.Sprintf("steps[%d]", index)
		if !identifierPattern.MatchString(step.ID) {
			return invalid(path+".id", "must be a canonical identifier")
		}
		if _, exists := seen[step.ID]; exists {
			return invalid(path+".id", "duplicate value")
		}
		seen[step.ID] = struct{}{}

		if !identifierPattern.MatchString(step.Executor) {
			return invalid(path+".executor", "must be a canonical identifier")
		}
		if !step.ExecutingIdentity.Valid() {
			return invalid(path+".executingIdentity", "unknown value")
		}
		if step.CommandRedacted.String() == "" {
			return invalid(path+".commandRedacted", "must not be empty")
		}
		if !step.Retry.Valid() {
			return invalid(path+".retry", "must be an explicit bounded retry policy")
		}
		if step.TimeoutSeconds <= 0 || step.TimeoutSeconds > domain.MaxStepTimeoutSeconds {
			return invalid(path+".timeoutSeconds", "must be positive and bounded")
		}
		if step.SuccessCondition.String() == "" {
			return invalid(path+".successCondition", "must not be empty")
		}
		if !step.FailureBehavior.Valid() {
			return invalid(path+".failureBehavior", "unknown value")
		}
		if len(step.Targets) == 0 {
			return invalid(path+".targets", "must bind at least one fingerprinted plan resource")
		}
		seenTargets := make(map[string]struct{}, len(step.Targets))
		for _, target := range step.Targets {
			key := planResourceKey(target)
			resource, exists := resourcesByKey[key]
			if !exists || target != resource {
				return invalid(path+".targets", "must exactly match a fingerprinted plan resource")
			}
			if _, duplicate := seenTargets[key]; duplicate {
				return invalid(path+".targets", "contains a duplicate resource")
			}
			seenTargets[key] = struct{}{}
			coveredResources[key] = struct{}{}
		}
	}
	if len(coveredResources) != len(resources) {
		return invalid("steps.targets", "must cover every plan resource")
	}

	if pointOfNoReturn != "" {
		if _, exists := seen[pointOfNoReturn]; !exists {
			return invalid("pointOfNoReturn", "must name a step in this plan")
		}
	}

	return nil
}

func validatePermissions(
	permissions []domain.PlanPermission,
	approvalClass domain.ApprovalClass,
	steps []domain.PlanStep,
	resources []domain.PlanResource,
) error {
	if approvalClass != domain.ApprovalRead && len(permissions) == 0 {
		return invalid("permissions", "must contain exact permission checks for a mutating plan")
	}

	stepsByID := make(map[string]domain.PlanStep, len(steps))
	for _, step := range steps {
		stepsByID[step.ID] = step
	}
	resourcesByKey := make(map[string]domain.PlanResource, len(resources))
	for _, resource := range resources {
		resourcesByKey[planResourceKey(resource)] = resource
	}
	seen := make(map[string]struct{}, len(permissions))
	coveredSteps := make(map[string]struct{}, len(steps))
	coveredIdentities := make(map[domain.ExecutionIdentity]struct{}, len(steps))
	coveredResources := make(map[string]struct{}, len(resources))
	for index, permission := range permissions {
		path := fmt.Sprintf("permissions[%d]", index)
		step, exists := stepsByID[permission.StepID]
		if !exists {
			return invalid(path+".stepId", "must name a step in this plan")
		}
		if !permission.Identity.Valid() {
			return invalid(path+".identity", "unknown value")
		}
		if permission.Identity != step.ExecutingIdentity {
			return invalid(path+".identity", "must match the named step")
		}
		if !permissionPattern.MatchString(permission.Permission) {
			return invalid(path+".permission", "must be an exact permission name")
		}
		resourceKey := planResourceKey(permission.Resource)
		resource, exists := resourcesByKey[resourceKey]
		if !exists || permission.Resource != resource {
			return invalid(path+".resource", "must exactly match a fingerprinted plan resource")
		}
		key := permission.StepID + "\x00" + string(permission.Identity) + "\x00" + permission.Permission + "\x00" + resourceKey
		if _, exists := seen[key]; exists {
			return invalid(path, "duplicates a step, identity, permission, and resource")
		}
		seen[key] = struct{}{}
		coveredSteps[permission.StepID] = struct{}{}
		coveredIdentities[permission.Identity] = struct{}{}
		coveredResources[resourceKey] = struct{}{}
	}

	if approvalClass != domain.ApprovalRead {
		for _, step := range steps {
			if _, exists := coveredSteps[step.ID]; !exists {
				return invalid("permissions", "must cover every mutating-plan step")
			}
			if _, exists := coveredIdentities[step.ExecutingIdentity]; !exists {
				return invalid("permissions", "must cover every executing identity")
			}
		}
		for _, resource := range resources {
			if _, exists := coveredResources[planResourceKey(resource)]; !exists {
				return invalid("permissions", "must cover every affected resource")
			}
		}
	}

	return nil
}

func planResourceKey(resource domain.PlanResource) string {
	return resource.Scope + "\x00" + resource.Kind + "\x00" + resource.Name + "\x00" + resource.Fingerprint
}

func validateCost(cost domain.PlanCost) error {
	if err := validateAmount("cost.runRate.amountUSD", cost.RunRate.AmountUSD); err != nil {
		return err
	}
	if cost.RunRate.Period == "" {
		return invalid("cost.runRate.period", "must not be empty")
	}
	for index, item := range cost.Items {
		path := fmt.Sprintf("cost.items[%d]", index)
		if item.Resource == "" || item.Kind == "" {
			return invalid(path, "resource and kind must not be empty")
		}
		if err := validateAmount(path+".amountUSD", item.AmountUSD); err != nil {
			return err
		}
	}
	if cost.Incremental != nil {
		if err := validateAmount("cost.incremental.amountUSD", cost.Incremental.AmountUSD); err != nil {
			return err
		}
		if cost.Incremental.Period == "" || cost.Incremental.Plan == "" {
			return invalid("cost.incremental", "period and plan must not be empty")
		}
	}
	if !cost.Source.Valid() {
		return invalid("cost.source", "unknown value")
	}
	if !datePattern.MatchString(cost.PriceTableDate) {
		return invalid("cost.priceTableDate", "must use YYYY-MM-DD")
	}
	if _, err := time.Parse(time.DateOnly, cost.PriceTableDate); err != nil {
		return invalid("cost.priceTableDate", "must be a real calendar date")
	}
	if !cost.Budget.State.Valid() {
		return invalid("cost.budget.state", "unknown value")
	}
	if cost.Budget.State == domain.BudgetOK && cost.Budget.CeilingUSD == nil {
		return invalid("cost.budget.ceilingUSD", "is required when budget state is ok")
	}
	if cost.Budget.State == domain.BudgetUnavailable && cost.Budget.Reason.String() == "" {
		return invalid("cost.budget.reason", "is required when budget state is unavailable")
	}
	if cost.Budget.State != domain.BudgetOK && cost.Budget.CeilingUSD != nil {
		return invalid("cost.budget.ceilingUSD", "is allowed only when budget state is ok")
	}
	if cost.Budget.CeilingUSD != nil {
		if err := validateAmount("cost.budget.ceilingUSD", *cost.Budget.CeilingUSD); err != nil {
			return err
		}
	}

	return nil
}

func validateAmount(path string, amount float64) error {
	if math.IsNaN(amount) || math.IsInf(amount, 0) || amount < 0 {
		return invalid(path, "must be a finite non-negative number")
	}

	return nil
}

func validateUTCTime(path string, value time.Time) error {
	if value.IsZero() {
		return invalid(path, "must not be zero")
	}
	_, offset := value.Zone()
	if offset != 0 {
		return invalid(path, "must be UTC")
	}

	return nil
}

func validatePrincipal(value string) error {
	if value == "" || len(value) > 254 || strings.TrimSpace(value) != value {
		return invalid("principal", "must be a non-empty canonical identity")
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return invalid("principal", "must not contain whitespace or control characters")
		}
	}

	return nil
}

func invalid(path, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidPlan, path, reason)
}
