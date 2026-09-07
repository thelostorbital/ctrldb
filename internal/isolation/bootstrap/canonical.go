// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/policy"
)

var (
	desiredProjectPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	desiredLocationPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
)

// CanonicalJSON returns the compact, hash-bound representation suitable for
// review, approval, and M1-05's BootstrapEnvelopeV1 handoff.
func (value CompiledPlan) CanonicalJSON() ([]byte, error) {
	contract, err := validateCompiledPayload(value.payload)
	if err != nil || contract.Digest() != value.contract.Digest() {
		return nil, invalidCompiled("payload")
	}
	digest, err := hashJSON(value.payload)
	if err != nil || digest != value.documentHash {
		return nil, invalidCompiled("document hash")
	}
	return json.Marshal(compiledWireV1{SchemaVersion: CompiledPlanSchemaV1, Payload: clonePayload(value.payload), DocumentSHA256: value.documentHash})
}

// ParseCompiledPlan accepts only canonical JSON with a complete valid
// cross-binding. Duplicate, unknown, null, or trailing fields fail closed.
func ParseCompiledPlan(encoded []byte) (CompiledPlan, error) {
	if len(encoded) == 0 || !json.Valid(encoded) {
		return CompiledPlan{}, invalidCompiled("document")
	}
	if err := rejectDuplicateKeys(encoded); err != nil {
		return CompiledPlan{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire compiledWireV1
	if err := decoder.Decode(&wire); err != nil {
		return CompiledPlan{}, invalidCompiled("document schema")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return CompiledPlan{}, invalidCompiled("trailing data")
	}
	if wire.SchemaVersion != CompiledPlanSchemaV1 || !sha256Pattern.MatchString(wire.DocumentSHA256) {
		return CompiledPlan{}, invalidCompiled("schema or document hash")
	}
	contract, err := validateCompiledPayload(wire.Payload)
	if err != nil {
		return CompiledPlan{}, err
	}
	digest, err := hashJSON(wire.Payload)
	if err != nil || digest != wire.DocumentSHA256 {
		return CompiledPlan{}, invalidCompiled("document integrity")
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return CompiledPlan{}, invalidCompiled("noncanonical encoding")
	}
	return CompiledPlan{payload: clonePayload(wire.Payload), documentHash: wire.DocumentSHA256, contract: contract}, nil
}

func sealCompiled(payload compiledPayloadV1, contract domain.ExecutionContract) (CompiledPlan, error) {
	validated, err := validateCompiledPayload(payload)
	if err != nil || validated.Digest() != contract.Digest() {
		return CompiledPlan{}, invalidCompiled("compiler output")
	}
	digest, err := hashJSON(payload)
	if err != nil {
		return CompiledPlan{}, invalidCompiled("document hash")
	}
	return CompiledPlan{payload: clonePayload(payload), documentHash: digest, contract: contract}, nil
}

func validateCompiledPayload(payload compiledPayloadV1) (domain.ExecutionContract, error) {
	if err := policy.ValidatePlan(payload.Plan); err != nil {
		return domain.ExecutionContract{}, invalidCompiled("PlanV1")
	}
	if err := validateDesiredState(payload.Desired, payload.Plan); err != nil {
		return domain.ExecutionContract{}, err
	}
	expectedResources, err := buildDesiredResources(payload.Desired)
	if err != nil || !equalCanonicalValue(expectedResources, payload.DesiredResources) {
		return domain.ExecutionContract{}, invalidCompiled("desired resources")
	}
	if err := validateLimitsAndPricing(payload.Limits, payload.Pricing, payload.Plan, payload.Desired); err != nil {
		return domain.ExecutionContract{}, err
	}
	if !slices.Equal(payload.CleanupCapabilities, isolation.InitialCleanupCapabilities()) {
		return domain.ExecutionContract{}, invalidCompiled("cleanup capabilities")
	}
	definitions := stepRegistry(expectedResources)
	if err := validatePermissionEvidence(payload.Permissions, definitions, payload.Desired.Account, payload.Desired.Project, payload.Plan.CreatedAt); err != nil {
		return domain.ExecutionContract{}, invalidCompiled("permission evidence")
	}
	if err := validateBinding(payload.Binding, payload.Plan, payload.Permissions.Revision); err != nil {
		return domain.ExecutionContract{}, err
	}
	expectedPlan, contract, err := buildPlanValues(
		payload.Plan.PlanID, payload.Desired.Project, payload.Plan.Environment, payload.Desired.Account,
		payload.Plan.CreatedAt, payload.Plan.ExpiresAt, payload.Plan.PolicyHash.Local, payload.Plan.PolicyHash.Approved,
		payload.Pricing, definitions, expectedResources, payload.Limits,
	)
	if err != nil || !equalCanonicalValue(expectedPlan, payload.Plan) {
		return domain.ExecutionContract{}, invalidCompiled("plan bindings")
	}
	expectedIntents := buildIntents(definitions, payload.Binding.BindingSHA256)
	if !equalCanonicalValue(expectedIntents, payload.Intents) {
		return domain.ExecutionContract{}, invalidCompiled("intent registry")
	}
	if !equalCanonicalValue(buildRiskSummary(payload.Limits), payload.Risks) {
		return domain.ExecutionContract{}, invalidCompiled("risk summary")
	}
	return contract, nil
}

func validateDesiredState(desired HarnessDesiredState, plan domain.Plan) error {
	if desired.Account != plan.Principal || desired.Project != plan.ProjectID ||
		!desiredProjectPattern.MatchString(desired.Project) || !desiredLocationPattern.MatchString(desired.Region) ||
		!desiredLocationPattern.MatchString(desired.Zone) || !strings.HasPrefix(desired.Zone, desired.Region+"-") {
		return invalidCompiled("desired provider context")
	}
	if desired.PlanValiditySeconds <= 0 || desired.PlanValiditySeconds > int64((1<<63-1)/time.Second) ||
		!plan.ExpiresAt.Equal(plan.CreatedAt.Add(time.Duration(desired.PlanValiditySeconds)*time.Second)) {
		return invalidCompiled("plan validity")
	}
	prefix, err := netip.ParsePrefix(desired.CIDR)
	if err != nil || prefix != prefix.Masked() || !prefix.Addr().IsPrivate() {
		return invalidCompiled("desired CIDR")
	}
	if !equalCanonicalValue(desired.Labels, map[string]string{
		config.LabelManagedBy:   config.LabelManagedByValue,
		config.LabelEnvironment: config.TestEnvironmentLabel,
		config.LabelPurpose:     config.TestResourcePurposeLabel,
	}) || desired.NamePrefix != config.TestResourcePrefix {
		return invalidCompiled("desired labels")
	}
	values := []string{desired.ControlBucket, desired.AuditBucket, desired.VPC, desired.Subnet, desired.Router, desired.NAT,
		desired.IAPFirewall, desired.InternalFirewall, desired.NodeTag, desired.OperatorPrincipal,
		desired.DestructivePrincipal, desired.VMPrincipal, desired.WipePrincipal, desired.CIPrincipal,
		desired.OperatorRole, desired.DestructiveRole, desired.WipeRunJob, desired.WipeSchedulerJob, desired.ImageDigest}
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return invalidCompiled("desired value")
		}
	}
	if desired.ControlBucket == desired.AuditBucket {
		return invalidCompiled("distinct control and audit buckets")
	}
	if desired.IAPFirewall != iapFirewallName || desired.InternalFirewall != internalFirewallName ||
		desired.NodeTag != testNodeTag || desired.OperatorRole != operatorRoleName ||
		desired.DestructiveRole != destructiveRoleName || desired.WipeScheduleUTC != wipeScheduleUTC ||
		!strings.HasPrefix(desired.ImageDigest, "sha256:") || !sha256Pattern.MatchString(strings.TrimPrefix(desired.ImageDigest, "sha256:")) {
		return invalidCompiled("protocol-owned desired state")
	}
	if err := config.ValidateHarnessPrincipalSet(
		desired.Project, desired.OperatorPrincipal, desired.DestructivePrincipal,
		desired.VMPrincipal, desired.WipePrincipal, desired.CIPrincipal,
	); err != nil {
		return invalidCompiled("desired principals")
	}
	return nil
}

func validateLimitsAndPricing(limits RunLimits, price PricingEvidence, plan domain.Plan, desired HarnessDesiredState) error {
	if limits.MaximumMachineType == "" || limits.MaximumMachineType != price.MachineType ||
		price.Region != desired.Region || price.Zone != desired.Zone || !strings.HasPrefix(price.Zone, price.Region+"-") ||
		limits.MaximumGuestCPUs != price.GuestCPUs || limits.MaximumMemoryMiB != price.MemoryMiB ||
		limits.MaximumDiskGiB != price.DiskGiB || limits.MaximumInstances != price.Instances ||
		limits.MaximumLifetimeSec != price.LifetimeSeconds || price.Currency != "USD" ||
		limits.MaximumDiskGiB <= 0 || limits.MaximumInstances <= 0 || limits.MaximumLifetimeSec <= 0 ||
		limits.MaximumCostMicros < 0 || limits.MaximumCostMicros > maximumExactMicros ||
		limits.EstimatedCostMicros != price.EstimatedRunMicros || limits.EstimatedCostMicros < 0 ||
		limits.EstimatedCostMicros > limits.MaximumCostMicros || price.Schema != PricingSchemaV1 ||
		!sha256Pattern.MatchString(price.Revision) || !validUTC(price.ObservedAt) || !validUTC(price.ValidUntil) ||
		!price.ObservedAt.Before(price.ValidUntil) || price.ObservedAt.After(plan.CreatedAt) ||
		!plan.CreatedAt.Before(price.ValidUntil) {
		return invalidCompiled("limits or pricing")
	}
	parsedDate, err := time.Parse(time.DateOnly, price.PriceTableDate)
	if err != nil || parsedDate.After(plan.CreatedAt) || plan.CreatedAt.Sub(parsedDate) > maximumPricingAge {
		return invalidCompiled("price table date")
	}
	if revision, err := pricingEvidenceRevision(price); err != nil || revision != price.Revision {
		return invalidCompiled("pricing revision")
	}
	return nil
}

func validateBinding(binding EnvelopeBinding, plan domain.Plan, permissionRevision string) error {
	if binding.WorkflowID != WorkflowID || binding.PlanID != plan.PlanID || binding.PlanHash != plan.PlanHash ||
		binding.Account != plan.Principal || !sha256Pattern.MatchString(binding.ManifestHash) ||
		!sha256Pattern.MatchString(binding.ObservationRevision) || !validUTC(binding.ObservedAt) ||
		binding.PermissionRevision != permissionRevision || !sha256Pattern.MatchString(binding.PermissionRevision) ||
		!validUTC(binding.ValidUntil) || !binding.ObservedAt.Before(binding.ValidUntil) ||
		plan.CreatedAt.Before(binding.ObservedAt) || !plan.CreatedAt.Before(binding.ValidUntil) ||
		!sha256Pattern.MatchString(binding.BindingSHA256) {
		return invalidCompiled("envelope binding")
	}
	copy := binding
	copy.BindingSHA256 = ""
	digest, err := hashJSON(copy)
	if err != nil || digest != binding.BindingSHA256 {
		return invalidCompiled("envelope binding integrity")
	}
	return nil
}

func rejectDuplicateKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := consumeUniqueValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return invalidCompiled("trailing data")
	}
	return nil
}

func consumeUniqueValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil || token == nil {
		return invalidCompiled("malformed or null JSON")
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
				return invalidCompiled("object key")
			}
			if _, exists := seen[key]; exists {
				return invalidCompiled("duplicate field")
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
		return invalidCompiled("JSON delimiter")
	}
	if err != nil {
		return invalidCompiled("malformed JSON")
	}
	return nil
}

func clonePayload(payload compiledPayloadV1) compiledPayloadV1 {
	payload.Plan = clonePlan(payload.Plan)
	payload.Desired = cloneDesired(payload.Desired)
	payload.DesiredResources = append([]DesiredResource(nil), payload.DesiredResources...)
	payload.Permissions = clonePermissionEvidence(payload.Permissions)
	payload.CleanupCapabilities = append([]isolation.CleanupCapability(nil), payload.CleanupCapabilities...)
	payload.Intents = cloneIntents(payload.Intents)
	payload.Risks = cloneRisks(payload.Risks)
	return payload
}

func clonePlan(plan domain.Plan) domain.Plan {
	encoded, _ := json.Marshal(plan)
	var result domain.Plan
	_ = json.Unmarshal(encoded, &result)
	return result
}

func cloneDesired(value HarnessDesiredState) HarnessDesiredState {
	value.Labels = cloneMap(value.Labels)
	return value
}

func cloneIntents(values []StepIntent) []StepIntent {
	result := make([]StepIntent, len(values))
	for index, value := range values {
		value.ResourceIDs = cloneStrings(value.ResourceIDs)
		value.Dependencies = cloneStrings(value.Dependencies)
		value.Preconditions = cloneStrings(value.Preconditions)
		value.Verification = cloneStrings(value.Verification)
		value.Transition = cloneTransition(value.Transition)
		result[index] = value
	}
	return result
}

func cloneTransition(value *HarnessTransition) *HarnessTransition {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneRisks(value RiskSummary) RiskSummary {
	value.PermanentResiduals = append([]string(nil), value.PermanentResiduals...)
	value.Risks = append([]string(nil), value.Risks...)
	value.Rollback = append([]string(nil), value.Rollback...)
	value.Compensation = append([]string(nil), value.Compensation...)
	return value
}

func clonePermissionEvidence(value PermissionEvidence) PermissionEvidence {
	value.Grants = append([]PermissionGrant(nil), value.Grants...)
	return value
}

func invalidCompiled(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidCompiledPlan, field)
}

func equalCanonicalValue(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}
