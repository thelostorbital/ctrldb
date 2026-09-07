// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/observation"
	"github.com/thelostorbital/ctrldb/internal/policy"
	"github.com/thelostorbital/ctrldb/internal/redact"
)

const (
	PricingSchemaV1      = "ctrldb.ctrlboard.dev/pricing-evidence/v1"
	minimumPlanValidity  = 30 * time.Minute
	maximumPricingAge    = 31 * 24 * time.Hour
	maximumExactMicros   = int64(1 << 53)
	iapFirewallName      = "ctrldb-test-iap-ssh"
	internalFirewallName = "ctrldb-test-internal"
	testNodeTag          = "ctrldb-test-node"
	operatorRoleName     = "ctrldbTestOperator"
	destructiveRoleName  = "ctrldbTestDestructive"
	wipeScheduleUTC      = "0 20 * * *"
)

var (
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	planIDPattern = regexp.MustCompile(`^plan-[0-9a-f]{16}$`)
)

var requiredAPIs = [...]string{
	"artifactregistry.googleapis.com",
	"cloudresourcemanager.googleapis.com",
	"cloudscheduler.googleapis.com",
	"compute.googleapis.com",
	"iam.googleapis.com",
	"iamcredentials.googleapis.com",
	"run.googleapis.com",
	"secretmanager.googleapis.com",
	"serviceusage.googleapis.com",
	"storage.googleapis.com",
}

// RequiredAPIs returns the closed provider service set that must be observed
// as enabled before WF-TEST-01 can be planned.
func RequiredAPIs() []string {
	return append([]string(nil), requiredAPIs[:]...)
}

type stepDefinition struct {
	id             string
	kind           IntentKind
	identity       domain.ExecutionIdentity
	resourceIDs    []string
	dependencies   []string
	preconditions  []string
	verification   []string
	retry          domain.RetryPolicy
	timeoutSeconds int64
	cancelSafe     bool
	compensation   string
	ponr           PointOfNoReturnClass
	transition     *HarnessTransition
	permissions    []string
	summary        string
	success        string
	failure        domain.FailureBehavior
}

// Compile validates all immutable inputs and seals a deterministic WF-TEST-01
// plan. It does not read files, run a process, contact a provider, or persist.
func Compile(request CompileRequest) (CompiledPlan, error) {
	if err := validateCompileRequest(request); err != nil {
		return CompiledPlan{}, err
	}

	desired := desiredState(request)
	desiredResources, err := buildDesiredResources(desired)
	if err != nil {
		return CompiledPlan{}, invalidCompile("desired resources")
	}
	if err := rejectTargetCollisions(request.Preflight, desiredResources); err != nil {
		return CompiledPlan{}, err
	}

	limits, err := buildRunLimits(request)
	if err != nil {
		return CompiledPlan{}, err
	}
	definitions := stepRegistry(desiredResources)
	if err := validatePermissionEvidence(request.Permissions, definitions, request.Preflight.Account(), request.Configuration.Project(), request.CreatedAt); err != nil {
		return CompiledPlan{}, err
	}
	plan, contract, err := buildPlanValues(
		request.PlanID, request.Configuration.Project(), request.Configuration.Environment(), request.Preflight.Account(),
		request.CreatedAt, request.ExpiresAt, request.LocalPolicyHash, request.ApprovedPolicyHash,
		request.Pricing, definitions, desiredResources, limits,
	)
	if err != nil {
		return CompiledPlan{}, err
	}
	binding, err := buildEnvelopeBinding(request, plan)
	if err != nil {
		return CompiledPlan{}, err
	}
	intents := buildIntents(definitions, binding.BindingSHA256)
	payload := compiledPayloadV1{
		Plan: plan, Binding: binding, Desired: desired, DesiredResources: desiredResources,
		Limits: limits, Pricing: request.Pricing, Permissions: clonePermissionEvidence(request.Permissions),
		CleanupCapabilities: isolation.InitialCleanupCapabilities(), Intents: intents,
		Risks: buildRiskSummary(limits),
	}

	return sealCompiled(payload, contract)
}

func validateCompileRequest(request CompileRequest) error {
	configuration := request.Configuration
	preflight := request.Preflight
	if !planIDPattern.MatchString(request.PlanID) {
		return invalidCompile("plan ID")
	}
	if !validUTC(request.CreatedAt) || !validUTC(request.ExpiresAt) ||
		!request.ExpiresAt.After(request.CreatedAt) ||
		request.ExpiresAt.Sub(request.CreatedAt) < minimumPlanValidity ||
		request.Configuration.PlanValidity() <= 0 ||
		!request.ExpiresAt.Equal(request.CreatedAt.Add(request.Configuration.PlanValidity())) {
		return invalidCompile("plan time window")
	}
	if !sha256Pattern.MatchString(request.LocalPolicyHash) ||
		request.LocalPolicyHash != request.ApprovedPolicyHash {
		return blocked("approved policy hash")
	}
	if configuration.ManifestHash() == "" || configuration.Environment() == "" ||
		configuration.Project() == "" || configuration.Region() == "" || configuration.Zone() == "" {
		return invalidCompile("harness configuration")
	}
	if preflight.Project() != configuration.Project() || preflight.Region() != configuration.Region() ||
		preflight.Zone() != configuration.Zone() || preflight.Account() == "" {
		return blocked("provider context")
	}
	if preflight.GcloudVersion() != observation.SupportedGcloudVersion ||
		preflight.CompletenessPolicy() != observation.GcloudCompletenessPolicy || !preflight.Exhaustive() ||
		!slices.Equal(preflight.Schemas(), observation.RequiredSchemas()) {
		return blocked("observation provenance")
	}
	if !preflight.FreshAt(request.CreatedAt) {
		return blocked("stale observation")
	}
	overlaps, err := preflight.CIDROverlapsAt(configuration.CIDR(), request.CreatedAt)
	if err != nil || overlaps {
		return blocked("CIDR overlap")
	}
	publicRules, err := preflight.PublicMongoDBIngressAt(request.CreatedAt)
	if err != nil || len(publicRules) != 0 {
		return blocked("public MongoDB ingress")
	}
	for _, service := range RequiredAPIs() {
		if preflight.APIState(service) != observation.APIEnabled {
			return blocked("required API state")
		}
	}
	if err := validatePricing(request); err != nil {
		return err
	}
	return nil
}

func validatePricing(request CompileRequest) error {
	price := request.Pricing
	if price.Schema != PricingSchemaV1 || !sha256Pattern.MatchString(price.Revision) ||
		price.MachineType != request.Configuration.Caps().MaxMachineType() ||
		price.Region != request.Configuration.Region() || price.Zone != request.Configuration.Zone() ||
		price.GuestCPUs <= 0 || price.MemoryMiB <= 0 || price.EstimatedRunMicros < 0 ||
		price.DiskGiB != request.Configuration.Caps().MaxDiskGiB() ||
		price.Instances != int64(request.Configuration.Caps().MaxInstances()) ||
		price.LifetimeSeconds != int64(request.Configuration.Caps().MaxLifetime()/time.Second) ||
		price.Currency != "USD" ||
		price.EstimatedRunMicros > maximumExactMicros || !validUTC(price.ObservedAt) ||
		!validUTC(price.ValidUntil) || !price.ObservedAt.Before(price.ValidUntil) ||
		request.CreatedAt.Before(price.ObservedAt) || !request.CreatedAt.Before(price.ValidUntil) {
		return invalidCompile("pricing evidence")
	}
	parsedDate, err := time.Parse(time.DateOnly, price.PriceTableDate)
	if err != nil || parsedDate.After(request.CreatedAt) || request.CreatedAt.Sub(parsedDate) > maximumPricingAge {
		return invalidCompile("price table date")
	}
	if price.EstimatedRunMicros > request.Configuration.Caps().MaxEstimatedCostMicros() {
		return blocked("run cost cap")
	}
	if revision, err := pricingEvidenceRevision(price); err != nil || revision != price.Revision {
		return invalidCompile("pricing revision")
	}
	matches := 0
	for _, machine := range request.Preflight.MachineTypes() {
		if machine.Name == price.MachineType {
			matches++
			if machine.Zone != request.Configuration.Zone() || machine.Deprecated ||
				machine.GuestCPUs != price.GuestCPUs || machine.MemoryMiB != price.MemoryMiB {
				return blocked("machine capability")
			}
		}
	}
	if matches != 1 {
		return blocked("machine capability")
	}
	return nil
}

func pricingEvidenceRevision(value PricingEvidence) (string, error) {
	value.Revision = ""
	return hashJSON(value)
}

func validatePermissionEvidence(
	evidence PermissionEvidence,
	definitions []stepDefinition,
	account, project string,
	at time.Time,
) error {
	if evidence.Schema != PermissionEvidenceSchemaV1 || evidence.Account != account || evidence.Project != project ||
		!validUTC(evidence.ObservedAt) || !validUTC(evidence.ValidUntil) ||
		!evidence.ObservedAt.Before(evidence.ValidUntil) || at.Before(evidence.ObservedAt) || !at.Before(evidence.ValidUntil) ||
		!sha256Pattern.MatchString(evidence.Revision) {
		return blocked("permission evidence")
	}
	expected := expectedPermissionGrants(definitions)
	if len(evidence.Grants) != len(expected) {
		return blocked("permission evidence")
	}
	for index, grant := range evidence.Grants {
		if grant != expected[index] || !grant.Granted {
			return blocked("permission evidence")
		}
	}
	copy := clonePermissionEvidence(evidence)
	copy.Revision = ""
	revision, err := hashJSON(copy)
	if err != nil || revision != evidence.Revision {
		return blocked("permission evidence")
	}
	return nil
}

func expectedPermissionGrants(definitions []stepDefinition) []PermissionGrant {
	result := make([]PermissionGrant, 0)
	for _, definition := range definitions {
		for _, permission := range definition.permissions {
			result = append(result, PermissionGrant{StepID: definition.id, Identity: definition.identity, Permission: permission, Granted: true})
		}
	}
	return result
}

func buildRunLimits(request CompileRequest) (RunLimits, error) {
	caps := request.Configuration.Caps()
	lifetime := caps.MaxLifetime()
	if lifetime <= 0 || lifetime%time.Second != 0 || caps.MaxDiskGiB() <= 0 || caps.MaxInstances() <= 0 ||
		caps.MaxEstimatedCostMicros() < 0 || caps.MaxEstimatedCostMicros() > maximumExactMicros ||
		int64(caps.MaxInstances()) <= 0 {
		return RunLimits{}, invalidCompile("run limits")
	}
	return RunLimits{
		MaximumMachineType: caps.MaxMachineType(), MaximumGuestCPUs: request.Pricing.GuestCPUs,
		MaximumMemoryMiB: request.Pricing.MemoryMiB, MaximumDiskGiB: caps.MaxDiskGiB(),
		MaximumInstances: int64(caps.MaxInstances()), MaximumLifetimeSec: int64(lifetime / time.Second),
		MaximumCostMicros: caps.MaxEstimatedCostMicros(), EstimatedCostMicros: request.Pricing.EstimatedRunMicros,
	}, nil
}

func desiredState(request CompileRequest) HarnessDesiredState {
	configuration := request.Configuration
	return HarnessDesiredState{
		Account: request.Preflight.Account(), Project: configuration.Project(), Region: configuration.Region(), Zone: configuration.Zone(),
		CIDR: configuration.CIDR(), NamePrefix: configuration.NamePrefix(), Labels: configuration.Labels(), ControlBucket: configuration.ControlBucket(),
		AuditBucket: configuration.AuditBucket(), VPC: configuration.VPC(), Subnet: configuration.Subnet(),
		Router: configuration.Router(), NAT: configuration.NAT(), IAPFirewall: iapFirewallName,
		InternalFirewall: internalFirewallName, NodeTag: testNodeTag,
		OperatorPrincipal: configuration.OperatorPrincipal(), DestructivePrincipal: configuration.DestructivePrincipal(),
		VMPrincipal: configuration.VMPrincipal(), WipePrincipal: configuration.WipeServiceAccount(),
		CIPrincipal: configuration.CIPrincipal(), OperatorRole: operatorRoleName,
		DestructiveRole: destructiveRoleName, WipeRunJob: configuration.WipeRunJob(),
		WipeSchedulerJob: configuration.WipeSchedulerJob(), WipeScheduleUTC: wipeScheduleUTC,
		ImageDigest:         configuration.ImageDigest(),
		PlanValiditySeconds: int64(configuration.PlanValidity() / time.Second),
	}
}

func buildDesiredResources(desired HarnessDesiredState) ([]DesiredResource, error) {
	project, region := desired.Project, desired.Region
	resources := []DesiredResource{
		resource("audit-bucket", ResourceBucket, desired.AuditBucket, project, region,
			provider(project, "global", string(ResourceBucket), desired.AuditBucket), ""),
		resource("control-bucket", ResourceBucket, desired.ControlBucket, project, region,
			provider(project, "global", string(ResourceBucket), desired.ControlBucket), ""),
		resource("test-network", ResourceNetwork, desired.VPC, project, "global",
			provider(project, "global", "networks", desired.VPC), ""),
		resource("test-subnet", ResourceSubnetwork, desired.Subnet, project, region,
			provider(project, "regions", region, "subnetworks", desired.Subnet), provider(project, "global", "networks", desired.VPC)),
		resource("test-router", ResourceRouter, desired.Router, project, region,
			provider(project, "regions", region, "routers", desired.Router), provider(project, "global", "networks", desired.VPC)),
		resource("test-nat", ResourceNAT, desired.NAT, project, region,
			provider(project, "regions", region, "routers", desired.Router, "nats", desired.NAT), provider(project, "regions", region, "routers", desired.Router)),
		resource("test-iap-firewall", ResourceFirewall, desired.IAPFirewall, project, "global",
			provider(project, "global", "firewalls", desired.IAPFirewall), provider(project, "global", "networks", desired.VPC)),
		resource("test-internal-firewall", ResourceFirewall, desired.InternalFirewall, project, "global",
			provider(project, "global", "firewalls", desired.InternalFirewall), provider(project, "global", "networks", desired.VPC)),
		resource("test-operator-sa", ResourceServiceAccount, desired.OperatorPrincipal, project, "global",
			provider(project, "serviceAccounts", desired.OperatorPrincipal), ""),
		resource("test-destructive-sa", ResourceServiceAccount, desired.DestructivePrincipal, project, "global",
			provider(project, "serviceAccounts", desired.DestructivePrincipal), ""),
		resource("test-vm-sa", ResourceServiceAccount, desired.VMPrincipal, project, "global",
			provider(project, "serviceAccounts", desired.VMPrincipal), ""),
		resource("test-wipe-sa", ResourceServiceAccount, desired.WipePrincipal, project, "global",
			provider(project, "serviceAccounts", desired.WipePrincipal), ""),
		resource("test-operator-role", ResourceCustomRole, desired.OperatorRole, project, "global",
			provider(project, "roles", desired.OperatorRole), ""),
		resource("test-destructive-role", ResourceCustomRole, desired.DestructiveRole, project, "global",
			provider(project, "roles", desired.DestructiveRole), ""),
		resource("test-wipe-job", ResourceRunJob, desired.WipeRunJob, project, region,
			provider(project, "regions", region, string(ResourceRunJob), desired.WipeRunJob), ""),
		resource("test-wipe-scheduler", ResourceSchedulerJob, desired.WipeSchedulerJob, project, region,
			provider(project, "locations", region, "jobs", desired.WipeSchedulerJob), provider(project, "regions", region, string(ResourceRunJob), desired.WipeRunJob)),
	}
	for index := range resources {
		descriptor := desiredResourceDescriptor(resources[index], desired)
		fingerprint, err := hashJSON(descriptor)
		if err != nil {
			return nil, err
		}
		resources[index].DesiredStateFingerprint = fingerprint
	}
	return resources, nil
}

func resource(id string, kind ResourceKind, name, project, location, providerID, parent string) DesiredResource {
	return DesiredResource{ID: id, Kind: kind, Name: name, Project: project, Location: location,
		ProviderID: providerID, ParentProviderID: parent, Permanence: PermanentSingleton}
}

type resourceDescriptor struct {
	Resource DesiredResource `json:"resource"`
	State    resourceStateV1 `json:"state"`
}

type resourceStateV1 struct {
	Mode          string            `json:"mode"`
	CIDR          string            `json:"cidr"`
	Labels        map[string]string `json:"labels"`
	Source        string            `json:"source"`
	Targets       []string          `json:"targets"`
	Protocol      string            `json:"protocol"`
	Port          int               `json:"port"`
	ScheduleUTC   string            `json:"scheduleUtc"`
	ImageDigest   string            `json:"imageDigest"`
	Principal     string            `json:"principal"`
	ControlPrefix string            `json:"controlPrefix"`
}

func desiredResourceDescriptor(resource DesiredResource, desired HarnessDesiredState) resourceDescriptor {
	copy := resource
	copy.DesiredStateFingerprint = ""
	state := resourceStateV1{Labels: map[string]string{}, Targets: []string{}}
	switch resource.ID {
	case "audit-bucket":
		state.Mode = "ubla-pap-standard-versioned-retention-365d-locked-archive-after-365d"
	case "control-bucket":
		state.Mode = "ubla-pap-standard-versioned-soft-delete-30d"
	case "test-network":
		state.Mode = "custom-subnet"
	case "test-subnet":
		state.Mode, state.CIDR = "private-google-access", desired.CIDR
	case "test-router":
		state.Mode = "custom-network-router"
	case "test-nat":
		state.Mode = "auto-ip-all-subnet-ranges"
	case "test-iap-firewall":
		state.Mode, state.Source, state.Targets, state.Protocol, state.Port = "ingress", "35.235.240.0/20", []string{desired.NodeTag}, "tcp", 22
	case "test-internal-firewall":
		state.Mode, state.Source, state.Targets, state.Protocol, state.Port = "ingress", desired.NodeTag, []string{desired.NodeTag}, "tcp", 27017
	case "test-operator-sa", "test-destructive-sa", "test-vm-sa", "test-wipe-sa":
		state.Mode, state.Principal = "no-keys", resource.Name
	case "test-operator-role":
		state.Mode = "closed-test-operator-capability"
	case "test-destructive-role":
		state.Mode = "closed-test-destructive-capability"
	case "test-wipe-job":
		state.Mode, state.ImageDigest, state.Principal = "test-wipe", desired.ImageDigest, desired.WipePrincipal
	case "test-wipe-scheduler":
		state.Mode, state.ScheduleUTC, state.Principal = "run-jobs-v2-oauth", desired.WipeScheduleUTC, desired.WipePrincipal
	}
	state.ControlPrefix = "test/"
	return resourceDescriptor{Resource: copy, State: state}
}

func rejectTargetCollisions(preflight observation.HarnessPreflight, desired []DesiredResource) error {
	for _, observed := range preflight.Resources() {
		for _, target := range desired {
			if string(observed.Kind) != string(target.Kind) || observed.Name != target.Name || observed.Project != target.Project {
				continue
			}
			if target.Kind == ResourceBucket {
				return blocked("bucket collision")
			}
			if observed.Location == target.Location && canonicalProviderID(observed.ProviderID) == target.ProviderID {
				return blocked("desired target collision")
			}
		}
	}
	return nil
}

func canonicalProviderID(value string) string {
	parts := strings.Split(value, "/")
	for index := range parts {
		if parts[index] == "projects" && index+1 < len(parts) {
			return strings.Join(parts[index:], "/")
		}
	}
	return value
}

func provider(project string, parts ...string) string {
	return strings.Join(append([]string{"projects", project}, parts...), "/")
}

func buildPlanValues(
	planID, projectID, environment, account string,
	createdAt, expiresAt time.Time,
	localPolicyHash, approvedPolicyHash string,
	pricing PricingEvidence,
	definitions []stepDefinition,
	desiredResources []DesiredResource,
	limits RunLimits,
) (domain.Plan, domain.ExecutionContract, error) {
	planResources := make([]domain.PlanResource, len(definitions))
	steps := make([]domain.PlanStep, len(definitions))
	permissions := make([]domain.PlanPermission, 0)
	contractSteps := make([]domain.ExecutionStepContract, len(definitions))
	for index, definition := range definitions {
		targets, ok := desiredResourcesByID(desiredResources, definition.resourceIDs)
		if !ok {
			return domain.Plan{}, domain.ExecutionContract{}, invalidCompile("step resource binding")
		}
		fingerprint, err := hashJSON(struct {
			ID        string            `json:"id"`
			Kind      IntentKind        `json:"kind"`
			Resources []DesiredResource `json:"resources"`
			Limits    RunLimits         `json:"limits"`
		}{definition.id, definition.kind, targets, limits})
		if err != nil {
			return domain.Plan{}, domain.ExecutionContract{}, invalidCompile("step fingerprint")
		}
		planResource := domain.PlanResource{Kind: "bootstrap-action", Scope: "projects/" + projectID + "/global", Name: definition.id, Fingerprint: fingerprint}
		planResources[index] = planResource
		steps[index] = domain.PlanStep{
			ID: definition.id, Executor: "typed-adapter", ExecutingIdentity: definition.identity,
			CommandRedacted: redact.Sanitize(definition.summary), Idempotent: true, Retry: definition.retry,
			CancelSafe: definition.cancelSafe, TimeoutSeconds: definition.timeoutSeconds,
			SuccessCondition: redact.Sanitize(definition.success), FailureBehavior: definition.failure,
			Targets: []domain.PlanResource{planResource},
		}
		for _, permission := range definition.permissions {
			permissions = append(permissions, domain.PlanPermission{StepID: definition.id, Identity: definition.identity,
				Permission: permission, Resource: planResource, Granted: true})
		}
		effect := domain.StepEffectMutation
		if definition.kind == IntentIsolationGate {
			effect = domain.StepEffectRead
		}
		contractSteps[index] = domain.ExecutionStepContract{
			ID: definition.id, Executor: "typed-adapter", ExecutingIdentity: definition.identity,
			CommandSummary: redact.Sanitize(definition.summary), Effect: effect,
			MinimumApproval: domain.ApprovalSecuritySensitive, TargetKinds: []string{"bootstrap-action"},
			RequiredPermissions: append([]string(nil), definition.permissions...), Idempotent: true,
			Retry: definition.retry, CancelSafe: definition.cancelSafe, TimeoutSeconds: definition.timeoutSeconds,
			SuccessCondition: redact.Sanitize(definition.success), FailureBehavior: definition.failure,
		}
	}
	contract, err := domain.NewExecutionContract(WorkflowID, "audit-retention-lock", "k1-retention-lock",
		domain.PointOfNoReturnMutationObserved, contractSteps)
	if err != nil {
		return domain.Plan{}, domain.ExecutionContract{}, fmt.Errorf("%w: execution contract", ErrInvalidCompileRequest)
	}
	ceilingUSD, ok := microsToUSD(limits.MaximumCostMicros)
	if !ok {
		return domain.Plan{}, domain.ExecutionContract{}, invalidCompile("cost ceiling")
	}
	estimateUSD, ok := microsToUSD(limits.EstimatedCostMicros)
	if !ok {
		return domain.Plan{}, domain.ExecutionContract{}, invalidCompile("cost estimate")
	}
	plan := domain.Plan{
		PlanID: planID, WorkflowID: WorkflowID, ProjectID: projectID,
		Environment: environment, EnvironmentClass: domain.EnvironmentDisposable,
		Principal: account, CreatedAt: createdAt, ExpiresAt: expiresAt,
		ApprovalClass: domain.ApprovalSecuritySensitive, CoolingOffSeconds: 0,
		Identity: domain.DefaultIdentityPlan(), PolicyHash: domain.PlanPolicyHash{Local: localPolicyHash, Approved: approvedPolicyHash, Match: true},
		Resources: planResources, Preconditions: planPreconditions(), Permissions: permissions, Steps: steps,
		Cost: domain.PlanCost{RunRate: domain.PlanCostRate{AmountUSD: estimateUSD, Period: "run"},
			Items:  []domain.PlanCostItem{{Resource: "wf-test-01", Kind: "test-harness", AmountUSD: estimateUSD}},
			Source: domain.CostSourceListPriceTable, PriceTableDate: pricing.PriceTableDate,
			Stale: false, Assumptions: []redact.Text{redact.Sanitize("estimate uses the explicitly selected region, machine shape, disk, count, and lifetime caps")},
			Unpriced: []string{}, Budget: domain.PlanCostBudget{State: domain.BudgetOK, CeilingUSD: &ceilingUSD}},
		Downtime: domain.PlanDowntime{ExpectedSeconds: 0, Kind: "none"}, Exposure: domain.ExposureNone,
		Protection:      []redact.Text{redact.Sanitize("production resources remain outside the reserved disposable namespace"), redact.Sanitize("permanent control resources are excluded from disposable cleanup")},
		Rollback:        domain.PlanRollback{Boundary: "audit-retention-lock", Assets: []domain.PlanRecoveryAsset{}},
		PointOfNoReturn: "k1-retention-lock", PointOfNoReturnTrigger: domain.PointOfNoReturnMutationObserved,
		Verification: []redact.Text{redact.Sanitize("every desired provider object is re-observed at exact desired state"), redact.Sanitize("T8 completes every TEST-ISO proof before opening test admission")},
	}
	sealed, err := policy.SealPlan(plan)
	if err != nil {
		return domain.Plan{}, domain.ExecutionContract{}, fmt.Errorf("%w: PlanV1 validation", ErrInvalidCompileRequest)
	}
	return sealed, contract, nil
}

func desiredResourcesByID(resources []DesiredResource, identifiers []string) ([]DesiredResource, bool) {
	result := make([]DesiredResource, len(identifiers))
	for index, identifier := range identifiers {
		matches := 0
		for _, resource := range resources {
			if resource.ID == identifier {
				matches++
				result[index] = resource
			}
		}
		if matches != 1 {
			return nil, false
		}
	}
	return result, true
}

func planPreconditions() []domain.PlanPrecondition {
	values := []struct{ id, detail string }{
		{"manifest-bound", "validated disposable manifest is hash-bound"},
		{"provider-context-bound", "account, project, region, and zone match"},
		{"observation-fresh", "provider evidence is current"},
		{"schemas-complete", "the closed discovery catalogue is exhaustive"},
		{"cidr-clear", "the selected private CIDR does not overlap"},
		{"api-set-enabled", "every required Google Cloud API is enabled"},
		{"no-public-mongodb", "no contracted classic rule exposes MongoDB internet-wide"},
		{"machine-cap-resolved", "the selected cap machine has exact observed numeric dimensions"},
		{"cost-cap-respected", "the upward-rounded integer micro-USD estimate is within the manifest cap"},
		{"target-identities-absent", "no exact desired provider identity collides"},
		{"bucket-conflict-guarded", "M1-05 must treat create-time global bucket-name conflict as a blocking outcome"},
		{"capability-set-closed", "mutation and cleanup are limited to the recorded three-kind capability set"},
		{"permissions-proven", "every declared bootstrap permission has fresh exact positive evidence"},
		{"pre-t8-admission", "only this approved WF-TEST-01 envelope may mutate before T8"},
	}
	result := make([]domain.PlanPrecondition, len(values))
	for index, value := range values {
		result[index] = domain.PlanPrecondition{ID: value.id, OK: true, Detail: redact.Sanitize(value.detail)}
	}
	return result
}

func buildEnvelopeBinding(request CompileRequest, plan domain.Plan) (EnvelopeBinding, error) {
	binding := EnvelopeBinding{WorkflowID: WorkflowID, PlanID: plan.PlanID, PlanHash: plan.PlanHash, Account: request.Preflight.Account(),
		ManifestHash: request.Configuration.ManifestHash(), ObservationRevision: request.Preflight.Revision(),
		PermissionRevision: request.Permissions.Revision,
		ObservedAt:         request.Preflight.ObservedAt(), ValidUntil: request.Preflight.ValidUntil()}
	digest, err := hashJSON(binding)
	if err != nil {
		return EnvelopeBinding{}, invalidCompile("envelope binding")
	}
	binding.BindingSHA256 = digest
	return binding, nil
}

func buildIntents(definitions []stepDefinition, binding string) []StepIntent {
	result := make([]StepIntent, len(definitions))
	for index, definition := range definitions {
		result[index] = StepIntent{StepID: definition.id, Kind: definition.kind, EnvelopeBindingSHA256: binding,
			ExecutingIdentity: definition.identity, ResourceIDs: cloneStrings(definition.resourceIDs),
			Dependencies: cloneStrings(definition.dependencies), Preconditions: cloneStrings(definition.preconditions),
			Verification: cloneStrings(definition.verification), Retry: definition.retry,
			TimeoutSeconds: definition.timeoutSeconds, CancelSafe: definition.cancelSafe,
			Compensation: definition.compensation, PointOfNoReturn: definition.ponr,
			Transition: cloneTransition(definition.transition)}
	}
	return result
}

func buildRiskSummary(limits RunLimits) RiskSummary {
	return RiskSummary{ExpectedCostCeilingMicros: limits.MaximumCostMicros, EstimatedRunCostMicros: limits.EstimatedCostMicros,
		ExpectedDowntimeSeconds: 0, ProductionExposure: "none",
		PermanentResiduals: []string{"audit bucket with locked 365-day retention", "versioned control bucket", "test harness singletons"},
		Risks:              []string{"audit retention lock is irreversible", "partial bootstrap must resume only from the same envelope hash", "Cloud NAT and retained audit data continue to incur bounded cost"},
		Rollback:           []string{"before the audit retention lock, remove only resources created by this operation", "after the lock, preserve both control buckets and converge or pause"},
		Compensation:       []string{"remove only in-operation reversible bindings and harness objects", "never age-wipe permanent singletons"},
		PointOfNoReturn:    "the irreversible boundary begins when K1 observes the audit bucket 365-day retention lock mutation"}
}

func stepRegistry(resources []DesiredResource) []stepDefinition {
	allPreconditions := []string{"manifest-bound", "provider-context-bound", "observation-fresh", "schemas-complete", "cidr-clear", "api-set-enabled", "no-public-mongodb", "machine-cap-resolved", "cost-cap-respected", "target-identities-absent", "bucket-conflict-guarded", "capability-set-closed", "permissions-proven", "pre-t8-admission"}
	retry3210 := domain.RetryPolicy{MaxAttempts: 3, InitialBackoffSeconds: 2, MaxBackoffSeconds: 10}
	retry3520 := domain.RetryPolicy{MaxAttempts: 3, InitialBackoffSeconds: 5, MaxBackoffSeconds: 20}
	retry5220 := domain.RetryPolicy{MaxAttempts: 5, InitialBackoffSeconds: 2, MaxBackoffSeconds: 20}
	retry3530 := domain.RetryPolicy{MaxAttempts: 3, InitialBackoffSeconds: 5, MaxBackoffSeconds: 30}
	once := domain.RetryPolicy{MaxAttempts: 1}
	return []stepDefinition{
		{id: "k1-audit-bootstrap", kind: IntentAuditBootstrap, identity: domain.IdentityHuman, resourceIDs: []string{"audit-bucket"}, preconditions: allPreconditions, verification: []string{"envelope hash and server generation match", "archive lifecycle has no delete rule"}, retry: retry3210, timeoutSeconds: 120, cancelSafe: true, compensation: "before retention lock remove only an audit bucket created by this operation", ponr: PONRReversible, permissions: []string{"storage.buckets.create", "storage.buckets.get", "storage.objects.create", "storage.objects.get"}, summary: "create and verify the audit bootstrap handoff", success: "the exact envelope is durable and verified before retention is locked", failure: domain.FailurePause},
		{id: "k1-retention-lock", kind: IntentAuditRetention, identity: domain.IdentityHuman, resourceIDs: []string{"audit-bucket"}, dependencies: []string{"k1-audit-bootstrap"}, preconditions: allPreconditions, verification: []string{"retention is locked for 365 days", "archive lifecycle has no delete rule"}, retry: retry3210, timeoutSeconds: 60, cancelSafe: false, compensation: "after the retention-lock mutation is observed pause and preserve the permanent audit bucket", ponr: PONRAuditRetentionLock, permissions: []string{"storage.buckets.get", "storage.buckets.update"}, summary: "lock the verified audit bucket retention policy", success: "the compliant 365-day audit retention policy is irreversibly locked", failure: domain.FailurePause},
		{id: "k2-control-bucket", kind: IntentControlBucket, identity: domain.IdentityHuman, resourceIDs: []string{"control-bucket"}, dependencies: []string{"k1-retention-lock"}, preconditions: allPreconditions, verification: []string{"control bucket desired state matches exactly"}, retry: retry3210, timeoutSeconds: 60, cancelSafe: true, compensation: "remove only a preexisting-empty control bucket created by this operation before durable state is written", ponr: PONRReversible, permissions: []string{"storage.buckets.create", "storage.buckets.get", "storage.buckets.update"}, summary: "create the permanent versioned control bucket", success: "the control bucket has exact UBLA, PAP, versioning, and soft-delete state", failure: domain.FailureRollback},
		{id: "k3-bucket-iam", kind: IntentBucketIAM, identity: domain.IdentityHuman, resourceIDs: []string{"audit-bucket", "control-bucket"}, dependencies: []string{"k2-control-bucket"}, preconditions: allPreconditions, verification: []string{"bucket IAM policies equal the closed rendered policy"}, retry: retry5220, timeoutSeconds: 120, cancelSafe: true, compensation: "remove only IAM bindings added by this operation", ponr: PONRReversible, permissions: []string{"storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy"}, summary: "apply exact control and audit bucket IAM", success: "bucket IAM equals the closed prefix-scoped policy", failure: domain.FailureRollback},
		{id: "k4-seed-control", kind: IntentSeedControl, identity: domain.IdentityHuman, resourceIDs: []string{"control-bucket"}, dependencies: []string{"k3-bucket-iam"}, preconditions: allPreconditions, verification: []string{"seed objects exist and preexisting generations are unchanged"}, retry: retry3210, timeoutSeconds: 30, cancelSafe: true, compensation: "preserve all create-only seed objects and converge from their exact contents", ponr: PONRReversible, permissions: []string{"storage.objects.create", "storage.objects.get"}, summary: "create the exact control-store seed objects", success: "all required create-only seed objects are present", failure: domain.FailurePause},
		{id: "k5-lock-round-trip", kind: IntentLockRoundTrip, identity: domain.IdentityHuman, resourceIDs: []string{"control-bucket"}, dependencies: []string{"k4-seed-control"}, preconditions: allPreconditions, verification: []string{"generation-preconditioned acquire and release succeeds"}, retry: once, timeoutSeconds: 30, cancelSafe: true, compensation: "release only the lock generation acquired by this operation", ponr: PONRReversible, permissions: []string{"storage.objects.create", "storage.objects.get", "storage.objects.update"}, summary: "prove the control-store lock round trip", success: "one generation-bound lock is acquired and released", failure: domain.FailurePause},
		{id: "t1-network", kind: IntentNetwork, identity: domain.IdentityHuman, resourceIDs: []string{"test-network"}, dependencies: []string{"k5-lock-round-trip"}, preconditions: allPreconditions, verification: []string{"network identity and custom-subnet state match"}, retry: retry3520, timeoutSeconds: 60, cancelSafe: true, compensation: "explicit teardown may remove only the network recorded as created by this operation", ponr: PONRReversible, permissions: []string{"compute.networks.create", "compute.networks.get"}, summary: "create the dedicated custom-mode test network", success: "the exact permanent test network exists", failure: domain.FailureRollback},
		{id: "t2-subnet", kind: IntentSubnet, identity: domain.IdentityHuman, resourceIDs: []string{"test-subnet"}, dependencies: []string{"t1-network"}, preconditions: allPreconditions, verification: []string{"subnet range, region, network, and private Google access match"}, retry: retry3520, timeoutSeconds: 60, cancelSafe: true, compensation: "explicit teardown may remove only the subnet recorded as created by this operation", ponr: PONRReversible, permissions: []string{"compute.subnetworks.create", "compute.subnetworks.get"}, summary: "create the explicit non-overlapping test subnet", success: "the exact regional test subnet exists", failure: domain.FailureRollback},
		{id: "t3-nat", kind: IntentNAT, identity: domain.IdentityHuman, resourceIDs: []string{"test-router", "test-nat"}, dependencies: []string{"t2-subnet"}, preconditions: allPreconditions, verification: []string{"router and NAT identities and operational state match"}, retry: retry3520, timeoutSeconds: 60, cancelSafe: true, compensation: "explicit teardown removes only the recorded NAT and router in dependency order", ponr: PONRReversible, permissions: []string{"compute.routers.create", "compute.routers.get", "compute.routers.update"}, summary: "create the test router and auto-allocated Cloud NAT", success: "the exact regional router and operational NAT exist", failure: domain.FailureRollback},
		{id: "t4-firewall", kind: IntentFirewall, identity: domain.IdentityHuman, resourceIDs: []string{"test-iap-firewall", "test-internal-firewall"}, dependencies: []string{"t3-nat"}, preconditions: allPreconditions, verification: []string{"IAP SSH and node-internal MongoDB rules match exactly", "no public or non-test source and target is present"}, retry: retry3520, timeoutSeconds: 60, cancelSafe: true, compensation: "delete only firewall rules recorded as created by this operation", ponr: PONRReversible, permissions: []string{"compute.firewalls.create", "compute.firewalls.get"}, summary: "create the two closed test firewall rules", success: "only the exact IAP SSH and test-node MongoDB rules exist", failure: domain.FailureRollback},
		{id: "t5-identities", kind: IntentIdentities, identity: domain.IdentityHuman, resourceIDs: []string{"test-operator-sa", "test-destructive-sa", "test-vm-sa", "test-wipe-sa", "test-operator-role", "test-destructive-role"}, dependencies: []string{"t4-firewall"}, preconditions: allPreconditions, verification: []string{"service accounts have no keys", "role and conditional binding fingerprints match", "expected allows and denies are proven exactly"}, retry: retry5220, timeoutSeconds: 180, cancelSafe: true, compensation: "remove only roles, bindings, and service accounts created by this operation", ponr: PONRReversible, permissions: []string{"iam.roles.create", "iam.roles.get", "iam.roles.update", "iam.serviceAccounts.create", "iam.serviceAccounts.get", "iam.serviceAccounts.setIamPolicy", "resourcemanager.projects.getIamPolicy", "resourcemanager.projects.setIamPolicy"}, summary: "create test identities, closed roles, and conditional bindings", success: "identity desired state and exact permission matrix are proven", failure: domain.FailureRollback},
		{id: "t6-control-prefix", kind: IntentControlPrefix, identity: domain.IdentityHuman, resourceIDs: []string{"control-bucket"}, dependencies: []string{"t5-identities"}, preconditions: allPreconditions, verification: []string{"only the test control prefix bindings are present"}, retry: retry5220, timeoutSeconds: 60, cancelSafe: true, compensation: "remove only prefix bindings added by this operation", ponr: PONRReversible, permissions: []string{"storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy"}, summary: "bind test identities to the control-store test prefix", success: "the exact test-prefix IAM bindings are present", failure: domain.FailureRollback},
		{id: "t7-nightly-wipe", kind: IntentNightlyWipe, identity: domain.IdentityHuman, resourceIDs: []string{"test-wipe-job", "test-wipe-scheduler"}, dependencies: []string{"t6-control-prefix"}, preconditions: allPreconditions, verification: []string{"wipe job image and identity match", "scheduler uses the exact Run Jobs v2 OAuth target", "first run reports zero deletions"}, retry: retry3530, timeoutSeconds: 180, cancelSafe: true, compensation: "delete only the job and scheduler recorded as created by this operation", ponr: PONRReversible, permissions: []string{"cloudscheduler.jobs.create", "cloudscheduler.jobs.get", "iam.serviceAccounts.actAs", "run.jobs.create", "run.jobs.get", "run.jobs.run"}, summary: "create and dry-run the immutable nightly wipe job", success: "the pinned wipe job and UTC scheduler exist and the first run deletes nothing", failure: domain.FailureRollback},
		{id: "t8-isolation-gate", kind: IntentIsolationGate, identity: domain.IdentityHuman, resourceIDs: desiredResourceIDs(resources), dependencies: []string{"t7-nightly-wipe"}, preconditions: allPreconditions, verification: []string{"every TEST-ISO proof passes", "harness fingerprints and cleanup capabilities match", "pending and unusable may transition to open and usable"}, retry: once, timeoutSeconds: 900, cancelSafe: true, compensation: "on failure retain pending and unusable state and keep TEST-I, TEST-D, and unrelated mutation blocked", ponr: PONRVerificationOnly, transition: &HarnessTransition{FromBootstrapPhase: "pending", FromTestUsability: "unusable", ToBootstrapPhase: "open", ToTestUsability: "usable"}, permissions: []string{"cloudscheduler.jobs.get", "compute.firewalls.get", "compute.networks.get", "compute.routers.get", "compute.subnetworks.get", "iam.roles.get", "iam.serviceAccounts.get", "iam.serviceAccounts.getIamPolicy", "resourcemanager.projects.getIamPolicy", "run.jobs.get", "storage.buckets.get", "storage.buckets.getIamPolicy"}, summary: "run the complete TEST-ISO gate without opening admission early", success: "every T8 proof passes and the proposed state transition is eligible to persist", failure: domain.FailurePause},
	}
}

func desiredResourceIDs(resources []DesiredResource) []string {
	result := make([]string, len(resources))
	for index, resource := range resources {
		result[index] = resource.ID
	}
	return result
}

func hashJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func microsToUSD(value int64) (float64, bool) {
	if value < 0 || value > maximumExactMicros {
		return 0, false
	}
	amount := float64(value) / 1_000_000
	return amount, int64(math.Round(amount*1_000_000)) == value
}

func validUTC(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

func invalidCompile(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidCompileRequest, field)
}

func blocked(gate string) error {
	return fmt.Errorf("%w: %s", ErrPlanBlocked, gate)
}

func cloneMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func cloneStrings(input []string) []string {
	return append([]string{}, input...)
}
