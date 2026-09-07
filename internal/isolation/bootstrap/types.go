// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package bootstrap compiles the I/O-free WF-TEST-01 bootstrap plan.
package bootstrap

import (
	"errors"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/observation"
)

const (
	CompiledPlanSchemaV1       = "ctrldb.ctrlboard.dev/wf-test-plan/v1"
	PermissionEvidenceSchemaV1 = "ctrldb.ctrlboard.dev/permission-evidence/v1"
	WorkflowID                 = isolation.WFTestWorkflowID
)

var (
	ErrInvalidCompileRequest = errors.New("invalid WF-TEST-01 compile request")
	ErrPlanBlocked           = errors.New("WF-TEST-01 plan blocked")
	ErrInvalidCompiledPlan   = errors.New("invalid compiled WF-TEST-01 plan")
)

// CompileRequest contains every decision and observation required to compile
// WF-TEST-01. There are deliberately no mutation defaults.
type CompileRequest struct {
	Configuration      config.HarnessConfiguration
	Preflight          observation.HarnessPreflight
	PlanID             string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	LocalPolicyHash    string
	ApprovedPolicyHash string
	Pricing            PricingEvidence
	Permissions        PermissionEvidence
}

// PricingEvidence is a fresh, externally obtained integer-micro-USD estimate.
// M1-04 validates and binds it but never performs pricing I/O.
type PricingEvidence struct {
	MachineType        string    `json:"machineType"`
	Region             string    `json:"region"`
	Zone               string    `json:"zone"`
	GuestCPUs          int64     `json:"guestCpus"`
	MemoryMiB          int64     `json:"memoryMiB"`
	DiskGiB            int64     `json:"diskGiB"`
	Instances          int64     `json:"instances"`
	LifetimeSeconds    int64     `json:"lifetimeSeconds"`
	EstimatedRunMicros int64     `json:"estimatedRunMicros"`
	Currency           string    `json:"currency"`
	PriceTableDate     string    `json:"priceTableDate"`
	Schema             string    `json:"schema"`
	Revision           string    `json:"revision"`
	ObservedAt         time.Time `json:"observedAt"`
	ValidUntil         time.Time `json:"validUntil"`
}

// PermissionGrant is one exact positive permission observation. Missing,
// denied, duplicated, or additional entries make the evidence unusable.
type PermissionGrant struct {
	StepID     string                   `json:"stepId"`
	Identity   domain.ExecutionIdentity `json:"identity"`
	Permission string                   `json:"permission"`
	Granted    bool                     `json:"granted"`
}

// PermissionEvidence binds the complete pre-mutation grant set to the human,
// project, and freshness window used to compile the plan.
type PermissionEvidence struct {
	Account    string            `json:"account"`
	Project    string            `json:"project"`
	Schema     string            `json:"schema"`
	Revision   string            `json:"revision"`
	ObservedAt time.Time         `json:"observedAt"`
	ValidUntil time.Time         `json:"validUntil"`
	Grants     []PermissionGrant `json:"grants"`
}

// ResourceKind is the closed set of provider objects referenced by M1-04.
type ResourceKind string

const (
	ResourceBucket         ResourceKind = "storage.bucket"
	ResourceNetwork        ResourceKind = "compute.network"
	ResourceSubnetwork     ResourceKind = "compute.subnetwork"
	ResourceRouter         ResourceKind = "compute.router"
	ResourceNAT            ResourceKind = "compute.nat"
	ResourceFirewall       ResourceKind = "compute.firewall"
	ResourceServiceAccount ResourceKind = "iam.service-account"
	ResourceCustomRole     ResourceKind = "iam.custom-role"
	ResourceRunJob         ResourceKind = "run.job"
	ResourceSchedulerJob   ResourceKind = "scheduler.job"
)

// Permanence separates durable harness singletons from future run resources.
type Permanence string

const (
	PermanentSingleton Permanence = "permanent-singleton"
	DisposableRun      Permanence = "disposable-run"
)

// DesiredResource is one exact provider identity and desired-state digest.
// ProviderID and ParentProviderID are identifiers, never arbitrary commands.
type DesiredResource struct {
	ID                      string       `json:"id"`
	Kind                    ResourceKind `json:"kind"`
	Name                    string       `json:"name"`
	Project                 string       `json:"project"`
	Location                string       `json:"location"`
	ProviderID              string       `json:"providerId"`
	ParentProviderID        string       `json:"parentProviderId"`
	Permanence              Permanence   `json:"permanence"`
	DesiredStateFingerprint string       `json:"desiredStateFingerprint"`
}

// HarnessDesiredState preserves all explicit manifest selections needed by
// later typed adapters. Protocol-owned constants are named separately.
type HarnessDesiredState struct {
	Account              string            `json:"account"`
	Project              string            `json:"project"`
	Region               string            `json:"region"`
	Zone                 string            `json:"zone"`
	CIDR                 string            `json:"cidr"`
	NamePrefix           string            `json:"namePrefix"`
	Labels               map[string]string `json:"labels"`
	ControlBucket        string            `json:"controlBucket"`
	AuditBucket          string            `json:"auditBucket"`
	VPC                  string            `json:"vpc"`
	Subnet               string            `json:"subnet"`
	Router               string            `json:"router"`
	NAT                  string            `json:"nat"`
	IAPFirewall          string            `json:"iapFirewall"`
	InternalFirewall     string            `json:"internalFirewall"`
	NodeTag              string            `json:"nodeTag"`
	OperatorPrincipal    string            `json:"operatorPrincipal"`
	DestructivePrincipal string            `json:"destructivePrincipal"`
	VMPrincipal          string            `json:"vmPrincipal"`
	WipePrincipal        string            `json:"wipePrincipal"`
	CIPrincipal          string            `json:"ciPrincipal"`
	OperatorRole         string            `json:"operatorRole"`
	DestructiveRole      string            `json:"destructiveRole"`
	WipeRunJob           string            `json:"wipeRunJob"`
	WipeSchedulerJob     string            `json:"wipeSchedulerJob"`
	WipeScheduleUTC      string            `json:"wipeScheduleUtc"`
	ImageDigest          string            `json:"imageDigest"`
	PlanValiditySeconds  int64             `json:"planValiditySeconds"`
}

// RunLimits is the exact future disposable-run ceiling recorded by the plan.
type RunLimits struct {
	MaximumMachineType  string `json:"maximumMachineType"`
	MaximumGuestCPUs    int64  `json:"maximumGuestCpus"`
	MaximumMemoryMiB    int64  `json:"maximumMemoryMiB"`
	MaximumDiskGiB      int64  `json:"maximumDiskGiB"`
	MaximumInstances    int64  `json:"maximumInstances"`
	MaximumLifetimeSec  int64  `json:"maximumLifetimeSeconds"`
	MaximumCostMicros   int64  `json:"maximumCostMicros"`
	EstimatedCostMicros int64  `json:"estimatedCostMicros"`
}

// EnvelopeBinding is the immutable handoff M1-05 must embed in the local and
// audit BootstrapEnvelopeV1. Every intent carries this same hash.
type EnvelopeBinding struct {
	WorkflowID          string    `json:"workflowId"`
	PlanID              string    `json:"planId"`
	PlanHash            string    `json:"planHash"`
	Account             string    `json:"account"`
	ManifestHash        string    `json:"manifestHash"`
	ObservationRevision string    `json:"observationRevision"`
	PermissionRevision  string    `json:"permissionRevision"`
	ObservedAt          time.Time `json:"observedAt"`
	ValidUntil          time.Time `json:"validUntil"`
	BindingSHA256       string    `json:"bindingSha256"`
}

// IntentKind is the closed WF-TEST-01 K/T registry.
type IntentKind string

const (
	IntentAuditBootstrap IntentKind = "audit-bootstrap"
	IntentAuditRetention IntentKind = "audit-retention-lock"
	IntentControlBucket  IntentKind = "control-bucket"
	IntentBucketIAM      IntentKind = "bucket-iam"
	IntentSeedControl    IntentKind = "seed-control"
	IntentLockRoundTrip  IntentKind = "lock-round-trip"
	IntentNetwork        IntentKind = "network"
	IntentSubnet         IntentKind = "subnet"
	IntentNAT            IntentKind = "nat"
	IntentFirewall       IntentKind = "firewall"
	IntentIdentities     IntentKind = "identities"
	IntentControlPrefix  IntentKind = "control-prefix"
	IntentNightlyWipe    IntentKind = "nightly-wipe"
	IntentIsolationGate  IntentKind = "isolation-gate"
)

// PointOfNoReturnClass is the per-step irreversible-boundary classification.
type PointOfNoReturnClass string

const (
	PONRReversible         PointOfNoReturnClass = "reversible"
	PONRAuditRetentionLock PointOfNoReturnClass = "audit-retention-lock"
	PONRVerificationOnly   PointOfNoReturnClass = "verification-only"
)

// HarnessTransition describes T8's proposed transition. It is review data;
// this package never persists or performs the transition.
type HarnessTransition struct {
	FromBootstrapPhase string `json:"fromBootstrapPhase"`
	FromTestUsability  string `json:"fromTestUsability"`
	ToBootstrapPhase   string `json:"toBootstrapPhase"`
	ToTestUsability    string `json:"toTestUsability"`
}

// StepIntent is a closed, provider-independent mutation or verification
// intent. It contains no command, argv, token, credential, or provider output.
type StepIntent struct {
	StepID                string                   `json:"stepId"`
	Kind                  IntentKind               `json:"kind"`
	EnvelopeBindingSHA256 string                   `json:"envelopeBindingSha256"`
	ExecutingIdentity     domain.ExecutionIdentity `json:"executingIdentity"`
	ResourceIDs           []string                 `json:"resourceIds"`
	Dependencies          []string                 `json:"dependencies"`
	Preconditions         []string                 `json:"preconditions"`
	Verification          []string                 `json:"verification"`
	Retry                 domain.RetryPolicy       `json:"retry"`
	TimeoutSeconds        int64                    `json:"timeoutSeconds"`
	CancelSafe            bool                     `json:"cancelSafe"`
	Compensation          string                   `json:"compensation"`
	PointOfNoReturn       PointOfNoReturnClass     `json:"pointOfNoReturn"`
	Transition            *HarnessTransition       `json:"transition,omitempty"`
}

// RiskSummary is the owner-facing non-secret impact summary sealed with the
// plan. The strings are protocol constants, not caller-authored free text.
type RiskSummary struct {
	ExpectedCostCeilingMicros int64    `json:"expectedCostCeilingMicros"`
	EstimatedRunCostMicros    int64    `json:"estimatedRunCostMicros"`
	ExpectedDowntimeSeconds   int64    `json:"expectedDowntimeSeconds"`
	ProductionExposure        string   `json:"productionExposure"`
	PermanentResiduals        []string `json:"permanentResiduals"`
	Risks                     []string `json:"risks"`
	Rollback                  []string `json:"rollback"`
	Compensation              []string `json:"compensation"`
	PointOfNoReturn           string   `json:"pointOfNoReturn"`
}

type compiledPayloadV1 struct {
	Plan                domain.Plan                   `json:"plan"`
	Binding             EnvelopeBinding               `json:"binding"`
	Desired             HarnessDesiredState           `json:"desired"`
	DesiredResources    []DesiredResource             `json:"desiredResources"`
	Limits              RunLimits                     `json:"limits"`
	Pricing             PricingEvidence               `json:"pricing"`
	Permissions         PermissionEvidence            `json:"permissions"`
	CleanupCapabilities []isolation.CleanupCapability `json:"cleanupCapabilities"`
	Intents             []StepIntent                  `json:"intents"`
	Risks               RiskSummary                   `json:"risks"`
}

type compiledWireV1 struct {
	SchemaVersion  string            `json:"schemaVersion"`
	Payload        compiledPayloadV1 `json:"payload"`
	DocumentSHA256 string            `json:"documentSha256"`
}

// CompiledPlan is immutable. Construction and parsing both validate every
// cross-binding before exposing detached values.
type CompiledPlan struct {
	payload      compiledPayloadV1
	documentHash string
	contract     domain.ExecutionContract
}

func (value CompiledPlan) Plan() domain.Plan                           { return clonePlan(value.payload.Plan) }
func (value CompiledPlan) ExecutionContract() domain.ExecutionContract { return value.contract }
func (value CompiledPlan) Binding() EnvelopeBinding                    { return value.payload.Binding }
func (value CompiledPlan) DesiredState() HarnessDesiredState {
	return cloneDesired(value.payload.Desired)
}
func (value CompiledPlan) DesiredResources() []DesiredResource {
	return append([]DesiredResource(nil), value.payload.DesiredResources...)
}
func (value CompiledPlan) Limits() RunLimits        { return value.payload.Limits }
func (value CompiledPlan) Pricing() PricingEvidence { return value.payload.Pricing }
func (value CompiledPlan) PermissionEvidence() PermissionEvidence {
	return clonePermissionEvidence(value.payload.Permissions)
}
func (value CompiledPlan) CleanupCapabilities() []isolation.CleanupCapability {
	return append([]isolation.CleanupCapability(nil), value.payload.CleanupCapabilities...)
}
func (value CompiledPlan) Intents() []StepIntent { return cloneIntents(value.payload.Intents) }
func (value CompiledPlan) Risks() RiskSummary    { return cloneRisks(value.payload.Risks) }
func (value CompiledPlan) DocumentHash() string  { return value.documentHash }
