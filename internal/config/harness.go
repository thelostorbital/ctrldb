// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

const (
	// TestRouterName is a protocol-owned permanent singleton, like the schema's
	// fixed test VPC and NAT names. It is not a location or capacity default.
	TestRouterName = "ctrldb-test-router"
	microsPerUSD   = int64(1_000_000)
)

var (
	ErrInvalidHarnessConfiguration   = errors.New("invalid test harness configuration")
	harnessServiceAccountPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	workloadIdentityPrincipalPattern = regexp.MustCompile(
		`^(?:principal://iam\.googleapis\.com/projects/[1-9][0-9]*/locations/global/workloadIdentityPools/[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?/subject/[A-Za-z0-9][A-Za-z0-9._:@/-]*|principalSet://iam\.googleapis\.com/projects/[1-9][0-9]*/locations/global/workloadIdentityPools/[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?/attribute\.repository/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)$`,
	)
)

// HarnessConfiguration is an immutable, non-secret projection of the fields
// needed to plan WF-TEST-01. It can only be built after the complete manifest
// schema and resource-independent policy checks pass.
type HarnessConfiguration struct {
	identity           ManifestIdentity
	manifestHash       string
	project            string
	region             string
	zone               string
	controlBucket      string
	auditBucket        string
	namePrefix         string
	labels             map[string]string
	operatorPrincipal  string
	destructive        string
	vmPrincipal        string
	ciPrincipal        string
	vpc                string
	subnet             string
	cidr               string
	router             string
	nat                string
	wipeSchedulerJob   string
	wipeRunJob         string
	wipeServiceAccount string
	imageDigest        string
	reconcilerEnabled  bool
	planValidity       time.Duration
	caps               HarnessCaps
}

// HarnessCaps preserves manifest choices in provider-independent units. The
// machine type remains a name until read-only discovery resolves its numeric
// CPU and memory shape.
type HarnessCaps struct {
	maxMachineType         string
	maxDiskGiB             int64
	maxInstances           int
	maxLifetime            time.Duration
	maxEstimatedCostMicros int64
}

type harnessManifestWire struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Metadata   ManifestMetadata `json:"metadata"`
	Spec       struct {
		GCP struct {
			Project  string `json:"project"`
			Region   string `json:"region"`
			Zone     string `json:"zone"`
			Identity struct {
				Discovery string `json:"discovery"`
			} `json:"identity"`
			SharedVPC struct {
				HostProject *string `json:"hostProject"`
			} `json:"sharedVpc"`
		} `json:"gcp"`
		Host struct {
			ServiceAccount string `json:"serviceAccount"`
		} `json:"host"`
		Control struct {
			StateBucket string `json:"stateBucket"`
			AuditBucket string `json:"auditBucket"`
		} `json:"control"`
		Reconciler struct {
			Enabled        bool   `json:"enabled"`
			SchedulerJob   string `json:"schedulerJob"`
			RunJob         string `json:"runJob"`
			ServiceAccount string `json:"serviceAccount"`
			ImageDigest    string `json:"imageDigest"`
		} `json:"reconciler"`
		Policy struct {
			PlanValidity string `json:"planValidity"`
		} `json:"policy"`
		TestIsolation *struct {
			NamePrefix                string            `json:"namePrefix"`
			Labels                    map[string]string `json:"labels"`
			OperatorServiceAccount    string            `json:"operatorServiceAccount"`
			DestructiveServiceAccount string            `json:"destructiveServiceAccount"`
			CIPrincipal               string            `json:"ciPrincipal"`
			Network                   struct {
				VPC    string `json:"vpc"`
				Subnet string `json:"subnet"`
				CIDR   string `json:"cidr"`
				NAT    string `json:"nat"`
			} `json:"network"`
			Caps struct {
				MaxMachineType        string      `json:"maxMachineType"`
				MaxDiskGiB            int64       `json:"maxDiskGiB"`
				MaxInstances          int         `json:"maxInstances"`
				MaxLifetime           string      `json:"maxLifetime"`
				MaxEstimatedUSDPerRun json.Number `json:"maxEstimatedUSDPerRun"`
			} `json:"caps"`
		} `json:"testIsolation"`
	} `json:"spec"`
}

// HarnessConfigurationFromManifest returns the immutable WF-TEST-01
// projection. It deliberately repeats full validation, so a document obtained
// from DecodeManifestEnvelope cannot bypass schema or policy checks.
func HarnessConfigurationFromManifest(document ManifestDocument) (HarnessConfiguration, error) {
	if err := ValidateManifestSchema(document); err != nil {
		return HarnessConfiguration{}, fmt.Errorf("%w: manifest has not passed schema validation", ErrInvalidHarnessConfiguration)
	}
	if err := ValidateManifestPolicy(document); err != nil {
		return HarnessConfiguration{}, fmt.Errorf("%w: manifest has not passed policy validation", ErrInvalidHarnessConfiguration)
	}

	var wire harnessManifestWire
	decoder := json.NewDecoder(bytes.NewReader(document.JSON()))
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		return HarnessConfiguration{}, fmt.Errorf("%w: manifest projection unavailable", ErrInvalidHarnessConfiguration)
	}
	if string(wire.Metadata.Class) != TestEnvironmentLabel || wire.Spec.TestIsolation == nil {
		return HarnessConfiguration{}, fmt.Errorf("%w: disposable testIsolation manifest required", ErrInvalidHarnessConfiguration)
	}
	if wire.Spec.GCP.Identity.Discovery != "user" {
		return HarnessConfiguration{}, fmt.Errorf("%w: disposable harness discovery must use the human identity", ErrInvalidHarnessConfiguration)
	}
	if wire.Spec.GCP.SharedVPC.HostProject != nil {
		return HarnessConfiguration{}, fmt.Errorf("%w: shared VPC is unsupported", ErrInvalidHarnessConfiguration)
	}

	lifetimeSeconds, ok := durationSeconds(wire.Spec.TestIsolation.Caps.MaxLifetime)
	maximumDurationSeconds := big.NewInt(int64(time.Duration(1<<63-1) / time.Second))
	if !ok || lifetimeSeconds.Sign() <= 0 || !lifetimeSeconds.IsInt64() || lifetimeSeconds.Cmp(maximumDurationSeconds) > 0 {
		return HarnessConfiguration{}, fmt.Errorf("%w: invalid test lifetime", ErrInvalidHarnessConfiguration)
	}
	lifetime := time.Duration(lifetimeSeconds.Int64()) * time.Second
	planValiditySeconds, ok := durationSeconds(wire.Spec.Policy.PlanValidity)
	if !ok || planValiditySeconds.Sign() <= 0 || !planValiditySeconds.IsInt64() ||
		planValiditySeconds.Cmp(maximumDurationSeconds) > 0 {
		return HarnessConfiguration{}, fmt.Errorf("%w: invalid plan validity", ErrInvalidHarnessConfiguration)
	}
	planValidity := time.Duration(planValiditySeconds.Int64()) * time.Second
	costMicros, err := usdNumberToMicrosCeiling(wire.Spec.TestIsolation.Caps.MaxEstimatedUSDPerRun)
	if err != nil {
		return HarnessConfiguration{}, fmt.Errorf("%w: invalid test cost cap", ErrInvalidHarnessConfiguration)
	}

	values := []string{
		wire.Metadata.Name, wire.Spec.GCP.Project, wire.Spec.GCP.Region, wire.Spec.GCP.Zone,
		wire.Spec.Control.StateBucket, wire.Spec.Control.AuditBucket,
		wire.Spec.TestIsolation.NamePrefix, wire.Spec.TestIsolation.OperatorServiceAccount,
		wire.Spec.TestIsolation.DestructiveServiceAccount, wire.Spec.Host.ServiceAccount,
		wire.Spec.TestIsolation.Network.VPC, wire.Spec.TestIsolation.Network.Subnet,
		wire.Spec.TestIsolation.Network.CIDR, wire.Spec.TestIsolation.Network.NAT,
		wire.Spec.Reconciler.SchedulerJob, wire.Spec.Reconciler.RunJob,
		wire.Spec.Reconciler.ServiceAccount, wire.Spec.Reconciler.ImageDigest,
		wire.Spec.TestIsolation.Caps.MaxMachineType,
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return HarnessConfiguration{}, fmt.Errorf("%w: required value is absent", ErrInvalidHarnessConfiguration)
		}
	}
	if wire.Spec.Control.StateBucket == wire.Spec.Control.AuditBucket {
		return HarnessConfiguration{}, fmt.Errorf("%w: control and audit buckets must be distinct", ErrInvalidHarnessConfiguration)
	}
	if wire.Spec.TestIsolation.Caps.MaxDiskGiB <= 0 || wire.Spec.TestIsolation.Caps.MaxInstances <= 0 {
		return HarnessConfiguration{}, fmt.Errorf("%w: invalid numeric caps", ErrInvalidHarnessConfiguration)
	}
	if err := ValidateHarnessPrincipalSet(
		wire.Spec.GCP.Project,
		wire.Spec.TestIsolation.OperatorServiceAccount,
		wire.Spec.TestIsolation.DestructiveServiceAccount,
		wire.Spec.Host.ServiceAccount,
		wire.Spec.Reconciler.ServiceAccount,
		wire.Spec.TestIsolation.CIPrincipal,
	); err != nil {
		return HarnessConfiguration{}, err
	}
	if !generatedResourceNamePattern.MatchString(wire.Spec.TestIsolation.Network.Subnet) {
		return HarnessConfiguration{}, fmt.Errorf("%w: test subnet must be a provider-valid Compute resource name", ErrInvalidHarnessConfiguration)
	}
	if !wire.Spec.Reconciler.Enabled {
		return HarnessConfiguration{}, fmt.Errorf("%w: disposable harness requires the wipe reconciler", ErrInvalidHarnessConfiguration)
	}

	hash := sha256.Sum256(document.JSON())
	return HarnessConfiguration{
		identity:     ManifestIdentity{APIVersion: wire.APIVersion, Kind: wire.Kind, Metadata: wire.Metadata},
		manifestHash: hex.EncodeToString(hash[:]), project: wire.Spec.GCP.Project,
		region: wire.Spec.GCP.Region, zone: wire.Spec.GCP.Zone,
		controlBucket: wire.Spec.Control.StateBucket, auditBucket: wire.Spec.Control.AuditBucket,
		namePrefix: wire.Spec.TestIsolation.NamePrefix, labels: cloneStringMap(wire.Spec.TestIsolation.Labels),
		operatorPrincipal: wire.Spec.TestIsolation.OperatorServiceAccount,
		destructive:       wire.Spec.TestIsolation.DestructiveServiceAccount,
		vmPrincipal:       wire.Spec.Host.ServiceAccount, ciPrincipal: wire.Spec.TestIsolation.CIPrincipal,
		vpc: wire.Spec.TestIsolation.Network.VPC, subnet: wire.Spec.TestIsolation.Network.Subnet,
		cidr: wire.Spec.TestIsolation.Network.CIDR, router: TestRouterName, nat: wire.Spec.TestIsolation.Network.NAT,
		wipeSchedulerJob: wire.Spec.Reconciler.SchedulerJob, wipeRunJob: wire.Spec.Reconciler.RunJob,
		wipeServiceAccount: wire.Spec.Reconciler.ServiceAccount, imageDigest: wire.Spec.Reconciler.ImageDigest,
		reconcilerEnabled: wire.Spec.Reconciler.Enabled, planValidity: planValidity,
		caps: HarnessCaps{
			maxMachineType: wire.Spec.TestIsolation.Caps.MaxMachineType,
			maxDiskGiB:     wire.Spec.TestIsolation.Caps.MaxDiskGiB,
			maxInstances:   wire.Spec.TestIsolation.Caps.MaxInstances,
			maxLifetime:    lifetime, maxEstimatedCostMicros: costMicros,
		},
	}, nil
}

// ValidateHarnessPrincipalSet applies the same canonical, project-ownership,
// and separation rules to manifest projections and parsed compiled plans.
func ValidateHarnessPrincipalSet(project, operator, destructive, vm, wipe, ci string) error {
	accounts := []string{operator, destructive, vm, wipe}
	seen := make(map[string]struct{}, len(accounts))
	for _, account := range accounts {
		if !harnessServiceAccountPattern.MatchString(account) || !serviceAccountBelongsToProject(account, project) {
			return fmt.Errorf("%w: harness service accounts must be canonical identities in the configured project", ErrInvalidHarnessConfiguration)
		}
		if _, duplicate := seen[account]; duplicate {
			return fmt.Errorf("%w: harness service accounts must be distinct", ErrInvalidHarnessConfiguration)
		}
		seen[account] = struct{}{}
	}
	if !workloadIdentityPrincipalPattern.MatchString(ci) {
		return fmt.Errorf("%w: CI principal must identify one canonical workload identity subject or repository", ErrInvalidHarnessConfiguration)
	}
	return nil
}

func usdNumberToMicrosCeiling(value json.Number) (int64, error) {
	amount := new(big.Rat)
	if value.String() == "" {
		return 0, ErrInvalidHarnessConfiguration
	}
	if _, ok := amount.SetString(value.String()); !ok || amount.Sign() < 0 {
		return 0, ErrInvalidHarnessConfiguration
	}
	amount.Mul(amount, big.NewRat(microsPerUSD, 1))
	quotient, remainder := new(big.Int).QuoRem(amount.Num(), amount.Denom(), new(big.Int))
	if remainder.Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsInt64() {
		return 0, ErrInvalidHarnessConfiguration
	}
	return quotient.Int64(), nil
}

func cloneStringMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func (configuration HarnessConfiguration) Identity() ManifestIdentity { return configuration.identity }
func (configuration HarnessConfiguration) Environment() string {
	return configuration.identity.Metadata.Name
}
func (configuration HarnessConfiguration) ManifestHash() string  { return configuration.manifestHash }
func (configuration HarnessConfiguration) Project() string       { return configuration.project }
func (configuration HarnessConfiguration) Region() string        { return configuration.region }
func (configuration HarnessConfiguration) Zone() string          { return configuration.zone }
func (configuration HarnessConfiguration) ControlBucket() string { return configuration.controlBucket }
func (configuration HarnessConfiguration) AuditBucket() string   { return configuration.auditBucket }
func (configuration HarnessConfiguration) NamePrefix() string    { return configuration.namePrefix }
func (configuration HarnessConfiguration) Labels() map[string]string {
	return cloneStringMap(configuration.labels)
}
func (configuration HarnessConfiguration) OperatorPrincipal() string {
	return configuration.operatorPrincipal
}
func (configuration HarnessConfiguration) DestructivePrincipal() string {
	return configuration.destructive
}
func (configuration HarnessConfiguration) VMPrincipal() string { return configuration.vmPrincipal }
func (configuration HarnessConfiguration) CIPrincipal() string { return configuration.ciPrincipal }
func (configuration HarnessConfiguration) VPC() string         { return configuration.vpc }
func (configuration HarnessConfiguration) Subnet() string      { return configuration.subnet }
func (configuration HarnessConfiguration) CIDR() string        { return configuration.cidr }
func (configuration HarnessConfiguration) Router() string      { return configuration.router }
func (configuration HarnessConfiguration) NAT() string         { return configuration.nat }
func (configuration HarnessConfiguration) WipeSchedulerJob() string {
	return configuration.wipeSchedulerJob
}
func (configuration HarnessConfiguration) WipeRunJob() string { return configuration.wipeRunJob }
func (configuration HarnessConfiguration) WipeServiceAccount() string {
	return configuration.wipeServiceAccount
}
func (configuration HarnessConfiguration) ImageDigest() string { return configuration.imageDigest }
func (configuration HarnessConfiguration) ReconcilerEnabled() bool {
	return configuration.reconcilerEnabled
}
func (configuration HarnessConfiguration) PlanValidity() time.Duration {
	return configuration.planValidity
}
func (configuration HarnessConfiguration) Caps() HarnessCaps { return configuration.caps }

func (caps HarnessCaps) MaxMachineType() string        { return caps.maxMachineType }
func (caps HarnessCaps) MaxDiskGiB() int64             { return caps.maxDiskGiB }
func (caps HarnessCaps) MaxInstances() int             { return caps.maxInstances }
func (caps HarnessCaps) MaxLifetime() time.Duration    { return caps.maxLifetime }
func (caps HarnessCaps) MaxEstimatedCostMicros() int64 { return caps.maxEstimatedCostMicros }
