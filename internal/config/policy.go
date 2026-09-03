// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

var (
	// ErrManifestPolicyViolation marks a structurally valid manifest that
	// violates a local policy invariant.
	ErrManifestPolicyViolation = errors.New("manifest policy violation")
	// ErrManifestPolicyUnavailable marks an internal failure to inspect a
	// previously normalized manifest.
	ErrManifestPolicyUnavailable = errors.New("manifest policy unavailable")
)

// ManifestPolicyViolation identifies one failed configuration rule without
// retaining or rendering manifest values.
type ManifestPolicyViolation struct {
	Rule string
	Path string
}

// ManifestPolicyError contains deterministic, value-free policy violations.
type ManifestPolicyError struct {
	violations []ManifestPolicyViolation
}

// Error implements error using only fixed rule identifiers and safe paths.
func (err *ManifestPolicyError) Error() string {
	parts := make([]string, 0, len(err.violations))
	for _, violation := range err.violations {
		parts = append(parts, violation.Rule+" at "+violation.Path)
	}
	if len(parts) == 1 {
		return "manifest policy violation: " + parts[0]
	}
	return "manifest policy violations: " + strings.Join(parts, ", ")
}

// Unwrap allows errors.Is(err, ErrManifestPolicyViolation).
func (err *ManifestPolicyError) Unwrap() error {
	return ErrManifestPolicyViolation
}

// Violations returns a copy of the deterministically ordered violations.
func (err *ManifestPolicyError) Violations() []ManifestPolicyViolation {
	return append([]ManifestPolicyViolation(nil), err.violations...)
}

// ValidateManifestPolicy validates the local, resource-independent E5 policy
// invariants. Checks that require live GCP state belong to discovery.
func ValidateManifestPolicy(document ManifestDocument) error {
	if err := ValidateManifestSchema(document); err != nil {
		return err
	}

	var manifest manifestPolicyWire
	if err := json.Unmarshal(document.JSON(), &manifest); err != nil {
		return ErrManifestPolicyUnavailable
	}

	violations := make([]ManifestPolicyViolation, 0)
	validateClassPolicy(manifest, &violations)
	validateResidencyPolicy(manifest, &violations)
	if len(violations) == 0 {
		return nil
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Rule == violations[j].Rule {
			return violations[i].Path < violations[j].Path
		}
		return violations[i].Rule < violations[j].Rule
	})
	violations = compactPolicyViolations(violations)
	return &ManifestPolicyError{violations: violations}
}

type manifestPolicyWire struct {
	Metadata struct {
		Class domain.EnvironmentClass `json:"class"`
	} `json:"metadata"`
	Spec struct {
		GCP struct {
			Region string `json:"region"`
			Zone   string `json:"zone"`
		} `json:"gcp"`
		Host struct {
			Members []struct {
				Zone string `json:"zone"`
			} `json:"members"`
			DataDisk struct {
				ReplicaZones []string `json:"replicaZones"`
			} `json:"dataDisk"`
			SecretsEscrow struct {
				ReplicationRegions []string `json:"replicationRegions"`
			} `json:"secretsEscrow"`
		} `json:"host"`
		Topology struct {
			HomeRegion string `json:"homeRegion"`
			Members    []struct {
				Zone   string `json:"zone"`
				Region string `json:"region"`
			} `json:"members"`
		} `json:"topology"`
		PBM struct {
			Replication struct {
				Regions []string `json:"regions"`
			} `json:"replication"`
		} `json:"pbm"`
		Policy struct {
			DataDestructiveCoolingOff string `json:"dataDestructiveCoolingOff"`
			PlanValidity              string `json:"planValidity"`
			Overrides                 struct {
				Acknowledged bool `json:"acknowledged"`
			} `json:"overrides"`
			Residency []string `json:"residency"`
		} `json:"policy"`
	} `json:"spec"`
}

func validateClassPolicy(manifest manifestPolicyWire, violations *[]ManifestPolicyViolation) {
	coolingOff, ok := durationSeconds(manifest.Spec.Policy.DataDestructiveCoolingOff)
	if !ok {
		*violations = append(*violations, ManifestPolicyViolation{Rule: "CFG-02", Path: "/spec/policy/dataDestructiveCoolingOff"})
		return
	}
	planValidity, ok := durationSeconds(manifest.Spec.Policy.PlanValidity)
	if !ok {
		*violations = append(*violations, ManifestPolicyViolation{Rule: "CFG-02", Path: "/spec/policy/planValidity"})
		return
	}

	minimumCoolingOff := classCoolingOffSeconds(manifest.Metadata.Class)
	if coolingOff.Cmp(minimumCoolingOff) < 0 && !manifest.Spec.Policy.Overrides.Acknowledged {
		*violations = append(*violations, ManifestPolicyViolation{Rule: "CFG-02", Path: "/spec/policy/dataDestructiveCoolingOff"})
	}

	minimumValidity := new(big.Int).Add(new(big.Int).Set(coolingOff), big.NewInt(30*60))
	if planValidity.Cmp(minimumValidity) < 0 {
		*violations = append(*violations, ManifestPolicyViolation{Rule: "CFG-02", Path: "/spec/policy/planValidity"})
	}
}

func validateResidencyPolicy(manifest manifestPolicyWire, violations *[]ManifestPolicyViolation) {
	allowed := make(map[string]struct{}, len(manifest.Spec.Policy.Residency))
	for _, region := range manifest.Spec.Policy.Residency {
		allowed[region] = struct{}{}
	}

	requireRegion(allowed, manifest.Spec.GCP.Region, "/spec/gcp/region", violations)
	requireZoneRegion(allowed, manifest.Spec.GCP.Zone, "/spec/gcp/zone", violations)
	if regionFromZone(manifest.Spec.GCP.Zone) != manifest.Spec.GCP.Region {
		*violations = append(*violations, ManifestPolicyViolation{Rule: "CFG-09", Path: "/spec/gcp/zone"})
	}
	requireRegion(allowed, manifest.Spec.Topology.HomeRegion, "/spec/topology/homeRegion", violations)

	for index, member := range manifest.Spec.Host.Members {
		requireZoneRegion(allowed, member.Zone, indexedPath("/spec/host/members", index, "zone"), violations)
	}
	for index, zone := range manifest.Spec.Host.DataDisk.ReplicaZones {
		requireZoneRegion(allowed, zone, indexedPath("/spec/host/dataDisk/replicaZones", index, ""), violations)
	}
	for index, region := range manifest.Spec.Host.SecretsEscrow.ReplicationRegions {
		requireRegion(allowed, region, indexedPath("/spec/host/secretsEscrow/replicationRegions", index, ""), violations)
	}
	for index, member := range manifest.Spec.Topology.Members {
		zonePath := indexedPath("/spec/topology/members", index, "zone")
		requireZoneRegion(allowed, member.Zone, zonePath, violations)
		if member.Region != "" {
			regionPath := indexedPath("/spec/topology/members", index, "region")
			requireRegion(allowed, member.Region, regionPath, violations)
			if member.Region != regionFromZone(member.Zone) {
				*violations = append(*violations, ManifestPolicyViolation{Rule: "CFG-09", Path: regionPath})
			}
		}
	}
	for index, region := range manifest.Spec.PBM.Replication.Regions {
		requireRegion(allowed, region, indexedPath("/spec/pbm/replication/regions", index, ""), violations)
	}
}

func requireRegion(allowed map[string]struct{}, region, path string, violations *[]ManifestPolicyViolation) {
	if _, ok := allowed[region]; !ok {
		*violations = append(*violations, ManifestPolicyViolation{Rule: "CFG-09", Path: path})
	}
}

func requireZoneRegion(allowed map[string]struct{}, zone, path string, violations *[]ManifestPolicyViolation) {
	requireRegion(allowed, regionFromZone(zone), path, violations)
}

func regionFromZone(zone string) string {
	separator := strings.LastIndexByte(zone, '-')
	if separator < 0 {
		return ""
	}
	return zone[:separator]
}

func indexedPath(base string, index int, field string) string {
	path := base + "/" + strconv.Itoa(index)
	if field != "" {
		path += "/" + field
	}
	return path
}

func durationSeconds(value string) (*big.Int, bool) {
	if len(value) < 2 {
		return nil, false
	}
	multiplier := int64(0)
	switch value[len(value)-1] {
	case 's':
		multiplier = 1
	case 'm':
		multiplier = 60
	case 'h':
		multiplier = 60 * 60
	case 'd':
		multiplier = 24 * 60 * 60
	default:
		return nil, false
	}
	amount, ok := new(big.Int).SetString(value[:len(value)-1], 10)
	if !ok || amount.Sign() < 0 {
		return nil, false
	}
	return amount.Mul(amount, big.NewInt(multiplier)), true
}

func classCoolingOffSeconds(class domain.EnvironmentClass) *big.Int {
	minutes := int64(0)
	switch class {
	case domain.EnvironmentProduction:
		minutes = 10
	case domain.EnvironmentStaging:
		minutes = 5
	}
	return big.NewInt(minutes * 60)
}

func compactPolicyViolations(values []ManifestPolicyViolation) []ManifestPolicyViolation {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
