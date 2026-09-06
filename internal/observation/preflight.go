// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Package observation defines immutable, normalized provider evidence.
package observation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	SupportedGcloudVersion   = "560.0.0"
	GcloudCompletenessPolicy = "gcloud-auto-pagination/unlimited"
	MaxEvidenceLifetime      = 5 * time.Minute
)

var (
	ErrInvalidObservation = errors.New("invalid provider observation")
	projectPattern        = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	accountPattern        = regexp.MustCompile(`^[^[:space:]@]+@[^[:space:]@]+$`)
	locationPattern       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
	resourceNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
	servicePattern        = regexp.MustCompile(`^[a-z][a-z0-9-]*\.googleapis\.com$`)
	immutableIDPattern    = regexp.MustCompile(`^[1-9][0-9]+$`)
	computeNamePattern    = regexp.MustCompile(`^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	serviceAccountPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,126}@[a-z0-9][a-z0-9.-]{0,126}\.gserviceaccount\.com$`)
	customRolePattern     = regexp.MustCompile(`^[A-Za-z0-9_.]{1,64}$`)
	secretNamePattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
	schedulerNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,500}$`)
)

type Availability string

const (
	AvailabilityUp         Availability = "up"
	AvailabilityDown       Availability = "down"
	AvailabilityDeprecated Availability = "deprecated"
)

type APIState string

const (
	APIEnabled  APIState = "enabled"
	APIDisabled APIState = "disabled"
	APIUnknown  APIState = "unknown"
)

type ResourceKind string

const (
	ResourceNetwork        ResourceKind = "compute.network"
	ResourceSubnetwork     ResourceKind = "compute.subnetwork"
	ResourceRouter         ResourceKind = "compute.router"
	ResourceNAT            ResourceKind = "compute.nat"
	ResourceFirewall       ResourceKind = "compute.firewall"
	ResourceInstance       ResourceKind = "compute.instance"
	ResourceDisk           ResourceKind = "compute.disk"
	ResourceSnapshot       ResourceKind = "compute.snapshot"
	ResourceAddress        ResourceKind = "compute.address"
	ResourceResourcePolicy ResourceKind = "compute.resource-policy"
	ResourceServiceAccount ResourceKind = "iam.service-account"
	ResourceCustomRole     ResourceKind = "iam.custom-role"
	ResourceBucket         ResourceKind = "storage.bucket"
	ResourceSecret         ResourceKind = "secretmanager.secret"
	ResourceRunJob         ResourceKind = "run.job"
	ResourceSchedulerJob   ResourceKind = "scheduler.job"
)

var knownResourceKinds = map[ResourceKind]struct{}{
	ResourceNetwork: {}, ResourceSubnetwork: {}, ResourceRouter: {}, ResourceNAT: {},
	ResourceFirewall: {}, ResourceInstance: {}, ResourceDisk: {}, ResourceSnapshot: {},
	ResourceAddress: {}, ResourceResourcePolicy: {}, ResourceServiceAccount: {},
	ResourceCustomRole: {}, ResourceBucket: {}, ResourceSecret: {}, ResourceRunJob: {},
	ResourceSchedulerJob: {},
}

var absenceProofKinds = map[ResourceKind]struct{}{
	ResourceNetwork: {}, ResourceSubnetwork: {}, ResourceRouter: {}, ResourceNAT: {},
	ResourceFirewall: {}, ResourceInstance: {}, ResourceDisk: {}, ResourceSnapshot: {},
	ResourceAddress: {}, ResourceResourcePolicy: {}, ResourceServiceAccount: {},
	ResourceCustomRole: {}, ResourceSecret: {}, ResourceRunJob: {}, ResourceSchedulerJob: {},
}

var requiredSchemas = []string{
	"gcloud-560/apis-enabled-v1",
	"gcloud-560/auth-list-v1",
	"gcloud-560/compute-addresses-v1",
	"gcloud-560/compute-disks-v1",
	"gcloud-560/compute-firewalls-v1",
	"gcloud-560/compute-instances-v1",
	"gcloud-560/compute-machine-types-v1",
	"gcloud-560/compute-networks-v1",
	"gcloud-560/compute-regions-v1",
	"gcloud-560/compute-resource-policies-v1",
	"gcloud-560/compute-routers-v1",
	"gcloud-560/compute-snapshots-v1",
	"gcloud-560/compute-subnetworks-v1",
	"gcloud-560/compute-zones-v1",
	"gcloud-560/config-list-v1",
	"gcloud-560/iam-roles-v1",
	"gcloud-560/iam-service-accounts-v1",
	"gcloud-560/project-describe-v1",
	"gcloud-560/run-jobs-v1",
	"gcloud-560/scheduler-jobs-v1",
	"gcloud-560/secrets-v1",
	"gcloud-560/storage-buckets-v1",
	"gcloud-560/version-v1",
}

// RequiredSchemas returns the closed M1-03 source catalogue. Its completeness,
// rather than a successful empty list alone, is what permits an absence proof.
func RequiredSchemas() []string { return append([]string(nil), requiredSchemas...) }

type Region struct {
	Name         string       `json:"name"`
	Availability Availability `json:"availability"`
	ProviderID   string       `json:"providerId"`
}

type Zone struct {
	Name         string       `json:"name"`
	Region       string       `json:"region"`
	Availability Availability `json:"availability"`
	ProviderID   string       `json:"providerId"`
}

type MachineType struct {
	Name       string `json:"name"`
	Zone       string `json:"zone"`
	GuestCPUs  int64  `json:"guestCpus"`
	MemoryMiB  int64  `json:"memoryMiB"`
	SharedCPU  bool   `json:"sharedCpu"`
	Deprecated bool   `json:"deprecated"`
	ProviderID string `json:"providerId"`
}

type SubnetRange struct {
	Name       string `json:"name"`
	Project    string `json:"project"`
	Region     string `json:"region"`
	CIDR       string `json:"cidr"`
	Secondary  bool   `json:"secondary"`
	ProviderID string `json:"providerId"`
}

type Resource struct {
	Kind        ResourceKind `json:"kind"`
	Name        string       `json:"name"`
	Project     string       `json:"project"`
	Location    string       `json:"location"`
	ProviderID  string       `json:"providerId"`
	ImmutableID string       `json:"immutableId"`
}

type APIService struct {
	Name  string   `json:"name"`
	State APIState `json:"state"`
}

type FirewallRule struct {
	Name         string     `json:"name"`
	Project      string     `json:"project"`
	ProviderID   string     `json:"providerId"`
	Direction    string     `json:"direction"`
	Disabled     bool       `json:"disabled"`
	SourceRanges []string   `json:"sourceRanges"`
	Allowed      []Protocol `json:"allowed"`
}

type Protocol struct {
	Name  string   `json:"name"`
	Ports []string `json:"ports"`
}

type Seed struct {
	Account            string
	Project            string
	Region             string
	Zone               string
	GcloudVersion      string
	CompletenessPolicy string
	ObservedAt         time.Time
	ValidUntil         time.Time
	Schemas            []string
	Regions            []Region
	Zones              []Zone
	MachineTypes       []MachineType
	SubnetRanges       []SubnetRange
	Resources          []Resource
	APIs               []APIService
	Firewalls          []FirewallRule
	Exhaustive         bool
}

type preflightPayload struct {
	Account            string         `json:"account"`
	Project            string         `json:"project"`
	Region             string         `json:"region"`
	Zone               string         `json:"zone"`
	GcloudVersion      string         `json:"gcloudVersion"`
	CompletenessPolicy string         `json:"completenessPolicy"`
	ObservedAt         time.Time      `json:"observedAt"`
	ValidUntil         time.Time      `json:"validUntil"`
	Schemas            []string       `json:"schemas"`
	Regions            []Region       `json:"regions"`
	Zones              []Zone         `json:"zones"`
	MachineTypes       []MachineType  `json:"machineTypes"`
	SubnetRanges       []SubnetRange  `json:"subnetRanges"`
	Resources          []Resource     `json:"resources"`
	APIs               []APIService   `json:"apis"`
	Firewalls          []FirewallRule `json:"firewalls"`
	Exhaustive         bool           `json:"exhaustive"`
}

// HarnessPreflight is immutable, exhaustive evidence for WF-TEST-01 planning.
type HarnessPreflight struct {
	payload  preflightPayload
	revision string
}

func NewHarnessPreflight(seed Seed) (HarnessPreflight, error) {
	payload := preflightPayload{
		Account: seed.Account, Project: seed.Project, Region: seed.Region, Zone: seed.Zone,
		GcloudVersion: seed.GcloudVersion, CompletenessPolicy: seed.CompletenessPolicy,
		ObservedAt: seed.ObservedAt, ValidUntil: seed.ValidUntil,
		Schemas: append([]string(nil), seed.Schemas...), Regions: append([]Region(nil), seed.Regions...),
		Zones: append([]Zone(nil), seed.Zones...), MachineTypes: append([]MachineType(nil), seed.MachineTypes...),
		SubnetRanges: append([]SubnetRange(nil), seed.SubnetRanges...),
		Resources:    append([]Resource(nil), seed.Resources...), APIs: append([]APIService(nil), seed.APIs...),
		Firewalls: cloneFirewalls(seed.Firewalls), Exhaustive: seed.Exhaustive,
	}
	canonicalize(&payload)
	if err := validatePayload(payload); err != nil {
		return HarnessPreflight{}, err
	}
	content := payload
	content.ObservedAt = time.Time{}
	content.ValidUntil = time.Time{}
	encoded, err := json.Marshal(content)
	if err != nil {
		return HarnessPreflight{}, fmt.Errorf("%w: canonical encoding failed", ErrInvalidObservation)
	}
	digest := sha256.Sum256(encoded)
	return HarnessPreflight{payload: payload, revision: hex.EncodeToString(digest[:])}, nil
}

func (value HarnessPreflight) Account() string            { return value.payload.Account }
func (value HarnessPreflight) Project() string            { return value.payload.Project }
func (value HarnessPreflight) Region() string             { return value.payload.Region }
func (value HarnessPreflight) Zone() string               { return value.payload.Zone }
func (value HarnessPreflight) GcloudVersion() string      { return value.payload.GcloudVersion }
func (value HarnessPreflight) CompletenessPolicy() string { return value.payload.CompletenessPolicy }
func (value HarnessPreflight) ObservedAt() time.Time      { return value.payload.ObservedAt }
func (value HarnessPreflight) ValidUntil() time.Time      { return value.payload.ValidUntil }
func (value HarnessPreflight) Exhaustive() bool           { return value.payload.Exhaustive }
func (value HarnessPreflight) Revision() string           { return value.revision }
func (value HarnessPreflight) Schemas() []string {
	return append([]string(nil), value.payload.Schemas...)
}
func (value HarnessPreflight) Regions() []Region {
	return append([]Region(nil), value.payload.Regions...)
}
func (value HarnessPreflight) CompatibleRegions() []Region {
	result := make([]Region, 0, len(value.payload.Regions))
	for _, region := range value.payload.Regions {
		if region.Availability == AvailabilityUp {
			result = append(result, region)
		}
	}
	return result
}
func (value HarnessPreflight) Zones() []Zone { return append([]Zone(nil), value.payload.Zones...) }
func (value HarnessPreflight) CompatibleZones() []Zone {
	upRegions := make(map[string]struct{})
	for _, region := range value.payload.Regions {
		if region.Availability == AvailabilityUp {
			upRegions[region.Name] = struct{}{}
		}
	}
	result := make([]Zone, 0, len(value.payload.Zones))
	for _, zone := range value.payload.Zones {
		if _, ok := upRegions[zone.Region]; ok && zone.Availability == AvailabilityUp {
			result = append(result, zone)
		}
	}
	return result
}
func (value HarnessPreflight) MachineTypes() []MachineType {
	return append([]MachineType(nil), value.payload.MachineTypes...)
}
func (value HarnessPreflight) CompatibleMachineTypes() []MachineType {
	result := make([]MachineType, 0, len(value.payload.MachineTypes))
	for _, machine := range value.payload.MachineTypes {
		if !machine.Deprecated {
			result = append(result, machine)
		}
	}
	return result
}
func (value HarnessPreflight) SubnetRanges() []SubnetRange {
	return append([]SubnetRange(nil), value.payload.SubnetRanges...)
}
func (value HarnessPreflight) Resources() []Resource {
	return append([]Resource(nil), value.payload.Resources...)
}
func (value HarnessPreflight) APIs() []APIService {
	return append([]APIService(nil), value.payload.APIs...)
}
func (value HarnessPreflight) Firewalls() []FirewallRule {
	return cloneFirewalls(value.payload.Firewalls)
}

func (value HarnessPreflight) APIState(name string) APIState {
	index := sort.Search(len(value.payload.APIs), func(index int) bool { return value.payload.APIs[index].Name >= name })
	if index < len(value.payload.APIs) && value.payload.APIs[index].Name == name {
		return value.payload.APIs[index].State
	}
	return APIUnknown
}

func (value HarnessPreflight) HasCollision(kind ResourceKind, name string) bool {
	for _, resource := range value.payload.Resources {
		if resource.Kind == kind && resource.Name == name {
			return true
		}
	}
	return false
}

// ProvesAbsenceAt returns true only from a fresh, complete preflight and for
// one resource kind whose listing proves provider-wide absence. Project-local
// bucket listing is collision evidence, but cannot prove globally unique name
// availability.
func (value HarnessPreflight) ProvesAbsenceAt(kind ResourceKind, name string, now time.Time) (bool, error) {
	if !value.payload.Exhaustive || !value.FreshAt(now) {
		return false, observationError("exhaustive", "is required for absence proof")
	}
	if _, ok := absenceProofKinds[kind]; !ok || name == "" || strings.TrimSpace(name) != name {
		return false, observationError("resource", "does not identify one supported kind and name")
	}
	return !value.HasCollision(kind, name), nil
}

func (value HarnessPreflight) FreshAt(now time.Time) bool {
	if now.IsZero() {
		return false
	}
	if _, offset := now.Zone(); offset != 0 {
		return false
	}
	return !now.Before(value.payload.ObservedAt) && now.Before(value.payload.ValidUntil)
}

func (value HarnessPreflight) CIDROverlapsAt(candidate string, now time.Time) (bool, error) {
	if !value.FreshAt(now) {
		return false, observationError("freshness", "is required for CIDR comparison")
	}
	prefix, err := netip.ParsePrefix(candidate)
	if err != nil || !prefix.Addr().IsPrivate() || prefix != prefix.Masked() {
		return false, fmt.Errorf("%w: candidate CIDR is not one canonical private prefix", ErrInvalidObservation)
	}
	for _, existing := range value.payload.SubnetRanges {
		other, parseErr := netip.ParsePrefix(existing.CIDR)
		if parseErr != nil {
			return false, fmt.Errorf("%w: stored subnet CIDR is invalid", ErrInvalidObservation)
		}
		if prefix.Overlaps(other) {
			return true, nil
		}
	}
	return false, nil
}

func (value HarnessPreflight) PublicMongoDBIngressAt(now time.Time) ([]string, error) {
	if !value.FreshAt(now) {
		return nil, observationError("freshness", "is required for firewall evaluation")
	}
	result := make([]string, 0)
	for _, rule := range value.payload.Firewalls {
		if exposesMongoDB(rule) {
			result = append(result, rule.Name)
		}
	}
	return result, nil
}

func validatePayload(value preflightPayload) error {
	if !value.Exhaustive {
		return observationError("exhaustive", "must be true for absence proof")
	}
	if !accountPattern.MatchString(value.Account) || !projectPattern.MatchString(value.Project) ||
		!locationPattern.MatchString(value.Region) || !locationPattern.MatchString(value.Zone) ||
		!strings.HasPrefix(value.Zone, value.Region+"-") {
		return observationError("context", "must contain one explicit matching account, project, region, and zone")
	}
	if value.GcloudVersion != SupportedGcloudVersion {
		return observationError("gcloudVersion", "is unsupported")
	}
	if value.CompletenessPolicy != GcloudCompletenessPolicy {
		return observationError("completenessPolicy", "is unsupported")
	}
	if err := validateWindow(value.ObservedAt, value.ValidUntil); err != nil {
		return err
	}
	if hasDuplicateOrBlank(value.Schemas) || len(value.Schemas) != len(requiredSchemas) {
		return observationError("schemas", "must be the complete unique source catalogue")
	}
	for index, expected := range requiredSchemas {
		if value.Schemas[index] != expected {
			return observationError("schemas", "does not match the closed source catalogue")
		}
	}
	regionNames := make(map[string]Availability, len(value.Regions))
	for _, region := range value.Regions {
		if !locationPattern.MatchString(region.Name) || !validAvailability(region.Availability) ||
			!providerPathEquals(region.ProviderID, value.Project, "regions", region.Name) {
			return observationError("regions", "contains an invalid or cross-project record")
		}
		if _, exists := regionNames[region.Name]; exists {
			return observationError("regions", "contains a duplicate identity")
		}
		regionNames[region.Name] = region.Availability
	}
	if regionNames[value.Region] != AvailabilityUp {
		return observationError("region", "is absent, unavailable, or deprecated")
	}
	zoneNames := make(map[string]Zone, len(value.Zones))
	for _, zone := range value.Zones {
		if !locationPattern.MatchString(zone.Name) || zone.Region == "" || !validAvailability(zone.Availability) ||
			!providerPathEquals(zone.ProviderID, value.Project, "zones", zone.Name) || !strings.HasPrefix(zone.Name, zone.Region+"-") {
			return observationError("zones", "contains an invalid or cross-project record")
		}
		if _, exists := regionNames[zone.Region]; !exists {
			return observationError("zones", "references an unknown region")
		}
		if _, exists := zoneNames[zone.Name]; exists {
			return observationError("zones", "contains a duplicate identity")
		}
		zoneNames[zone.Name] = zone
	}
	selectedZone, exists := zoneNames[value.Zone]
	if !exists || selectedZone.Region != value.Region || selectedZone.Availability != AvailabilityUp {
		return observationError("zone", "is absent, unavailable, deprecated, or outside the selected region")
	}
	seenMachines := make(map[string]struct{}, len(value.MachineTypes))
	for _, machine := range value.MachineTypes {
		if !resourceNamePattern.MatchString(machine.Name) || machine.Zone != value.Zone || machine.GuestCPUs <= 0 ||
			machine.MemoryMiB <= 0 || !providerPathEquals(machine.ProviderID, value.Project, "zones", machine.Zone, "machineTypes", machine.Name) {
			return observationError("machineTypes", "contains an invalid, cross-zone, or cross-project record")
		}
		if _, exists := seenMachines[machine.Name]; exists {
			return observationError("machineTypes", "contains a duplicate identity")
		}
		seenMachines[machine.Name] = struct{}{}
	}
	seenSubnets := make(map[string]struct{}, len(value.SubnetRanges))
	for _, subnet := range value.SubnetRanges {
		prefix, err := netip.ParsePrefix(subnet.CIDR)
		if err != nil || prefix != prefix.Masked() || subnet.Project != value.Project ||
			!locationPattern.MatchString(subnet.Region) ||
			!providerPathEquals(subnet.ProviderID, value.Project, "regions", subnet.Region, "subnetworks", subnet.Name) {
			return observationError("subnetRanges", "contains an invalid or cross-project record")
		}
		key := subnet.ProviderID + "\x00" + subnet.CIDR
		if _, exists := seenSubnets[key]; exists {
			return observationError("subnetRanges", "contains a duplicate identity")
		}
		seenSubnets[key] = struct{}{}
	}
	seenResources := make(map[string]struct{}, len(value.Resources))
	for _, resource := range value.Resources {
		if _, ok := knownResourceKinds[resource.Kind]; !ok || resource.Project != value.Project ||
			!validResourceIdentity(resource) || !validResourceProviderID(resource) {
			return observationError("resources."+string(resource.Kind), "contains an unknown, incomplete, or cross-project record")
		}
		if resource.Kind == ResourceServiceAccount {
			if !immutableIDPattern.MatchString(resource.ImmutableID) {
				return observationError("resources."+string(resource.Kind), "contains an invalid immutable identity")
			}
		} else if resource.ImmutableID != "" {
			return observationError("resources."+string(resource.Kind), "contains an unexpected immutable identity")
		}
		key := string(resource.Kind) + "\x00" + resource.ProviderID
		if _, exists := seenResources[key]; exists {
			return observationError("resources", "contains a duplicate identity")
		}
		seenResources[key] = struct{}{}
	}
	seenAPIs := make(map[string]struct{}, len(value.APIs))
	for _, service := range value.APIs {
		if !servicePattern.MatchString(service.Name) || (service.State != APIEnabled && service.State != APIDisabled) {
			return observationError("apis", "contains an invalid or unknown state")
		}
		if _, exists := seenAPIs[service.Name]; exists {
			return observationError("apis", "contains a duplicate service")
		}
		seenAPIs[service.Name] = struct{}{}
	}
	seenFirewalls := make(map[string]struct{}, len(value.Firewalls))
	for _, firewall := range value.Firewalls {
		if firewall.Project != value.Project || firewall.Name == "" ||
			!providerPathEquals(firewall.ProviderID, value.Project, "global", "firewalls", firewall.Name) ||
			(firewall.Direction != "INGRESS" && firewall.Direction != "EGRESS") {
			return observationError("firewalls", "contains an invalid or cross-project record")
		}
		if _, exists := seenFirewalls[firewall.ProviderID]; exists {
			return observationError("firewalls", "contains a duplicate identity")
		}
		seenFirewalls[firewall.ProviderID] = struct{}{}
		seenProtocols := make(map[string]struct{}, len(firewall.Allowed))
		for _, source := range firewall.SourceRanges {
			prefix, err := netip.ParsePrefix(source)
			if err != nil || prefix != prefix.Masked() {
				return observationError("firewalls", "contains an invalid source CIDR")
			}
		}
		for _, allowed := range firewall.Allowed {
			if !validIPProtocol(allowed.Name) {
				return observationError("firewalls", "contains an unsupported protocol")
			}
			if _, duplicate := seenProtocols[allowed.Name]; duplicate {
				return observationError("firewalls", "contains a duplicate protocol")
			}
			seenProtocols[allowed.Name] = struct{}{}
			for _, port := range allowed.Ports {
				if !validPortExpression(port) {
					return observationError("firewalls", "contains an invalid port expression")
				}
			}
		}
	}
	return nil
}

func validateWindow(observedAt, validUntil time.Time) error {
	if observedAt.IsZero() || validUntil.IsZero() || !observedAt.Before(validUntil) ||
		validUntil.Sub(observedAt) > MaxEvidenceLifetime {
		return observationError("observationWindow", "must be positive and bounded")
	}
	if _, offset := observedAt.Zone(); offset != 0 {
		return observationError("observedAt", "must use UTC")
	}
	if _, offset := validUntil.Zone(); offset != 0 {
		return observationError("validUntil", "must use UTC")
	}
	return nil
}

func validAvailability(value Availability) bool {
	return value == AvailabilityUp || value == AvailabilityDown || value == AvailabilityDeprecated
}

func validIPProtocol(value string) bool {
	switch value {
	case "tcp", "udp", "icmp", "esp", "ah", "ipip", "sctp", "all":
		return true
	}
	number, err := strconv.ParseUint(value, 10, 8)
	return err == nil && strconv.FormatUint(number, 10) == value
}

func validResourceIdentity(resource Resource) bool {
	switch resource.Kind {
	case ResourceNetwork, ResourceSubnetwork, ResourceRouter, ResourceNAT, ResourceFirewall,
		ResourceInstance, ResourceDisk, ResourceSnapshot, ResourceAddress, ResourceResourcePolicy:
		return computeNamePattern.MatchString(resource.Name) && validResourceLocation(resource)
	case ResourceServiceAccount:
		return serviceAccountPattern.MatchString(resource.Name) && resource.Location == "global"
	case ResourceCustomRole:
		return customRolePattern.MatchString(resource.Name) && resource.Location == "global"
	case ResourceBucket:
		return validBucketName(resource.Name) && locationPattern.MatchString(resource.Location)
	case ResourceSecret:
		return secretNamePattern.MatchString(resource.Name) && resource.Location == "global"
	case ResourceRunJob:
		return len(resource.Name) <= 49 && computeNamePattern.MatchString(resource.Name) && locationPattern.MatchString(resource.Location)
	case ResourceSchedulerJob:
		return schedulerNamePattern.MatchString(resource.Name) && locationPattern.MatchString(resource.Location)
	default:
		return false
	}
}

func validResourceLocation(resource Resource) bool {
	switch resource.Kind {
	case ResourceNetwork, ResourceFirewall, ResourceSnapshot:
		return resource.Location == "global"
	case ResourceSubnetwork, ResourceRouter, ResourceNAT, ResourceInstance, ResourceDisk, ResourceResourcePolicy:
		return resource.Location != "global" && locationPattern.MatchString(resource.Location)
	case ResourceAddress:
		return resource.Location == "global" || locationPattern.MatchString(resource.Location)
	default:
		return false
	}
}

func validBucketName(value string) bool {
	if len(value) < 3 || len(value) > 222 {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	if !lowerAlphaNumeric(value[0]) || !lowerAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for _, component := range strings.Split(value, ".") {
		if len(component) == 0 || len(component) > 63 {
			return false
		}
		for _, character := range component {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
				return false
			}
		}
	}
	return true
}

func lowerAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func validProviderID(value, project string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0 {
		return false
	}
	parts := strings.Split(value, "/")
	projectScopes := 0
	for index, part := range parts {
		if part != "projects" {
			continue
		}
		if index+1 >= len(parts) || parts[index+1] != project {
			return false
		}
		projectScopes++
	}
	return projectScopes == 1
}

func providerPathEquals(value, project string, expected ...string) bool {
	if !validProviderID(value, project) {
		return false
	}
	parts := strings.Split(value, "/")
	for index, part := range parts {
		if part == "projects" && index+1 < len(parts) && parts[index+1] == project {
			return slicesEqual(parts[index+2:], expected)
		}
	}
	return false
}

func validResourceProviderID(resource Resource) bool {
	project, location, name := resource.Project, resource.Location, resource.Name
	switch resource.Kind {
	case ResourceNetwork:
		return providerPathEquals(resource.ProviderID, project, "global", "networks", name)
	case ResourceSubnetwork:
		return providerPathEquals(resource.ProviderID, project, "regions", location, "subnetworks", name)
	case ResourceRouter:
		return providerPathEquals(resource.ProviderID, project, "regions", location, "routers", name)
	case ResourceNAT:
		parts := providerPath(resource.ProviderID, project)
		return len(parts) == 6 && parts[0] == "regions" && parts[1] == location &&
			parts[2] == "routers" && parts[3] != "" && parts[4] == "nats" && parts[5] == name
	case ResourceFirewall:
		return providerPathEquals(resource.ProviderID, project, "global", "firewalls", name)
	case ResourceInstance:
		return providerPathEquals(resource.ProviderID, project, "zones", location, "instances", name)
	case ResourceDisk:
		return providerPathEquals(resource.ProviderID, project, "zones", location, "disks", name) ||
			providerPathEquals(resource.ProviderID, project, "regions", location, "disks", name)
	case ResourceSnapshot:
		return providerPathEquals(resource.ProviderID, project, "global", "snapshots", name)
	case ResourceAddress:
		return providerPathEquals(resource.ProviderID, project, "global", "addresses", name) ||
			providerPathEquals(resource.ProviderID, project, "regions", location, "addresses", name)
	case ResourceResourcePolicy:
		return providerPathEquals(resource.ProviderID, project, "regions", location, "resourcePolicies", name)
	case ResourceServiceAccount:
		return providerPathEquals(resource.ProviderID, project, "serviceAccounts", name)
	case ResourceCustomRole:
		return providerPathEquals(resource.ProviderID, project, "roles", name)
	case ResourceBucket:
		return providerPathEquals(resource.ProviderID, project, "global", string(ResourceBucket), name)
	case ResourceSecret:
		return providerPathEquals(resource.ProviderID, project, "secrets", name)
	case ResourceRunJob:
		return providerPathEquals(resource.ProviderID, project, "regions", location, string(ResourceRunJob), name)
	case ResourceSchedulerJob:
		return providerPathEquals(resource.ProviderID, project, "locations", location, "jobs", name)
	default:
		return false
	}
}

func providerPath(value, project string) []string {
	if !validProviderID(value, project) {
		return nil
	}
	parts := strings.Split(value, "/")
	for index, part := range parts {
		if part == "projects" && index+1 < len(parts) && parts[index+1] == project {
			return parts[index+2:]
		}
	}
	return nil
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hasDuplicateOrBlank(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return true
		}
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func validPortExpression(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	first, ok := canonicalPort(parts[0])
	if !ok {
		return false
	}
	if len(parts) == 1 {
		return true
	}
	last, ok := canonicalPort(parts[1])
	return ok && first <= last
}

func canonicalPort(value string) (uint64, bool) {
	number, err := strconv.ParseUint(value, 10, 16)
	return number, err == nil && strconv.FormatUint(number, 10) == value
}

func exposesMongoDB(rule FirewallRule) bool {
	if rule.Disabled || rule.Direction != "INGRESS" {
		return false
	}
	public := false
	for _, source := range rule.SourceRanges {
		if source == "0.0.0.0/0" {
			public = true
			break
		}
	}
	if !public {
		return false
	}
	for _, allowed := range rule.Allowed {
		if allowed.Name != "tcp" && allowed.Name != "6" && allowed.Name != "all" {
			continue
		}
		if len(allowed.Ports) == 0 {
			return true
		}
		for _, port := range allowed.Ports {
			if port == "27017" {
				return true
			}
			parts := strings.Split(port, "-")
			if len(parts) != 2 {
				continue
			}
			first, firstErr := strconv.ParseUint(parts[0], 10, 16)
			last, lastErr := strconv.ParseUint(parts[1], 10, 16)
			if firstErr == nil && lastErr == nil && first <= 27017 && last >= 27017 {
				return true
			}
		}
	}
	return false
}

func canonicalize(value *preflightPayload) {
	sort.Strings(value.Schemas)
	sort.Slice(value.Regions, func(i, j int) bool { return value.Regions[i].Name < value.Regions[j].Name })
	sort.Slice(value.Zones, func(i, j int) bool { return value.Zones[i].Name < value.Zones[j].Name })
	sort.Slice(value.MachineTypes, func(i, j int) bool { return value.MachineTypes[i].Name < value.MachineTypes[j].Name })
	sort.Slice(value.SubnetRanges, func(i, j int) bool {
		if value.SubnetRanges[i].ProviderID == value.SubnetRanges[j].ProviderID {
			return value.SubnetRanges[i].CIDR < value.SubnetRanges[j].CIDR
		}
		return value.SubnetRanges[i].ProviderID < value.SubnetRanges[j].ProviderID
	})
	sort.Slice(value.Resources, func(i, j int) bool {
		if value.Resources[i].Kind == value.Resources[j].Kind {
			return value.Resources[i].ProviderID < value.Resources[j].ProviderID
		}
		return value.Resources[i].Kind < value.Resources[j].Kind
	})
	sort.Slice(value.APIs, func(i, j int) bool { return value.APIs[i].Name < value.APIs[j].Name })
	for index := range value.Firewalls {
		sort.Strings(value.Firewalls[index].SourceRanges)
		for protocol := range value.Firewalls[index].Allowed {
			sort.Strings(value.Firewalls[index].Allowed[protocol].Ports)
		}
		sort.Slice(value.Firewalls[index].Allowed, func(i, j int) bool {
			return value.Firewalls[index].Allowed[i].Name < value.Firewalls[index].Allowed[j].Name
		})
	}
	sort.Slice(value.Firewalls, func(i, j int) bool { return value.Firewalls[i].ProviderID < value.Firewalls[j].ProviderID })
}

func cloneFirewalls(values []FirewallRule) []FirewallRule {
	result := make([]FirewallRule, len(values))
	for index, value := range values {
		result[index] = value
		result[index].SourceRanges = append([]string(nil), value.SourceRanges...)
		result[index].Allowed = make([]Protocol, len(value.Allowed))
		for protocol, allowed := range value.Allowed {
			result[index].Allowed[protocol] = allowed
			result[index].Allowed[protocol].Ports = append([]string(nil), allowed.Ports...)
		}
	}
	return result
}

func observationError(path, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidObservation, path, reason)
}
