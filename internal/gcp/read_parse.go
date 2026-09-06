// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/thelostorbital/ctrldb/internal/observation"
)

const (
	schemaVersion          = "gcloud-560/version-v1"
	schemaAuth             = "gcloud-560/auth-list-v1"
	schemaConfiguration    = "gcloud-560/config-list-v1"
	schemaProject          = "gcloud-560/project-describe-v1"
	schemaRegions          = "gcloud-560/compute-regions-v1"
	schemaZones            = "gcloud-560/compute-zones-v1"
	schemaMachineTypes     = "gcloud-560/compute-machine-types-v1"
	schemaNetworks         = "gcloud-560/compute-networks-v1"
	schemaSubnets          = "gcloud-560/compute-subnetworks-v1"
	schemaRouters          = "gcloud-560/compute-routers-v1"
	schemaFirewalls        = "gcloud-560/compute-firewalls-v1"
	schemaInstances        = "gcloud-560/compute-instances-v1"
	schemaDisks            = "gcloud-560/compute-disks-v1"
	schemaSnapshots        = "gcloud-560/compute-snapshots-v1"
	schemaAddresses        = "gcloud-560/compute-addresses-v1"
	schemaResourcePolicies = "gcloud-560/compute-resource-policies-v1"
	schemaServiceAccounts  = "gcloud-560/iam-service-accounts-v1"
	schemaRoles            = "gcloud-560/iam-roles-v1"
	schemaBuckets          = "gcloud-560/storage-buckets-v1"
	schemaSecrets          = "gcloud-560/secrets-v1"
	schemaRunJobs          = "gcloud-560/run-jobs-v1"
	schemaSchedulerJobs    = "gcloud-560/scheduler-jobs-v1"
	schemaAPIs             = "gcloud-560/apis-enabled-v1"
)

type deprecatedWire struct {
	State string `json:"state"`
}
type regionWire struct {
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	SelfLink   string          `json:"selfLink"`
	Deprecated *deprecatedWire `json:"deprecated,omitempty"`
}
type zoneWire struct {
	Name       string          `json:"name"`
	Region     string          `json:"region"`
	Status     string          `json:"status"`
	SelfLink   string          `json:"selfLink"`
	Deprecated *deprecatedWire `json:"deprecated,omitempty"`
}
type machineWire struct {
	Name        string          `json:"name"`
	Zone        string          `json:"zone"`
	GuestCPUs   int64           `json:"guestCpus"`
	MemoryMB    int64           `json:"memoryMb"`
	IsSharedCPU bool            `json:"isSharedCpu"`
	SelfLink    string          `json:"selfLink"`
	Deprecated  *deprecatedWire `json:"deprecated,omitempty"`
}
type namedGlobalWire struct {
	Name     string `json:"name"`
	SelfLink string `json:"selfLink"`
}
type namedRegionalWire struct {
	Name     string `json:"name"`
	Region   string `json:"region"`
	SelfLink string `json:"selfLink"`
}
type namedZonalWire struct {
	Name     string `json:"name"`
	Zone     string `json:"zone"`
	SelfLink string `json:"selfLink"`
}
type namedEitherWire struct {
	Name     string `json:"name"`
	Zone     string `json:"zone"`
	Region   string `json:"region"`
	SelfLink string `json:"selfLink"`
}
type subnetWire struct {
	Name              string `json:"name"`
	Region            string `json:"region"`
	IPCIDRRange       string `json:"ipCidrRange"`
	SelfLink          string `json:"selfLink"`
	SecondaryIPRanges []struct {
		IPCIDRRange string `json:"ipCidrRange"`
	} `json:"secondaryIpRanges"`
}
type routerWire struct {
	Name     string `json:"name"`
	Region   string `json:"region"`
	SelfLink string `json:"selfLink"`
	NATs     []struct {
		Name string `json:"name"`
	} `json:"nats"`
}
type allowedWire struct {
	IPProtocol string   `json:"IPProtocol"`
	Ports      []string `json:"ports"`
}
type firewallWire struct {
	Name         string        `json:"name"`
	SelfLink     string        `json:"selfLink"`
	Direction    string        `json:"direction"`
	Disabled     bool          `json:"disabled"`
	SourceRanges []string      `json:"sourceRanges"`
	Allowed      []allowedWire `json:"allowed"`
}
type authWire struct {
	Account string `json:"account"`
}
type configurationWire struct {
	Auth struct {
		ImpersonateServiceAccount string `json:"impersonate_service_account"`
	} `json:"auth"`
	Core struct {
		Account string `json:"account"`
		Project string `json:"project"`
	} `json:"core"`
}
type projectWire struct {
	ProjectID      string `json:"projectId"`
	ProjectNumber  string `json:"projectNumber"`
	LifecycleState string `json:"lifecycleState"`
}
type serviceAccountWire struct {
	Email     string `json:"email"`
	ProjectID string `json:"projectId"`
	UniqueID  string `json:"uniqueId"`
}
type roleWire struct {
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
}
type bucketWire struct {
	Name     string `json:"name"`
	Location string `json:"location"`
}
type secretWire struct {
	Name string `json:"name"`
}
type runJobWire struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
}
type schedulerJobWire struct {
	Name string `json:"name"`
}
type serviceWire struct {
	State  string `json:"state"`
	Config struct {
		Name string `json:"name"`
	} `json:"config"`
}

func authArguments(ctx commandContext) []string {
	return globalArguments(ctx, "auth", "list", "--filter=account="+ctx.account, "--format=json(account)")
}
func configurationArguments(ctx commandContext) []string {
	return globalArguments(ctx, "config", "list", "--format=json(core.account,core.project,auth.impersonate_service_account)")
}
func projectArguments(ctx commandContext) []string {
	return globalArguments(ctx, "projects", "describe", ctx.project, "--format=json(projectId,projectNumber,lifecycleState)")
}

func (client *ReadClient) readRegions(ctx context.Context, command commandContext) ([]observation.Region, error) {
	data, err := client.run(ctx, schemaRegions, globalArguments(command, "compute", "regions", "list", "--format=json(name,status,deprecated.state,selfLink)"))
	if err != nil {
		return nil, err
	}
	var wire []regionWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaRegions, err)
	}
	result := make([]observation.Region, 0, len(wire))
	for _, item := range wire {
		availability, ok := availability(item.Status, item.Deprecated)
		if !ok {
			return nil, sourceError(schemaRegions, errInvalidJSON)
		}
		result = append(result, observation.Region{Name: item.Name, Availability: availability, ProviderID: item.SelfLink})
	}
	return result, nil
}

func (client *ReadClient) readZones(ctx context.Context, command commandContext) ([]observation.Zone, error) {
	data, err := client.run(ctx, schemaZones, globalArguments(command, "compute", "zones", "list", "--format=json(name,region,status,deprecated.state,selfLink)"))
	if err != nil {
		return nil, err
	}
	var wire []zoneWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaZones, err)
	}
	result := make([]observation.Zone, 0, len(wire))
	for _, item := range wire {
		region, locationOK := normalizeComputeLocation(item.Region, command.project, "regions")
		if !locationOK {
			return nil, sourceError(schemaZones, errInvalidJSON)
		}
		availability, ok := availability(item.Status, item.Deprecated)
		if !ok {
			return nil, sourceError(schemaZones, errInvalidJSON)
		}
		result = append(result, observation.Zone{Name: item.Name, Region: region, Availability: availability, ProviderID: item.SelfLink})
	}
	return result, nil
}

func (client *ReadClient) readMachineTypes(ctx context.Context, command commandContext) ([]observation.MachineType, error) {
	args := globalArguments(command, "compute", "machine-types", "list", "--zones="+command.zone, "--format=json(name,zone,guestCpus,memoryMb,isSharedCpu,deprecated.state,selfLink)")
	data, err := client.run(ctx, schemaMachineTypes, args)
	if err != nil {
		return nil, err
	}
	var wire []machineWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaMachineTypes, err)
	}
	result := make([]observation.MachineType, 0, len(wire))
	for _, item := range wire {
		zone, locationOK := normalizeComputeLocation(item.Zone, command.project, "zones")
		if !locationOK {
			return nil, sourceError(schemaMachineTypes, errInvalidJSON)
		}
		deprecated, ok := deprecatedValue(item.Deprecated)
		if !ok {
			return nil, sourceError(schemaMachineTypes, errInvalidJSON)
		}
		result = append(result, observation.MachineType{Name: item.Name, Zone: zone, GuestCPUs: item.GuestCPUs, MemoryMiB: item.MemoryMB, SharedCPU: item.IsSharedCPU, Deprecated: deprecated, ProviderID: item.SelfLink})
	}
	return result, nil
}

func (client *ReadClient) readNetworks(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	return client.readGlobalResources(ctx, command, schemaNetworks, observation.ResourceNetwork, []string{"compute", "networks", "list", "--format=json(name,selfLink)"})
}

func (client *ReadClient) readSubnets(ctx context.Context, command commandContext) ([]observation.SubnetRange, []observation.Resource, error) {
	data, err := client.run(ctx, schemaSubnets, globalArguments(command, "compute", "networks", "subnets", "list", "--format=json(name,region,ipCidrRange,secondaryIpRanges.ipCidrRange,selfLink)"))
	if err != nil {
		return nil, nil, err
	}
	var wire []subnetWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, nil, sourceError(schemaSubnets, err)
	}
	ranges := make([]observation.SubnetRange, 0, len(wire))
	resources := make([]observation.Resource, 0, len(wire))
	for _, item := range wire {
		region, locationOK := normalizeComputeLocation(item.Region, command.project, "regions")
		if !locationOK {
			return nil, nil, sourceError(schemaSubnets, errInvalidJSON)
		}
		resources = append(resources, resource(command.project, observation.ResourceSubnetwork, item.Name, region, item.SelfLink))
		ranges = append(ranges, observation.SubnetRange{Name: item.Name, Project: command.project, Region: region, CIDR: item.IPCIDRRange, ProviderID: item.SelfLink})
		for _, secondary := range item.SecondaryIPRanges {
			ranges = append(ranges, observation.SubnetRange{Name: item.Name, Project: command.project, Region: region, CIDR: secondary.IPCIDRRange, Secondary: true, ProviderID: item.SelfLink})
		}
	}
	return ranges, resources, nil
}

func (client *ReadClient) readRouters(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	data, err := client.run(ctx, schemaRouters, globalArguments(command, "compute", "routers", "list", "--format=json(name,region,nats.name,selfLink)"))
	if err != nil {
		return nil, err
	}
	var wire []routerWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaRouters, err)
	}
	result := make([]observation.Resource, 0, len(wire)*2)
	for _, item := range wire {
		region, locationOK := normalizeComputeLocation(item.Region, command.project, "regions")
		if !locationOK {
			return nil, sourceError(schemaRouters, errInvalidJSON)
		}
		result = append(result, resource(command.project, observation.ResourceRouter, item.Name, region, item.SelfLink))
		for _, nat := range item.NATs {
			providerID := item.SelfLink + "/nats/" + nat.Name
			result = append(result, resource(command.project, observation.ResourceNAT, nat.Name, region, providerID))
		}
	}
	return result, nil
}

func (client *ReadClient) readFirewalls(ctx context.Context, command commandContext) ([]observation.FirewallRule, []observation.Resource, error) {
	data, err := client.run(ctx, schemaFirewalls, globalArguments(command, "compute", "firewall-rules", "list", "--format=json(name,selfLink,direction,disabled,sourceRanges,allowed.IPProtocol,allowed.ports)"))
	if err != nil {
		return nil, nil, err
	}
	var wire []firewallWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, nil, sourceError(schemaFirewalls, err)
	}
	proofs := make([]observation.FirewallRule, 0, len(wire))
	resources := make([]observation.Resource, 0, len(wire))
	for _, item := range wire {
		allowed := make([]observation.Protocol, len(item.Allowed))
		for index, protocol := range item.Allowed {
			allowed[index] = observation.Protocol{Name: protocol.IPProtocol, Ports: append([]string(nil), protocol.Ports...)}
		}
		proofs = append(proofs, observation.FirewallRule{Name: item.Name, Project: command.project, ProviderID: item.SelfLink, Direction: item.Direction, Disabled: item.Disabled, SourceRanges: append([]string(nil), item.SourceRanges...), Allowed: allowed})
		resources = append(resources, resource(command.project, observation.ResourceFirewall, item.Name, "global", item.SelfLink))
	}
	return proofs, resources, nil
}

func (client *ReadClient) readInstances(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	return client.readZonalResources(ctx, command, schemaInstances, observation.ResourceInstance, []string{"compute", "instances", "list", "--format=json(name,zone,selfLink)"})
}
func (client *ReadClient) readDisks(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	data, err := client.run(ctx, schemaDisks, globalArguments(command, "compute", "disks", "list", "--format=json(name,zone,region,selfLink)"))
	if err != nil {
		return nil, err
	}
	var wire []namedEitherWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaDisks, err)
	}
	result := make([]observation.Resource, 0, len(wire))
	for _, item := range wire {
		if (item.Zone == "") == (item.Region == "") {
			return nil, sourceError(schemaDisks, errInvalidJSON)
		}
		location, locationOK := normalizeComputeLocation(item.Zone, command.project, "zones")
		if item.Zone == "" {
			location, locationOK = normalizeComputeLocation(item.Region, command.project, "regions")
		}
		if !locationOK {
			return nil, sourceError(schemaDisks, errInvalidJSON)
		}
		result = append(result, resource(command.project, observation.ResourceDisk, item.Name, location, item.SelfLink))
	}
	return result, nil
}
func (client *ReadClient) readSnapshots(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	return client.readGlobalResources(ctx, command, schemaSnapshots, observation.ResourceSnapshot, []string{"compute", "snapshots", "list", "--format=json(name,selfLink)"})
}
func (client *ReadClient) readAddresses(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	data, err := client.run(ctx, schemaAddresses, globalArguments(command, "compute", "addresses", "list", "--format=json(name,region,selfLink)"))
	if err != nil {
		return nil, err
	}
	var wire []namedRegionalWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaAddresses, err)
	}
	result := make([]observation.Resource, 0, len(wire))
	for _, item := range wire {
		location := "global"
		if item.Region != "" {
			var locationOK bool
			location, locationOK = normalizeComputeLocation(item.Region, command.project, "regions")
			if !locationOK {
				return nil, sourceError(schemaAddresses, errInvalidJSON)
			}
		}
		result = append(result, resource(command.project, observation.ResourceAddress, item.Name, location, item.SelfLink))
	}
	return result, nil
}
func (client *ReadClient) readResourcePolicies(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	return client.readRegionalResources(ctx, command, schemaResourcePolicies, observation.ResourceResourcePolicy, []string{"compute", "resource-policies", "list", "--format=json(name,region,selfLink)"})
}

func (client *ReadClient) readServiceAccounts(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	data, err := client.run(ctx, schemaServiceAccounts, globalArguments(command, "iam", "service-accounts", "list", "--format=json(email,projectId,uniqueId)"))
	if err != nil {
		return nil, err
	}
	var wire []serviceAccountWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaServiceAccounts, err)
	}
	result := make([]observation.Resource, 0, len(wire))
	for _, item := range wire {
		if item.ProjectID != command.project || item.UniqueID == "" {
			return nil, sourceError(schemaServiceAccounts, errInvalidJSON)
		}
		providerID := "projects/" + item.ProjectID + "/serviceAccounts/" + item.Email
		value := resource(command.project, observation.ResourceServiceAccount, item.Email, "global", providerID)
		value.ImmutableID = item.UniqueID
		result = append(result, value)
	}
	return result, nil
}

func (client *ReadClient) readRoles(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	data, err := client.run(ctx, schemaRoles, globalArguments(command, "iam", "roles", "list", "--show-deleted", "--format=json(name,deleted)"))
	if err != nil {
		return nil, err
	}
	var wire []roleWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaRoles, err)
	}
	result := make([]observation.Resource, 0, len(wire))
	prefix := "projects/" + command.project + "/roles/"
	for _, item := range wire {
		if !strings.HasPrefix(item.Name, prefix) {
			return nil, sourceError(schemaRoles, errInvalidJSON)
		}
		result = append(result, resource(command.project, observation.ResourceCustomRole, strings.TrimPrefix(item.Name, prefix), "global", item.Name))
	}
	return result, nil
}

func (client *ReadClient) readBuckets(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	data, err := client.run(ctx, schemaBuckets, globalArguments(command, "storage", "buckets", "list", "--format=json(name,location)"))
	if err != nil {
		return nil, err
	}
	var wire []bucketWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaBuckets, err)
	}
	result := make([]observation.Resource, 0, len(wire))
	for _, item := range wire {
		providerID := normalizedProviderID(command.project, observation.ResourceBucket, "global", item.Name)
		result = append(result, resource(command.project, observation.ResourceBucket, item.Name, strings.ToLower(item.Location), providerID))
	}
	return result, nil
}

func (client *ReadClient) readSecrets(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	data, err := client.run(ctx, schemaSecrets, globalArguments(command, "secrets", "list", "--format=json(name)"))
	if err != nil {
		return nil, err
	}
	var wire []secretWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaSecrets, err)
	}
	result := make([]observation.Resource, 0, len(wire))
	prefix := "projects/" + command.project + "/secrets/"
	for _, item := range wire {
		if !strings.HasPrefix(item.Name, prefix) {
			return nil, sourceError(schemaSecrets, errInvalidJSON)
		}
		result = append(result, resource(command.project, observation.ResourceSecret, strings.TrimPrefix(item.Name, prefix), "global", item.Name))
	}
	return result, nil
}

func (client *ReadClient) readRunJobs(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	args := globalArguments(command, "run", "jobs", "list", "--region="+command.region, "--format=json(metadata.name)")
	data, err := client.run(ctx, schemaRunJobs, args)
	if err != nil {
		return nil, err
	}
	var wire []runJobWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaRunJobs, err)
	}
	result := make([]observation.Resource, 0, len(wire))
	for _, item := range wire {
		providerID := fmt.Sprintf("projects/%s/regions/%s/%s/%s", command.project, command.region, observation.ResourceRunJob, item.Metadata.Name)
		result = append(result, resource(command.project, observation.ResourceRunJob, item.Metadata.Name, command.region, providerID))
	}
	return result, nil
}

func (client *ReadClient) readSchedulerJobs(ctx context.Context, command commandContext) ([]observation.Resource, error) {
	args := globalArguments(command, "scheduler", "jobs", "list", "--location="+command.region, "--format=json(name)")
	data, err := client.run(ctx, schemaSchedulerJobs, args)
	if err != nil {
		return nil, err
	}
	var wire []schedulerJobWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaSchedulerJobs, err)
	}
	result := make([]observation.Resource, 0, len(wire))
	prefix := fmt.Sprintf("projects/%s/locations/%s/jobs/", command.project, command.region)
	for _, item := range wire {
		if !strings.HasPrefix(item.Name, prefix) {
			return nil, sourceError(schemaSchedulerJobs, errInvalidJSON)
		}
		result = append(result, resource(command.project, observation.ResourceSchedulerJob, strings.TrimPrefix(item.Name, prefix), command.region, item.Name))
	}
	return result, nil
}

func (client *ReadClient) readAPIs(ctx context.Context, command commandContext, required []string) ([]observation.APIService, error) {
	data, err := client.run(ctx, schemaAPIs, globalArguments(command, "services", "list", "--enabled", "--format=json(config.name,state)"))
	if err != nil {
		return nil, err
	}
	var wire []serviceWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schemaAPIs, err)
	}
	enabled := make(map[string]struct{}, len(wire))
	for _, item := range wire {
		if item.State != "ENABLED" || !servicePattern.MatchString(item.Config.Name) {
			return nil, sourceError(schemaAPIs, errInvalidJSON)
		}
		if _, duplicate := enabled[item.Config.Name]; duplicate {
			return nil, sourceError(schemaAPIs, errInvalidJSON)
		}
		enabled[item.Config.Name] = struct{}{}
	}
	result := make([]observation.APIService, 0, len(required))
	for _, name := range required {
		state := observation.APIDisabled
		if _, ok := enabled[name]; ok {
			state = observation.APIEnabled
		}
		result = append(result, observation.APIService{Name: name, State: state})
	}
	return result, nil
}

func (client *ReadClient) readGlobalResources(ctx context.Context, command commandContext, schema string, kind observation.ResourceKind, commandParts []string) ([]observation.Resource, error) {
	data, err := client.run(ctx, schema, globalArguments(command, commandParts...))
	if err != nil {
		return nil, err
	}
	var wire []namedGlobalWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schema, err)
	}
	result := make([]observation.Resource, 0, len(wire))
	for _, item := range wire {
		result = append(result, resource(command.project, kind, item.Name, "global", item.SelfLink))
	}
	return result, nil
}
func (client *ReadClient) readRegionalResources(ctx context.Context, command commandContext, schema string, kind observation.ResourceKind, commandParts []string) ([]observation.Resource, error) {
	data, err := client.run(ctx, schema, globalArguments(command, commandParts...))
	if err != nil {
		return nil, err
	}
	var wire []namedRegionalWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schema, err)
	}
	result := make([]observation.Resource, 0, len(wire))
	for _, item := range wire {
		location, locationOK := normalizeComputeLocation(item.Region, command.project, "regions")
		if !locationOK {
			return nil, sourceError(schema, errInvalidJSON)
		}
		result = append(result, resource(command.project, kind, item.Name, location, item.SelfLink))
	}
	return result, nil
}
func (client *ReadClient) readZonalResources(ctx context.Context, command commandContext, schema string, kind observation.ResourceKind, commandParts []string) ([]observation.Resource, error) {
	data, err := client.run(ctx, schema, globalArguments(command, commandParts...))
	if err != nil {
		return nil, err
	}
	var wire []namedZonalWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return nil, sourceError(schema, err)
	}
	result := make([]observation.Resource, 0, len(wire))
	for _, item := range wire {
		location, locationOK := normalizeComputeLocation(item.Zone, command.project, "zones")
		if !locationOK {
			return nil, sourceError(schema, errInvalidJSON)
		}
		result = append(result, resource(command.project, kind, item.Name, location, item.SelfLink))
	}
	return result, nil
}

func parseVersion(data []byte) (string, error) {
	var values map[string]string
	if err := decodeVersionJSON(data, &values); err != nil {
		return "", err
	}
	value := values["Google Cloud SDK"]
	if value == "" {
		return "", errInvalidJSON
	}
	return value, nil
}
func verifyAuth(data []byte, expected string) error {
	var values []authWire
	if err := decodeStrictJSON(data, &values); err != nil || len(values) != 1 || values[0].Account != expected {
		return errInvalidJSON
	}
	return nil
}
func verifyConfiguration(data []byte, expectedAccount, expectedProject string) error {
	var value configurationWire
	if err := decodeStrictJSON(data, &value); err != nil || value.Core.Account != expectedAccount ||
		value.Core.Project != expectedProject || value.Auth.ImpersonateServiceAccount != "" {
		return errInvalidJSON
	}
	return nil
}
func verifyProject(data []byte, expected string) error {
	var value projectWire
	if err := decodeStrictJSON(data, &value); err != nil || value.ProjectID != expected || value.ProjectNumber == "" || value.LifecycleState != "ACTIVE" {
		return errInvalidJSON
	}
	return nil
}

func availability(status string, deprecated *deprecatedWire) (observation.Availability, bool) {
	deprecatedValue, ok := deprecatedValue(deprecated)
	if !ok {
		return "", false
	}
	if deprecatedValue {
		return observation.AvailabilityDeprecated, true
	}
	switch status {
	case "UP":
		return observation.AvailabilityUp, true
	case "DOWN":
		return observation.AvailabilityDown, true
	default:
		return "", false
	}
}
func deprecatedValue(value *deprecatedWire) (bool, bool) {
	if value == nil {
		return false, true
	}
	switch value.State {
	case "ACTIVE":
		return false, true
	case "DEPRECATED", "OBSOLETE", "DELETED":
		return true, true
	default:
		return false, false
	}
}
func resource(project string, kind observation.ResourceKind, name, location, providerID string) observation.Resource {
	return observation.Resource{Kind: kind, Name: name, Project: project, Location: location, ProviderID: providerID}
}
