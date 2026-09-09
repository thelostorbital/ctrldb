// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/isolation"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
)

// expectedNetworkResource is one closed desired resource derived only from the
// validated harness configuration, bound to its fixed argv templates and its
// strict observation parser.
type expectedNetworkResource struct {
	resource bootstrap.DesiredResource
	command  commandContext
	vpc      string
	router   string
	nat      string
	cidr     string
	firewall networkFirewallSpec
}

// networkStateV1 reproduces the M1-04 desired-state descriptor byte for byte
// so an observed resource can be reduced to the same fingerprint the approved
// plan carries. The compiler's descriptor is unexported; this mirror is the
// adapter's equality oracle and is pinned by golden tests.
type networkStateV1 struct {
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

type networkDescriptorV1 struct {
	Resource bootstrap.DesiredResource `json:"resource"`
	State    networkStateV1            `json:"state"`
}

func networkFingerprint(resource bootstrap.DesiredResource, state networkStateV1) (string, error) {
	resource.DesiredStateFingerprint = ""
	if state.Labels == nil {
		state.Labels = map[string]string{}
	}
	if state.Targets == nil {
		state.Targets = []string{}
	}
	state.ControlPrefix = "test/"
	encoded, err := json.Marshal(networkDescriptorV1{Resource: resource, State: state})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func networkOwnershipDescription(resource bootstrap.DesiredResource) string {
	return fmt.Sprintf("%s workflow=%s permanence=%s resource=%s fingerprint=%s",
		networkOwnershipSchema, bootstrap.WorkflowID, resource.Permanence, resource.ID, resource.DesiredStateFingerprint)
}

func networkProvider(project string, parts ...string) string {
	return strings.Join(append([]string{"projects", project}, parts...), "/")
}

// expectedNetworkResources derives the closed T1-T4 resource set from the
// configuration and requires the supplied plan resources to equal it exactly,
// fingerprint included. Cross-project, cross-region, renamed, reordered,
// extra, missing, disposable, or retargeted resources fail here.
func expectedNetworkResources(intent bootstrap.StepIntent, resources []bootstrap.DesiredResource, target NetworkTarget) ([]expectedNetworkResource, error) {
	configuration := target.Configuration
	project, region := configuration.Project(), configuration.Region()
	vpc, subnet, router, nat, cidr := configuration.VPC(), configuration.Subnet(), configuration.Router(), configuration.NAT(), configuration.CIDR()
	for _, name := range []string{vpc, subnet, router, nat, isolation.TestIAPSSHFirewallName, isolation.TestInternalFirewallName, networkTestNodeTag} {
		if !networkNamePattern.MatchString(name) || !strings.HasPrefix(name, config.TestResourcePrefix) {
			return nil, networkError(NetworkFailureTarget, "reserved test name")
		}
	}
	if router != config.TestRouterName || !canonicalPrivateIPv4Prefix(cidr) {
		return nil, networkError(NetworkFailureTarget, "router name or subnet CIDR")
	}
	if err := isolation.ValidateFirewallTags([]string{networkTestNodeTag}, []string{networkTestNodeTag}); err != nil {
		return nil, networkError(NetworkFailureTarget, "test node tag")
	}
	command := commandContext{account: target.Account, project: project, region: region, zone: configuration.Zone()}
	networkParent := networkProvider(project, "global", "networks", vpc)
	routerProvider := networkProvider(project, "regions", region, "routers", router)
	catalogue := map[string]struct {
		resource bootstrap.DesiredResource
		state    networkStateV1
	}{
		"test-network": {resource: networkDesired("test-network", bootstrap.ResourceNetwork, vpc, project, "global", networkParent, ""),
			state: networkStateV1{Mode: "custom-subnet"}},
		"test-subnet": {resource: networkDesired("test-subnet", bootstrap.ResourceSubnetwork, subnet, project, region, networkProvider(project, "regions", region, "subnetworks", subnet), networkParent),
			state: networkStateV1{Mode: "private-google-access", CIDR: cidr}},
		"test-router": {resource: networkDesired("test-router", bootstrap.ResourceRouter, router, project, region, routerProvider, networkParent),
			state: networkStateV1{Mode: "custom-network-router"}},
		"test-nat": {resource: networkDesired("test-nat", bootstrap.ResourceNAT, nat, project, region, routerProvider+"/nats/"+nat, routerProvider),
			state: networkStateV1{Mode: "auto-ip-all-subnet-ranges"}},
		"test-iap-firewall": {resource: networkDesired("test-iap-firewall", bootstrap.ResourceFirewall, isolation.TestIAPSSHFirewallName, project, "global", networkProvider(project, "global", "firewalls", isolation.TestIAPSSHFirewallName), networkParent),
			state: networkStateV1{Mode: "ingress", Source: isolation.IAPTCPSourceCIDR, Targets: []string{networkTestNodeTag}, Protocol: "tcp", Port: networkSSHPort}},
		"test-internal-firewall": {resource: networkDesired("test-internal-firewall", bootstrap.ResourceFirewall, isolation.TestInternalFirewallName, project, "global", networkProvider(project, "global", "firewalls", isolation.TestInternalFirewallName), networkParent),
			state: networkStateV1{Mode: "ingress", Source: networkTestNodeTag, Targets: []string{networkTestNodeTag}, Protocol: "tcp", Port: networkMongoDBPort}},
	}
	if len(resources) != len(intent.ResourceIDs) {
		return nil, networkError(NetworkFailureTarget, "resource count")
	}
	result := make([]expectedNetworkResource, 0, len(resources))
	for index, supplied := range resources {
		entry, ok := catalogue[intent.ResourceIDs[index]]
		if !ok {
			return nil, networkError(NetworkFailureTarget, "resource identity")
		}
		fingerprint, err := networkFingerprint(entry.resource, entry.state)
		if err != nil {
			return nil, networkError(NetworkFailureInvalid, "desired fingerprint")
		}
		entry.resource.DesiredStateFingerprint = fingerprint
		if supplied != entry.resource {
			return nil, networkError(NetworkFailureTarget, "resource "+intent.ResourceIDs[index])
		}
		expected := expectedNetworkResource{resource: entry.resource, command: command, vpc: vpc, router: router, nat: nat, cidr: cidr}
		description := networkOwnershipDescription(entry.resource)
		switch entry.resource.ID {
		case "test-iap-firewall":
			expected.firewall = iapFirewallSpec(vpc, description)
		case "test-internal-firewall":
			expected.firewall = internalFirewallSpec(vpc, description)
		}
		result = append(result, expected)
	}
	return result, nil
}

func networkDesired(id string, kind bootstrap.ResourceKind, name, project, location, providerID, parent string) bootstrap.DesiredResource {
	return bootstrap.DesiredResource{ID: id, Kind: kind, Name: name, Project: project, Location: location,
		ProviderID: providerID, ParentProviderID: parent, Permanence: bootstrap.PermanentSingleton}
}

func canonicalPrivateIPv4Prefix(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix.Addr().Is4() && prefix.Addr().IsPrivate() && prefix == prefix.Masked() && prefix.Bits() < 32
}

func (expected expectedNetworkResource) createArguments() []string {
	switch expected.resource.Kind {
	case bootstrap.ResourceNetwork:
		return networkCreateArguments(expected.command, expected.resource.Name)
	case bootstrap.ResourceSubnetwork:
		return subnetCreateArguments(expected.command, expected.resource.Name, expected.vpc, expected.cidr)
	case bootstrap.ResourceRouter:
		return routerCreateArguments(expected.command, expected.resource.Name, expected.vpc)
	case bootstrap.ResourceNAT:
		return natCreateArguments(expected.command, expected.resource.Name, expected.router)
	default:
		return firewallCreateArguments(expected.command, expected.firewall)
	}
}

func (expected expectedNetworkResource) observeArguments() []string {
	switch expected.resource.Kind {
	case bootstrap.ResourceNetwork:
		return networkObserveArguments(expected.command, expected.resource.Name)
	case bootstrap.ResourceSubnetwork:
		return subnetObserveArguments(expected.command, expected.resource.Name)
	case bootstrap.ResourceRouter:
		return routerObserveArguments(expected.command, expected.resource.Name)
	case bootstrap.ResourceNAT:
		return natObserveArguments(expected.command, expected.router)
	default:
		return firewallObserveArguments(expected.command, expected.resource.Name)
	}
}

func (expected expectedNetworkResource) statusArguments() []string {
	return natStatusArguments(expected.command, expected.router)
}

// Wire projections. Pointer fields distinguish an absent provider value from
// its zero value where the distinction is security-relevant.
type networkListWire struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	SelfLink              string `json:"selfLink"`
	AutoCreateSubnetworks *bool  `json:"autoCreateSubnetworks"`
	IPv4Range             string `json:"IPv4Range"`
	Peerings              []struct {
		Name string `json:"name"`
	} `json:"peerings"`
}
type subnetListWire struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	SelfLink              string `json:"selfLink"`
	Region                string `json:"region"`
	Network               string `json:"network"`
	IPCIDRRange           string `json:"ipCidrRange"`
	PrivateIPGoogleAccess bool   `json:"privateIpGoogleAccess"`
	Purpose               string `json:"purpose"`
	SecondaryIPRanges     []struct {
		IPCIDRRange string `json:"ipCidrRange"`
	} `json:"secondaryIpRanges"`
	StackType      string `json:"stackType"`
	EnableFlowLogs bool   `json:"enableFlowLogs"`
}
type routerListWire struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	SelfLink string `json:"selfLink"`
	Region   string `json:"region"`
	Network  string `json:"network"`
	NATs     []struct {
		Name string `json:"name"`
	} `json:"nats"`
	Interfaces []struct {
		Name string `json:"name"`
	} `json:"interfaces"`
	BGPPeers []struct {
		Name string `json:"name"`
	} `json:"bgpPeers"`
	EncryptedInterconnectRouter bool `json:"encryptedInterconnectRouter"`
}
type natOwnerWire struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	SelfLink    string `json:"selfLink"`
	Region      string `json:"region"`
	Fingerprint string `json:"fingerprint"`
}
type natListWire struct {
	Name                          string   `json:"name"`
	NATIPAllocateOption           string   `json:"natIpAllocateOption"`
	SourceSubnetworkIPRangesToNAT string   `json:"sourceSubnetworkIpRangesToNat"`
	NATIPs                        []string `json:"natIps"`
	Type                          string   `json:"type"`
}
type routerStatusWire struct {
	Result struct {
		Network   string `json:"network"`
		NATStatus []struct {
			Name                 string `json:"name"`
			MinExtraNATIPsNeeded *int64 `json:"minExtraNatIpsNeeded"`
		} `json:"natStatus"`
	} `json:"result"`
}
type firewallListWire struct {
	ID                    string        `json:"id"`
	Name                  string        `json:"name"`
	SelfLink              string        `json:"selfLink"`
	Network               string        `json:"network"`
	Direction             string        `json:"direction"`
	Disabled              bool          `json:"disabled"`
	Priority              *int64        `json:"priority"`
	Description           string        `json:"description"`
	SourceRanges          []string      `json:"sourceRanges"`
	SourceTags            []string      `json:"sourceTags"`
	TargetTags            []string      `json:"targetTags"`
	DestinationRanges     []string      `json:"destinationRanges"`
	SourceServiceAccounts []string      `json:"sourceServiceAccounts"`
	TargetServiceAccounts []string      `json:"targetServiceAccounts"`
	Allowed               []allowedWire `json:"allowed"`
	Denied                []allowedWire `json:"denied"`
	LogConfig             *struct {
		Enable bool `json:"enable"`
	} `json:"logConfig"`
}

type networkObservation struct {
	present       bool
	incarnationID string
}

// parseObservation reduces one exact-name read to presence. A present
// resource must reduce to the desired fingerprint and identity exactly.
func (expected expectedNetworkResource) parseObservation(data []byte) (networkObservation, error) {
	switch expected.resource.Kind {
	case bootstrap.ResourceNetwork:
		return parseNetworkObservation(expected, data)
	case bootstrap.ResourceSubnetwork:
		return parseSubnetObservation(expected, data)
	case bootstrap.ResourceRouter:
		return parseRouterObservation(expected, data)
	case bootstrap.ResourceNAT:
		return parseNATObservation(expected, data)
	default:
		return parseFirewallObservation(expected, data)
	}
}

func decodeNetworkList[T any](data []byte, id string) ([]T, error) {
	var wire []T
	if err := decodeNetworkProviderJSON(data, &wire); err != nil || len(wire) > 1 {
		return nil, networkError(NetworkFailureSchema, id+" observation")
	}
	return wire, nil
}

// decodeNetworkProviderJSON adds case-folded duplicate rejection to the
// shared strict decoder. encoding/json matches struct fields using Unicode
// case folding, so accepting both "name" and "Name" would otherwise let a
// later contradictory value replace the projected provider field.
func decodeNetworkProviderJSON(data []byte, target any) error {
	if err := decodeProviderJSON(data, target, false); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return inspectFoldedNetworkJSON(decoder)
}

func inspectFoldedNetworkJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make([]string, 0)
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			for _, prior := range seen {
				if strings.EqualFold(prior, key) {
					return fmt.Errorf("case-folded duplicate object key")
				}
			}
			seen = append(seen, key)
			if valueErr := inspectFoldedNetworkJSON(decoder); valueErr != nil {
				return valueErr
			}
		}
	case '[':
		for decoder.More() {
			if valueErr := inspectFoldedNetworkJSON(decoder); valueErr != nil {
				return valueErr
			}
		}
	default:
		return fmt.Errorf("unexpected delimiter")
	}
	closing, closeErr := decoder.Token()
	if closeErr != nil || closing != map[json.Delim]json.Delim{'{': '}', '[': ']'}[delimiter] {
		return fmt.Errorf("composite value is not closed")
	}
	return nil
}

func (expected expectedNetworkResource) identityMatches(name, selfLink string) bool {
	return name == expected.resource.Name && computeSelfLinkMatches(selfLink, expected.resource.ProviderID)
}

func (expected expectedNetworkResource) fingerprintMatches(state networkStateV1) bool {
	fingerprint, err := networkFingerprint(expected.resource, state)
	return err == nil && fingerprint == expected.resource.DesiredStateFingerprint
}

func (expected expectedNetworkResource) drift(detail string) error {
	return networkError(NetworkFailureDrift, expected.resource.ID+" "+detail)
}

func parseNetworkObservation(expected expectedNetworkResource, data []byte) (networkObservation, error) {
	wire, err := decodeNetworkList[networkListWire](data, expected.resource.ID)
	if err != nil || len(wire) == 0 {
		return networkObservation{}, err
	}
	item := wire[0]
	if !expected.identityMatches(item.Name, item.SelfLink) {
		return networkObservation{}, networkError(NetworkFailureSchema, expected.resource.ID+" identity")
	}
	if !validNetworkID(item.ID) {
		return networkObservation{}, networkError(NetworkFailureSchema, expected.resource.ID+" incarnation")
	}
	if len(item.Peerings) != 0 {
		return networkObservation{}, expected.drift("has network peerings")
	}
	state := networkStateV1{}
	if item.AutoCreateSubnetworks != nil && !*item.AutoCreateSubnetworks && item.IPv4Range == "" {
		state.Mode = "custom-subnet"
	}
	if !expected.fingerprintMatches(state) {
		return networkObservation{}, expected.drift("is not a custom-mode network")
	}
	return networkObservation{present: true, incarnationID: item.ID}, nil
}

func parseSubnetObservation(expected expectedNetworkResource, data []byte) (networkObservation, error) {
	wire, err := decodeNetworkList[subnetListWire](data, expected.resource.ID)
	if err != nil || len(wire) == 0 {
		return networkObservation{}, err
	}
	item := wire[0]
	region, regionOK := normalizeComputeLocation(item.Region, expected.command.project, "regions")
	if !expected.identityMatches(item.Name, item.SelfLink) || !regionOK || region != expected.command.region {
		return networkObservation{}, networkError(NetworkFailureSchema, expected.resource.ID+" identity")
	}
	if !validNetworkID(item.ID) {
		return networkObservation{}, networkError(NetworkFailureSchema, expected.resource.ID+" incarnation")
	}
	if !computeSelfLinkMatches(item.Network, expected.resource.ParentProviderID) {
		return networkObservation{}, expected.drift("belongs to another network")
	}
	if len(item.SecondaryIPRanges) != 0 || (item.Purpose != "" && item.Purpose != "PRIVATE") ||
		(item.StackType != "" && item.StackType != "IPV4_ONLY") || item.EnableFlowLogs {
		return networkObservation{}, expected.drift("has secondary ranges, a special purpose, an IPv6 stack, or flow logs")
	}
	if !canonicalPrivateIPv4Prefix(item.IPCIDRRange) {
		return networkObservation{}, expected.drift("has a non-private or non-canonical range")
	}
	state := networkStateV1{CIDR: item.IPCIDRRange}
	if item.PrivateIPGoogleAccess {
		state.Mode = "private-google-access"
	}
	if !expected.fingerprintMatches(state) {
		return networkObservation{}, expected.drift("range or private Google access differs")
	}
	return networkObservation{present: true, incarnationID: item.ID}, nil
}

func parseRouterObservation(expected expectedNetworkResource, data []byte) (networkObservation, error) {
	wire, err := decodeNetworkList[routerListWire](data, expected.resource.ID)
	if err != nil || len(wire) == 0 {
		return networkObservation{}, err
	}
	item := wire[0]
	region, regionOK := normalizeComputeLocation(item.Region, expected.command.project, "regions")
	if !expected.identityMatches(item.Name, item.SelfLink) || !regionOK || region != expected.command.region {
		return networkObservation{}, networkError(NetworkFailureSchema, expected.resource.ID+" identity")
	}
	if !validNetworkID(item.ID) {
		return networkObservation{}, networkError(NetworkFailureSchema, expected.resource.ID+" incarnation")
	}
	if len(item.Interfaces) != 0 || len(item.BGPPeers) != 0 || item.EncryptedInterconnectRouter {
		return networkObservation{}, expected.drift("has attached interfaces, BGP peers, or encrypted interconnect state")
	}
	state := networkStateV1{}
	if computeSelfLinkMatches(item.Network, expected.resource.ParentProviderID) {
		state.Mode = "custom-network-router"
	}
	for _, nat := range item.NATs {
		if nat.Name != expected.nat {
			return networkObservation{}, expected.drift("carries an unexpected NAT")
		}
	}
	if len(item.NATs) > 1 {
		return networkObservation{}, expected.drift("carries duplicate NAT state")
	}
	if !expected.fingerprintMatches(state) {
		return networkObservation{}, expected.drift("belongs to another network")
	}
	return networkObservation{present: true, incarnationID: item.ID}, nil
}

func parseNATObservation(expected expectedNetworkResource, data []byte) (networkObservation, error) {
	var wire []natListWire
	if err := decodeNetworkProviderJSON(data, &wire); err != nil {
		return networkObservation{}, networkError(NetworkFailureSchema, expected.resource.ID+" observation")
	}
	var found *natListWire
	for index := range wire {
		if wire[index].Name != expected.resource.Name {
			return networkObservation{}, expected.drift("router carries an unexpected NAT")
		}
		if found != nil {
			return networkObservation{}, networkError(NetworkFailureSchema, expected.resource.ID+" duplicate")
		}
		found = &wire[index]
	}
	if found == nil {
		return networkObservation{}, nil
	}
	if len(found.NATIPs) != 0 || (found.Type != "" && found.Type != "PUBLIC") {
		return networkObservation{}, expected.drift("uses manual or private NAT addressing")
	}
	state := networkStateV1{}
	if found.NATIPAllocateOption == "AUTO_ONLY" && found.SourceSubnetworkIPRangesToNAT == "ALL_SUBNETWORKS_ALL_IP_RANGES" {
		state.Mode = "auto-ip-all-subnet-ranges"
	}
	if !expected.fingerprintMatches(state) {
		return networkObservation{}, expected.drift("allocation or subnet range mode differs")
	}
	return networkObservation{present: true}, nil
}

func (expected expectedNetworkResource) parseNATOwner(data []byte) (string, error) {
	wire, err := decodeNetworkList[natOwnerWire](data, expected.resource.ID)
	if err != nil || len(wire) != 1 {
		return "", networkError(NetworkFailureSchema, expected.resource.ID+" owner")
	}
	item := wire[0]
	region, regionOK := normalizeComputeLocation(item.Region, expected.command.project, "regions")
	if item.Name != expected.router || !computeSelfLinkMatches(item.SelfLink, expected.resource.ParentProviderID) ||
		!regionOK || region != expected.command.region || !validNetworkID(item.ID) ||
		!validRouterFingerprint(item.Fingerprint) {
		return "", networkError(NetworkFailureSchema, expected.resource.ID+" owner")
	}
	return item.ID + ":" + item.Fingerprint, nil
}

// parseNATStatus proves the NAT is operational: the router status names
// exactly the desired NAT on the desired network with no missing addresses.
func (expected expectedNetworkResource) parseNATStatus(data []byte) error {
	var wire routerStatusWire
	if err := decodeNetworkProviderJSON(data, &wire); err != nil {
		return networkError(NetworkFailureSchema, expected.resource.ID+" status")
	}
	if !computeSelfLinkMatches(wire.Result.Network, networkProvider(expected.command.project, "global", "networks", expected.vpc)) {
		return expected.drift("router status names another network")
	}
	if len(wire.Result.NATStatus) != 1 || wire.Result.NATStatus[0].Name != expected.resource.Name {
		return expected.drift("router status does not name exactly the desired NAT")
	}
	if wire.Result.NATStatus[0].MinExtraNATIPsNeeded == nil || *wire.Result.NATStatus[0].MinExtraNATIPsNeeded != 0 {
		return expected.drift("is not operational")
	}
	return nil
}

func parseFirewallObservation(expected expectedNetworkResource, data []byte) (networkObservation, error) {
	wire, err := decodeNetworkList[firewallListWire](data, expected.resource.ID)
	if err != nil || len(wire) == 0 {
		return networkObservation{}, err
	}
	item := wire[0]
	if !expected.identityMatches(item.Name, item.SelfLink) {
		return networkObservation{}, networkError(NetworkFailureSchema, expected.resource.ID+" identity")
	}
	if !validNetworkID(item.ID) {
		return networkObservation{}, networkError(NetworkFailureSchema, expected.resource.ID+" incarnation")
	}
	if !computeSelfLinkMatches(item.Network, expected.resource.ParentProviderID) {
		return networkObservation{}, expected.drift("belongs to another network")
	}
	if item.Direction != "INGRESS" || item.Disabled || item.Priority == nil || *item.Priority != int64(isolation.FirewallPriority) {
		return networkObservation{}, expected.drift("direction, state, or priority differs")
	}
	if len(item.Denied) != 0 || len(item.DestinationRanges) != 0 || len(item.SourceServiceAccounts) != 0 ||
		len(item.TargetServiceAccounts) != 0 || (item.LogConfig != nil && item.LogConfig.Enable) {
		return networkObservation{}, expected.drift("carries denied tuples, destinations, service accounts, or logging")
	}
	if item.Description != expected.firewall.description {
		return networkObservation{}, expected.drift("ownership description differs")
	}
	if err := isolation.ValidateFirewallTags(item.SourceTags, item.TargetTags); err != nil {
		return networkObservation{}, expected.drift("uses tags outside the test namespace")
	}
	state := networkStateV1{Mode: "ingress", Targets: append([]string(nil), item.TargetTags...)}
	switch {
	case len(item.SourceRanges) == 1 && len(item.SourceTags) == 0 && item.SourceRanges[0] == isolation.IAPTCPSourceCIDR:
		state.Source = item.SourceRanges[0]
	case len(item.SourceRanges) == 0 && len(item.SourceTags) == 1:
		state.Source = item.SourceTags[0]
	default:
		return networkObservation{}, expected.drift("admits a public or non-test source")
	}
	if len(item.Allowed) != 1 || len(item.Allowed[0].Ports) != 1 {
		return networkObservation{}, expected.drift("allows more than one protocol tuple")
	}
	port, portErr := strconv.Atoi(item.Allowed[0].Ports[0])
	if portErr != nil || port <= 0 || port > 65535 || strconv.Itoa(port) != item.Allowed[0].Ports[0] {
		return networkObservation{}, expected.drift("allows a port range")
	}
	state.Protocol, state.Port = item.Allowed[0].IPProtocol, port
	if !expected.fingerprintMatches(state) {
		return networkObservation{}, expected.drift("source, target, protocol, or port differs")
	}
	return networkObservation{present: true, incarnationID: item.ID}, nil
}

// computeSelfLinkMatches accepts only the documented Compute v1 self-link
// bases and requires the remainder to equal the desired provider identity.
func computeSelfLinkMatches(selfLink, providerID string) bool {
	for _, base := range []string{"https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"} {
		if strings.HasPrefix(selfLink, base) {
			return strings.TrimPrefix(selfLink, base) == providerID
		}
	}
	return false
}
