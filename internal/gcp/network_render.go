// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"strconv"
	"strings"

	"github.com/thelostorbital/ctrldb/internal/isolation"
)

// Fixed WF-TEST-01 T1-T4 argument templates. Every value interpolated here
// is a validated resource name, region, CIDR, or protocol constant; there is
// no shell, no caller argv, no --async, and every command carries the explicit
// account and project (and region where the resource is regional). Absence is
// proven by an exact-name list which returns an empty JSON array, because
// gcloud describe reports absence only through exit status and human text.
const (
	networkFormat   = "--format=json(id,name,selfLink,autoCreateSubnetworks,IPv4Range,peerings.name)"
	subnetFormat    = "--format=json(id,name,selfLink,region,network,ipCidrRange,privateIpGoogleAccess,purpose,secondaryIpRanges.ipCidrRange,stackType,enableFlowLogs)"
	routerFormat    = "--format=json(id,name,selfLink,region,network,nats.name,interfaces.name,bgpPeers.name,encryptedInterconnectRouter)"
	natFormat       = "--format=json(name,natIpAllocateOption,sourceSubnetworkIpRangesToNat,natIps,type)"
	natOwnerFormat  = "--format=json(id,name,selfLink,region,fingerprint)"
	allSubnetFormat = "--format=json(name,region,ipCidrRange,secondaryIpRanges.ipCidrRange,selfLink)"
	natStatusFmt    = "--format=json(result.network,result.natStatus.name,result.natStatus.minExtraNatIpsNeeded)"
	firewallFormat  = "--format=json(id,name,selfLink,network,direction,disabled,priority,description,sourceRanges,sourceTags,targetTags,destinationRanges,sourceServiceAccounts,targetServiceAccounts,allowed.IPProtocol,allowed.ports,denied.IPProtocol,denied.ports,logConfig.enable)"
)

func exactNameFilter(name string) string { return "--filter=name=" + name }

// T1 — `compute networks create <vpc> --subnet-mode=custom`.
func networkCreateArguments(command commandContext, vpc string) []string {
	return globalArguments(command, "compute", "networks", "create", vpc, "--subnet-mode=custom")
}

func networkObserveArguments(command commandContext, vpc string) []string {
	return globalArguments(command, "compute", "networks", "list", exactNameFilter(vpc), networkFormat)
}

// T2 — `compute networks subnets create <subnet> --network=<vpc> --region=<region>
// --range=<cidr> --enable-private-ip-google-access`.
func subnetCreateArguments(command commandContext, subnet, vpc, cidr string) []string {
	return globalArguments(command, "compute", "networks", "subnets", "create", subnet,
		"--network="+vpc, "--region="+command.region, "--range="+cidr, "--enable-private-ip-google-access")
}

func subnetObserveArguments(command commandContext, subnet string) []string {
	return globalArguments(command, "compute", "networks", "subnets", "list", "--regions="+command.region, exactNameFilter(subnet), subnetFormat)
}

func allSubnetObserveArguments(command commandContext) []string {
	return globalArguments(command, "compute", "networks", "subnets", "list", allSubnetFormat)
}

// T3 — `compute routers create <router> --network=<vpc> --region=<region>`.
func routerCreateArguments(command commandContext, router, vpc string) []string {
	return globalArguments(command, "compute", "routers", "create", router, "--network="+vpc, "--region="+command.region)
}

func routerObserveArguments(command commandContext, router string) []string {
	return globalArguments(command, "compute", "routers", "list", "--regions="+command.region, exactNameFilter(router), routerFormat)
}

// T3 — `compute routers nats create <nat> --router=<router> --region=<region>
// --auto-allocate-nat-external-ips --nat-all-subnet-ip-ranges`.
func natCreateArguments(command commandContext, nat, router string) []string {
	return globalArguments(command, "compute", "routers", "nats", "create", nat, "--router="+router, "--region="+command.region,
		"--auto-allocate-nat-external-ips", "--nat-all-subnet-ip-ranges")
}

func natObserveArguments(command commandContext, router string) []string {
	return globalArguments(command, "compute", "routers", "nats", "list", "--router="+router, "--region="+command.region, natFormat)
}

func natOwnerObserveArguments(command commandContext, router string) []string {
	return globalArguments(command, "compute", "routers", "list", "--regions="+command.region, exactNameFilter(router), natOwnerFormat)
}

func natStatusArguments(command commandContext, router string) []string {
	return globalArguments(command, "compute", "routers", "get-status", router, "--region="+command.region, natStatusFmt)
}

// T4 — `compute firewall-rules create <name> --network=<vpc> --direction=INGRESS
// --action=ALLOW --rules=tcp:<port> (--source-ranges=<iap>|--source-tags=<tag>)
// --target-tags=<tag> --priority=1000 --description=<ownership>`. The
// direction, action, and priority are the documented defaults, spelled out so
// the rendered command and the verified state cannot diverge.
func firewallCreateArguments(command commandContext, spec networkFirewallSpec) []string {
	args := []string{"compute", "firewall-rules", "create", spec.name, "--network=" + spec.network,
		"--direction=INGRESS", "--action=ALLOW", "--rules=tcp:" + strconv.Itoa(spec.port)}
	if spec.sourceRange != "" {
		args = append(args, "--source-ranges="+spec.sourceRange)
	} else {
		args = append(args, "--source-tags="+spec.sourceTag)
	}
	args = append(args, "--target-tags="+strings.Join(spec.targetTags, ","),
		"--priority="+strconv.FormatUint(uint64(isolation.FirewallPriority), 10), "--description="+spec.description)
	return globalArguments(command, args...)
}

func firewallObserveArguments(command commandContext, name string) []string {
	return globalArguments(command, "compute", "firewall-rules", "list", exactNameFilter(name), firewallFormat)
}

// Compensation templates. They are reachable only through a
// compensableNetworkResource, which exists only for a resource whose durable
// creation record names this exact operation and step; Apply and Verify
// cannot render them. `--quiet` suppresses the interactive confirmation.
func networkDeleteArguments(command commandContext, vpc string) []string {
	return globalArguments(command, "compute", "networks", "delete", vpc)
}

func subnetDeleteArguments(command commandContext, subnet string) []string {
	return globalArguments(command, "compute", "networks", "subnets", "delete", subnet, "--region="+command.region)
}

func routerDeleteArguments(command commandContext, router string) []string {
	return globalArguments(command, "compute", "routers", "delete", router, "--region="+command.region)
}

func natDeleteArguments(command commandContext, nat, router string) []string {
	return globalArguments(command, "compute", "routers", "nats", "delete", nat, "--router="+router, "--region="+command.region)
}

func firewallDeleteArguments(command commandContext, name string) []string {
	return globalArguments(command, "compute", "firewall-rules", "delete", name)
}
