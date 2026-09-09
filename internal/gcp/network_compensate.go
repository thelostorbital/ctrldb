// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/observation"
)

// compensableNetworkResource is the only value which can render a delete. It
// is constructed solely by admitCompensation from a creation record whose
// operation, step, attempt, and complete provider identity were verified.
type compensableNetworkResource struct {
	expected expectedNetworkResource
	record   NetworkCreatedResource
}

func (compensable compensableNetworkResource) deleteArguments() []string {
	expected := compensable.expected
	switch expected.resource.Kind {
	case bootstrap.ResourceNetwork:
		return networkDeleteArguments(expected.command, expected.resource.Name)
	case bootstrap.ResourceSubnetwork:
		return subnetDeleteArguments(expected.command, expected.resource.Name)
	case bootstrap.ResourceRouter:
		return routerDeleteArguments(expected.command, expected.resource.Name)
	case bootstrap.ResourceNAT:
		return natDeleteArguments(expected.command, expected.resource.Name, expected.router)
	default:
		return firewallDeleteArguments(expected.command, expected.resource.Name)
	}
}

// CompensateStep removes, in reverse dependency order, only the resources
// whose creation records name this exact operation and step. A recorded
// resource which is already absent is reported as absent without a delete; a
// recorded resource whose live state no longer equals the desired state is
// refused, because the adapter cannot prove it is still the object it created.
func (client *NetworkClient) CompensateStep(
	ctx context.Context,
	authorization NetworkMutationAuthorization,
	intent bootstrap.StepIntent,
	resources []bootstrap.DesiredResource,
	target NetworkTarget,
	created []NetworkCreatedResource,
) (NetworkStepResult, error) {
	if client == nil || client.boundary == nil || ctx == nil {
		return NetworkStepResult{}, networkError(NetworkFailureInvalid, "client context")
	}
	plan, err := client.admit(authorization, intent, resources, target)
	if err != nil {
		return NetworkStepResult{}, err
	}
	compensable, err := admitCompensation(plan, authorization, intent, created)
	if err != nil {
		return NetworkStepResult{}, err
	}
	stepContext, cancel := context.WithTimeout(ctx, stepTimeout(intent))
	defer cancel()

	result := NetworkStepResult{OperationID: authorization.OperationID, StepID: intent.StepID, Attempt: authorization.Attempt, Kind: intent.Kind}
	for _, item := range compensable {
		outcome, deleteErr := client.deleteResource(stepContext, item)
		if deleteErr != nil {
			return result, deleteErr
		}
		result.Resources = append(result.Resources, outcome)
	}
	return result, nil
}

// admitCompensation binds every creation record to exactly one admitted
// desired resource of this operation and step and orders the deletes so a
// dependent (NAT, firewall) never outlives a delete of its parent.
func admitCompensation(plan []expectedNetworkResource, authorization NetworkMutationAuthorization, intent bootstrap.StepIntent, created []NetworkCreatedResource) ([]compensableNetworkResource, error) {
	byID := make(map[string]expectedNetworkResource, len(plan))
	for _, expected := range plan {
		byID[expected.resource.ID] = expected
	}
	selected := make(map[string]compensableNetworkResource, len(created))
	for _, record := range created {
		if record.OperationID != authorization.OperationID || record.StepID != intent.StepID ||
			record.Attempt < 1 || record.Attempt > authorization.Attempt {
			return nil, networkError(NetworkFailureAuthorization, "creation record operation")
		}
		expected, ok := byID[record.ResourceID]
		if !ok {
			return nil, networkError(NetworkFailureTarget, "creation record resource")
		}
		resource := expected.resource
		if record.Kind != resource.Kind || record.Name != resource.Name || record.Project != resource.Project ||
			record.Location != resource.Location || record.ProviderID != resource.ProviderID {
			return nil, networkError(NetworkFailureTarget, "creation record identity")
		}
		if _, duplicate := selected[record.ResourceID]; duplicate {
			return nil, networkError(NetworkFailureTarget, "creation record duplicate")
		}
		selected[record.ResourceID] = compensableNetworkResource{expected: expected, record: record}
	}
	result := make([]compensableNetworkResource, 0, len(selected))
	for index := len(plan) - 1; index >= 0; index-- {
		if item, ok := selected[plan[index].resource.ID]; ok {
			result = append(result, item)
		}
	}
	return result, nil
}

func (client *NetworkClient) deleteResource(ctx context.Context, item compensableNetworkResource) (NetworkResourceResult, error) {
	expected := item.expected
	result := NetworkResourceResult{
		ResourceID: expected.resource.ID, Kind: expected.resource.Kind, Name: expected.resource.Name,
		Project: expected.resource.Project, Location: expected.resource.Location, ProviderID: expected.resource.ProviderID,
		DesiredStateFingerprint: expected.resource.DesiredStateFingerprint,
	}
	present, err := client.observe(ctx, expected)
	if err != nil {
		return NetworkResourceResult{}, err
	}
	if !present {
		result.Outcome = NetworkResourceAbsent
		return result, nil
	}
	if expected.resource.Kind == bootstrap.ResourceRouter {
		if err := client.requireNoNAT(ctx, expected); err != nil {
			return NetworkResourceResult{}, err
		}
	}
	if _, err := client.run(ctx, item.deleteArguments(), expected.resource.ID+" delete"); err != nil {
		var failure *NetworkError
		if errors.As(err, &failure) {
			return NetworkResourceResult{}, networkMutationError(failure.kind, failure.source, domain.MutationUnknown)
		}
		return NetworkResourceResult{}, networkMutationError(NetworkFailureProcess, expected.resource.ID+" delete", domain.MutationUnknown)
	}
	result.Outcome = NetworkResourceDeleted
	present, err = client.observe(ctx, expected)
	if err != nil || present {
		return NetworkResourceResult{}, networkMutationError(NetworkFailureUnverified, expected.resource.ID+" present after delete", domain.MutationOccurred)
	}
	return result, nil
}

// requireNoNAT refuses a router delete while any NAT is attached, because a
// router delete would also remove a NAT this operation did not record.
func (client *NetworkClient) requireNoNAT(ctx context.Context, expected expectedNetworkResource) error {
	data, err := client.run(ctx, natObserveArguments(expected.command, expected.router), expected.resource.ID+" nats")
	if err != nil {
		return err
	}
	var wire []natListWire
	if err := decodeProviderJSON(data, &wire, false); err != nil {
		return networkError(NetworkFailureSchema, expected.resource.ID+" nats")
	}
	if len(wire) != 0 {
		return expected.drift("still carries a NAT")
	}
	return nil
}

// rejectSubnetOverlap applies the fresh preflight's CIDR overlap decision at
// the authorization's exact time. The only tolerated overlap is the desired
// subnet itself (same name, project, region, exact primary range, and
// provider identity), which a retry after a successful create observes.
func rejectSubnetOverlap(preflight observation.HarnessPreflight, expected expectedNetworkResource, now time.Time) error {
	overlaps, err := preflight.CIDROverlapsAt(expected.cidr, now)
	if err != nil {
		return networkError(NetworkFailureAuthorization, "subnet overlap freshness")
	}
	if !overlaps {
		return nil
	}
	desired, err := netip.ParsePrefix(expected.cidr)
	if err != nil {
		return networkError(NetworkFailureTarget, "subnet CIDR")
	}
	for _, existing := range preflight.SubnetRanges() {
		other, parseErr := netip.ParsePrefix(existing.CIDR)
		if parseErr != nil || !desired.Overlaps(other) {
			continue
		}
		resource := expected.resource
		if !existing.Secondary && existing.Name == resource.Name && existing.Project == resource.Project &&
			existing.Region == resource.Location && existing.CIDR == expected.cidr && computeSelfLinkMatches(existing.ProviderID, resource.ProviderID) {
			continue
		}
		return networkError(NetworkFailureTarget, "subnet CIDR overlaps a discovered range")
	}
	return nil
}
