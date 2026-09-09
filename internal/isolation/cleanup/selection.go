// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/isolation"
)

// deletionSealDomain separates the sealed-deletion fingerprint from every
// other SHA-256 value in the repository.
const deletionSealDomain = "ctrldb.ctrlboard.dev/test-wipe/deletion-seal/v1"

// Deletion is one selected, ordered removal. Its seal can only be produced by
// this package; a provider adapter must refuse an unsealed value so that a
// plain resource name can never reach a delete verb.
type Deletion struct {
	Sequence   int
	Capability isolation.CleanupCapability
	Identity   isolation.ResourceIdentity
	RunID      string
	CreatedAt  time.Time
	ExpiredAt  time.Time
	KeepDisks  bool
	Attempt    uint32
	seal       string
}

// Sealed reports whether the deletion was produced unchanged by Select.
func (deletion Deletion) Sealed() bool {
	return deletion.seal != "" && deletion.seal == sealDeletion(deletion)
}

// RetainedResource is an owned resource which has not reached expiry.
type RetainedResource struct {
	Capability isolation.CleanupCapability
	Identity   isolation.ResourceIdentity
	ExpiresAt  time.Time
}

// DeferredResource is a selected disk still attached to an instance which the
// wipe does not own or has not selected. It is recorded and left in place.
type DeferredResource struct {
	Identity  isolation.ResourceIdentity
	Reason    string
	BlockedBy []string
}

// ProtectedResource is a permanent harness singleton observed in the test
// namespace. It is never a wipe candidate.
type ProtectedResource struct {
	Identity isolation.ResourceIdentity
}

// Selection is the complete, ordered, sealed result of one exhaustive
// inventory: instances first, then disks, then run firewall rules.
type Selection struct {
	ProjectID         string
	InventoryRevision string
	Now               time.Time
	MaxLifetime       time.Duration
	Ignored           int
	Deletions         []Deletion
	Retained          []RetainedResource
	Deferred          []DeferredResource
	Protected         []ProtectedResource
}

// Select evaluates the whole inventory. Any ambiguous, cross-project,
// unsupported, duplicated, or unprovable test-namespace resource refuses the
// entire selection; nothing is silently skipped.
func Select(policy WipePolicy, capabilities []isolation.CleanupCapability, inventory Inventory, records []LifetimeRecord, now time.Time) (Selection, error) {
	if err := validatePolicy(policy); err != nil {
		return Selection{}, err
	}
	if err := validateNow(now); err != nil {
		return Selection{}, err
	}
	if err := isolation.ValidateCleanupCapabilities(capabilities); err != nil {
		return Selection{}, inputError("capabilities", "must be the exact recorded cleanup capability set")
	}
	if err := validateInventoryWindow(policy, inventory, now); err != nil {
		return Selection{}, err
	}
	if err := rejectDuplicateIdentities(inventory); err != nil {
		return Selection{}, err
	}
	selection := Selection{ProjectID: policy.ProjectID, InventoryRevision: inventory.Revision, Now: now, MaxLifetime: policy.MaxLifetime}
	instances, err := selectInstances(policy, inventory, now, &selection)
	if err != nil {
		return Selection{}, err
	}
	if err := selectDisks(policy, inventory, now, instances, &selection); err != nil {
		return Selection{}, err
	}
	if err := selectFirewalls(policy, inventory, records, now, &selection); err != nil {
		return Selection{}, err
	}
	for index := range selection.Deletions {
		selection.Deletions[index].Sequence = index + 1
		selection.Deletions[index].seal = sealDeletion(selection.Deletions[index])
	}
	return selection, nil
}

func rejectDuplicateIdentities(inventory Inventory) error {
	seen := make(map[string]struct{})
	check := func(path string, identity isolation.ResourceIdentity) error {
		if identity.CanonicalKey == "" {
			return refusal(path, "does not carry a complete canonical identity")
		}
		if _, duplicate := seen[identity.CanonicalKey]; duplicate {
			return refusal(path, "duplicates an earlier inventory entry")
		}
		seen[identity.CanonicalKey] = struct{}{}
		return nil
	}
	for index, item := range inventory.Instances {
		if err := check(indexedField("inventory.instances", index), item.Identity); err != nil {
			return err
		}
	}
	for index, item := range inventory.Disks {
		if err := check(indexedField("inventory.disks", index), item.Identity); err != nil {
			return err
		}
	}
	for index, item := range inventory.Firewalls {
		if err := check(indexedField("inventory.firewalls", index), item.Identity); err != nil {
			return err
		}
	}
	return nil
}

type ownershipClass uint8

const (
	ownershipForeign ownershipClass = iota + 1
	ownershipRun
)

// classifyLabelCapable applies D-157 to instances and disks. A name in the
// test namespace without the three reserved labels, reserved labels without
// the run prefix, or a run resource whose run-id label does not bind its own
// name are all ambiguous and refuse the inventory.
func classifyLabelCapable(path, name string, labels map[string]string) (ownershipClass, string, error) {
	prefixed := strings.HasPrefix(name, config.TestResourcePrefix)
	labelled := labels[config.LabelManagedBy] == config.LabelManagedByValue &&
		labels[config.LabelEnvironment] == config.TestEnvironmentLabel &&
		labels[config.LabelPurpose] == config.TestResourcePurposeLabel
	switch {
	case !prefixed && !labelled:
		return ownershipForeign, "", nil
	case prefixed && !labelled:
		return 0, "", refusal(path, "uses the test namespace without the reserved disposable labels")
	case !prefixed && labelled:
		return 0, "", refusal(path, "carries disposable labels outside the test namespace")
	}
	runID := labels[isolation.LabelRunID]
	runPrefix, err := isolation.RunResourcePrefix(runID)
	if err != nil {
		return 0, "", refusal(path, "does not carry a valid run-id label")
	}
	if !strings.HasPrefix(name, runPrefix) || len(name) == len(runPrefix) {
		return 0, "", refusal(path, "run-id label does not bind the exact run prefix")
	}
	if !config.IsTestResource(config.GeneratedResource{Name: name, Labels: labels}) {
		return 0, "", refusal(path, "does not have exact disposable identity")
	}
	return ownershipRun, runID, nil
}

type expirable struct {
	target isolation.ExpirableTarget
	runID  string
}

func selectInstances(policy WipePolicy, inventory Inventory, now time.Time, selection *Selection) (map[string]struct{}, error) {
	candidates := make([]expirable, 0, len(inventory.Instances))
	for index, item := range inventory.Instances {
		path := indexedField("inventory.instances", index)
		if err := validateObservedIdentity(policy, path, item.Identity, isolation.ComputeInstanceKind); err != nil {
			return nil, err
		}
		if err := validateObservedTimestamp(path, item.CreatedAt, now); err != nil {
			return nil, err
		}
		class, runID, err := classifyLabelCapable(path, item.Identity.Name, item.Labels)
		if err != nil {
			return nil, err
		}
		if class == ownershipForeign {
			selection.Ignored++
			continue
		}
		candidates = append(candidates, expirable{target: isolation.ExpirableTarget{
			Target: isolation.MutationTarget{Identity: item.Identity, Labels: cloneLabels(item.Labels)}, CreatedAt: item.CreatedAt,
		}, runID: runID})
	}
	expired, err := expiredTargets(policy, candidates, now, isolation.CleanupComputeInstances, selection)
	if err != nil {
		return nil, err
	}
	selected := make(map[string]struct{}, len(expired))
	for _, item := range expired {
		selected[item.target.Target.Identity.Name] = struct{}{}
		selection.Deletions = append(selection.Deletions, Deletion{
			Capability: isolation.CleanupComputeInstances, Identity: item.target.Target.Identity, RunID: item.runID,
			CreatedAt: item.target.CreatedAt, ExpiredAt: item.target.CreatedAt.Add(policy.MaxLifetime), KeepDisks: true,
		})
	}
	return selected, nil
}

func selectDisks(policy WipePolicy, inventory Inventory, now time.Time, selectedInstances map[string]struct{}, selection *Selection) error {
	candidates := make([]expirable, 0, len(inventory.Disks))
	attachments := make(map[string][]string, len(inventory.Disks))
	for index, item := range inventory.Disks {
		path := indexedField("inventory.disks", index)
		if err := validateObservedIdentity(policy, path, item.Identity, isolation.ComputeDiskKind); err != nil {
			return err
		}
		if err := validateObservedTimestamp(path, item.CreatedAt, now); err != nil {
			return err
		}
		class, runID, err := classifyLabelCapable(path, item.Identity.Name, item.Labels)
		if err != nil {
			return err
		}
		if class == ownershipForeign {
			selection.Ignored++
			continue
		}
		attachments[item.Identity.CanonicalKey] = sortedNames(item.AttachedInstances)
		candidates = append(candidates, expirable{target: isolation.ExpirableTarget{
			Target: isolation.MutationTarget{Identity: item.Identity, Labels: cloneLabels(item.Labels)}, CreatedAt: item.CreatedAt,
		}, runID: runID})
	}
	expired, err := expiredTargets(policy, candidates, now, isolation.CleanupComputeDisks, selection)
	if err != nil {
		return err
	}
	for _, item := range expired {
		identity := item.target.Target.Identity
		var blockers []string
		for _, user := range attachments[identity.CanonicalKey] {
			if _, ok := selectedInstances[user]; !ok {
				blockers = append(blockers, user)
			}
		}
		if len(blockers) != 0 {
			selection.Deferred = append(selection.Deferred, DeferredResource{Identity: identity, Reason: "attached to an instance outside this selection", BlockedBy: blockers})
			continue
		}
		selection.Deletions = append(selection.Deletions, Deletion{
			Capability: isolation.CleanupComputeDisks, Identity: identity, RunID: item.runID,
			CreatedAt: item.target.CreatedAt, ExpiredAt: item.target.CreatedAt.Add(policy.MaxLifetime),
		})
	}
	return nil
}

// expiredTargets delegates age evaluation to the isolation guard, which
// re-validates every candidate and fails the whole set on any ambiguity.
func expiredTargets(policy WipePolicy, candidates []expirable, now time.Time, capability isolation.CleanupCapability, selection *Selection) ([]expirable, error) {
	targets := make([]isolation.ExpirableTarget, len(candidates))
	byKey := make(map[string]expirable, len(candidates))
	for index, candidate := range candidates {
		targets[index] = candidate.target
		byKey[candidate.target.Target.Identity.CanonicalKey] = candidate
	}
	expired, err := isolation.SelectExpiredTargets(isolation.CleanupPolicy{ProjectID: policy.ProjectID}, targets, now, policy.MaxLifetime)
	if err != nil {
		return nil, refusal(string(capability), "did not pass the isolation cleanup guard")
	}
	expiredKeys := make(map[string]struct{}, len(expired))
	result := make([]expirable, 0, len(expired))
	for _, item := range expired {
		key := item.Target.Identity.CanonicalKey
		expiredKeys[key] = struct{}{}
		result = append(result, byKey[key])
	}
	for _, candidate := range candidates {
		if _, ok := expiredKeys[candidate.target.Target.Identity.CanonicalKey]; ok {
			continue
		}
		selection.Retained = append(selection.Retained, RetainedResource{
			Capability: capability, Identity: candidate.target.Target.Identity, ExpiresAt: candidate.target.CreatedAt.Add(policy.MaxLifetime),
		})
	}
	return result, nil
}

func selectFirewalls(policy WipePolicy, inventory Inventory, records []LifetimeRecord, now time.Time, selection *Selection) error {
	byName, err := firewallRecordsByName(records)
	if err != nil {
		return err
	}
	cleanupPolicy := isolation.CleanupPolicy{ProjectID: policy.ProjectID}
	deletions := make([]Deletion, 0)
	for index, item := range inventory.Firewalls {
		path := indexedField("inventory.firewalls", index)
		if err := validateObservedIdentity(policy, path, item.Identity, isolation.ComputeFirewallKind); err != nil {
			return err
		}
		if err := validateObservedTimestamp(path, item.CreatedAt, now); err != nil {
			return err
		}
		name := item.Identity.Name
		if name == isolation.TestIAPSSHFirewallName || name == isolation.TestInternalFirewallName {
			selection.Protected = append(selection.Protected, ProtectedResource{Identity: item.Identity})
			continue
		}
		if !strings.HasPrefix(name, config.TestResourcePrefix) {
			selection.Ignored++
			continue
		}
		record, ok := byName[name]
		if !ok {
			return refusal(path, "uses the test namespace without a durable run lifetime record")
		}
		target := isolation.RunFirewallCleanupTarget{
			Identity: item.Identity, Description: item.Description, RunLifetime: record.Contract,
			ExpectedRecord: record.Expected, ObservedAt: inventory.ObservedAt,
		}
		if err := isolation.ValidateRunFirewallCleanupTarget(cleanupPolicy, target, isolation.RunFirewallCleanupRecordedTeardown, now, policy.MaxLifetime); err != nil {
			return refusal(path, "does not match its durable run lifetime record")
		}
		if now.Before(record.Contract.ExpiresAt) {
			selection.Retained = append(selection.Retained, RetainedResource{Capability: isolation.CleanupComputeFirewalls, Identity: item.Identity, ExpiresAt: record.Contract.ExpiresAt})
			continue
		}
		if err := isolation.ValidateRunFirewallCleanupTarget(cleanupPolicy, target, isolation.RunFirewallCleanupExpiredWipe, now, policy.MaxLifetime); err != nil {
			return refusal(path, "has not reached a provable expiry")
		}
		deletions = append(deletions, Deletion{
			Capability: isolation.CleanupComputeFirewalls, Identity: item.Identity, RunID: record.Contract.RunID,
			CreatedAt: item.CreatedAt, ExpiredAt: record.Contract.ExpiresAt,
		})
	}
	sort.SliceStable(deletions, func(i, j int) bool { return deletions[i].Identity.CanonicalKey < deletions[j].Identity.CanonicalKey })
	selection.Deletions = append(selection.Deletions, deletions...)
	return nil
}

func firewallRecordsByName(records []LifetimeRecord) (map[string]LifetimeRecord, error) {
	byName := make(map[string]LifetimeRecord, 2*len(records))
	for index, record := range records {
		path := indexedField("lifetimeRecords", index)
		if _, err := isolation.RunLifetimeContractFingerprint(record.Contract); err != nil {
			return nil, inputError(path, "is not a complete run lifetime record")
		}
		for _, purpose := range []isolation.FirewallPurpose{isolation.FirewallPurposeIAPSSH, isolation.FirewallPurposeInternalMongo} {
			name, err := isolation.RunFirewallRuleName(record.Contract.RunID, purpose)
			if err != nil {
				return nil, inputError(path, "does not derive exact run firewall names")
			}
			if _, duplicate := byName[name]; duplicate {
				return nil, inputError(path, "duplicates an earlier run lifetime record")
			}
			byName[name] = record
		}
	}
	return byName, nil
}

type deletionSealPayload struct {
	Domain     string                      `json:"domain"`
	Sequence   int                         `json:"sequence"`
	Capability isolation.CleanupCapability `json:"capability"`
	Identity   isolation.ResourceIdentity  `json:"identity"`
	RunID      string                      `json:"runId"`
	CreatedAt  time.Time                   `json:"createdAt"`
	ExpiredAt  time.Time                   `json:"expiredAt"`
	KeepDisks  bool                        `json:"keepDisks"`
	Attempt    uint32                      `json:"attempt"`
}

func sealDeletion(deletion Deletion) string {
	encoded, err := json.Marshal(deletionSealPayload{
		Domain: deletionSealDomain, Sequence: deletion.Sequence, Capability: deletion.Capability, Identity: deletion.Identity,
		RunID: deletion.RunID, CreatedAt: deletion.CreatedAt, ExpiredAt: deletion.ExpiredAt, KeepDisks: deletion.KeepDisks, Attempt: deletion.Attempt,
	})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func cloneLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
