// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// Every IAM command is a fixed foreground gcloud 560 argv with explicit
// --account and --project, --quiet, --verbosity=error, and a strict JSON
// field projection. No key verb, impersonation flag, alpha/beta track,
// filter, or caller-supplied argument is renderable from this file.
const (
	iamSchemaServiceAccountDescribe  = "gcloud-560/iam-service-account-describe-v1"
	iamSchemaServiceAccountCreate    = "gcloud-560/iam-service-account-create-v1"
	iamSchemaServiceAccountDelete    = "gcloud-560/iam-service-account-delete-v1"
	iamSchemaServiceAccountKeys      = "gcloud-560/iam-service-account-keys-list-v1"
	iamSchemaServiceAccountPolicyGet = "gcloud-560/iam-service-account-get-iam-policy-v1"
	iamSchemaServiceAccountPolicySet = "gcloud-560/iam-service-account-set-iam-policy-v1"
	iamSchemaRoleDescribe            = "gcloud-560/iam-role-describe-v1"
	iamSchemaRoleCreate              = "gcloud-560/iam-role-create-v1"
	iamSchemaRoleUpdate              = "gcloud-560/iam-role-update-v1"
	iamSchemaRoleDelete              = "gcloud-560/iam-role-delete-v1"
	iamSchemaProjectPolicyGet        = "gcloud-560/project-get-iam-policy-v1"
	iamSchemaProjectPolicySet        = "gcloud-560/project-set-iam-policy-v1"

	iamServiceAccountFields = "--format=json(email,name,projectId,uniqueId,disabled,etag)"
	iamKeyFields            = "--format=json(name,keyType)"
	iamRoleFields           = "--format=json(name,title,description,includedPermissions,stage,etag,deleted)"
	iamPolicyFields         = "--format=json(bindings,etag,version)"
	iamPolicyVersion        = int64(3)
)

var errIAMRender = errors.New("iam render rejected")

type iamCommand struct {
	schema    string
	arguments []string
}

func iamServiceAccountDescribeArguments(ctx commandContext, email string) iamCommand {
	return iamCommand{iamSchemaServiceAccountDescribe, globalArguments(ctx, "iam", "service-accounts", "describe", email, iamServiceAccountFields)}
}

func iamServiceAccountCreateArguments(ctx commandContext, accountID, displayName, description string) iamCommand {
	return iamCommand{iamSchemaServiceAccountCreate, globalArguments(ctx, "iam", "service-accounts", "create", accountID,
		"--display-name="+displayName, "--description="+description, iamServiceAccountFields)}
}

func iamServiceAccountDeleteArguments(ctx commandContext, email string) iamCommand {
	return iamCommand{iamSchemaServiceAccountDelete, globalArguments(ctx, "iam", "service-accounts", "delete", email, "--format=json")}
}

func iamServiceAccountKeysArguments(ctx commandContext, email string) iamCommand {
	return iamCommand{iamSchemaServiceAccountKeys, globalArguments(ctx, "iam", "service-accounts", "keys", "list",
		"--iam-account="+email, "--managed-by=user", iamKeyFields)}
}

func iamServiceAccountPolicyGetArguments(ctx commandContext, email string) iamCommand {
	return iamCommand{iamSchemaServiceAccountPolicyGet, globalArguments(ctx, "iam", "service-accounts", "get-iam-policy", email, iamPolicyFields)}
}

func iamServiceAccountPolicySetArguments(ctx commandContext, email, policyPath string) iamCommand {
	return iamCommand{iamSchemaServiceAccountPolicySet, globalArguments(ctx, "iam", "service-accounts", "set-iam-policy", email, policyPath, iamPolicyFields)}
}

func iamRoleDescribeArguments(ctx commandContext, roleID string) iamCommand {
	return iamCommand{iamSchemaRoleDescribe, globalArguments(ctx, "iam", "roles", "describe", roleID, iamRoleFields)}
}

func iamRoleCreateArguments(ctx commandContext, roleID, rolePath string) iamCommand {
	return iamCommand{iamSchemaRoleCreate, globalArguments(ctx, "iam", "roles", "create", roleID, "--file="+rolePath, iamRoleFields)}
}

func iamRoleUpdateArguments(ctx commandContext, roleID, rolePath string) iamCommand {
	return iamCommand{iamSchemaRoleUpdate, globalArguments(ctx, "iam", "roles", "update", roleID, "--file="+rolePath, iamRoleFields)}
}

func iamRoleDeleteArguments(ctx commandContext, roleID string) iamCommand {
	return iamCommand{iamSchemaRoleDelete, globalArguments(ctx, "iam", "roles", "delete", roleID, iamRoleFields)}
}

func iamProjectPolicyGetArguments(ctx commandContext) iamCommand {
	return iamCommand{iamSchemaProjectPolicyGet, globalArguments(ctx, "projects", "get-iam-policy", ctx.project, iamPolicyFields)}
}

func iamProjectPolicySetArguments(ctx commandContext, policyPath string) iamCommand {
	return iamCommand{iamSchemaProjectPolicySet, globalArguments(ctx, "projects", "set-iam-policy", ctx.project, policyPath, iamPolicyFields)}
}

// iamRoleDocument is the exact --file payload for roles create/update. The
// etag makes an update a compare-and-swap on the observed role revision.
type iamRoleDocument struct {
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	IncludedPermissions []string `json:"includedPermissions"`
	Stage               string   `json:"stage"`
	Etag                string   `json:"etag,omitempty"`
}

func iamRenderRoleDocument(definition IAMRoleDefinition, etag string) ([]byte, error) {
	if err := ValidateIAMRoleDefinition(definition); err != nil {
		return nil, err
	}
	return json.Marshal(iamRoleDocument{
		Title: definition.Title, Description: definition.Description,
		IncludedPermissions: append([]string(nil), definition.Permissions...), Stage: definition.Stage, Etag: etag,
	})
}

// iamPolicy is a normalized IAM allow policy: bindings sorted by role, then
// condition, then members sorted. It is the unit compared before and after
// every set-iam-policy.
type iamPolicy struct {
	Bindings []iamPolicyBinding
	Etag     string
	Version  int64
}

type iamPolicyBinding struct {
	Role      string
	Members   []string
	Condition *IAMCondition
}

type iamPolicyDocument struct {
	Bindings []iamPolicyBindingDocument `json:"bindings"`
	Etag     string                     `json:"etag"`
	Version  int64                      `json:"version"`
}

type iamPolicyBindingDocument struct {
	Condition *IAMCondition `json:"condition,omitempty"`
	Members   []string      `json:"members"`
	Role      string        `json:"role"`
}

// iamRenderPolicyDocument renders the policy at version 3 with the observed
// etag so the provider rejects a concurrent modification.
func iamRenderPolicyDocument(policy iamPolicy) ([]byte, error) {
	if policy.Etag == "" {
		return nil, errIAMRender
	}
	normalized := iamNormalizePolicy(policy)
	document := iamPolicyDocument{Bindings: make([]iamPolicyBindingDocument, 0, len(normalized.Bindings)), Etag: normalized.Etag, Version: iamPolicyVersion}
	for _, binding := range normalized.Bindings {
		document.Bindings = append(document.Bindings, iamPolicyBindingDocument{
			Condition: iamCloneCondition(binding.Condition), Members: append([]string(nil), binding.Members...), Role: binding.Role,
		})
	}
	return json.Marshal(document)
}

func iamCloneCondition(condition *IAMCondition) *IAMCondition {
	if condition == nil {
		return nil
	}
	clone := *condition
	return &clone
}

func iamConditionKey(condition *IAMCondition) string {
	if condition == nil {
		return ""
	}
	return condition.Title + "\x00" + condition.Description + "\x00" + condition.Expression
}

func iamNormalizePolicy(policy iamPolicy) iamPolicy {
	bindings := make([]iamPolicyBinding, 0, len(policy.Bindings))
	for _, binding := range policy.Bindings {
		members := append([]string(nil), binding.Members...)
		sort.Strings(members)
		bindings = append(bindings, iamPolicyBinding{Role: binding.Role, Members: members, Condition: iamCloneCondition(binding.Condition)})
	}
	sort.SliceStable(bindings, func(i, j int) bool {
		if bindings[i].Role != bindings[j].Role {
			return bindings[i].Role < bindings[j].Role
		}
		return iamConditionKey(bindings[i].Condition) < iamConditionKey(bindings[j].Condition)
	})
	return iamPolicy{Bindings: bindings, Etag: policy.Etag, Version: policy.Version}
}

func iamBindingIndex(policy iamPolicy, role string, condition *IAMCondition) int {
	key := iamConditionKey(condition)
	for index, binding := range policy.Bindings {
		if binding.Role == role && iamConditionKey(binding.Condition) == key {
			return index
		}
	}
	return -1
}

func iamMemberIndex(members []string, member string) int {
	for index, candidate := range members {
		if candidate == member {
			return index
		}
	}
	return -1
}

// iamPolicyContains reports whether the exact (role, condition, member)
// binding is present.
func iamPolicyContains(policy iamPolicy, spec IAMBindingSpec) bool {
	index := iamBindingIndex(policy, spec.Role, spec.Condition)
	return index >= 0 && iamMemberIndex(policy.Bindings[index].Members, spec.Member) >= 0
}

// iamPolicyWithBindings returns the observed policy with the desired
// bindings merged in and the subset of specs that were actually absent, so
// rollback can remove only what this operation added.
func iamPolicyWithBindings(policy iamPolicy, specs []IAMBindingSpec) (iamPolicy, []IAMBindingSpec) {
	result := iamNormalizePolicy(policy)
	added := make([]IAMBindingSpec, 0)
	for _, spec := range specs {
		if iamPolicyContains(result, spec) {
			continue
		}
		added = append(added, spec)
		index := iamBindingIndex(result, spec.Role, spec.Condition)
		if index < 0 {
			result.Bindings = append(result.Bindings, iamPolicyBinding{Role: spec.Role, Condition: iamCloneCondition(spec.Condition)})
			index = len(result.Bindings) - 1
		}
		result.Bindings[index].Members = append(result.Bindings[index].Members, spec.Member)
	}
	return iamNormalizePolicy(result), added
}

// iamPolicyWithoutBindings removes exactly the given members from their
// bindings; absent members are ignored so rollback stays idempotent. A
// binding left without members is dropped.
func iamPolicyWithoutBindings(policy iamPolicy, specs []IAMBindingSpec) iamPolicy {
	result := iamNormalizePolicy(policy)
	for _, spec := range specs {
		index := iamBindingIndex(result, spec.Role, spec.Condition)
		if index < 0 {
			continue
		}
		member := iamMemberIndex(result.Bindings[index].Members, spec.Member)
		if member < 0 {
			continue
		}
		result.Bindings[index].Members = append(result.Bindings[index].Members[:member], result.Bindings[index].Members[member+1:]...)
	}
	kept := result.Bindings[:0]
	for _, binding := range result.Bindings {
		if len(binding.Members) > 0 {
			kept = append(kept, binding)
		}
	}
	result.Bindings = kept
	return iamNormalizePolicy(result)
}

func iamEqualPolicyBindings(first, second iamPolicy) bool {
	first, second = iamNormalizePolicy(first), iamNormalizePolicy(second)
	if len(first.Bindings) != len(second.Bindings) {
		return false
	}
	for index := range first.Bindings {
		left, right := first.Bindings[index], second.Bindings[index]
		if left.Role != right.Role || iamConditionKey(left.Condition) != iamConditionKey(right.Condition) || !equalStrings(left.Members, right.Members) {
			return false
		}
	}
	return true
}

// iamServiceAccountID returns the local account ID for a create command.
func iamServiceAccountID(email string) (string, bool) {
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return "", false
	}
	return email[:at], true
}
