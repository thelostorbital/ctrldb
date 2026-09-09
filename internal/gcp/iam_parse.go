// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"errors"
	"regexp"
	"sort"
	"strings"
)

var (
	errIAMParse           = errors.New("iam provider output rejected")
	iamUniqueIDPattern    = regexp.MustCompile(`^[0-9]{1,32}$`)
	iamEtagPattern        = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{1,256}$`)
	iamRoleNamePattern    = regexp.MustCompile(`^(?:roles/[A-Za-z0-9_.]{1,128}|projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/roles/[A-Za-z0-9_.]{3,64}|organizations/[0-9]+/roles/[A-Za-z0-9_.]{3,64})$`)
	iamMemberValuePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*:[^[:space:][:cntrl:]]+$|^principal(?:Set)?://[^[:space:][:cntrl:]]+$|^allUsers$|^allAuthenticatedUsers$`)
)

// IAMServiceAccountObservation is one exact describe/create result.
type IAMServiceAccountObservation struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	ProjectID string `json:"projectId"`
	UniqueID  string `json:"uniqueId"`
	Disabled  bool   `json:"disabled"`
	Etag      string `json:"etag"`
}

type iamServiceAccountWire struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	ProjectID string `json:"projectId"`
	UniqueID  string `json:"uniqueId"`
	Disabled  bool   `json:"disabled"`
	Etag      string `json:"etag"`
}

// iamParseServiceAccount accepts only the exact expected account in the
// expected project. Anything else, including a cross-project account with
// the same local ID, is rejected.
func iamParseServiceAccount(data []byte, project, email string) (IAMServiceAccountObservation, error) {
	var wire iamServiceAccountWire
	if err := decodeProviderJSON(data, &wire, false); err != nil {
		return IAMServiceAccountObservation{}, errIAMParse
	}
	if wire.Email != email || wire.ProjectID != project || wire.Name != "projects/"+project+"/serviceAccounts/"+email ||
		!iamUniqueIDPattern.MatchString(wire.UniqueID) || !iamEtagPattern.MatchString(wire.Etag) {
		return IAMServiceAccountObservation{}, errIAMParse
	}
	return IAMServiceAccountObservation(wire), nil
}

type iamKeyWire struct {
	Name    string `json:"name"`
	KeyType string `json:"keyType"`
}

// iamParseUserManagedKeyCount returns the number of user-managed keys. A
// non-array or malformed response is an error, never zero.
func iamParseUserManagedKeyCount(data []byte) (int, error) {
	var wire []iamKeyWire
	if err := decodeProviderJSON(data, &wire, false); err != nil {
		return 0, errIAMParse
	}
	for _, key := range wire {
		if key.Name == "" || key.KeyType == "" {
			return 0, errIAMParse
		}
	}
	return len(wire), nil
}

// IAMRoleObservation is one exact custom-role describe/create/update result.
type IAMRoleObservation struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Stage       string   `json:"stage"`
	Etag        string   `json:"etag"`
	Deleted     bool     `json:"deleted"`
}

type iamRoleWire struct {
	Name                string   `json:"name"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	IncludedPermissions []string `json:"includedPermissions"`
	Stage               string   `json:"stage"`
	Etag                string   `json:"etag"`
	Deleted             bool     `json:"deleted"`
}

func iamParseRole(data []byte, project, roleID string) (IAMRoleObservation, error) {
	var wire iamRoleWire
	if err := decodeProviderJSON(data, &wire, false); err != nil {
		return IAMRoleObservation{}, errIAMParse
	}
	if wire.Name != IAMCustomRoleName(project, roleID) || !iamEtagPattern.MatchString(wire.Etag) || wire.Stage == "" {
		return IAMRoleObservation{}, errIAMParse
	}
	permissions := append([]string(nil), wire.IncludedPermissions...)
	for index, permission := range permissions {
		if !iamPermissionPattern.MatchString(permission) {
			return IAMRoleObservation{}, errIAMParse
		}
		for _, earlier := range permissions[:index] {
			if earlier == permission {
				return IAMRoleObservation{}, errIAMParse
			}
		}
	}
	return IAMRoleObservation{Name: wire.Name, Title: wire.Title, Description: wire.Description,
		Permissions: permissions, Stage: wire.Stage, Etag: wire.Etag, Deleted: wire.Deleted}, nil
}

// iamRoleMatches reports exact desired-state equality: same permission set,
// stage, title, and description, and not deleted.
func iamRoleMatches(observed IAMRoleObservation, definition IAMRoleDefinition) bool {
	if observed.Deleted || observed.Stage != definition.Stage || observed.Title != definition.Title || observed.Description != definition.Description {
		return false
	}
	sorted := append([]string(nil), observed.Permissions...)
	sort.Strings(sorted)
	return equalStrings(sorted, definition.Permissions)
}

type iamConditionWire struct {
	Expression  string `json:"expression"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

type iamBindingWire struct {
	Role      string            `json:"role"`
	Members   []string          `json:"members"`
	Condition *iamConditionWire `json:"condition"`
}

type iamPolicyWire struct {
	Bindings []iamBindingWire `json:"bindings"`
	Etag     string           `json:"etag"`
	Version  int64            `json:"version"`
}

// iamParsePolicy accepts a version 1 or 3 allow policy with a non-empty
// etag. Duplicate (role, condition) bindings, duplicate members, malformed
// roles or members, and conditions without an expression are rejected.
func iamParsePolicy(data []byte) (iamPolicy, error) {
	var wire iamPolicyWire
	if err := decodeProviderJSON(data, &wire, false); err != nil {
		return iamPolicy{}, errIAMParse
	}
	if (wire.Version != 1 && wire.Version != 3) || !iamEtagPattern.MatchString(wire.Etag) {
		return iamPolicy{}, errIAMParse
	}
	policy := iamPolicy{Etag: wire.Etag, Version: wire.Version}
	seen := make(map[string]struct{}, len(wire.Bindings))
	for _, binding := range wire.Bindings {
		if !iamRoleNamePattern.MatchString(binding.Role) || len(binding.Members) == 0 {
			return iamPolicy{}, errIAMParse
		}
		var condition *IAMCondition
		if binding.Condition != nil {
			if strings.TrimSpace(binding.Condition.Expression) == "" || wire.Version != 3 {
				return iamPolicy{}, errIAMParse
			}
			condition = &IAMCondition{Title: binding.Condition.Title, Description: binding.Condition.Description, Expression: binding.Condition.Expression}
		}
		key := binding.Role + "\x00" + iamConditionKey(condition)
		if _, duplicate := seen[key]; duplicate {
			return iamPolicy{}, errIAMParse
		}
		seen[key] = struct{}{}
		members := make([]string, 0, len(binding.Members))
		for _, member := range binding.Members {
			if !iamMemberValuePattern.MatchString(member) || iamMemberIndex(members, member) >= 0 {
				return iamPolicy{}, errIAMParse
			}
			members = append(members, member)
		}
		policy.Bindings = append(policy.Bindings, iamPolicyBinding{Role: binding.Role, Members: members, Condition: condition})
	}
	return iamNormalizePolicy(policy), nil
}
