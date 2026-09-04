// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"errors"
	"regexp"
	"strings"
)

var (
	// ErrPermissionProof marks incomplete, ambiguous, or contradictory
	// permission evidence.
	ErrPermissionProof = errors.New("invalid isolation permission proof")
	// ErrForbiddenPermission marks a granted Monitoring, Scheduler, or Cloud
	// Run write permission, forbidden for every test identity.
	ErrForbiddenPermission = errors.New("forbidden test identity permission")
)

var permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)+$`)

// PermissionObservation is one exact testIamPermissions-style observation.
// Expected and observed slices use the same tuple shape so callers, rather
// than this package, remain authoritative for the permission inventory.
type PermissionObservation struct {
	Identity   string
	Resource   string
	Permission string
	Granted    bool
}

// ValidatePermissionProof proves that observations are an exact, complete
// match for caller-supplied expectations. No missing, duplicate, or unexpected
// tuple is tolerated. Independently, a granted Monitoring, Scheduler, or Cloud
// Run write is always rejected even if an expectation incorrectly permits it.
func ValidatePermissionProof(expected, observed []PermissionObservation) error {
	if len(expected) == 0 {
		return guardError(ErrPermissionProof, "expected", "must not be empty")
	}

	expectedByKey := make(map[permissionObservationKey]PermissionObservation, len(expected))
	for index, item := range expected {
		path := indexedField("expected", index)
		if err := validatePermissionObservation(path, item); err != nil {
			return err
		}
		key := newPermissionObservationKey(item)
		if _, exists := expectedByKey[key]; exists {
			return guardError(ErrPermissionProof, path, "duplicates an earlier tuple")
		}
		if item.Granted && isForbiddenServiceWrite(item.Permission) {
			return guardError(ErrForbiddenPermission, path, "expects a forbidden service write")
		}
		expectedByKey[key] = item
	}

	seen := make(map[permissionObservationKey]struct{}, len(observed))
	for index, item := range observed {
		path := indexedField("observed", index)
		if err := validatePermissionObservation(path, item); err != nil {
			return err
		}
		key := newPermissionObservationKey(item)
		if _, exists := seen[key]; exists {
			return guardError(ErrPermissionProof, path, "duplicates an earlier tuple")
		}
		seen[key] = struct{}{}
		if item.Granted && isForbiddenServiceWrite(item.Permission) {
			return guardError(ErrForbiddenPermission, path, "observes a forbidden service write")
		}
		want, exists := expectedByKey[key]
		if !exists {
			return guardError(ErrPermissionProof, path, "is an unexpected tuple")
		}
		if item.Granted != want.Granted {
			return guardError(ErrPermissionProof, path, "does not match the expected decision")
		}
	}
	if len(seen) != len(expectedByKey) {
		return guardError(ErrPermissionProof, "observed", "is missing an expected tuple")
	}
	return nil
}

func validatePermissionObservation(path string, item PermissionObservation) error {
	if strings.TrimSpace(item.Identity) == "" || strings.TrimSpace(item.Resource) == "" {
		return guardError(ErrPermissionProof, path, "must identify an identity and resource")
	}
	if item.Identity != strings.TrimSpace(item.Identity) || item.Resource != strings.TrimSpace(item.Resource) {
		return guardError(ErrPermissionProof, path, "contains non-canonical identity or resource text")
	}
	if !permissionPattern.MatchString(item.Permission) {
		return guardError(ErrPermissionProof, path, "contains a malformed permission")
	}
	return nil
}

type permissionObservationKey struct {
	identity   string
	resource   string
	permission string
}

func newPermissionObservationKey(item PermissionObservation) permissionObservationKey {
	return permissionObservationKey{identity: item.Identity, resource: item.Resource, permission: item.Permission}
}

func isForbiddenServiceWrite(permission string) bool {
	service, action, ok := permissionServiceAndAction(permission)
	if !ok {
		return false
	}
	switch service {
	case "monitoring", "cloudscheduler", "run":
		return action != "get" && action != "list" && action != "getIamPolicy"
	default:
		return false
	}
}

func permissionServiceAndAction(permission string) (string, string, bool) {
	parts := strings.Split(permission, ".")
	if len(parts) < 3 {
		return "", "", false
	}
	return parts[0], parts[len(parts)-1], true
}
