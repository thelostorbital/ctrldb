// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package isolation

import (
	"errors"
	"regexp"
	"sort"
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

var (
	permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*){2,}$`)
)

// PermissionObservation is one exact testIamPermissions-style observation.
// Expected and observed slices use the same tuple shape so callers, rather
// than this package, remain authoritative for the permission inventory.
type PermissionObservation struct {
	Identity   Principal
	Resource   ResourceIdentity
	Permission string
	Granted    bool
}

// PermissionProofInput carries exact expected and observed tuples separately
// from the policy-owned inventory pin. This package deliberately does not
// compile role definitions; the future bootstrap policy owner supplies the
// authoritative pin and expected tuples.
type PermissionProofInput struct {
	Expected []PermissionObservation
	Observed []PermissionObservation
}

// ValidatePermissionProof proves that observations are an exact, complete
// match for the separately pinned caller-supplied inventory and that every
// tuple covers the exact mutation principal. No missing, duplicate, or
// unexpected tuple is tolerated. Independently, a granted Monitoring,
// Scheduler, or Cloud Run write is always rejected even if an expectation
// incorrectly permits it.
func ValidatePermissionProof(pin PolicyInventoryPin, input PermissionProofInput, mutationPrincipal Principal) error {
	if err := validateInventoryPin("permissionInventory", pin); err != nil {
		return guardError(ErrPermissionProof, "permissionInventory", "must contain a valid policy pin")
	}
	if !validPrincipal(mutationPrincipal) {
		return guardError(ErrPermissionProof, "mutationPrincipal", "must be canonical")
	}
	if len(input.Expected) == 0 {
		return guardError(ErrPermissionProof, "expected", "must not be empty")
	}

	expectedByKey := make(map[permissionObservationKey]PermissionObservation, len(input.Expected))
	for index, item := range input.Expected {
		path := indexedField("expected", index)
		if err := validatePermissionObservation(path, item); err != nil {
			return err
		}
		if item.Identity != mutationPrincipal {
			return guardError(ErrPermissionProof, path, "does not cover the exact mutation principal")
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

	fingerprint, err := PermissionInventoryFingerprint(input.Expected)
	if err != nil {
		return err
	}
	if fingerprint != pin.Fingerprint {
		return guardError(ErrPermissionProof, "inventory.fingerprint", "does not match the expected tuple inventory")
	}

	seen := make(map[permissionObservationKey]struct{}, len(input.Observed))
	for index, item := range input.Observed {
		path := indexedField("observed", index)
		if err := validatePermissionObservation(path, item); err != nil {
			return err
		}
		if item.Identity != mutationPrincipal {
			return guardError(ErrPermissionProof, path, "does not cover the exact mutation principal")
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

// PermissionInventoryFingerprint returns the deterministic SHA-256 identity
// of an expected tuple inventory. It does not assert that the inventory is the
// policy-authoritative one; callers must separately pin ID, version, and the
// returned fingerprint in their policy boundary.
func PermissionInventoryFingerprint(expected []PermissionObservation) (string, error) {
	if len(expected) == 0 {
		return "", guardError(ErrPermissionProof, "expected", "must not be empty")
	}
	canonical := append([]PermissionObservation(nil), expected...)
	for index, item := range canonical {
		if err := validatePermissionObservation(indexedField("expected", index), item); err != nil {
			return "", err
		}
	}
	sort.Slice(canonical, func(i, j int) bool {
		first := newPermissionObservationKey(canonical[i])
		second := newPermissionObservationKey(canonical[j])
		if first.identityKind != second.identityKind {
			return first.identityKind < second.identityKind
		}
		if first.identitySubject != second.identitySubject {
			return first.identitySubject < second.identitySubject
		}
		if first.resource != second.resource {
			return first.resource < second.resource
		}
		if first.permission != second.permission {
			return first.permission < second.permission
		}
		return !canonical[i].Granted && canonical[j].Granted
	})
	return canonicalJSONFingerprint(canonical)
}

func validatePermissionObservation(path string, item PermissionObservation) error {
	if !validPrincipal(item.Identity) {
		return guardError(ErrPermissionProof, path, "must contain a canonical principal")
	}
	if err := validateResourceIdentity(item.Resource); err != nil {
		return guardError(ErrPermissionProof, path, "must contain a canonical explicit resource identity")
	}
	if !permissionPattern.MatchString(item.Permission) {
		return guardError(ErrPermissionProof, path, "contains a malformed permission")
	}
	return nil
}

type permissionObservationKey struct {
	identityKind    PrincipalKind
	identitySubject string
	resource        string
	permission      string
}

func newPermissionObservationKey(item PermissionObservation) permissionObservationKey {
	return permissionObservationKey{
		identityKind: item.Identity.Kind, identitySubject: item.Identity.Subject,
		resource: item.Resource.CanonicalKey, permission: item.Permission,
	}
}

func isForbiddenServiceWrite(permission string) bool {
	service, action, ok := permissionServiceAndAction(permission)
	if !ok {
		return false
	}
	switch service {
	case "monitoring", "cloudscheduler", "run":
		if action == "get" || action == "list" || action == "getIamPolicy" {
			return false
		}
		return permission != "monitoring.timeSeries.query" && permission != "cloudscheduler.jobs.fullView"
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
