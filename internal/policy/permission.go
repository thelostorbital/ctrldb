// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

// ErrPlanBlocked identifies a structurally valid review artifact that must not
// execute because one or more discovery-backed safety checks failed.
var (
	ErrPlanBlocked            = errors.New("plan blocked")
	ErrInvalidPermissionProbe = errors.New("invalid permission probe")
)

// PlanBlockerKind distinguishes independently reviewable execution blockers.
type PlanBlockerKind string

const (
	BlockerPrecondition PlanBlockerKind = "precondition"
	BlockerPermission   PlanBlockerKind = "permission"
)

// PlanBlocker names one failed safety check without carrying provider output.
type PlanBlocker struct {
	Kind     PlanBlockerKind
	ID       string
	Identity domain.ExecutionIdentity
}

// BlockedPlanError is returned before any mutation for a reviewable but
// non-executable plan. ExitCode is the stable command-mode validation code.
type BlockedPlanError struct {
	planID   string
	blockers []PlanBlocker
}

// PermissionChecks converts an exact testIamPermissions-style response into
// stable plan evidence. The response may contain only requested permissions;
// omissions are recorded as denied rather than treated as a runtime error.
func PermissionChecks(identity domain.ExecutionIdentity, required, granted []string) ([]domain.PlanPermission, error) {
	if !identity.Valid() {
		return nil, fmt.Errorf("%w: unknown identity", ErrInvalidPermissionProbe)
	}
	if len(required) == 0 {
		return nil, fmt.Errorf("%w: required set is empty", ErrInvalidPermissionProbe)
	}

	requiredSet := make(map[string]struct{}, len(required))
	for _, permission := range required {
		if !permissionPattern.MatchString(permission) {
			return nil, fmt.Errorf("%w: malformed required permission", ErrInvalidPermissionProbe)
		}
		if _, exists := requiredSet[permission]; exists {
			return nil, fmt.Errorf("%w: duplicate required permission", ErrInvalidPermissionProbe)
		}
		requiredSet[permission] = struct{}{}
	}

	grantedSet := make(map[string]struct{}, len(granted))
	for _, permission := range granted {
		if _, requested := requiredSet[permission]; !requested {
			return nil, fmt.Errorf("%w: response contains an unrequested permission", ErrInvalidPermissionProbe)
		}
		if _, exists := grantedSet[permission]; exists {
			return nil, fmt.Errorf("%w: duplicate granted permission", ErrInvalidPermissionProbe)
		}
		grantedSet[permission] = struct{}{}
	}

	checks := make([]domain.PlanPermission, len(required))
	for index, permission := range required {
		_, isGranted := grantedSet[permission]
		checks[index] = domain.PlanPermission{Identity: identity, Permission: permission, Granted: isGranted}
	}

	return checks, nil
}

// Error implements error.
func (err *BlockedPlanError) Error() string {
	if err == nil {
		return ErrPlanBlocked.Error()
	}

	return fmt.Sprintf("%s: plan %s has %d blocker(s)", ErrPlanBlocked, err.planID, len(err.blockers))
}

// Unwrap supports errors.Is(err, ErrPlanBlocked).
func (err *BlockedPlanError) Unwrap() error { return ErrPlanBlocked }

// ExitCode is the stable command-mode exit code for a validation blocker.
func (err *BlockedPlanError) ExitCode() int { return 3 }

// PlanID returns the immutable plan identity associated with the blockers.
func (err *BlockedPlanError) PlanID() string {
	if err == nil {
		return ""
	}

	return err.planID
}

// Blockers returns a detached copy in deterministic plan order.
func (err *BlockedPlanError) Blockers() []PlanBlocker {
	if err == nil {
		return nil
	}

	result := make([]PlanBlocker, len(err.blockers))
	copy(result, err.blockers)

	return result
}

// ValidatePlanForExecutionAt validates integrity and expiry before converting
// denied permissions and false preconditions into a typed, deterministic
// execution blocker. It performs no I/O and has no mutation capability.
func ValidatePlanForExecutionAt(plan domain.Plan, now time.Time) error {
	if err := ValidatePlanAt(plan, now); err != nil {
		return err
	}

	blockers := make([]PlanBlocker, 0)
	for _, precondition := range plan.Preconditions {
		if !precondition.OK {
			blockers = append(blockers, PlanBlocker{Kind: BlockerPrecondition, ID: precondition.ID})
		}
	}
	for _, permission := range plan.Permissions {
		if !permission.Granted {
			blockers = append(blockers, PlanBlocker{
				Kind:     BlockerPermission,
				ID:       permission.Permission,
				Identity: permission.Identity,
			})
		}
	}
	if len(blockers) != 0 {
		return &BlockedPlanError{planID: plan.PlanID, blockers: blockers}
	}

	return nil
}
