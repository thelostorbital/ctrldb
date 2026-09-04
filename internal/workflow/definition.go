// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/redact"
)

// ErrInvalidDefinition is returned when an implemented workflow omits a
// mandatory execution contract or attempts to register a placeholder.
var ErrInvalidDefinition = errors.New("invalid workflow definition")

var definitionWorkflowIDPattern = regexp.MustCompile(`^WF-[A-Z0-9]+-[0-9]{2}$`)

// StepDefinition is the resource-independent execution contract registered by
// an implemented workflow.
type StepDefinition struct {
	ID                string
	Executor          string
	ExecutingIdentity domain.ExecutionIdentity
	Idempotent        bool
	Retry             domain.RetryPolicy
	CancelSafe        bool
	TimeoutSeconds    int64
	SuccessCondition  redact.Text
	FailureBehavior   domain.FailureBehavior
}

// Definition is immutable after construction. Its fields are intentionally
// private so callers cannot weaken a validated step contract in place.
type Definition struct {
	workflowID string
	steps      []StepDefinition
}

// NewDefinition validates and defensively copies one implemented workflow.
func NewDefinition(workflowID string, steps []StepDefinition) (Definition, error) {
	if !definitionWorkflowIDPattern.MatchString(workflowID) {
		return Definition{}, definitionError("workflowId", "must match WF-<GROUP>-<NN>")
	}
	if len(steps) == 0 {
		return Definition{}, definitionError("steps", "must contain at least one implemented step")
	}

	seen := make(map[string]struct{}, len(steps))
	copyOfSteps := make([]StepDefinition, len(steps))
	for index, step := range steps {
		path := fmt.Sprintf("steps[%d]", index)
		if !stepIDPattern.MatchString(step.ID) {
			return Definition{}, definitionError(path+".id", "must match [a-z][a-z0-9-]{0,63}")
		}
		if _, exists := seen[step.ID]; exists {
			return Definition{}, definitionError(path+".id", "duplicate value")
		}
		seen[step.ID] = struct{}{}
		if step.Executor == "" {
			return Definition{}, definitionError(path+".executor", "must not be empty")
		}
		if !step.ExecutingIdentity.Valid() {
			return Definition{}, definitionError(path+".executingIdentity", "unknown value")
		}
		if !step.Retry.Valid() {
			return Definition{}, definitionError(path+".retry", "must be explicit and bounded")
		}
		if step.TimeoutSeconds <= 0 || step.TimeoutSeconds > domain.MaxStepTimeoutSeconds {
			return Definition{}, definitionError(path+".timeoutSeconds", "must be positive and bounded")
		}
		if step.SuccessCondition.String() == "" {
			return Definition{}, definitionError(path+".successCondition", "must not be empty")
		}
		if !step.FailureBehavior.Valid() {
			return Definition{}, definitionError(path+".failureBehavior", "unknown value")
		}
		copyOfSteps[index] = step
	}

	return Definition{workflowID: workflowID, steps: copyOfSteps}, nil
}

// WorkflowID returns the stable workflow registry key.
func (definition Definition) WorkflowID() string { return definition.workflowID }

// Steps returns a detached copy of the validated step contracts.
func (definition Definition) Steps() []StepDefinition {
	steps := make([]StepDefinition, len(definition.steps))
	copy(steps, definition.steps)

	return steps
}

// Registry contains only definitions supplied by implemented workflow code.
// It intentionally has no catalogue-derived placeholder population.
type Registry struct {
	definitions map[string]Definition
}

// NewRegistry validates unique, fully constructed implemented workflows.
func NewRegistry(definitions ...Definition) (Registry, error) {
	registered := make(map[string]Definition, len(definitions))
	for index, definition := range definitions {
		if definition.workflowID == "" || len(definition.steps) == 0 {
			return Registry{}, definitionError(fmt.Sprintf("definitions[%d]", index), "was not constructed by NewDefinition")
		}
		if _, exists := registered[definition.workflowID]; exists {
			return Registry{}, definitionError(fmt.Sprintf("definitions[%d]", index), "duplicates a workflowId")
		}
		registered[definition.workflowID] = cloneDefinition(definition)
	}

	return Registry{definitions: registered}, nil
}

// Lookup returns a detached immutable definition for workflowID.
func (registry Registry) Lookup(workflowID string) (Definition, bool) {
	definition, ok := registry.definitions[workflowID]
	if !ok {
		return Definition{}, false
	}

	return cloneDefinition(definition), true
}

// Len returns the number of implemented workflows in the registry.
func (registry Registry) Len() int { return len(registry.definitions) }

func cloneDefinition(definition Definition) Definition {
	return Definition{workflowID: definition.workflowID, steps: definition.Steps()}
}

func definitionError(path, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidDefinition, path, reason)
}
