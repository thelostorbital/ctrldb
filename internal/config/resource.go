// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

const (
	GeneratedResourcePrefix = "ctrldb-"
	TestResourcePrefix      = "ctrldb-test-"

	LabelManagedBy   = "managed-by"
	LabelEnvironment = "environment"
	LabelPurpose     = "purpose"

	LabelManagedByValue      = "ctrldb"
	TestEnvironmentLabel     = "disposable"
	TestResourcePurposeLabel = "test"
)

var ErrInvalidGeneratedResource = errors.New("invalid generated resource")

var (
	generatedResourceNamePattern = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	resourceEnvironmentPattern   = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// GeneratedResource contains the identity fields required before CtrlDB may
// treat a cloud object as one of its generated resources.
type GeneratedResource struct {
	Name   string
	Labels map[string]string
}

// ExpectedLabels returns fresh required labels for an environment class.
// Callers may add resource-specific labels to the returned map.
func ExpectedLabels(environment string, class domain.EnvironmentClass) (map[string]string, error) {
	if !resourceEnvironmentPattern.MatchString(environment) {
		return nil, resourceError("environment", "must be a lowercase DNS-label-style name of 1 to 63 characters")
	}
	if !class.Valid() {
		return nil, resourceError("class", "unknown value")
	}
	if class != domain.EnvironmentDisposable &&
		(environment == "test" || strings.HasPrefix(environment, "test-")) {
		return nil, resourceError("environment", "the test namespace is reserved for disposable resources")
	}

	labels := map[string]string{LabelManagedBy: LabelManagedByValue}
	if class == domain.EnvironmentDisposable {
		labels[LabelEnvironment] = TestEnvironmentLabel
		labels[LabelPurpose] = TestResourcePurposeLabel
	} else {
		labels[LabelEnvironment] = environment
	}

	return labels, nil
}

// ValidateGeneratedResource enforces the reserved namespace and required
// labels. It applies only to resources CtrlDB generated; adopted resources are
// tracked explicitly and need not be renamed to satisfy this function.
func ValidateGeneratedResource(resource GeneratedResource, environment string, class domain.EnvironmentClass) error {
	if !generatedResourceNamePattern.MatchString(resource.Name) {
		return resourceError("name", "must be a lowercase DNS-label-style name of 1 to 63 characters")
	}

	wantLabels, err := ExpectedLabels(environment, class)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(resource.Name, GeneratedResourcePrefix) {
		return resourceError("name", "must use the "+GeneratedResourcePrefix+" namespace")
	}
	if class == domain.EnvironmentDisposable {
		if !strings.HasPrefix(resource.Name, TestResourcePrefix) {
			return resourceError("name", "disposable resources must use the "+TestResourcePrefix+" namespace")
		}
	} else if strings.HasPrefix(resource.Name, TestResourcePrefix) {
		return resourceError("name", "the test namespace is reserved for disposable resources")
	}

	keys := []string{LabelManagedBy, LabelEnvironment}
	if class == domain.EnvironmentDisposable {
		keys = append(keys, LabelPurpose)
	}
	for _, key := range keys {
		want := wantLabels[key]
		if resource.Labels[key] != want {
			return resourceError("labels."+key, "must equal "+want)
		}
	}

	return nil
}

// IsTestResource reports whether both halves of the destructive test selector
// match: the reserved prefix and all mandatory isolation labels.
func IsTestResource(resource GeneratedResource) bool {
	return ValidateGeneratedResource(resource, TestEnvironmentLabel, domain.EnvironmentDisposable) == nil
}

func resourceError(path, reason string) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidGeneratedResource, path, reason)
}
