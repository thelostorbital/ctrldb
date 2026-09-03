// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package domain_test

import (
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

func TestDefaultIdentityPlanUsesSeparatedPrivileges(t *testing.T) {
	t.Parallel()

	got := domain.DefaultIdentityPlan()
	want := domain.IdentityPlan{
		Default:          domain.IdentityOperator,
		HostControlSteps: domain.IdentityProvisioner,
		DeleteSteps:      domain.IdentityDestructive,
		BootstrapSteps:   domain.IdentityHuman,
	}
	if got != want {
		t.Fatalf("DefaultIdentityPlan() = %#v, want %#v", got, want)
	}
}

func TestPlanCostClosedEnums(t *testing.T) {
	t.Parallel()

	for _, source := range []domain.CostSource{
		domain.CostSourceListPriceTable,
		domain.CostSourceBudgetAPI,
	} {
		if !source.Valid() {
			t.Errorf("CostSource(%q).Valid() = false", source)
		}
	}
	if domain.CostSource("unknown").Valid() {
		t.Fatal("unknown CostSource.Valid() = true")
	}

	for _, state := range []domain.BudgetState{
		domain.BudgetOK,
		domain.BudgetMissing,
		domain.BudgetUnavailable,
	} {
		if !state.Valid() {
			t.Errorf("BudgetState(%q).Valid() = false", state)
		}
	}
	if domain.BudgetState("unknown").Valid() {
		t.Fatal("unknown BudgetState.Valid() = true")
	}
}
