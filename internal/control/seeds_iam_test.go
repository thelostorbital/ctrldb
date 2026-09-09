// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSeedObjectsAreExactAndCreateOnly(t *testing.T) {
	t.Parallel()
	envelope := fixtureEnvelope(t)
	seeds, err := SeedObjects(envelope)
	if err != nil {
		t.Fatalf("SeedObjects() error: %v", err)
	}
	wantNames := []string{"locks/disposable-test.json", "adoption/disposable-test.json", "policy/disposable-test/manifest-approved.json", "policy/disposable-test/cost-ceiling.json"}
	if len(seeds) != len(wantNames) {
		t.Fatalf("seeds = %d", len(seeds))
	}
	for index, seed := range seeds {
		if seed.Name.String() != wantNames[index] {
			t.Fatalf("seed %d = %q, want %q", index, seed.Name.String(), wantNames[index])
		}
	}
	var lock LockRecordV1
	if err := json.Unmarshal(seeds[0].Content, &lock); err != nil || lock.State != LockStateReleased || lock.Holder != nil || lock.Readers == nil {
		t.Fatalf("lock seed = %s (%v)", seeds[0].Content, err)
	}
	var policy ApprovedPolicyV1
	if err := json.Unmarshal(seeds[2].Content, &policy); err != nil || policy.SHA256 != envelope.Plan().Binding().ManifestHash || policy.ApprovedBy != fixtureAccount || policy.PlanID != fixturePlanID {
		t.Fatalf("policy seed = %s", seeds[2].Content)
	}
	var ceiling CostCeilingV1
	if err := json.Unmarshal(seeds[3].Content, &ceiling); err != nil || ceiling.CeilingMicros != envelope.Plan().Limits().MaximumCostMicros || ceiling.Currency != "USD" {
		t.Fatalf("ceiling seed = %s", seeds[3].Content)
	}
	var adoption AdoptionRecordV1
	if err := json.Unmarshal(seeds[1].Content, &adoption); err != nil || len(adoption.Resources) != 2 || adoption.Resources["audit-bucket"].Fingerprint == "" {
		t.Fatalf("adoption seed = %s", seeds[1].Content)
	}
	again, _ := SeedObjects(envelope)
	for index := range seeds {
		if !bytes.Equal(seeds[index].Content, again[index].Content) {
			t.Fatal("seed rendering is not deterministic")
		}
	}

	ctx := context.Background()
	store := NewMemoryControlStore()
	first, err := SeedControlStore(ctx, store, envelope)
	if err != nil || len(first) != 4 {
		t.Fatalf("SeedControlStore() = %v, %v", first, err)
	}
	for _, outcome := range first {
		if outcome.Preexisting || outcome.Descriptor.Generation == 0 {
			t.Fatalf("first seeding outcome = %#v", outcome)
		}
	}
	// A concurrent holder changed the lock meanwhile: K4 must preserve it.
	held, _ := store.CompareAndSwap(ctx, first[0].Name, first[0].Descriptor.Generation, []byte(`{"schema":"ctrldb.ctrlboard.dev/lock/v1","environment":"disposable-test","excludesHostAutomations":true,"state":"held","readers":[]}`))
	second, err := SeedControlStore(ctx, store, envelope)
	if err != nil {
		t.Fatalf("second SeedControlStore() error: %v", err)
	}
	for index, outcome := range second {
		if !outcome.Preexisting {
			t.Fatalf("second seeding re-created %s", outcome.Name)
		}
		want := first[index].Descriptor
		if index == 0 {
			want = held
		}
		if outcome.Descriptor != want {
			t.Fatalf("second seeding changed %s: %#v", outcome.Name, outcome.Descriptor)
		}
	}
	lockObject, _ := store.Read(ctx, first[0].Name)
	if !strings.Contains(string(lockObject.Content), `"state":"held"`) {
		t.Fatal("preexisting lock was reseeded")
	}

	// An existing approved policy for a different manifest blocks K4.
	mismatched := NewMemoryControlStore()
	policyName, _ := ApprovedPolicyObjectName("disposable-test")
	if _, err := mismatched.Create(ctx, policyName, []byte(`{"schema":"ctrldb.ctrlboard.dev/approved-policy/v1","sha256":"`+repeatHex("f")+`","approvedBy":"x@example.invalid","planId":"plan-fedcba9876543210"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := SeedControlStore(ctx, mismatched, envelope); !errors.Is(err, ErrApprovedPolicyMismatch) {
		t.Fatalf("mismatched policy error = %v", err)
	}
	if names := mismatched.Names(); len(names) != 1 {
		t.Fatalf("a rejected seeding created partial state: %v", names)
	}
	// Existing seeds are parsed strictly and must be semantically compatible.
	lockName, _ := LockObjectName("disposable-test")
	adoptionName, _ := AdoptionObjectName("disposable-test")
	ceilingName, _ := CostCeilingObjectName("disposable-test")
	for name, existing := range map[string]struct {
		object  ControlObjectName
		content string
		want    error
	}{
		"duplicate policy keys": {policyName, `{"schema":"ctrldb.ctrlboard.dev/approved-policy/v1","sha256":"` + repeatHex("f") + `","sha256":"` + envelope.Plan().Binding().ManifestHash + `","approvedBy":"x@example.invalid","planId":"plan-fedcba9876543210"}`, ErrSeedIncompatible},
		"unknown policy field":  {policyName, `{"schema":"ctrldb.ctrlboard.dev/approved-policy/v1","sha256":"` + envelope.Plan().Binding().ManifestHash + `","approvedBy":"x@example.invalid","planId":"plan-fedcba9876543210","extra":1}`, ErrSeedIncompatible},
		"foreign lock":          {lockName, `{"schema":"ctrldb.ctrlboard.dev/lock/v1","environment":"production","excludesHostAutomations":false,"state":"released","readers":[]}`, ErrSeedIncompatible},
		"malformed lock":        {lockName, `not json`, ErrSeedIncompatible},
		"foreign adoption":      {adoptionName, `{"schema":"ctrldb.ctrlboard.dev/adoption/v1","environment":"disposable-test","project":"other-project","operationId":"op-fedcba9876543210","planId":"plan-fedcba9876543210","adoptedAt":"2026-09-09T12:00:00Z","resources":{}}`, ErrSeedIncompatible},
		"different ceiling":     {ceilingName, `{"schema":"ctrldb.ctrlboard.dev/cost-ceiling/v1","environment":"disposable-test","ceilingMicros":1,"estimatedRunMicros":1,"currency":"USD","approvedBy":"x@example.invalid","planId":"plan-fedcba9876543210"}`, ErrApprovedPolicyMismatch},
	} {
		store := NewMemoryControlStore()
		if _, err := store.Create(ctx, existing.object, []byte(existing.content)); err != nil {
			t.Fatal(err)
		}
		if _, err := SeedControlStore(ctx, store, envelope); !errors.Is(err, existing.want) {
			t.Fatalf("%s error = %v, want %v", name, err, existing.want)
		}
		if names := store.Names(); len(names) != 1 {
			t.Fatalf("%s: rejected seeding created partial state: %v", name, names)
		}
		after, _ := store.Read(ctx, existing.object)
		if string(after.Content) != existing.content {
			t.Fatalf("%s: existing object was modified", name)
		}
	}
	// A compatible earlier bootstrap's records are preserved and accepted.
	compatible := NewMemoryControlStore()
	priorAdoption := strings.Replace(string(seeds[1].Content), fixtureOperationID, "op-fedcba9876543210", 1)
	if _, err := compatible.Create(ctx, adoptionName, []byte(priorAdoption)); err != nil {
		t.Fatal(err)
	}
	outcomes, err := SeedControlStore(ctx, compatible, envelope)
	if err != nil || len(outcomes) != 4 || !outcomes[1].Preexisting {
		t.Fatalf("compatible prior adoption = %v, %v", outcomes, err)
	}
	if _, err := SeedControlStore(ctx, nil, envelope); !errors.Is(err, ErrInvalidStoreRequest) {
		t.Fatalf("nil store error = %v", err)
	}
}

func TestBucketPolicyIsResourceScopedAndClosed(t *testing.T) {
	t.Parallel()
	desired := fixturePlan(t).DesiredState()
	k3, err := RenderBucketPolicy("k3-bucket-iam", desired)
	if err != nil || len(k3.Bindings) != 8 || k3.Fingerprint == "" {
		t.Fatalf("RenderBucketPolicy(k3) = %#v, %v", k3, err)
	}
	t6, err := RenderBucketPolicy("t6-control-prefix", desired)
	if err != nil || len(t6.Bindings) != 2 {
		t.Fatalf("RenderBucketPolicy(t6) = %#v, %v", t6, err)
	}
	for _, item := range append(k3.Bindings, t6.Bindings...) {
		if item.Prefix == "" || !strings.Contains(item.ConditionExpression, `projects/_/buckets/`+item.Bucket+`/objects/`+item.Prefix) ||
			!strings.HasPrefix(item.Prefix, TestPrefix) || item.Role == "roles/storage.admin" || strings.Contains(item.Role, "legacy") {
			t.Fatalf("binding is not resource-scoped: %#v", item)
		}
		if item.Bucket != desired.AuditBucket && item.Bucket != desired.ControlBucket {
			t.Fatalf("binding names a foreign bucket: %#v", item)
		}
	}
	for _, item := range t6.Bindings {
		if item.Bucket != desired.ControlBucket || item.Role != RoleObjectUser {
			t.Fatalf("T6 binding = %#v", item)
		}
	}
	for _, item := range k3.Bindings {
		if item.Bucket == desired.AuditBucket && item.Role == RoleObjectUser {
			t.Fatalf("audit bucket grants overwrite capability: %#v", item)
		}
	}
	if _, err := RenderBucketPolicy("t5-identities", desired); !errors.Is(err, ErrInvalidBucketBinding) {
		t.Fatalf("foreign step rendered a policy: %v", err)
	}
	same := desired
	same.ControlBucket = same.AuditBucket
	if _, err := RenderBucketPolicy("k3-bucket-iam", same); !errors.Is(err, ErrInvalidBucketBinding) {
		t.Fatalf("identical buckets accepted: %v", err)
	}

	valid := k3.Bindings[0]
	invalid := map[string]func(*BucketBinding){
		"foreign bucket":      func(b *BucketBinding) { b.Bucket = "someone-elses-bucket" },
		"bucket-wide prefix":  func(b *BucketBinding) { b.Prefix = "" },
		"production prefix":   func(b *BucketBinding) { b.Prefix = "locks/" },
		"admin role":          func(b *BucketBinding) { b.Role = "roles/storage.admin" },
		"user member":         func(b *BucketBinding) { b.Member = "user:someone@example.invalid" },
		"foreign account":     func(b *BucketBinding) { b.Member = "serviceAccount:other-sa@example-project.iam.gserviceaccount.com" },
		"loosened expression": func(b *BucketBinding) { b.ConditionExpression = `resource.type == "storage.googleapis.com/Object"` },
		"other-bucket expr": func(b *BucketBinding) {
			b.ConditionExpression = strings.Replace(b.ConditionExpression, b.Bucket, "other", 1)
		},
	}
	for name, mutate := range invalid {
		item := valid
		mutate(&item)
		if err := ValidateBucketBinding(item, desired); !errors.Is(err, ErrInvalidBucketBinding) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}

	preexisting := []BucketBinding{k3.Bindings[1], k3.Bindings[4]}
	compensation := CompensationBindings(k3.Bindings, preexisting)
	if len(compensation) != len(k3.Bindings)-2 {
		t.Fatalf("compensation = %d bindings", len(compensation))
	}
	for _, item := range compensation {
		for _, kept := range preexisting {
			if item == kept {
				t.Fatalf("compensation would remove a preexisting binding: %#v", item)
			}
		}
	}
}
