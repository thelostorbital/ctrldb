// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
)

func TestStoreInterfacesExposeNoDeleteOrOverwriteSurface(t *testing.T) {
	t.Parallel()
	methods := func(value any) []string {
		kind := reflect.TypeOf(value).Elem()
		result := make([]string, 0, kind.NumMethod())
		for index := 0; index < kind.NumMethod(); index++ {
			result = append(result, kind.Method(index).Name)
		}
		sort.Strings(result)
		return result
	}
	if got := methods((*AuditStore)(nil)); !reflect.DeepEqual(got, []string{"Create", "Read"}) {
		t.Fatalf("AuditStore methods = %v", got)
	}
	if got := methods((*ControlStore)(nil)); !reflect.DeepEqual(got, []string{"CompareAndSwap", "Create", "Read"}) {
		t.Fatalf("ControlStore methods = %v", got)
	}
	if got := methods((*AuditBucketPort)(nil)); !reflect.DeepEqual(got, []string{
		"ConfigureArchiveLifecycle", "ConfigureRetention", "CreateAuditBucket", "DescribeBucket", "DescribeObject", "LockRetention", "ReadObject", "UploadCreateOnly",
	}) {
		t.Fatalf("AuditBucketPort methods = %v", got)
	}
	for _, kind := range []reflect.Type{reflect.TypeOf(&MemoryAuditStore{}), reflect.TypeOf(&MemoryControlStore{})} {
		for index := 0; index < kind.NumMethod(); index++ {
			name := kind.Method(index).Name
			if name == "Delete" || name == "Remove" || name == "Overwrite" || name == "Put" || name == "Write" {
				t.Fatalf("%s exposes %s", kind, name)
			}
		}
	}
}

func TestObjectNamesFollowArchitecturePrefixes(t *testing.T) {
	t.Parallel()
	plan := fixturePlan(t)
	entry := fixtureJournalEntry(plan, fixtureNow)
	cases := []struct {
		name string
		got  func() (string, error)
		want string
	}{
		{"lock", func() (string, error) { n, err := LockObjectName("prod"); return n.String(), err }, "locks/prod.json"},
		{"harness", func() (string, error) { return HarnessStateObjectName().String(), nil }, "test/harness-state.json"},
		{"ownership", func() (string, error) {
			n, err := OwnershipRecordObjectName("dev", "test-network")
			return n.String(), err
		}, "test/ownership/dev/test-network.json"},
		{"lifetime", func() (string, error) { n, err := LifetimeRecordObjectName("dev", "run-1"); return n.String(), err }, "test/lifetime/dev/run-1.json"},
		{"adoption", func() (string, error) { n, err := AdoptionObjectName("dev"); return n.String(), err }, "adoption/dev.json"},
		{"policy", func() (string, error) { n, err := ApprovedPolicyObjectName("dev"); return n.String(), err }, "policy/dev/manifest-approved.json"},
		{"ceiling", func() (string, error) { n, err := CostCeilingObjectName("dev"); return n.String(), err }, "policy/dev/cost-ceiling.json"},
		{"plan", func() (string, error) { n, err := PlanObjectName("dev", fixturePlanID); return n.String(), err }, "plans/dev/" + fixturePlanID + ".json"},
		{"approval", func() (string, error) { n, err := PlanApprovalObjectName("dev", fixturePlanID); return n.String(), err }, "plans/dev/" + fixturePlanID + "-approval.json"},
		{"operation", func() (string, error) {
			n, err := OperationRecordObjectName("dev", fixtureOperationID)
			return n.String(), err
		}, "operations/dev/" + fixtureOperationID + ".json"},
		{"envelope", func() (string, error) {
			n, err := BootstrapEnvelopeObjectName("dev", fixtureOperationID)
			return n.String(), err
		}, "operations/dev/" + fixtureOperationID + "/bootstrap-envelope.json"},
		{"journal", func() (string, error) { n, err := JournalEntryObjectName("dev", entry); return n.String(), err }, "operations/dev/" + fixtureOperationID + "/steps/00000000000000000001-state-discover.json"},
	}
	for _, test := range cases {
		got, err := test.got()
		if err != nil || got != test.want {
			t.Fatalf("%s = %q, %v; want %q", test.name, got, err, test.want)
		}
	}
	invalidEntry := entry
	invalidEntry.Sequence = 0
	for name, err := range map[string]error{
		"env upper":   firstError(LockObjectName("Prod")),
		"env slash":   firstError(AdoptionObjectName("a/b")),
		"env dots":    firstError(CostCeilingObjectName("..")),
		"resource":    firstError(OwnershipRecordObjectName("dev", "Bad/ID")),
		"plan id":     firstError(PlanObjectName("dev", "plan-x")),
		"op id":       firstError(OperationRecordObjectName("dev", "op-x")),
		"journal":     firstError(JournalEntryObjectName("dev", invalidEntry)),
		"journal env": firstError(JournalEntryObjectName("Dev", entry)),
	} {
		if !errors.Is(err, ErrInvalidObjectName) {
			t.Fatalf("%s error = %v", name, err)
		}
	}
	if _, err := JournalEntryObjectName("dev", domain.JournalEntry{}); !errors.Is(err, ErrInvalidObjectName) {
		t.Fatalf("empty entry error = %v", err)
	}
}

func firstError[T any](_ T, err error) error { return err }

func TestMemoryStoresEnforceGenerationPreconditions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	control := NewMemoryControlStore()
	lock, _ := LockObjectName("dev")
	first, err := control.Create(ctx, lock, []byte(`{"state":"released"}`))
	if err != nil || first.Generation == 0 || !first.MatchesContent([]byte(`{"state":"released"}`)) {
		t.Fatalf("Create() = %#v, %v", first, err)
	}
	if _, err := control.Create(ctx, lock, []byte("x")); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("duplicate Create() error = %v", err)
	}
	if _, err := control.CompareAndSwap(ctx, lock, first.Generation+1, []byte("y")); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale CompareAndSwap() error = %v", err)
	}
	if _, err := control.CompareAndSwap(ctx, lock, 0, []byte("y")); !errors.Is(err, ErrInvalidStoreRequest) {
		t.Fatalf("zero-generation CompareAndSwap() error = %v", err)
	}
	if _, err := control.CompareAndSwap(ctx, HarnessStateObjectName(), first.Generation, []byte("y")); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("absent CompareAndSwap() error = %v", err)
	}
	second, err := control.CompareAndSwap(ctx, lock, first.Generation, []byte(`{"state":"held"}`))
	if err != nil || second.Generation <= first.Generation {
		t.Fatalf("CompareAndSwap() = %#v, %v", second, err)
	}
	read, err := control.Read(ctx, lock)
	if err != nil || read.Descriptor != second || string(read.Content) != `{"state":"held"}` {
		t.Fatalf("Read() = %#v, %v", read, err)
	}
	if _, err := control.Read(ctx, HarnessStateObjectName()); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("absent Read() error = %v", err)
	}
	if _, err := control.Create(ctx, ControlObjectName{}, []byte("x")); !errors.Is(err, ErrInvalidStoreRequest) {
		t.Fatalf("zero-value name accepted: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := control.Read(cancelled, lock); !errors.Is(err, ErrInvalidStoreRequest) {
		t.Fatalf("cancelled context accepted: %v", err)
	}

	audit := NewMemoryAuditStore()
	name, _ := PlanObjectName("dev", fixturePlanID)
	created, err := audit.Create(ctx, name, []byte("plan"))
	if err != nil || created.Generation == 0 {
		t.Fatalf("audit Create() = %#v, %v", created, err)
	}
	if _, err := audit.Create(ctx, name, []byte("plan2")); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("audit overwrite error = %v", err)
	}
	object, err := audit.Read(ctx, name)
	if err != nil || string(object.Content) != "plan" || object.Descriptor != created {
		t.Fatalf("audit Read() = %#v, %v", object, err)
	}
	if got := audit.Names(); len(got) != 1 || got[0] != name.String() {
		t.Fatalf("audit names = %v", got)
	}
}

func TestMemoryControlStoreCompareAndSwapRaceHasExactlyOneWinner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryControlStore()
	lock, _ := LockObjectName("dev")
	base, err := store.Create(ctx, lock, []byte("released"))
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 32
	var wins, losses int
	var mutex sync.Mutex
	var group sync.WaitGroup
	for index := 0; index < contenders; index++ {
		group.Add(1)
		go func(holder int) {
			defer group.Done()
			_, err := store.CompareAndSwap(ctx, lock, base.Generation, []byte{byte(holder)})
			mutex.Lock()
			defer mutex.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrPreconditionFailed):
				losses++
			default:
				t.Errorf("unexpected error %v", err)
			}
		}(index)
	}
	group.Wait()
	if wins != 1 || losses != contenders-1 {
		t.Fatalf("wins = %d, losses = %d", wins, losses)
	}
}

func TestObjectDescriptorNeverMatchesWithoutGeneration(t *testing.T) {
	t.Parallel()
	content := []byte("content")
	descriptor := DescribeContent(content)
	if descriptor.MatchesContent(content) {
		t.Fatal("descriptor without a generation matched")
	}
	descriptor.Generation = 7
	if !descriptor.MatchesContent(content) || descriptor.MatchesContent([]byte("content!")) {
		t.Fatal("descriptor matching is not exact")
	}
}
