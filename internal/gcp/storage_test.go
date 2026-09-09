// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/control"
	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/redact"
	"github.com/thelostorbital/ctrldb/internal/runner"
)

const (
	storageTestAccount = "operator@example.invalid"
	storageTestProject = "example-project"
	storageTestRegion  = "us-central1"
	storageTestAudit   = "example-project-ctrldb-audit"
	storageTestControl = "example-project-ctrldb-state"
	storageTestBinding = "d31f90cdb0354b17c102e948ef5b8ec579f97ff876ce03334714b146a719af7d"
)

var storageTestNow = time.Date(2026, 9, 9, 12, 5, 0, 0, time.UTC)

// gcloudStorageFake is an in-memory provider that answers the exact argv
// templates the adapter renders. It never accepts a delete verb.
type gcloudStorageFake struct {
	mutex       sync.Mutex
	calls       [][]string
	globalTaken map[string]bool
	buckets     map[string]*fakeBucket
	generation  int64
	failNext    map[string]int
}

type fakeBucket struct {
	project  string
	state    map[string]any
	objects  map[string]fakeStoredObject
	bindings []control.BucketBinding
}

type fakeStoredObject struct {
	generation int64
	content    []byte
}

func newGcloudStorageFake() *gcloudStorageFake {
	return &gcloudStorageFake{globalTaken: map[string]bool{}, buckets: map[string]*fakeBucket{}, failNext: map[string]int{}}
}

func (fake *gcloudStorageFake) Run(_ context.Context, request runner.Request) (runner.Result, error) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	args := append([]string(nil), request.Arguments...)
	fake.calls = append(fake.calls, args)
	joined := strings.Join(args, " ")
	for _, forbidden := range []string{" delete", " rm ", " rb ", "remove-iam-policy-binding --all", "--clear-", "--no-"} {
		if strings.Contains(joined, forbidden) {
			return runner.Result{ExitCode: 99}, errors.New("fake: forbidden verb reached the provider: " + joined)
		}
	}
	if !strings.Contains(joined, "--account="+storageTestAccount) || !strings.Contains(joined, "--project="+storageTestProject) ||
		!strings.Contains(joined, "--quiet") || !strings.Contains(joined, "--verbosity=error") {
		return runner.Result{ExitCode: 98}, errors.New("fake: missing explicit identity/project globals: " + joined)
	}
	key := strings.Join(args[:3], " ")
	if strings.HasPrefix(joined, "storage cp") {
		key = "storage cp"
	}
	if strings.HasPrefix(joined, "storage cat") {
		key = "storage cat"
	}
	if fake.failNext[key] > 0 {
		fake.failNext[key]--
		return runner.Result{ExitCode: 1, Stderr: redact.Sanitize("ERROR: synthetic provider failure")}, &processFailure{kind: processFailureExit, exitCode: 1}
	}
	switch {
	case key == "storage buckets list":
		return fake.bucketsList(args)
	case key == "storage buckets create":
		return fake.bucketsCreate(args)
	case key == "storage buckets update":
		return fake.bucketsUpdate(args)
	case key == "storage cp":
		return fake.cp(args)
	case key == "storage objects list":
		return fake.objectsList(args)
	case key == "storage cat":
		return fake.cat(args)
	case strings.HasPrefix(key, "storage buckets get-iam-policy"):
		return fake.getIAM(args)
	case strings.HasPrefix(key, "storage buckets add-iam-policy-binding"), strings.HasPrefix(key, "storage buckets remove-iam-policy-binding"):
		return fake.changeIAM(args)
	}
	return runner.Result{ExitCode: 2}, errors.New("fake: unknown command " + joined)
}

func flag(args []string, name string) (string, bool) {
	for _, arg := range args {
		if strings.HasPrefix(arg, name+"=") {
			return strings.TrimPrefix(arg, name+"="), true
		}
		if arg == name {
			return "", true
		}
	}
	return "", false
}

func okJSON(value any) (runner.Result, error) {
	encoded, _ := json.Marshal(value)
	return runner.Result{ExitCode: 0, Stdout: encoded, Stderr: redact.Sanitize("")}, nil
}

func failure(message string) (runner.Result, error) {
	return runner.Result{ExitCode: 1, Stderr: redact.Sanitize(message)}, &processFailure{kind: processFailureExit, exitCode: 1}
}

func (fake *gcloudStorageFake) bucketsList(args []string) (runner.Result, error) {
	name, _ := flag(args, "--filter")
	name = strings.TrimPrefix(name, "name=")
	bucket := fake.buckets[name]
	if bucket == nil || bucket.project != storageTestProject {
		return okJSON([]any{})
	}
	return okJSON([]any{bucket.state})
}

func (fake *gcloudStorageFake) bucketsCreate(args []string) (runner.Result, error) {
	name := strings.TrimPrefix(args[3], "gs://")
	if fake.globalTaken[name] || fake.buckets[name] != nil {
		return failure("ERROR: (gcloud.storage.buckets.create) HTTPError 409: The requested bucket name is not available.")
	}
	location, _ := flag(args, "--location")
	class, _ := flag(args, "--default-storage-class")
	_, ubla := flag(args, "--uniform-bucket-level-access")
	_, pap := flag(args, "--public-access-prevention")
	state := map[string]any{
		"name": name, "location": strings.ToUpper(location), "metageneration": 1, "creation_time": "2026-09-09T12:05:00+0000",
		"default_storage_class": class, "uniform_bucket_level_access": ubla,
	}
	if pap {
		state["public_access_prevention"] = "enforced"
	} else {
		state["public_access_prevention"] = "inherited"
	}
	if softDelete, ok := flag(args, "--soft-delete-duration"); ok {
		state["soft_delete_policy"] = map[string]any{"retentionDurationSeconds": strings.TrimSuffix(softDelete, "s"), "effectiveTime": "2026-09-09T12:05:00.000000+00:00"}
	}
	fake.buckets[name] = &fakeBucket{project: storageTestProject, state: state, objects: map[string]fakeStoredObject{}}
	return okJSON(map[string]any{})
}

func (fake *gcloudStorageFake) bucketsUpdate(args []string) (runner.Result, error) {
	name := strings.TrimPrefix(args[3], "gs://")
	bucket := fake.buckets[name]
	if bucket == nil {
		return failure("ERROR: NotFoundException 404")
	}
	bump := func() { bucket.state["metageneration"] = bucket.state["metageneration"].(int) + 1 }
	if _, ok := flag(args, "--versioning"); ok {
		bucket.state["versioning_enabled"] = true
		bump()
	}
	if path, ok := flag(args, "--lifecycle-file"); ok {
		content, err := os.ReadFile(path)
		if err != nil {
			return failure("ERROR: lifecycle file unreadable")
		}
		var lifecycle any
		if err := json.Unmarshal(content, &lifecycle); err != nil {
			return failure("ERROR: lifecycle file malformed")
		}
		bucket.state["lifecycle_config"] = lifecycle
		bump()
	}
	if period, ok := flag(args, "--retention-period"); ok {
		if locked, _ := bucket.state["retention_policy_is_locked"].(bool); locked {
			return failure("ERROR: retention policy is locked")
		}
		seconds, err := strconv.ParseInt(strings.TrimSuffix(period, "s"), 10, 64)
		if err != nil {
			return failure("ERROR: bad period")
		}
		bucket.state["retention_period"] = seconds
		bump()
	}
	if _, ok := flag(args, "--lock-retention-period"); ok {
		if _, has := bucket.state["retention_period"]; !has {
			return failure("ERROR: no retention period")
		}
		bucket.state["retention_policy_is_locked"] = true
		bump()
	}
	return okJSON(map[string]any{})
}

func (fake *gcloudStorageFake) cp(args []string) (runner.Result, error) {
	source := args[2]
	target := strings.TrimPrefix(args[3], "gs://")
	bucketName, object, _ := strings.Cut(target, "/")
	bucket := fake.buckets[bucketName]
	if bucket == nil {
		return failure("ERROR: NotFoundException 404 bucket")
	}
	expected, _ := flag(args, "--if-generation-match")
	want, err := strconv.ParseInt(expected, 10, 64)
	if err != nil {
		return failure("ERROR: bad precondition")
	}
	existing, exists := bucket.objects[object]
	if (want == 0 && exists) || (want != 0 && (!exists || existing.generation != want)) {
		return failure("ERROR: HTTPError 412: At least one of the pre-conditions you specified did not hold.")
	}
	content, err := os.ReadFile(source)
	if err != nil {
		return failure("ERROR: source unreadable")
	}
	fake.generation++
	bucket.objects[object] = fakeStoredObject{generation: fake.generation, content: append([]byte(nil), content...)}
	return okJSON(map[string]any{})
}

func objectJSON(bucket, name string, stored fakeStoredObject) map[string]any {
	sum := make([]byte, 4)
	binary.BigEndian.PutUint32(sum, crc32.Checksum(stored.content, crc32.MakeTable(crc32.Castagnoli)))
	return map[string]any{"bucket": bucket, "name": name, "generation": strconv.FormatInt(stored.generation, 10), "metageneration": 1,
		"size": len(stored.content), "crc32c_hash": base64.StdEncoding.EncodeToString(sum)}
}

func (fake *gcloudStorageFake) objectsList(args []string) (runner.Result, error) {
	target := strings.TrimPrefix(args[3], "gs://")
	bucketName, object, _ := strings.Cut(target, "/")
	bucket := fake.buckets[bucketName]
	if bucket == nil {
		return failure("ERROR: NotFoundException 404 bucket")
	}
	stored, exists := bucket.objects[object]
	if !exists {
		return okJSON([]any{})
	}
	return okJSON([]any{objectJSON(bucketName, object, stored)})
}

func (fake *gcloudStorageFake) cat(args []string) (runner.Result, error) {
	target := strings.TrimPrefix(args[2], "gs://")
	path, generation, pinned := strings.Cut(target, "#")
	if !pinned {
		return failure("fake: cat must pin a generation")
	}
	bucketName, object, _ := strings.Cut(path, "/")
	bucket := fake.buckets[bucketName]
	if bucket == nil {
		return failure("ERROR: NotFoundException 404 bucket")
	}
	stored, exists := bucket.objects[object]
	if !exists || strconv.FormatInt(stored.generation, 10) != generation {
		return failure("ERROR: NotFoundException 404 object generation")
	}
	return runner.Result{ExitCode: 0, Stdout: append([]byte(nil), stored.content...), Stderr: redact.Sanitize("")}, nil
}

func (fake *gcloudStorageFake) getIAM(args []string) (runner.Result, error) {
	name := strings.TrimPrefix(args[3], "gs://")
	bucket := fake.buckets[name]
	if bucket == nil {
		return failure("ERROR: NotFoundException 404")
	}
	bindings := make([]any, 0)
	for _, item := range bucket.bindings {
		bindings = append(bindings, map[string]any{"role": item.Role, "members": []string{item.Member},
			"condition": map[string]any{"expression": item.ConditionExpression, "title": item.ConditionTitle}})
	}
	return okJSON(map[string]any{"bindings": bindings, "etag": "BwY="})
}

func (fake *gcloudStorageFake) changeIAM(args []string) (runner.Result, error) {
	name := strings.TrimPrefix(args[3], "gs://")
	bucket := fake.buckets[name]
	if bucket == nil {
		return failure("ERROR: NotFoundException 404")
	}
	member, _ := flag(args, "--member")
	role, _ := flag(args, "--role")
	condition, _ := flag(args, "--condition")
	expression := strings.TrimPrefix(strings.SplitN(condition, ",title=", 2)[0], "expression=")
	title := strings.SplitN(condition, ",title=", 2)[1]
	item := control.BucketBinding{Bucket: name, Role: role, Member: member, Prefix: control.PrefixFromCondition(name, expression), ConditionTitle: title, ConditionExpression: expression}
	if args[2] == "add-iam-policy-binding" {
		bucket.bindings = append(bucket.bindings, item)
	} else {
		kept := bucket.bindings[:0]
		for _, existing := range bucket.bindings {
			if existing != item {
				kept = append(kept, existing)
			}
		}
		bucket.bindings = kept
	}
	return okJSON(map[string]any{})
}

func (fake *gcloudStorageFake) argv() []string {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	result := make([]string, len(fake.calls))
	for index, call := range fake.calls {
		result[index] = strings.Join(call, " ")
	}
	return result
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func testStorageClient(t *testing.T) (*StorageClient, *gcloudStorageFake) {
	t.Helper()
	client, err := NewStorageClient(StorageClientOptions{
		GcloudPath: readHelperExecutable(t), SearchPath: "/usr/bin:/bin", Home: t.TempDir(), CloudSDKConfig: t.TempDir(),
		Locale: "C.UTF-8", CommandTimeout: 5 * time.Second, WorkDirectory: privateTempDir(t), Clock: func() time.Time { return storageTestNow },
	})
	if err != nil {
		t.Fatalf("NewStorageClient() error = %v", err)
	}
	fake := newGcloudStorageFake()
	client.boundary = fake
	return client, fake
}

func storageIntent(stepID string, kind bootstrap.IntentKind, resourceIDs ...string) bootstrap.StepIntent {
	return bootstrap.StepIntent{StepID: stepID, Kind: kind, EnvelopeBindingSHA256: storageTestBinding, ExecutingIdentity: domain.IdentityHuman,
		ResourceIDs: resourceIDs, Retry: domain.RetryPolicy{MaxAttempts: 3, InitialBackoffSeconds: 2, MaxBackoffSeconds: 10}, TimeoutSeconds: 120, CancelSafe: true}
}

func storageResource(id, name string) bootstrap.DesiredResource {
	return bootstrap.DesiredResource{ID: id, Kind: bootstrap.ResourceBucket, Name: name, Project: storageTestProject, Location: storageTestRegion,
		ProviderID: "projects/" + storageTestProject + "/global/storage.bucket/" + name, Permanence: bootstrap.PermanentSingleton,
		DesiredStateFingerprint: strings.Repeat("e", 64)}
}

func validStorageAuthorization(stepID string) StorageMutationAuthorization {
	return StorageMutationAuthorization{
		PlanDocumentSHA256: strings.Repeat("a", 64), PlanV1Hash: strings.Repeat("b", 64), EnvelopeBindingSHA256: storageTestBinding,
		OperationID: "op-0123456789abcdef", StepID: stepID, Attempt: 1, ClaimGeneration: 7, ExecutingIdentity: domain.IdentityHuman,
		ObservationRevision: strings.Repeat("c", 64), ObservedAt: storageTestNow.Add(-time.Minute), ValidUntil: storageTestNow.Add(4 * time.Minute), Now: storageTestNow,
	}
}

func storageTarget(t *testing.T) StorageTarget {
	t.Helper()
	return StorageTarget{Account: storageTestAccount, Configuration: validHarnessConfiguration(t)}
}

func auditIdentity() control.BucketIdentity {
	return control.BucketIdentity{Name: storageTestAudit, Project: storageTestProject, Location: storageTestRegion}
}

func controlIdentity() control.BucketIdentity {
	return control.BucketIdentity{Name: storageTestControl, Project: storageTestProject, Location: storageTestRegion}
}

func TestStorageAuthorizeFailsClosedBeforeAnyProcess(t *testing.T) {
	t.Parallel()
	client, fake := testStorageClient(t)
	target := storageTarget(t)
	base := validStorageAuthorization("k1-audit-bootstrap")
	intent := storageIntent("k1-audit-bootstrap", bootstrap.IntentAuditBootstrap, "audit-bucket")
	resources := []bootstrap.DesiredResource{storageResource("audit-bucket", storageTestAudit)}
	tests := []struct {
		name string
		auth func(a *StorageMutationAuthorization)
		want StorageFailureKind
	}{
		{"missing plan hash", func(a *StorageMutationAuthorization) { a.PlanDocumentSHA256 = "" }, StorageFailureUnauthorized},
		{"binding mismatch", func(a *StorageMutationAuthorization) { a.EnvelopeBindingSHA256 = strings.Repeat("f", 64) }, StorageFailureUnauthorized},
		{"step mismatch", func(a *StorageMutationAuthorization) { a.StepID = "k2-control-bucket" }, StorageFailureUnauthorized},
		{"zero attempt", func(a *StorageMutationAuthorization) { a.Attempt = 0 }, StorageFailureUnauthorized},
		{"attempt beyond retry", func(a *StorageMutationAuthorization) { a.Attempt = 4 }, StorageFailureUnauthorized},
		{"zero claim generation", func(a *StorageMutationAuthorization) { a.ClaimGeneration = 0 }, StorageFailureUnauthorized},
		{"wrong identity", func(a *StorageMutationAuthorization) { a.ExecutingIdentity = domain.IdentityOperator }, StorageFailureIdentity},
		{"stale", func(a *StorageMutationAuthorization) { a.Now = a.ValidUntil }, StorageFailureUnauthorized},
		{"before observation", func(a *StorageMutationAuthorization) { a.Now = a.ObservedAt.Add(-time.Second) }, StorageFailureUnauthorized},
		{"non-UTC", func(a *StorageMutationAuthorization) { a.Now = a.Now.In(time.FixedZone("X", 3600)) }, StorageFailureUnauthorized},
		{"bad operation id", func(a *StorageMutationAuthorization) { a.OperationID = "op-x" }, StorageFailureUnauthorized},
	}
	for _, test := range tests {
		auth := base
		test.auth(&auth)
		_, err := client.Authorize(auth, intent, resources, target)
		var failure *StorageError
		if !errors.As(err, &failure) || failure.Kind() != test.want || !errors.Is(err, ErrStorageRejected) {
			t.Fatalf("%s: error = %v, want %s", test.name, err, test.want)
		}
	}
	// Intent and resource refusals.
	networkIntent := storageIntent("t1-network", bootstrap.IntentNetwork, "test-network")
	if _, err := client.Authorize(validStorageAuthorization("t1-network"), networkIntent, resources, target); err == nil {
		t.Fatal("network intent accepted by the storage adapter")
	}
	t6 := storageIntent("t6-control-prefix", bootstrap.IntentControlPrefix, "control-bucket")
	if _, err := client.Authorize(validStorageAuthorization("t6-control-prefix"), t6, []bootstrap.DesiredResource{storageResource("control-bucket", storageTestControl)}, target); err == nil {
		t.Fatal("non-K intent accepted by the storage adapter")
	}
	mismatchedKind := intent
	mismatchedKind.Kind = bootstrap.IntentControlBucket
	if _, err := client.Authorize(base, mismatchedKind, resources, target); err == nil {
		t.Fatal("step/kind mismatch accepted")
	}
	foreignName := []bootstrap.DesiredResource{storageResource("audit-bucket", "someone-elses-audit-bucket")}
	if _, err := client.Authorize(base, intent, foreignName, target); err == nil {
		t.Fatal("unapproved bucket name accepted")
	}
	foreignProject := resources[0]
	foreignProject.Project = "other-project"
	foreignProject.ProviderID = "projects/other-project/global/storage.bucket/" + storageTestAudit
	if _, err := client.Authorize(base, intent, []bootstrap.DesiredResource{foreignProject}, target); err == nil {
		t.Fatal("cross-project resource accepted")
	}
	if _, err := client.Authorize(base, intent, nil, target); err == nil {
		t.Fatal("empty resource set accepted")
	}
	if _, err := client.Authorize(base, intent, resources, StorageTarget{Account: "not an account", Configuration: target.Configuration}); err == nil {
		t.Fatal("malformed account accepted")
	}
	if len(fake.argv()) != 0 {
		t.Fatalf("a refused authorization reached the provider: %v", fake.argv())
	}

	// A valid session still refuses operations outside its intent and buckets.
	session, err := client.Authorize(base, intent, resources, target)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	ctx := context.Background()
	if err := session.LockRetention(ctx, auditIdentity(), 1); err == nil {
		t.Fatal("K1a session locked retention")
	}
	if err := session.CreateControlBucket(ctx, controlIdentity()); err == nil {
		t.Fatal("K1a session created the control bucket")
	}
	if _, _, err := session.DescribeBucket(ctx, storageTestControl); err == nil {
		t.Fatal("K1a session observed a bucket outside its resources")
	}
	if len(fake.argv()) != 0 {
		t.Fatalf("a refused operation reached the provider: %v", fake.argv())
	}
}

func TestStorageSessionDrivesTheAuditHandoffEndToEnd(t *testing.T) {
	t.Parallel()
	client, fake := testStorageClient(t)
	target := storageTarget(t)
	k1a, err := client.Authorize(validStorageAuthorization("k1-audit-bootstrap"), storageIntent("k1-audit-bootstrap", bootstrap.IntentAuditBootstrap, "audit-bucket"),
		[]bootstrap.DesiredResource{storageResource("audit-bucket", storageTestAudit)}, target)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := control.NewStateDirectory(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	envelope := storageTestEnvelope(t)
	ticks := storageTestNow
	clock := func() time.Time { ticks = ticks.Add(time.Second); return ticks }
	handoff, err := control.NewAuditHandoff(directory, k1a, clock)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	status, err := handoff.Bootstrap(ctx, envelope)
	if err != nil || status.Phase != control.PhaseHandoffVerified || status.Envelope.Generation == 0 {
		t.Fatalf("Bootstrap() = %#v, %v", status, err)
	}
	argv := fake.argv()
	// Describe precedes create; create is followed by a describe (post-create equality).
	index := func(prefix string) int {
		for position, line := range argv {
			if strings.HasPrefix(line, prefix) {
				return position
			}
		}
		return -1
	}
	if index("storage buckets list --filter=name="+storageTestAudit) > index("storage buckets create gs://"+storageTestAudit) || index("storage buckets create") < 0 {
		t.Fatalf("describe-before-create violated: %v", argv)
	}
	create := argv[index("storage buckets create")]
	for _, want := range []string{"--location=" + storageTestRegion, "--uniform-bucket-level-access", "--public-access-prevention", "--default-storage-class=STANDARD", "--project=" + storageTestProject} {
		if !strings.Contains(create, want) {
			t.Fatalf("create argv lacks %q: %s", want, create)
		}
	}
	if index("storage cp") < 0 || !strings.Contains(argv[index("storage cp")], "--if-generation-match=0") {
		t.Fatalf("uploads are not create-only: %v", argv)
	}
	if index("storage buckets update gs://"+storageTestAudit+" --lock-retention-period") >= 0 {
		t.Fatalf("K1a locked retention: %v", argv)
	}

	// K1b: verification (objects list + cat + bucket list) precedes the lock.
	k1b, err := client.Authorize(validStorageAuthorization("k1-retention-lock"), storageIntent("k1-retention-lock", bootstrap.IntentAuditRetention, "audit-bucket"),
		[]bootstrap.DesiredResource{storageResource("audit-bucket", storageTestAudit)}, target)
	if err != nil {
		t.Fatal(err)
	}
	lockHandoff, _ := control.NewAuditHandoff(directory, k1b, clock)
	before := len(fake.argv())
	locked, err := lockHandoff.LockRetention(ctx, envelope)
	if err != nil || !locked.RetentionLocked {
		t.Fatalf("LockRetention() = %#v, %v", locked, err)
	}
	tail := fake.argv()[before:]
	lockAt, catAt, retentionAt := -1, -1, -1
	for position, line := range tail {
		switch {
		case strings.Contains(line, "--lock-retention-period"):
			lockAt = position
		case strings.HasPrefix(line, "storage cat") && catAt < 0:
			catAt = position
		case strings.Contains(line, "--retention-period=31536000s"):
			retentionAt = position
		}
	}
	locks := 0
	for _, line := range tail {
		if strings.Contains(line, "--lock-retention-period") {
			locks++
		}
	}
	// Byte verification and retention configuration precede the single lock
	// call, which is immediately preceded by a fresh bucket observation and
	// followed by the post-lock verification.
	if lockAt < 0 || catAt < 0 || retentionAt < 0 || catAt > lockAt || retentionAt > lockAt || locks != 1 ||
		!strings.HasPrefix(tail[lockAt-1], "storage buckets list") || lockAt == len(tail)-1 {
		t.Fatalf("lock ordering: cat=%d retention=%d lock=%d of %d: %v", catAt, retentionAt, lockAt, len(tail), tail)
	}
	state := fake.buckets[storageTestAudit].state
	if state["retention_policy_is_locked"] != true || state["retention_period"] != int64(31536000) || state["versioning_enabled"] != true {
		t.Fatalf("final audit bucket = %v", state)
	}
	for _, line := range fake.argv() {
		if strings.Contains(line, storageTestControl) {
			t.Fatalf("audit steps touched the control bucket: %s", line)
		}
	}
}

func TestStorageCreateConflictIsAnExplicitPreconditionFailureNeverAbsence(t *testing.T) {
	t.Parallel()
	client, fake := testStorageClient(t)
	fake.globalTaken[storageTestAudit] = true
	session, err := client.Authorize(validStorageAuthorization("k1-audit-bootstrap"), storageIntent("k1-audit-bootstrap", bootstrap.IntentAuditBootstrap, "audit-bucket"),
		[]bootstrap.DesiredResource{storageResource("audit-bucket", storageTestAudit)}, storageTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, exists, err := session.DescribeBucket(ctx, storageTestAudit)
	if err != nil || exists {
		t.Fatalf("describe = %v, %v", exists, err)
	}
	err = session.CreateAuditBucket(ctx, auditIdentity())
	var failure *StorageError
	// gcloud exposes no machine-readable conflict signal, so the refusal is
	// reported as the process failure with sanitized diagnostics: it blocks,
	// it is never relabelled as a name conflict, and it never claims absence.
	if !errors.As(err, &failure) || failure.Kind() != StorageFailureProcess || !errors.Is(err, ErrStorageRejected) ||
		errors.Is(err, control.ErrBucketNameConflict) || errors.Is(err, control.ErrObjectNotFound) {
		t.Fatalf("create refusal error = %v", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "absent") || strings.Contains(strings.ToLower(err.Error()), "not found") {
		t.Fatalf("refusal error claims absence: %v", err)
	}
	if failure.Diagnostics().String() == "" {
		t.Fatal("sanitized diagnostics were dropped")
	}
	argv := fake.argv()
	if len(argv) != 4 || !strings.HasPrefix(argv[1], "storage buckets list") || !strings.HasPrefix(argv[2], "storage buckets create") || !strings.HasPrefix(argv[3], "storage buckets list") {
		t.Fatalf("create path argv = %v", fake.argv())
	}

	// A project-local bucket is a positive collision (precondition) and the
	// create is never rendered.
	local := newGcloudStorageFake()
	local.buckets[storageTestAudit] = &fakeBucket{project: storageTestProject, objects: map[string]fakeStoredObject{},
		state: map[string]any{"name": storageTestAudit, "location": "US-CENTRAL1", "metageneration": 1, "creation_time": "2026-09-09T12:05:00+0000",
			"default_storage_class": "STANDARD", "uniform_bucket_level_access": true, "public_access_prevention": "enforced"}}
	client.boundary = local
	err = session.CreateAuditBucket(ctx, auditIdentity())
	if !errors.As(err, &failure) || failure.Kind() != StorageFailurePrecondition || !errors.Is(err, control.ErrPreconditionFailed) {
		t.Fatalf("local collision error = %v", err)
	}
	for _, line := range local.argv() {
		if strings.HasPrefix(line, "storage buckets create") {
			t.Fatalf("create rendered over an existing bucket: %v", local.argv())
		}
	}
}

func TestStorageSessionUsesTheTrustedClockAndRefusesRetainedSessions(t *testing.T) {
	t.Parallel()
	client, fake := testStorageClient(t)
	current := storageTestNow
	client.clock = func() time.Time { return current }
	target := storageTarget(t)
	intent := storageIntent("k2-control-bucket", bootstrap.IntentControlBucket, "control-bucket")
	resources := []bootstrap.DesiredResource{storageResource("control-bucket", storageTestControl)}
	// The caller's Now inside the window does not help when the trusted clock is past it.
	current = storageTestNow.Add(10 * time.Minute)
	if _, err := client.Authorize(validStorageAuthorization("k2-control-bucket"), intent, resources, target); err == nil {
		t.Fatal("expired authorization accepted on the trusted clock")
	}
	current = storageTestNow
	session, err := client.Authorize(validStorageAuthorization("k2-control-bucket"), intent, resources, target)
	if err != nil {
		t.Fatal(err)
	}
	// A retained session is refused at the next mutation once the window passes.
	current = storageTestNow.Add(4*time.Minute + 30*time.Second)
	err = session.CreateControlBucket(context.Background(), controlIdentity())
	var failure *StorageError
	if !errors.As(err, &failure) || failure.Kind() != StorageFailureUnauthorized {
		t.Fatalf("retained session error = %v", err)
	}
	for _, line := range fake.argv() {
		if strings.HasPrefix(line, "storage buckets create") || strings.HasPrefix(line, "storage buckets update") {
			t.Fatalf("stale session mutated: %v", fake.argv())
		}
	}
}

func TestStorageControlBucketAndIAMAndCAS(t *testing.T) {
	t.Parallel()
	client, fake := testStorageClient(t)
	target := storageTarget(t)
	ctx := context.Background()
	k2, err := client.Authorize(validStorageAuthorization("k2-control-bucket"), storageIntent("k2-control-bucket", bootstrap.IntentControlBucket, "control-bucket"),
		[]bootstrap.DesiredResource{storageResource("control-bucket", storageTestControl)}, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := k2.CreateAuditBucket(ctx, auditIdentity()); err == nil {
		t.Fatal("K2 session created the audit bucket")
	}
	if err := k2.CreateControlBucket(ctx, auditIdentity()); err == nil {
		t.Fatal("K2 session accepted the audit identity for the control bucket")
	}
	if err := k2.CreateControlBucket(ctx, controlIdentity()); err != nil {
		t.Fatalf("CreateControlBucket() error = %v", err)
	}
	state, exists, err := k2.DescribeBucket(ctx, storageTestControl)
	if err != nil || !exists || !state.Versioning || !state.UniformBucketLevelAccess || state.PublicAccessPrevention != "enforced" || state.Identity != controlIdentity() || state.SoftDeleteSeconds != 2592000 {
		t.Fatalf("control bucket state = %#v, %v, %v", state, exists, err)
	}
	if !strings.Contains(strings.Join(fake.argv(), "\n"), "--soft-delete-duration=2592000s") {
		t.Fatalf("control bucket create lacks 30-day soft delete: %v", fake.argv())
	}

	fake.buckets[storageTestAudit] = &fakeBucket{project: storageTestProject, objects: map[string]fakeStoredObject{},
		state: map[string]any{"name": storageTestAudit, "location": "US-CENTRAL1", "metageneration": 1, "creation_time": "2026-09-09T12:05:00+0000",
			"default_storage_class": "STANDARD", "uniform_bucket_level_access": true, "public_access_prevention": "enforced", "versioning_enabled": true}}
	k3, err := client.Authorize(validStorageAuthorization("k3-bucket-iam"), storageIntent("k3-bucket-iam", bootstrap.IntentBucketIAM, "audit-bucket", "control-bucket"),
		[]bootstrap.DesiredResource{storageResource("audit-bucket", storageTestAudit), storageResource("control-bucket", storageTestControl)}, target)
	if err != nil {
		t.Fatal(err)
	}
	desired := bootstrap.HarnessDesiredState{AuditBucket: storageTestAudit, ControlBucket: storageTestControl,
		OperatorPrincipal: "ctrldb-test-operator@example-project.iam.gserviceaccount.com", DestructivePrincipal: "ctrldb-test-destructive@example-project.iam.gserviceaccount.com",
		VMPrincipal: "ctrldb-test-vm@example-project.iam.gserviceaccount.com", WipePrincipal: "ctrldb-test-wipe@example-project.iam.gserviceaccount.com"}
	policy, err := control.RenderBucketPolicy("k3-bucket-iam", desired)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range policy.Bindings {
		identity := auditIdentity()
		if item.Bucket == storageTestControl {
			identity = controlIdentity()
		}
		if err := k3.AddBinding(ctx, identity, item); err != nil {
			t.Fatalf("AddBinding(%v) error = %v", item, err)
		}
	}
	observed, err := k3.GetBindings(ctx, auditIdentity())
	if err != nil || len(observed) != 5 {
		t.Fatalf("GetBindings() = %v, %v", observed, err)
	}
	for _, item := range observed {
		if item.Prefix != control.TestPrefix || control.ValidateBucketBindingShape(item, storageTestAudit, storageTestControl) != nil {
			t.Fatalf("observed binding is not resource-scoped: %#v", item)
		}
	}
	unscoped := policy.Bindings[0]
	unscoped.ConditionExpression = `resource.type == "storage.googleapis.com/Object"`
	if err := k3.AddBinding(ctx, auditIdentity(), unscoped); err == nil {
		t.Fatal("bucket-wide binding rendered")
	}
	foreignMember := control.BucketBinding{Bucket: storageTestAudit, Role: control.RoleObjectViewer, Member: "serviceAccount:intruder@other-project.iam.gserviceaccount.com", Prefix: control.TestPrefix}
	foreignMember.ConditionTitle, foreignMember.ConditionExpression = policy.Bindings[0].ConditionTitle, policy.Bindings[0].ConditionExpression
	if err := k3.AddBinding(ctx, auditIdentity(), foreignMember); err == nil {
		t.Fatal("binding outside the rendered policy rendered")
	}
	auditUser := control.BucketBinding{Bucket: storageTestAudit, Role: control.RoleObjectUser, Member: policy.Bindings[0].Member, Prefix: control.TestPrefix}
	auditUser.ConditionTitle = "ctrldb-test-objectUser"
	auditUser.ConditionExpression = policy.Bindings[0].ConditionExpression
	if err := k3.AddBinding(ctx, auditIdentity(), auditUser); err == nil {
		t.Fatal("objectUser on the audit bucket rendered")
	}
	if err := k3.RemoveBinding(ctx, auditIdentity(), control.CompensationBindings(policy.Bindings, nil)[0]); err != nil {
		t.Fatalf("RemoveBinding() error = %v", err)
	}

	// K4/K5: create-only seed then generation-preconditioned CAS.
	k4, err := client.Authorize(validStorageAuthorization("k4-seed-control"), storageIntent("k4-seed-control", bootstrap.IntentSeedControl, "control-bucket"),
		[]bootstrap.DesiredResource{storageResource("control-bucket", storageTestControl)}, target)
	if err != nil {
		t.Fatal(err)
	}
	lockName, _ := control.LockObjectName("disposable-test")
	seeded, err := k4.UploadCreateOnly(ctx, controlIdentity(), control.AuditObjectName{}, []byte(`{"state":"released"}`))
	if err == nil {
		t.Fatalf("empty object name accepted: %#v", seeded)
	}
	seedContent := []byte(`{"state":"released"}`)
	k4Descriptor, err := k4.UploadControlCreateOnly(ctx, controlIdentity(), lockName, seedContent)
	if err != nil || !k4Descriptor.MatchesContent(seedContent) {
		t.Fatalf("UploadControlCreateOnly() = %#v, %v", k4Descriptor, err)
	}
	if _, err := k4.UploadControlCreateOnly(ctx, controlIdentity(), lockName, []byte(`{"state":"held"}`)); !errors.Is(err, control.ErrPreconditionFailed) {
		t.Fatalf("second create-only upload error = %v", err)
	}
	k5, err := client.Authorize(validStorageAuthorization("k5-lock-round-trip"), storageIntent("k5-lock-round-trip", bootstrap.IntentLockRoundTrip, "control-bucket"),
		[]bootstrap.DesiredResource{storageResource("control-bucket", storageTestControl)}, target)
	if err != nil {
		t.Fatal(err)
	}
	held, err := k5.UploadIfGenerationMatch(ctx, controlIdentity(), lockName, k4Descriptor.Generation, []byte(`{"state":"held"}`))
	if err != nil || held.Generation <= k4Descriptor.Generation {
		t.Fatalf("CAS acquire = %#v, %v", held, err)
	}
	if _, err := k5.UploadIfGenerationMatch(ctx, controlIdentity(), lockName, k4Descriptor.Generation, []byte(`{"state":"released"}`)); !errors.Is(err, control.ErrPreconditionFailed) {
		t.Fatalf("stale CAS error = %v", err)
	}
	if _, err := k5.UploadIfGenerationMatch(ctx, controlIdentity(), lockName, 0, []byte(`x`)); err == nil {
		t.Fatal("CAS with generation 0 accepted")
	}
	if _, err := k5.UploadIfGenerationMatch(ctx, controlIdentity(), control.HarnessStateObjectName(), held.Generation, []byte(`x`)); err == nil {
		t.Fatal("K5 CAS reached an object other than the approved lock")
	}
	if _, _, err := k5.DescribeControlObject(ctx, controlIdentity(), control.HarnessStateObjectName()); err == nil {
		t.Fatal("K5 observed an object other than the approved lock")
	}
	if _, err := k4.UploadControlCreateOnly(ctx, controlIdentity(), control.HarnessStateObjectName(), []byte(`x`)); err == nil {
		t.Fatal("K4 wrote an object outside the seed set")
	}
	content, descriptor, exists, err := k5.ReadControlObject(ctx, controlIdentity(), lockName)
	if err != nil || !exists || descriptor != held || string(content) != `{"state":"held"}` {
		t.Fatalf("ReadControlObject() = %s, %#v, %v, %v", content, descriptor, exists, err)
	}
	for _, line := range fake.argv() {
		lower := strings.ToLower(line)
		for _, forbidden := range []string{" delete", " rm ", " rb ", "--all"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("delete-class verb rendered: %s", line)
			}
		}
	}
	entries, _ := os.ReadDir(client.workDirectory)
	if len(entries) != 0 {
		t.Fatalf("work files were left behind: %v", entries)
	}
}

func TestStorageParsersFailClosedOnHostileOutput(t *testing.T) {
	t.Parallel()
	for name, input := range map[string]string{
		"two buckets":       `[{"name":"` + storageTestAudit + `","location":"US","metageneration":1,"creation_time":"2026-09-09T12:05:00+0000","default_storage_class":"STANDARD"},{"name":"` + storageTestAudit + `","location":"US","metageneration":1,"creation_time":"2026-09-09T12:05:00+0000","default_storage_class":"STANDARD"}]`,
		"wrong name":        `[{"name":"other","location":"US","metageneration":1,"creation_time":"2026-09-09T12:05:00+0000","default_storage_class":"STANDARD"}]`,
		"unknown key":       `[{"name":"` + storageTestAudit + `","location":"US","metageneration":1,"creation_time":"2026-09-09T12:05:00+0000","default_storage_class":"STANDARD","surprise":1}]`,
		"duplicate key":     `[{"name":"` + storageTestAudit + `","name":"` + storageTestAudit + `","location":"US","metageneration":1,"creation_time":"2026-09-09T12:05:00+0000","default_storage_class":"STANDARD"}]`,
		"delete lifecycle":  `[{"name":"` + storageTestAudit + `","location":"US","metageneration":1,"creation_time":"2026-09-09T12:05:00+0000","default_storage_class":"STANDARD","lifecycle_config":{"rule":[{"action":{"type":"Unknown"},"condition":{"age":1}}]}}]`,
		"null":              `null`,
		"trailing":          `[] {}`,
		"two archive rules": `[{"name":"` + storageTestAudit + `","location":"US","metageneration":1,"creation_time":"2026-09-09T12:05:00+0000","default_storage_class":"STANDARD","lifecycle_config":{"rule":[{"action":{"type":"SetStorageClass","storageClass":"ARCHIVE"},"condition":{"age":30}},{"action":{"type":"SetStorageClass","storageClass":"ARCHIVE"},"condition":{"age":365}}]}}]`,
		"bad soft delete":   `[{"name":"` + storageTestAudit + `","location":"US","metageneration":1,"creation_time":"2026-09-09T12:05:00+0000","default_storage_class":"STANDARD","soft_delete_policy":{"retentionDurationSeconds":"x"}}]`,
	} {
		if _, _, err := parseBucketState([]byte(input), storageTestAudit); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	state, exists, err := parseBucketState([]byte(`[{"name":"`+storageTestAudit+`","location":"US-CENTRAL1","metageneration":4,"creation_time":"2026-09-09T12:05:00+0000","default_storage_class":"STANDARD","uniform_bucket_level_access":true,"public_access_prevention":"enforced","versioning_enabled":true,"retention_period":31536000,"retention_policy_is_locked":true,"soft_delete_policy":{"retentionDurationSeconds":"2592000","effectiveTime":"2026-09-09T12:05:00.000000+00:00"},"lifecycle_config":{"rule":[{"action":{"type":"SetStorageClass","storageClass":"ARCHIVE"},"condition":{"age":365}},{"action":{"type":"Delete"},"condition":{"age":9}}]}}]`), storageTestAudit)
	if err != nil || !exists || state.Identity.Location != "us-central1" || state.RetentionSeconds != 31536000 || !state.RetentionLocked ||
		state.LifecycleArchiveAfterDay != 365 || !state.LifecycleDeleteRule || state.Metageneration != 4 || state.SoftDeleteSeconds != 2592000 || !state.TimeCreated.Equal(time.Date(2026, 9, 9, 12, 5, 0, 0, time.UTC)) {
		t.Fatalf("parsed = %#v, %v, %v", state, exists, err)
	}
	if _, exists, err := parseBucketState([]byte(`[]`), storageTestAudit); err != nil || exists {
		t.Fatalf("empty list = %v, %v", exists, err)
	}
	for name, input := range map[string]string{
		"wrong bucket": `[{"bucket":"other","name":"o","generation":"5","metageneration":1,"size":3,"crc32c_hash":"AAAAAA=="}]`,
		"bad crc":      `[{"bucket":"b","name":"o","generation":"5","metageneration":1,"size":3,"crc32c_hash":"zz"}]`,
		"zero gen":     `[{"bucket":"b","name":"o","generation":"0","metageneration":1,"size":3,"crc32c_hash":"AAAAAA=="}]`,
		"two objects":  `[{"bucket":"b","name":"o","generation":"5","metageneration":1,"size":3,"crc32c_hash":"AAAAAA=="},{"bucket":"b","name":"o","generation":"6","metageneration":1,"size":3,"crc32c_hash":"AAAAAA=="}]`,
	} {
		if _, _, err := parseObjectDescriptor([]byte(input), "b", "o"); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestStorageClientRejectsUnsafeOptions(t *testing.T) {
	t.Parallel()
	shared := t.TempDir()
	_ = os.Chmod(shared, 0o755)
	base := StorageClientOptions{GcloudPath: readHelperExecutable(t), SearchPath: "/usr/bin:/bin", Home: t.TempDir(), CloudSDKConfig: t.TempDir(),
		Locale: "C.UTF-8", CommandTimeout: time.Second, WorkDirectory: privateTempDir(t), Clock: func() time.Time { return storageTestNow }}
	for name, mutate := range map[string]func(*StorageClientOptions){
		"no clock":         func(o *StorageClientOptions) { o.Clock = nil },
		"long timeout":     func(o *StorageClientOptions) { o.CommandTimeout = time.Hour },
		"locale":           func(o *StorageClientOptions) { o.Locale = "fr_FR" },
		"shared work dir":  func(o *StorageClientOptions) { o.WorkDirectory = shared },
		"relative workdir": func(o *StorageClientOptions) { o.WorkDirectory = "work" },
		"not gcloud":       func(o *StorageClientOptions) { o.GcloudPath = "/bin/sh" },
	} {
		options := base
		mutate(&options)
		if _, err := NewStorageClient(options); !errors.Is(err, ErrStorageRejected) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}

func storageTestEnvelope(t *testing.T) control.BootstrapEnvelopeV1 {
	t.Helper()
	// Reuse the compiler through a fixture plan identical to control's tests.
	plan := storageFixturePlan(t)
	approval, err := control.NewApprovalProof(plan, storageTestAccount, storageTestNow.Add(-2*time.Minute), storageTestNow.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := control.SealBootstrapEnvelope(control.EnvelopeSeed{
		Plan: plan, OperationID: "op-0123456789abcdef", Approval: approval,
		FirstJournalEntry: domain.JournalEntry{Schema: domain.JournalSchemaV1, OperationID: "op-0123456789abcdef", PlanID: plan.Plan().PlanID,
			ContractHash: plan.ExecutionContract().Digest(), Sequence: 1, Kind: domain.JournalEntryTransition, RecordedAt: storageTestNow.Add(-time.Minute), OperationState: domain.OperationDiscover},
		SealedAt: storageTestNow.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("SealBootstrapEnvelope() error = %v", err)
	}
	return envelope
}
