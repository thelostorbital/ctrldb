// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/redact"
	"github.com/thelostorbital/ctrldb/internal/runner"
)

const (
	testBindingSHA   = "1111111111111111111111111111111111111111111111111111111111111111"
	testPlanSHA      = "2222222222222222222222222222222222222222222222222222222222222222"
	testPlanV1SHA    = "3333333333333333333333333333333333333333333333333333333333333333"
	testObservation  = "4444444444444444444444444444444444444444444444444444444444444444"
	testOperationID  = "op-0123456789abcdef"
	testIAMGcloud    = "/opt/ctrldb-test/gcloud"
	testProject      = "example-project"
	testRolePreEtag  = "role-etag-1"
	testPolicyPrefix = "policy-etag-"
)

// iamSimulator is a package-owned fake of the IAM surface the client
// renders. It reads documents from the paths in argv, enforces etags, and
// counts every mutation so tests can prove that rejected requests mutate
// nothing. It is not a production injection point: IAMClient's runner field
// is unexported and NewIAMClient always seals the process boundary.
type iamSimulator struct {
	t             *testing.T
	accounts      map[string]string
	keys          map[string]int
	roles         map[string]iamSimulatedRole
	policies      map[string]iamSimulatedPolicy
	calls         []string
	mutations     int
	conflictOnce  bool
	failCommand   string
	policyCounter int
}

type iamSimulatedRole struct {
	document iamRoleDocument
	etag     int
	deleted  bool
}

type iamSimulatedPolicy struct {
	bindings []iamPolicyBindingDocument
	etag     string
}

func newIAMSimulator(t *testing.T) *iamSimulator {
	t.Helper()
	return &iamSimulator{t: t, accounts: map[string]string{}, keys: map[string]int{}, roles: map[string]iamSimulatedRole{}, policies: map[string]iamSimulatedPolicy{}}
}

func (simulator *iamSimulator) policy(resource string) iamSimulatedPolicy {
	policy, ok := simulator.policies[resource]
	if !ok {
		simulator.policyCounter++
		policy = iamSimulatedPolicy{etag: testPolicyPrefix + strconv.Itoa(simulator.policyCounter)}
		simulator.policies[resource] = policy
	}
	return policy
}

func (simulator *iamSimulator) bumpPolicy(resource string, bindings []iamPolicyBindingDocument) {
	simulator.policyCounter++
	simulator.policies[resource] = iamSimulatedPolicy{bindings: bindings, etag: testPolicyPrefix + strconv.Itoa(simulator.policyCounter)}
}

func (simulator *iamSimulator) Run(_ context.Context, request runner.Request) (runner.Result, error) {
	if request.Executable != testIAMGcloud {
		simulator.t.Fatalf("unexpected executable %q", request.Executable)
	}
	line := strings.Join(request.Arguments, " ")
	simulator.calls = append(simulator.calls, line)
	if !strings.Contains(line, "--account="+testHumanAccount) || !strings.Contains(line, "--project="+testProject) ||
		!strings.Contains(line, "--quiet --verbosity=error") {
		simulator.t.Fatalf("command lacks explicit identity/project/quiet flags: %s", line)
	}
	for _, forbidden := range []string{"keys create", "keys upload", "--impersonate-service-account", "alpha ", "beta ", "add-iam-policy-binding", "remove-iam-policy-binding", "print-access-token", "--async"} {
		if strings.Contains(line, forbidden) {
			simulator.t.Fatalf("command admitted forbidden token %q: %s", forbidden, line)
		}
	}
	key := strings.Join(request.Arguments[:iamSimulatorVerbLength(request.Arguments)], " ")
	if simulator.failCommand != "" && strings.HasPrefix(key, simulator.failCommand) {
		return runner.Result{ExitCode: 1, Stderr: redact.Sanitize("simulated failure")}, &processFailure{kind: processFailureExit, exitCode: 1}
	}
	output, err := simulator.dispatch(key, request.Arguments)
	if err != nil {
		return runner.Result{ExitCode: 1, Stderr: redact.Sanitize(err.Error())}, &processFailure{kind: processFailureExit, exitCode: 1}
	}
	return runner.Result{Stdout: []byte(output)}, nil
}

func iamSimulatorVerbLength(arguments []string) int {
	if arguments[0] == "iam" {
		return 3
	}
	return 2
}

func (simulator *iamSimulator) dispatch(key string, arguments []string) (string, error) {
	switch key {
	case "iam service-accounts list":
		items := make([]string, 0, len(simulator.accounts))
		for email, uniqueID := range simulator.accounts {
			items = append(items, fmt.Sprintf(`{"email":%q,"projectId":%q,"uniqueId":%q}`, email, testProject, uniqueID))
		}
		return "[" + strings.Join(items, ",") + "]", nil
	case "iam service-accounts create":
		simulator.mutations++
		email := arguments[3] + "@" + testProject + ".iam.gserviceaccount.com"
		if _, exists := simulator.accounts[email]; exists {
			return "", errors.New("ALREADY_EXISTS")
		}
		simulator.accounts[email] = strconv.Itoa(100000000000000000 + len(simulator.accounts))
		return simulator.serviceAccountJSON(email), nil
	case "iam service-accounts describe":
		if _, exists := simulator.accounts[arguments[3]]; !exists {
			return "", errors.New("NOT_FOUND")
		}
		return simulator.serviceAccountJSON(arguments[3]), nil
	case "iam service-accounts keys":
		email := strings.TrimPrefix(arguments[4], "--iam-account=")
		items := make([]string, 0)
		for index := 0; index < simulator.keys[email]; index++ {
			items = append(items, fmt.Sprintf(`{"name":"projects/%s/serviceAccounts/%s/keys/%d","keyType":"USER_MANAGED"}`, testProject, email, index))
		}
		return "[" + strings.Join(items, ",") + "]", nil
	case "iam service-accounts delete":
		simulator.mutations++
		delete(simulator.accounts, arguments[3])
		return "{}", nil
	case "iam service-accounts get-iam-policy":
		return simulator.policyJSON(arguments[3]), nil
	case "iam service-accounts set-iam-policy":
		return simulator.setPolicy(arguments[3], arguments[4])
	case "projects get-iam-policy":
		return simulator.policyJSON("project"), nil
	case "projects set-iam-policy":
		return simulator.setPolicy("project", arguments[3])
	case "iam roles list":
		items := make([]string, 0, len(simulator.roles))
		for id, role := range simulator.roles {
			items = append(items, fmt.Sprintf(`{"name":%q,"deleted":%t}`, IAMCustomRoleName(testProject, id), role.deleted))
		}
		return "[" + strings.Join(items, ",") + "]", nil
	case "iam roles describe":
		return simulator.roleJSON(arguments[3])
	case "iam roles create", "iam roles update":
		return simulator.mutateRole(key, arguments[3], strings.TrimPrefix(arguments[4], "--file="))
	case "iam roles delete":
		simulator.mutations++
		delete(simulator.roles, arguments[3])
		return "{}", nil
	}
	return "", fmt.Errorf("unsupported command %q", key)
}

func (simulator *iamSimulator) serviceAccountJSON(email string) string {
	return fmt.Sprintf(`{"email":%q,"name":"projects/%s/serviceAccounts/%s","projectId":%q,"uniqueId":%q,"etag":"BwYz"}`, email, testProject, email, testProject, simulator.accounts[email])
}

func (simulator *iamSimulator) roleJSON(id string) (string, error) {
	role, ok := simulator.roles[id]
	if !ok {
		return "", errors.New("NOT_FOUND")
	}
	encoded, _ := json.Marshal(struct {
		Name                string   `json:"name"`
		Title               string   `json:"title"`
		Description         string   `json:"description"`
		IncludedPermissions []string `json:"includedPermissions"`
		Stage               string   `json:"stage"`
		Etag                string   `json:"etag"`
		Deleted             bool     `json:"deleted,omitempty"`
	}{IAMCustomRoleName(testProject, id), role.document.Title, role.document.Description, role.document.IncludedPermissions, role.document.Stage, "role-etag-" + strconv.Itoa(role.etag), role.deleted})
	return string(encoded), nil
}

func (simulator *iamSimulator) mutateRole(key, id, path string) (string, error) {
	simulator.mutations++
	var document iamRoleDocument
	if err := simulator.readDocument(path, &document); err != nil {
		return "", err
	}
	current, exists := simulator.roles[id]
	if key == "iam roles create" {
		if exists || document.Etag != "" {
			return "", errors.New("ALREADY_EXISTS")
		}
		simulator.roles[id] = iamSimulatedRole{document: document, etag: 1}
		return simulator.roleJSON(id)
	}
	if !exists || document.Etag != "role-etag-"+strconv.Itoa(current.etag) {
		return "", errors.New("ABORTED etag")
	}
	simulator.roles[id] = iamSimulatedRole{document: document, etag: current.etag + 1}
	return simulator.roleJSON(id)
}

func (simulator *iamSimulator) readDocument(path string, target any) error {
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != iamDocumentMode || !filepath.IsAbs(path) {
		return fmt.Errorf("document %q unreadable or not mode 0600", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(content, target)
}

func (simulator *iamSimulator) policyJSON(resource string) string {
	policy := simulator.policy(resource)
	version := int64(1)
	for _, binding := range policy.bindings {
		if binding.Condition != nil {
			version = 3
		}
	}
	encoded, _ := json.Marshal(iamPolicyDocument{Bindings: policy.bindings, Etag: policy.etag, Version: version})
	if len(policy.bindings) == 0 {
		return fmt.Sprintf(`{"etag":%q,"version":1}`, policy.etag)
	}
	return string(encoded)
}

func (simulator *iamSimulator) setPolicy(resource, path string) (string, error) {
	simulator.mutations++
	var document iamPolicyDocument
	if err := simulator.readDocument(path, &document); err != nil {
		return "", err
	}
	if simulator.conflictOnce {
		simulator.conflictOnce = false
		simulator.bumpPolicy(resource, simulator.policy(resource).bindings)
	}
	if document.Etag != simulator.policy(resource).etag || document.Version != 3 {
		return "", errors.New("ABORTED There were concurrent policy changes")
	}
	simulator.bumpPolicy(resource, document.Bindings)
	return simulator.policyJSON(resource), nil
}

func (simulator *iamSimulator) countCalls(prefix string) int {
	count := 0
	for _, call := range simulator.calls {
		if strings.HasPrefix(call, prefix) {
			count++
		}
	}
	return count
}

func testIAMClient(t *testing.T, simulator *iamSimulator) *IAMClient {
	t.Helper()
	scratch := filepath.Join(t.TempDir(), "scratch")
	if err := os.Mkdir(scratch, 0o700); err != nil {
		t.Fatalf("create scratch: %v", err)
	}
	return &IAMClient{runner: simulator, executable: testIAMGcloud, environment: nil, commandTimeout: time.Second, scratch: scratch, clock: fixedClock}
}

func testAuthorization() IAMMutationAuthorization {
	now := fixedClock()
	return IAMMutationAuthorization{
		PlanDocumentSHA256: testPlanSHA, PlanV1Hash: testPlanV1SHA, EnvelopeBindingSHA256: testBindingSHA,
		OperationID: testOperationID, StepID: "t5-identities", Attempt: 1, ClaimGeneration: 7,
		ExecutingIdentity: domain.IdentityHuman, ObservationRevision: testObservation,
		ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(3 * time.Minute), Now: now,
	}
}

func testIdentityIntent() bootstrap.StepIntent {
	return bootstrap.StepIntent{StepID: "t5-identities", Kind: bootstrap.IntentIdentities, EnvelopeBindingSHA256: testBindingSHA, ExecutingIdentity: domain.IdentityHuman}
}

func testDesired(t *testing.T) IAMIdentitiesDesired {
	t.Helper()
	desired, err := IAMDesiredIdentities(validHarnessConfiguration(t), testHumanAccount)
	if err != nil {
		t.Fatalf("IAMDesiredIdentities() error = %v", err)
	}
	return desired
}

func assertIAMFailure(t *testing.T, name string, err error, kind IAMFailureKind) {
	t.Helper()
	var failure *IAMError
	if !errors.As(err, &failure) || failure.Kind() != kind || !errors.Is(err, ErrIAMRejected) {
		t.Fatalf("%s error = %#v, want kind %q", name, err, kind)
	}
}

func TestApplyIdentitiesConvergesFromEmptyProjectWithExactArgv(t *testing.T) {
	simulator := newIAMSimulator(t)
	client := testIAMClient(t, simulator)
	desired := testDesired(t)
	record, err := client.ApplyIdentities(context.Background(), testAuthorization(), testIdentityIntent(), desired)
	if err != nil {
		t.Fatalf("ApplyIdentities() error = %v", err)
	}
	if len(record.CreatedServiceAccounts) != 4 || len(record.CreatedRoles) != 2 || len(record.UpdatedRoles) != 0 || record.UserManagedKeys != 0 ||
		len(record.AddedBindings) != len(desired.ProjectBindings)+len(desired.ServiceAccountBindings) || record.RoleFingerprint == "" || record.BindingFingerprint == "" {
		t.Fatalf("record = %#v", record)
	}
	for _, spec := range desired.ProjectBindings {
		if !iamPolicyContains(simulatedPolicy(t, simulator, "project"), spec) {
			t.Fatalf("project policy lacks %#v", spec)
		}
	}
	for _, spec := range desired.ServiceAccountBindings {
		if !iamPolicyContains(simulatedPolicy(t, simulator, spec.Resource), spec) {
			t.Fatalf("service-account policy lacks %#v", spec)
		}
	}
	if len(simulator.roles) != 2 || !iamRoleMatches(mustRole(t, simulator, IAMTestOperatorRoleID), IAMTestOperatorRole()) {
		t.Fatalf("roles = %#v", simulator.roles)
	}
	tail := " --account=" + testHumanAccount + " --project=" + testProject + " --quiet --verbosity=error"
	scratch := client.scratch
	wantPrefixes := []string{
		"iam service-accounts list --format=json(email,projectId,uniqueId)" + tail,
		"iam service-accounts create ctrldb-test-operator --display-name=CtrlDB test-operator --description=CtrlDB WF-TEST-01 test-operator (" + IAMCatalogVersion + ") --format=json(email,name,projectId,uniqueId,disabled,etag)" + tail,
		"iam service-accounts describe ctrldb-test-operator@example-project.iam.gserviceaccount.com --format=json(email,name,projectId,uniqueId,disabled,etag)" + tail,
		"iam service-accounts keys list --iam-account=ctrldb-test-operator@example-project.iam.gserviceaccount.com --managed-by=user --format=json(name,keyType)" + tail,
	}
	for index, want := range wantPrefixes {
		if simulator.calls[index] != want {
			t.Fatalf("call[%d] = %q, want %q", index, simulator.calls[index], want)
		}
	}
	rolesList := "iam roles list --show-deleted --format=json(name,deleted)" + tail
	if simulator.calls[13] != rolesList {
		t.Fatalf("call[13] = %q, want %q", simulator.calls[13], rolesList)
	}
	createPrefix := "iam roles create ctrldbTestOperator --file=" + scratch + "/iam-" + testOperationID + "-t5-identities-a1-ctrldbTestOperator-"
	if !strings.HasPrefix(simulator.calls[14], createPrefix) || !strings.HasSuffix(simulator.calls[14], ".json --format=json(name,title,description,includedPermissions,stage,etag,deleted)"+tail) {
		t.Fatalf("call[14] = %q", simulator.calls[14])
	}
	if simulator.calls[18] != "projects get-iam-policy example-project --format=json(bindings,etag,version)"+tail {
		t.Fatalf("call[18] = %q", simulator.calls[18])
	}
	setPrefix := "projects set-iam-policy example-project " + scratch + "/iam-" + testOperationID + "-t5-identities-a1-project-a1-"
	if !strings.HasPrefix(simulator.calls[19], setPrefix) {
		t.Fatalf("call[19] = %q", simulator.calls[19])
	}
	entries, _ := os.ReadDir(scratch)
	if len(entries) != 0 {
		t.Fatalf("scratch documents were not removed: %d remain", len(entries))
	}

	second, err := client.ApplyIdentities(context.Background(), testAuthorization(), testIdentityIntent(), desired)
	if err != nil {
		t.Fatalf("second ApplyIdentities() error = %v", err)
	}
	if len(second.CreatedServiceAccounts) != 0 || len(second.CreatedRoles) != 0 || len(second.AddedBindings) != 0 ||
		second.RoleFingerprint != record.RoleFingerprint || second.BindingFingerprint != record.BindingFingerprint {
		t.Fatalf("second record = %#v", second)
	}
	if mutations := simulator.mutations; mutations != 4+2+1+3 {
		t.Fatalf("mutation count after idempotent reapply = %d", mutations)
	}
}

func simulatedPolicy(t *testing.T, simulator *iamSimulator, resource string) iamPolicy {
	t.Helper()
	policy, err := iamParsePolicy([]byte(simulator.policyJSON(resource)))
	if err != nil {
		t.Fatalf("simulated policy for %s unparsable: %v", resource, err)
	}
	return policy
}

func mustRole(t *testing.T, simulator *iamSimulator, id string) IAMRoleObservation {
	t.Helper()
	encoded, err := simulator.roleJSON(id)
	if err != nil {
		t.Fatalf("role %s: %v", id, err)
	}
	observed, err := iamParseRole([]byte(encoded), testProject, id)
	if err != nil {
		t.Fatalf("parse role %s: %v", id, err)
	}
	return observed
}

func TestApplyIdentitiesRetriesEtagConflictAndPreservesForeignBindings(t *testing.T) {
	simulator := newIAMSimulator(t)
	foreign := iamPolicyBindingDocument{Members: []string{"user:owner@example.invalid"}, Role: "roles/owner"}
	simulator.bumpPolicy("project", []iamPolicyBindingDocument{foreign})
	simulator.conflictOnce = true
	client := testIAMClient(t, simulator)
	desired := testDesired(t)
	record, err := client.ApplyIdentities(context.Background(), testAuthorization(), testIdentityIntent(), desired)
	if err != nil {
		t.Fatalf("ApplyIdentities() error = %v", err)
	}
	if simulator.countCalls("projects set-iam-policy") != 2 || simulator.countCalls("projects get-iam-policy") != 3 {
		t.Fatalf("project policy calls = %v", simulator.calls)
	}
	policy := simulatedPolicy(t, simulator, "project")
	if !iamPolicyContains(policy, IAMBindingSpec{Role: "roles/owner", Member: "user:owner@example.invalid"}) {
		t.Fatal("foreign binding was dropped")
	}
	rollback, err := client.RollbackIdentities(context.Background(), testAuthorization(), testIdentityIntent(), desired, record)
	if err != nil {
		t.Fatalf("RollbackIdentities() error = %v", err)
	}
	if len(rollback.RemovedBindings) != len(record.AddedBindings) || len(rollback.DeletedRoles) != 2 || len(rollback.DeletedServiceAccounts) != 4 {
		t.Fatalf("rollback = %#v", rollback)
	}
	after := simulatedPolicy(t, simulator, "project")
	if len(after.Bindings) != 1 || !iamPolicyContains(after, IAMBindingSpec{Role: "roles/owner", Member: "user:owner@example.invalid"}) {
		t.Fatalf("policy after rollback = %#v", after)
	}
	if len(simulator.roles) != 0 || len(simulator.accounts) != 0 {
		t.Fatalf("rollback left roles=%d accounts=%d", len(simulator.roles), len(simulator.accounts))
	}
}

func TestApplyIdentitiesUpdatesDriftedRoleWithEtagAndRollbackRestoresIt(t *testing.T) {
	simulator := newIAMSimulator(t)
	prior := iamRoleDocument{Title: "old", Description: "old", IncludedPermissions: []string{"compute.instances.get", "compute.snapshots.create"}, Stage: "GA"}
	simulator.roles[IAMTestOperatorRoleID] = iamSimulatedRole{document: prior, etag: 4}
	preexisting := "ctrldb-test-vm@example-project.iam.gserviceaccount.com"
	simulator.accounts[preexisting] = "100000000000000000009"
	client := testIAMClient(t, simulator)
	desired := testDesired(t)
	record, err := client.ApplyIdentities(context.Background(), testAuthorization(), testIdentityIntent(), desired)
	if err != nil {
		t.Fatalf("ApplyIdentities() error = %v", err)
	}
	if len(record.UpdatedRoles) != 1 || record.UpdatedRoles[0].ID != IAMTestOperatorRoleID || record.UpdatedRoles[0].Prior.Etag != "role-etag-4" ||
		len(record.CreatedRoles) != 1 || len(record.CreatedServiceAccounts) != 3 {
		t.Fatalf("record = %#v", record)
	}
	if !iamRoleMatches(mustRole(t, simulator, IAMTestOperatorRoleID), IAMTestOperatorRole()) {
		t.Fatal("drifted role was not converged")
	}
	rollback, err := client.RollbackIdentities(context.Background(), testAuthorization(), testIdentityIntent(), desired, record)
	if err != nil {
		t.Fatalf("RollbackIdentities() error = %v", err)
	}
	if len(rollback.RestoredRoles) != 1 || len(rollback.DeletedRoles) != 1 || len(rollback.DeletedServiceAccounts) != 3 {
		t.Fatalf("rollback = %#v", rollback)
	}
	restored := mustRole(t, simulator, IAMTestOperatorRoleID)
	if restored.Title != "old" || len(restored.Permissions) != 2 {
		t.Fatalf("restored role = %#v", restored)
	}
	if _, exists := simulator.accounts[preexisting]; !exists {
		t.Fatal("rollback deleted a preexisting service account")
	}
}

func TestApplyIdentitiesFailsClosedWithoutMutation(t *testing.T) {
	desired := testDesired(t)
	cases := []struct {
		name      string
		authorize func(*IAMMutationAuthorization)
		intent    func(*bootstrap.StepIntent)
		desired   func(*IAMIdentitiesDesired)
		kind      IAMFailureKind
	}{
		{name: "missing plan hash", authorize: func(a *IAMMutationAuthorization) { a.PlanDocumentSHA256 = "" }, kind: IAMFailureAuthorization},
		{name: "stale observation", authorize: func(a *IAMMutationAuthorization) { a.Now = a.ValidUntil }, kind: IAMFailureAuthorization},
		{name: "future observation", authorize: func(a *IAMMutationAuthorization) { a.ObservedAt = a.Now.Add(time.Second) }, kind: IAMFailureAuthorization},
		{name: "long evidence", authorize: func(a *IAMMutationAuthorization) { a.ValidUntil = a.ObservedAt.Add(time.Hour) }, kind: IAMFailureAuthorization},
		{name: "non-utc", authorize: func(a *IAMMutationAuthorization) { a.Now = a.Now.In(time.FixedZone("x", 3600)) }, kind: IAMFailureAuthorization},
		{name: "wrong identity", authorize: func(a *IAMMutationAuthorization) { a.ExecutingIdentity = domain.IdentityTestOperator }, kind: IAMFailureAuthorization},
		{name: "unknown identity", authorize: func(a *IAMMutationAuthorization) { a.ExecutingIdentity = "root" }, kind: IAMFailureAuthorization},
		{name: "zero attempt", authorize: func(a *IAMMutationAuthorization) { a.Attempt = 0 }, kind: IAMFailureAuthorization},
		{name: "malformed operation", authorize: func(a *IAMMutationAuthorization) { a.OperationID = "op-1" }, kind: IAMFailureAuthorization},
		{name: "step mismatch", authorize: func(a *IAMMutationAuthorization) { a.StepID = "t6-control-prefix" }, kind: IAMFailureAuthorization},
		{name: "wrong kind", intent: func(i *bootstrap.StepIntent) { i.Kind = bootstrap.IntentControlPrefix }, kind: IAMFailureAuthorization},
		{name: "binding mismatch", intent: func(i *bootstrap.StepIntent) { i.EnvelopeBindingSHA256 = testPlanSHA }, kind: IAMFailureAuthorization},
		{name: "intent identity mismatch", intent: func(i *bootstrap.StepIntent) { i.ExecutingIdentity = domain.IdentityOperator }, kind: IAMFailureAuthorization},
		{name: "foreign role", desired: func(d *IAMIdentitiesDesired) {
			d.Roles[0].Permissions = append(d.Roles[0].Permissions, "storage.buckets.delete")
		}, kind: IAMFailureInvalid},
		{name: "one role", desired: func(d *IAMIdentitiesDesired) { d.Roles = d.Roles[:1] }, kind: IAMFailureInvalid},
		{name: "cross-project account", desired: func(d *IAMIdentitiesDesired) {
			d.Principals.TestWipe = IAMPrincipal{Role: IAMPrincipalTestWipe, Member: "serviceAccount:ctrldb-test-wipe@foreign-project.iam.gserviceaccount.com", Email: "ctrldb-test-wipe@foreign-project.iam.gserviceaccount.com"}
		}, kind: IAMFailureInvalid},
		{name: "human project binding", desired: func(d *IAMIdentitiesDesired) { d.ProjectBindings[0].Member = d.Principals.Human.Member }, kind: IAMFailureInvalid},
		{name: "unconditioned project binding", desired: func(d *IAMIdentitiesDesired) { d.ProjectBindings[0].Condition = nil }, kind: IAMFailureInvalid},
		{name: "predefined project role", desired: func(d *IAMIdentitiesDesired) { d.ProjectBindings[0].Role = "roles/compute.admin" }, kind: IAMFailureInvalid},
		{name: "cross-project binding", desired: func(d *IAMIdentitiesDesired) {
			d.ProjectBindings[2].Project = "foreign-project"
			d.ProjectBindings[2].Resource = "foreign-project"
		}, kind: IAMFailureInvalid},
		{name: "owner on service account", desired: func(d *IAMIdentitiesDesired) { d.ServiceAccountBindings[0].Role = "roles/owner" }, kind: IAMFailureInvalid},
		{name: "foreign member", desired: func(d *IAMIdentitiesDesired) { d.ServiceAccountBindings[0].Member = "user:intruder@example.invalid" }, kind: IAMFailureInvalid},
		{name: "duplicate binding", desired: func(d *IAMIdentitiesDesired) { d.ProjectBindings = append(d.ProjectBindings, d.ProjectBindings[0]) }, kind: IAMFailureInvalid},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			simulator := newIAMSimulator(t)
			client := testIAMClient(t, simulator)
			authorization, intent, mutated := testAuthorization(), testIdentityIntent(), testDesired(t)
			if testCase.authorize != nil {
				testCase.authorize(&authorization)
			}
			if testCase.intent != nil {
				testCase.intent(&intent)
			}
			if testCase.desired != nil {
				testCase.desired(&mutated)
			}
			_, err := client.ApplyIdentities(context.Background(), authorization, intent, mutated)
			assertIAMFailure(t, testCase.name, err, testCase.kind)
			if len(simulator.calls) != 0 {
				t.Fatalf("%s ran %d commands before rejection", testCase.name, len(simulator.calls))
			}
			_, err = client.RollbackIdentities(context.Background(), authorization, intent, mutated, IAMIdentitiesRecord{OperationID: testOperationID, StepID: "t5-identities", Project: testProject})
			assertIAMFailure(t, testCase.name+" rollback", err, testCase.kind)
			if len(simulator.calls) != 0 {
				t.Fatalf("%s rollback ran %d commands before rejection", testCase.name, len(simulator.calls))
			}
		})
	}
	_ = desired
}

func TestApplyIdentitiesStopsOnKeysDeletedRoleAndProcessFailures(t *testing.T) {
	t.Run("user-managed key", func(t *testing.T) {
		simulator := newIAMSimulator(t)
		simulator.accounts["ctrldb-test-operator@example-project.iam.gserviceaccount.com"] = "100000000000000000001"
		simulator.keys["ctrldb-test-operator@example-project.iam.gserviceaccount.com"] = 1
		client := testIAMClient(t, simulator)
		_, err := client.ApplyIdentities(context.Background(), testAuthorization(), testIdentityIntent(), testDesired(t))
		assertIAMFailure(t, "keys", err, IAMFailureVerification)
		if simulator.mutations != 0 {
			t.Fatalf("mutations = %d", simulator.mutations)
		}
	})
	t.Run("deleted reserved role", func(t *testing.T) {
		simulator := newIAMSimulator(t)
		simulator.roles[IAMTestDestructiveRoleID] = iamSimulatedRole{document: iamRoleDocument{Title: "x", Stage: "GA"}, etag: 1, deleted: true}
		client := testIAMClient(t, simulator)
		_, err := client.ApplyIdentities(context.Background(), testAuthorization(), testIdentityIntent(), testDesired(t))
		assertIAMFailure(t, "deleted role", err, IAMFailureDrift)
		if simulator.countCalls("iam roles create") != 0 || simulator.countCalls("projects set-iam-policy") != 0 {
			t.Fatalf("calls = %v", simulator.calls)
		}
	})
	t.Run("policy set failure without etag change is terminal", func(t *testing.T) {
		simulator := newIAMSimulator(t)
		simulator.failCommand = "projects set-iam-policy"
		client := testIAMClient(t, simulator)
		_, err := client.ApplyIdentities(context.Background(), testAuthorization(), testIdentityIntent(), testDesired(t))
		assertIAMFailure(t, "set failure", err, IAMFailureProcess)
		if simulator.countCalls("projects set-iam-policy") != 1 || simulator.countCalls("iam service-accounts set-iam-policy") != 0 {
			t.Fatalf("calls = %v", simulator.calls)
		}
	})
	t.Run("rollback record outside desired set", func(t *testing.T) {
		simulator := newIAMSimulator(t)
		client := testIAMClient(t, simulator)
		record := IAMIdentitiesRecord{OperationID: testOperationID, StepID: "t5-identities", Project: testProject,
			CreatedServiceAccounts: []string{"ctrldb-host@example-project.iam.gserviceaccount.com"}}
		_, err := client.RollbackIdentities(context.Background(), testAuthorization(), testIdentityIntent(), testDesired(t), record)
		assertIAMFailure(t, "foreign record", err, IAMFailureAuthorization)
		record = IAMIdentitiesRecord{OperationID: "op-fedcba9876543210", StepID: "t5-identities", Project: testProject}
		_, err = client.RollbackIdentities(context.Background(), testAuthorization(), testIdentityIntent(), testDesired(t), record)
		assertIAMFailure(t, "other operation", err, IAMFailureAuthorization)
		if len(simulator.calls) != 0 {
			t.Fatalf("rollback ran %d commands before rejection", len(simulator.calls))
		}
	})
}

func TestNewIAMClientRejectsInvalidOptionsAndSealsBoundary(t *testing.T) {
	scratch := filepath.Join(t.TempDir(), "scratch")
	if err := os.Mkdir(scratch, 0o700); err != nil {
		t.Fatalf("create scratch: %v", err)
	}
	executable := readHelperExecutable(t)
	base := IAMClientOptions{GcloudPath: executable, SearchPath: "/usr/bin:/bin", Home: t.TempDir(), CloudSDKConfig: t.TempDir(), Locale: "C.UTF-8", CommandTimeout: time.Second, ScratchDirectory: scratch, Clock: fixedClock}
	if client, err := NewIAMClient(base); err != nil || client == nil || client.runner == nil {
		t.Fatalf("NewIAMClient() = %v, %v", client, err)
	}
	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatalf("create loose scratch: %v", err)
	}
	cases := map[string]func(*IAMClientOptions){
		"timeout":        func(o *IAMClientOptions) { o.CommandTimeout = 0 },
		"long timeout":   func(o *IAMClientOptions) { o.CommandTimeout = time.Hour },
		"clock":          func(o *IAMClientOptions) { o.Clock = nil },
		"locale":         func(o *IAMClientOptions) { o.Locale = "POSIX" },
		"relative":       func(o *IAMClientOptions) { o.ScratchDirectory = "scratch" },
		"missing":        func(o *IAMClientOptions) { o.ScratchDirectory = filepath.Join(scratch, "absent") },
		"group-readable": func(o *IAMClientOptions) { o.ScratchDirectory = loose },
		"executable":     func(o *IAMClientOptions) { o.GcloudPath = filepath.Join(t.TempDir(), "not-gcloud") },
	}
	for name, mutate := range cases {
		options := base
		mutate(&options)
		if _, err := NewIAMClient(options); err == nil {
			t.Fatalf("%s accepted", name)
		} else {
			assertIAMFailure(t, name, err, IAMFailureInvalid)
		}
	}
}
