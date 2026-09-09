// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/config"
)

const testHumanAccount = "operator@example.invalid"

func testPrincipals(t *testing.T) (config.HarnessConfiguration, IAMPrincipalSet) {
	t.Helper()
	configuration := validHarnessConfiguration(t)
	principals, err := IAMHarnessPrincipals(configuration, testHumanAccount)
	if err != nil {
		t.Fatalf("IAMHarnessPrincipals() error = %v", err)
	}
	return configuration, principals
}

func TestIAMCatalogRolesAreClosedSortedAndExcludeForbiddenFamilies(t *testing.T) {
	escrow, err := IAMEscrowWriterRole("disposable-test")
	if err != nil {
		t.Fatalf("IAMEscrowWriterRole() error = %v", err)
	}
	if escrow.ID != "ctrldbEscrowWriter_disposable_test" || len(escrow.Permissions) != 1 || escrow.Permissions[0] != "secretmanager.versions.add" {
		t.Fatalf("escrow role = %#v", escrow)
	}
	for _, definition := range []IAMRoleDefinition{IAMTestOperatorRole(), IAMTestDestructiveRole()} {
		if err := ValidateIAMRoleDefinition(definition); err != nil {
			t.Fatalf("ValidateIAMRoleDefinition(%s) error = %v", definition.ID, err)
		}
		if !sort.StringsAreSorted(definition.Permissions) {
			t.Fatalf("%s permissions are not sorted", definition.ID)
		}
		for _, permission := range definition.Permissions {
			if IAMPermissionExcluded(permission) || !IAMTestPermissionAdmitted(permission) {
				t.Fatalf("%s carries excluded or unadmitted permission %q", definition.ID, permission)
			}
			if !strings.HasPrefix(permission, "compute.") {
				t.Fatalf("%s carries a non-Compute permission %q", definition.ID, permission)
			}
		}
	}
	operator, destructive := IAMTestOperatorRole(), IAMTestDestructiveRole()
	for _, forbidden := range []string{"compute.instances.delete", "compute.disks.delete", "compute.firewalls.delete", "iam.serviceAccounts.actAs", "compute.snapshots.create", "storage.objects.delete"} {
		if sort.SearchStrings(operator.Permissions, forbidden) < len(operator.Permissions) && operator.Permissions[sort.SearchStrings(operator.Permissions, forbidden)] == forbidden {
			t.Fatalf("operator role must not contain %q", forbidden)
		}
	}
	for _, forbidden := range []string{"compute.instances.create", "compute.disks.create", "compute.firewalls.create", "compute.instances.setMetadata"} {
		if index := sort.SearchStrings(destructive.Permissions, forbidden); index < len(destructive.Permissions) && destructive.Permissions[index] == forbidden {
			t.Fatalf("destructive role must not contain %q", forbidden)
		}
	}
	for _, unknown := range []string{"compute.snapshots.create", "compute.addresses.create", "compute.resourcePolicies.create", "storage.buckets.delete", "secretmanager.versions.access", "iam.serviceAccounts.create", "iam.roles.update", "run.jobs.delete", "cloudscheduler.jobs.delete", "compute.instances.unknownVerb", "totally.unknown.permission"} {
		if IAMTestPermissionAdmitted(unknown) {
			t.Fatalf("%q must not be admitted", unknown)
		}
	}
}

func TestValidateIAMRoleDefinitionRejectsDrift(t *testing.T) {
	cases := map[string]func(*IAMRoleDefinition){
		"extra permission": func(d *IAMRoleDefinition) {
			d.Permissions = append(d.Permissions, "compute.snapshots.create")
			sort.Strings(d.Permissions)
		},
		"missing permission": func(d *IAMRoleDefinition) { d.Permissions = d.Permissions[1:] },
		"unsorted":           func(d *IAMRoleDefinition) { d.Permissions[0], d.Permissions[1] = d.Permissions[1], d.Permissions[0] },
		"stage":              func(d *IAMRoleDefinition) { d.Stage = "BETA" },
		"title":              func(d *IAMRoleDefinition) { d.Title = "other" },
		"id":                 func(d *IAMRoleDefinition) { d.ID = "ctrldbOperator" },
		"delete in operator": func(d *IAMRoleDefinition) {
			d.Permissions = append(d.Permissions, "compute.instances.delete")
			sort.Strings(d.Permissions)
		},
	}
	for name, mutate := range cases {
		definition := IAMTestOperatorRole()
		mutate(&definition)
		if err := ValidateIAMRoleDefinition(definition); !errors.Is(err, ErrIAMCatalog) {
			t.Fatalf("%s: error = %v, want ErrIAMCatalog", name, err)
		}
	}
	if _, err := IAMEscrowWriterRole("Bad-Env"); !errors.Is(err, ErrIAMCatalog) {
		t.Fatalf("escrow environment error = %v", err)
	}
}

func TestIAMHarnessPrincipalsRejectsMalformedHumanAndMatchesManifest(t *testing.T) {
	configuration, principals := testPrincipals(t)
	if principals.Project != configuration.Project() || principals.Human.Member != "user:"+testHumanAccount ||
		principals.CI.Member != configuration.CIPrincipal() || principals.CI.Email != "" ||
		principals.TestOperator.Member != "serviceAccount:"+configuration.OperatorPrincipal() ||
		principals.TestWipe.Email != configuration.WipeServiceAccount() {
		t.Fatalf("principals = %#v", principals)
	}
	for _, human := range []string{"", "Operator@Example.invalid", "operator@example.invalid ", "no-at-sign", "user:operator@example.invalid"} {
		if _, err := IAMHarnessPrincipals(configuration, human); !errors.Is(err, ErrIAMCatalog) {
			t.Fatalf("human %q error = %v", human, err)
		}
	}
}

func TestIAMProjectBindingsAreConditionedPerKindWithinOperatorLimit(t *testing.T) {
	configuration, principals := testPrincipals(t)
	bindings, err := IAMProjectBindings(principals, configuration)
	if err != nil {
		t.Fatalf("IAMProjectBindings() error = %v", err)
	}
	project := configuration.Project()
	operatorRole, destructiveRole := IAMCustomRoleName(project, IAMTestOperatorRoleID), IAMCustomRoleName(project, IAMTestDestructiveRoleID)
	counts := map[string]int{}
	for _, binding := range bindings {
		if binding.Target != IAMBindingTargetProject || binding.Resource != project || binding.Condition == nil {
			t.Fatalf("binding = %#v", binding)
		}
		if iamConditionOperatorCount(binding.Condition.Expression) > iamMaxConditionOperators {
			t.Fatalf("condition exceeds operator limit: %s", binding.Condition.Expression)
		}
		if strings.Contains(binding.Condition.Expression, "ctrldb-test-") && !strings.Contains(binding.Condition.Expression, `resource.type == "`) &&
			!strings.Contains(binding.Condition.Expression, "/operations/") {
			t.Fatalf("run-scoped clause lacks a resource type guard: %s", binding.Condition.Expression)
		}
		counts[binding.Member+" "+binding.Role]++
	}
	if counts[principals.TestOperator.Member+" "+operatorRole] != 7 || counts[principals.TestDestructive.Member+" "+destructiveRole] != 6 ||
		counts[principals.TestWipe.Member+" "+destructiveRole] != 6 || len(counts) != 3 {
		t.Fatalf("binding distribution = %v", counts)
	}
	firewallClause := ""
	for _, binding := range bindings {
		if binding.Condition.Title == "test-destructive/firewalls" {
			firewallClause = binding.Condition.Expression
		}
	}
	for _, permanent := range []string{"ctrldb-test-iap-ssh", "ctrldb-test-internal"} {
		if !strings.Contains(firewallClause, `resource.name != "projects/`+project+`/global/firewalls/`+permanent+`"`) {
			t.Fatalf("firewall clause does not exclude %s: %s", permanent, firewallClause)
		}
	}
	if _, err := IAMBindingFingerprint(bindings); err != nil {
		t.Fatalf("IAMBindingFingerprint() error = %v", err)
	}
	reordered := append([]IAMBindingSpec(nil), bindings...)
	reordered[0], reordered[len(reordered)-1] = reordered[len(reordered)-1], reordered[0]
	first, _ := IAMBindingFingerprint(bindings)
	second, _ := IAMBindingFingerprint(reordered)
	if first != second {
		t.Fatal("binding fingerprint depends on order")
	}
	duplicate := append(append([]IAMBindingSpec(nil), bindings...), bindings[0])
	if _, err := IAMBindingFingerprint(duplicate); !errors.Is(err, ErrIAMCatalog) {
		t.Fatalf("duplicate fingerprint error = %v", err)
	}
	foreign := append([]IAMBindingSpec(nil), bindings...)
	foreign[1].Project = "foreign-project"
	if err := ValidateIAMBindingSpecs(foreign); !errors.Is(err, ErrIAMCatalog) {
		t.Fatalf("cross-project error = %v", err)
	}
}

func TestIAMServiceAccountControlPrefixAndInvokerBindings(t *testing.T) {
	configuration, principals := testPrincipals(t)
	serviceAccount, err := IAMServiceAccountBindings(principals, configuration)
	if err != nil {
		t.Fatalf("IAMServiceAccountBindings() error = %v", err)
	}
	want := map[string]struct{}{
		principals.TestOperator.Email + " " + IAMTokenCreatorRole + " " + principals.Human.Member:        {},
		principals.TestOperator.Email + " " + IAMTokenCreatorRole + " " + principals.CI.Member:           {},
		principals.TestDestructive.Email + " " + IAMTokenCreatorRole + " " + principals.Human.Member:     {},
		principals.TestDestructive.Email + " " + IAMTokenCreatorRole + " " + principals.CI.Member:        {},
		principals.TestVM.Email + " " + IAMServiceAccountUserRole + " " + principals.TestOperator.Member: {},
	}
	if len(serviceAccount) != len(want) {
		t.Fatalf("service-account bindings = %#v", serviceAccount)
	}
	for _, binding := range serviceAccount {
		key := binding.Resource + " " + binding.Role + " " + binding.Member
		if _, ok := want[key]; !ok || binding.Target != IAMBindingTargetServiceAccount || binding.Condition != nil {
			t.Fatalf("unexpected service-account binding %#v", binding)
		}
	}
	control, err := IAMControlPrefixBindings(principals, configuration)
	if err != nil {
		t.Fatalf("IAMControlPrefixBindings() error = %v", err)
	}
	if len(control) != 2 {
		t.Fatalf("control prefix bindings = %#v", control)
	}
	for _, binding := range control {
		if binding.Target != IAMBindingTargetBucket || binding.Resource != configuration.ControlBucket() || binding.Condition == nil || binding.Role != IAMObjectUserRole ||
			binding.Condition.Expression != `resource.type == "storage.googleapis.com/Object" && resource.name.startsWith("projects/_/buckets/`+configuration.ControlBucket()+`/objects/test/")` {
			t.Fatalf("control prefix binding = %#v", binding)
		}
		if binding.Member != principals.TestOperator.Member && binding.Member != principals.TestDestructive.Member {
			t.Fatalf("control prefix binding grants an unexpected member %#v", binding)
		}
	}
	invoker, err := IAMWipeInvokerBindings(principals, configuration)
	if err != nil {
		t.Fatalf("IAMWipeInvokerBindings() error = %v", err)
	}
	if len(invoker) != 1 || invoker[0].Target != IAMBindingTargetRunJob || invoker[0].Resource != configuration.WipeRunJob() ||
		invoker[0].Location != configuration.Region() || invoker[0].Role != IAMRunInvokerRole || invoker[0].Member != principals.TestWipe.Member {
		t.Fatalf("invoker binding = %#v", invoker)
	}
	tampered := principals
	tampered.TestWipe.Member = principals.TestOperator.Member
	if _, err := IAMProjectBindings(tampered, configuration); !errors.Is(err, ErrIAMCatalog) {
		t.Fatalf("tampered principal error = %v", err)
	}
}

func TestIAMRenderRoleAndPolicyDocumentsAreCanonical(t *testing.T) {
	document, err := iamRenderRoleDocument(IAMTestDestructiveRole(), "etag-1")
	if err != nil {
		t.Fatalf("iamRenderRoleDocument() error = %v", err)
	}
	want := `{"title":"CtrlDB test destructive","description":"CtrlDB WF-TEST-01 run-scoped Compute instance, disk, and classic firewall deletion (` + IAMCatalogVersion +
		`)","includedPermissions":["compute.disks.delete","compute.disks.get","compute.disks.list","compute.firewalls.delete","compute.firewalls.get","compute.firewalls.list","compute.globalOperations.get","compute.instances.delete","compute.instances.get","compute.instances.list","compute.networks.updatePolicy","compute.regionOperations.get","compute.zoneOperations.get"],"stage":"GA","etag":"etag-1"}`
	if string(document) != want {
		t.Fatalf("role document = %s", document)
	}
	policy := iamPolicy{Etag: "BwX", Version: 1, Bindings: []iamPolicyBinding{{Role: "roles/viewer", Members: []string{"user:z@example.invalid", "user:a@example.invalid"}}}}
	spec := IAMBindingSpec{Target: IAMBindingTargetProject, Project: "example-project", Resource: "example-project", Role: "projects/example-project/roles/ctrldbTestOperator",
		Member: "serviceAccount:ctrldb-test-operator@example-project.iam.gserviceaccount.com", Condition: &IAMCondition{Title: "t", Description: "d", Expression: `resource.name == "x"`}}
	merged, added := iamPolicyWithBindings(policy, []IAMBindingSpec{spec, spec})
	if len(added) != 1 {
		t.Fatalf("added = %#v", added)
	}
	rendered, err := iamRenderPolicyDocument(merged)
	if err != nil {
		t.Fatalf("iamRenderPolicyDocument() error = %v", err)
	}
	wantPolicy := `{"bindings":[{"condition":{"title":"t","description":"d","expression":"resource.name == \"x\""},"members":["serviceAccount:ctrldb-test-operator@example-project.iam.gserviceaccount.com"],"role":"projects/example-project/roles/ctrldbTestOperator"},{"members":["user:a@example.invalid","user:z@example.invalid"],"role":"roles/viewer"}],"etag":"BwX","version":3}`
	if string(rendered) != wantPolicy {
		t.Fatalf("policy document = %s", rendered)
	}
	if _, again := iamPolicyWithBindings(merged, []IAMBindingSpec{spec}); len(again) != 0 {
		t.Fatal("merging a present binding reported an addition")
	}
	reduced := iamPolicyWithoutBindings(merged, []IAMBindingSpec{spec})
	if !iamEqualPolicyBindings(reduced, policy) || iamPolicyContains(reduced, spec) {
		t.Fatalf("reduced policy = %#v", reduced)
	}
	if _, err := iamRenderPolicyDocument(iamPolicy{Version: 3}); err == nil {
		t.Fatal("policy without an etag rendered")
	}
}

func TestIAMParseRejectsCrossProjectMalformedAndDuplicateOutput(t *testing.T) {
	project, email := "example-project", "ctrldb-test-operator@example-project.iam.gserviceaccount.com"
	good := `{"email":"` + email + `","name":"projects/example-project/serviceAccounts/` + email + `","projectId":"example-project","uniqueId":"123456789012345678901","etag":"BwYz"}`
	if _, err := iamParseServiceAccount([]byte(good), project, email); err != nil {
		t.Fatalf("valid service account rejected: %v", err)
	}
	for name, payload := range map[string]string{
		"cross-project":   strings.Replace(good, `"projectId":"example-project"`, `"projectId":"foreign-project"`, 1),
		"other email":     strings.Replace(good, `"email":"`+email+`"`, `"email":"ctrldb-test-other@example-project.iam.gserviceaccount.com"`, 1),
		"unknown field":   strings.Replace(good, `"etag":"BwYz"`, `"etag":"BwYz","privateKeyData":"x"`, 1),
		"duplicate field": strings.Replace(good, `"etag":"BwYz"`, `"etag":"BwYz","etag":"BwYy"`, 1),
		"trailing":        good + `{}`,
		"malformed":       good[:10],
		"empty":           "",
	} {
		if _, err := iamParseServiceAccount([]byte(payload), project, email); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if count, err := iamParseUserManagedKeyCount([]byte(`[{"name":"projects/example-project/serviceAccounts/x/keys/1","keyType":"USER_MANAGED"}]`)); err != nil || count != 1 {
		t.Fatalf("key count = %d, %v", count, err)
	}
	if _, err := iamParseUserManagedKeyCount([]byte(`{"name":"x"}`)); err == nil {
		t.Fatal("non-array key list accepted")
	}
	role := `{"name":"projects/example-project/roles/ctrldbTestOperator","title":"t","description":"d","includedPermissions":["compute.instances.get"],"stage":"GA","etag":"BwZ"}`
	if _, err := iamParseRole([]byte(role), project, IAMTestOperatorRoleID); err != nil {
		t.Fatalf("valid role rejected: %v", err)
	}
	if _, err := iamParseRole([]byte(strings.Replace(role, "projects/example-project/", "projects/foreign-project/", 1)), project, IAMTestOperatorRoleID); err == nil {
		t.Fatal("cross-project role accepted")
	}
	if _, err := iamParseRole([]byte(strings.Replace(role, `["compute.instances.get"]`, `["compute.instances.get","compute.instances.get"]`, 1)), project, IAMTestOperatorRoleID); err == nil {
		t.Fatal("duplicate permission accepted")
	}
	policy := `{"bindings":[{"members":["user:a@example.invalid"],"role":"roles/viewer"}],"etag":"BwX","version":1}`
	if _, err := iamParsePolicy([]byte(policy)); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	for name, payload := range map[string]string{
		"conditional at version 1": strings.Replace(policy, `"role":"roles/viewer"`, `"role":"roles/viewer","condition":{"expression":"true","title":"t"}`, 1),
		"duplicate binding":        strings.Replace(policy, `}],`, `},{"members":["user:b@example.invalid"],"role":"roles/viewer"}],`, 1),
		"duplicate member":         strings.Replace(policy, `["user:a@example.invalid"]`, `["user:a@example.invalid","user:a@example.invalid"]`, 1),
		"empty members":            strings.Replace(policy, `["user:a@example.invalid"]`, `[]`, 1),
		"missing etag":             strings.Replace(policy, `"etag":"BwX",`, ``, 1),
		"unknown version":          strings.Replace(policy, `"version":1`, `"version":2`, 1),
		"malformed member":         strings.Replace(policy, `user:a@example.invalid`, `user a`, 1),
	} {
		if _, err := iamParsePolicy([]byte(payload)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
