// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/thelostorbital/ctrldb/internal/config"
)

// The D-159 identity catalog. Every value here is protocol-owned planning
// data: the closed test write authority, its explicit exclusions, and the
// exact conditioned bindings WF-TEST-01 T5/T6 render. Nothing in this file
// performs I/O. Adding a permission, kind, or binding requires the single
// D-159 capability-extension change, never an edit made during execution.
const (
	IAMCatalogVersion        = "ctrldb.ctrlboard.dev/iam-catalog/d159-v1"
	IAMTestOperatorRoleID    = "ctrldbTestOperator"
	IAMTestDestructiveRoleID = "ctrldbTestDestructive"
	IAMEscrowWriterRoleBase  = "ctrldbEscrowWriter"
	IAMRoleStageGA           = "GA"
	IAMTestResourcePrefix    = config.TestResourcePrefix
	IAMControlTestPrefix     = "objects/test/"

	IAMTokenCreatorRole       = "roles/iam.serviceAccountTokenCreator"
	IAMServiceAccountUserRole = "roles/iam.serviceAccountUser"
	IAMRunInvokerRole         = "roles/run.invoker"
	IAMObjectUserRole         = "roles/storage.objectUser"

	// The two permanent T4 firewall rules share the harness prefix and are
	// therefore excluded by name from every run-scoped firewall condition.
	iamPermanentIAPFirewall      = "ctrldb-test-iap-ssh"
	iamPermanentInternalFirewall = "ctrldb-test-internal"

	// IAM allows at most twelve logical operators per condition expression.
	iamMaxConditionOperators = 12
)

// ErrIAMCatalog marks a catalog value that cannot be rendered safely.
var ErrIAMCatalog = errors.New("invalid IAM catalog input")

var (
	iamRoleIDPattern       = regexp.MustCompile(`^[A-Za-z0-9_.]{3,64}$`)
	iamPermissionPattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*){2,}$`)
	iamHumanAccountPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	iamEnvironmentPattern  = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// PERM-TEST-OP write authority: create/get/list/update/use operations of the
// closed run-scoped Compute instance, disk, and classic firewall contracts.
// iam.serviceAccounts.actAs is deliberately absent; it is granted only on the
// VM service account resource.
var iamTestOperatorPermissions = [...]string{
	"compute.disks.create",
	"compute.disks.get",
	"compute.disks.list",
	"compute.disks.use",
	"compute.firewalls.create",
	"compute.firewalls.get",
	"compute.firewalls.list",
	"compute.globalOperations.get",
	"compute.instances.create",
	"compute.instances.get",
	"compute.instances.list",
	"compute.instances.reset",
	"compute.instances.setMetadata",
	"compute.networks.get",
	"compute.networks.updatePolicy",
	"compute.regionOperations.get",
	"compute.subnetworks.get",
	"compute.subnetworks.use",
	"compute.zoneOperations.get",
}

// PERM-TEST-DX: delete of the same three kinds plus the reads their
// pre-delete proofs require. compute.networks.updatePolicy is required by
// v1.compute.firewalls.delete.
var iamTestDestructivePermissions = [...]string{
	"compute.disks.delete",
	"compute.disks.get",
	"compute.disks.list",
	"compute.firewalls.delete",
	"compute.firewalls.get",
	"compute.firewalls.list",
	"compute.globalOperations.get",
	"compute.instances.delete",
	"compute.instances.get",
	"compute.instances.list",
	"compute.networks.updatePolicy",
	"compute.regionOperations.get",
	"compute.zoneOperations.get",
}

// V-089: the predefined secretVersionAdder role also grants
// secretmanager.secrets.rotate and project reads, so escrow uses a
// one-permission custom role.
var iamEscrowWriterPermissions = [...]string{"secretmanager.versions.add"}

// iamExcludedPermissionFamilies is the explicit D-159 exclusion list. Any
// permission in one of these families is rejected from every test role even
// if a caller-supplied definition names it. Everything outside the closed
// allow set is rejected as unknown regardless of this list.
var iamExcludedPermissionFamilies = [...]string{
	"cloudscheduler.",
	"compute.addresses.",
	"compute.globalAddresses.",
	"compute.images.",
	"compute.networks.create",
	"compute.networks.delete",
	"compute.resourcePolicies.",
	"compute.routers.",
	"compute.snapshots.",
	"compute.subnetworks.create",
	"compute.subnetworks.delete",
	"dns.",
	"iam.roles.",
	"iam.serviceAccountKeys.",
	"iam.serviceAccounts.",
	"logging.",
	"monitoring.",
	"resourcemanager.",
	"run.",
	"secretmanager.",
	"storage.",
}

// IAMRoleDefinition is one exact custom role. Permissions are sorted and
// unique so the definition hashes deterministically.
type IAMRoleDefinition struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Stage       string   `json:"stage"`
	Permissions []string `json:"permissions"`
}

// IAMTestOperatorRole returns the closed PERM-TEST-OP custom role.
func IAMTestOperatorRole() IAMRoleDefinition {
	return IAMRoleDefinition{
		ID: IAMTestOperatorRoleID, Title: "CtrlDB test operator",
		Description: "CtrlDB WF-TEST-01 run-scoped Compute instance, disk, and classic firewall mutation (" + IAMCatalogVersion + ")",
		Stage:       IAMRoleStageGA, Permissions: append([]string(nil), iamTestOperatorPermissions[:]...),
	}
}

// IAMTestDestructiveRole returns the closed PERM-TEST-DX custom role.
func IAMTestDestructiveRole() IAMRoleDefinition {
	return IAMRoleDefinition{
		ID: IAMTestDestructiveRoleID, Title: "CtrlDB test destructive",
		Description: "CtrlDB WF-TEST-01 run-scoped Compute instance, disk, and classic firewall deletion (" + IAMCatalogVersion + ")",
		Stage:       IAMRoleStageGA, Permissions: append([]string(nil), iamTestDestructivePermissions[:]...),
	}
}

// IAMEscrowWriterRole returns the V-089 add-only escrow role for one
// environment. Role IDs cannot contain hyphens, so environment hyphens become
// underscores in the ID only.
func IAMEscrowWriterRole(environment string) (IAMRoleDefinition, error) {
	if !iamEnvironmentPattern.MatchString(environment) {
		return IAMRoleDefinition{}, fmt.Errorf("%w: environment must be a canonical environment name", ErrIAMCatalog)
	}
	id := IAMEscrowWriterRoleBase + "_" + strings.ReplaceAll(environment, "-", "_")
	if !iamRoleIDPattern.MatchString(id) {
		return IAMRoleDefinition{}, fmt.Errorf("%w: escrow role ID is not representable", ErrIAMCatalog)
	}
	return IAMRoleDefinition{
		ID: id, Title: "CtrlDB escrow writer " + environment,
		Description: "CtrlDB add-only escrow secret version writer for " + environment + " (" + IAMCatalogVersion + ")",
		Stage:       IAMRoleStageGA, Permissions: append([]string(nil), iamEscrowWriterPermissions[:]...),
	}, nil
}

// IAMExcludedPermissionFamilies returns the explicit exclusion list.
func IAMExcludedPermissionFamilies() []string {
	return append([]string(nil), iamExcludedPermissionFamilies[:]...)
}

// IAMPermissionExcluded reports whether a permission belongs to an explicitly
// excluded family.
func IAMPermissionExcluded(permission string) bool {
	for _, family := range iamExcludedPermissionFamilies {
		if strings.HasPrefix(permission, family) {
			return true
		}
	}
	return false
}

// IAMTestPermissionAdmitted reports whether a permission belongs to the closed
// test write catalog. Unknown permissions are never admitted.
func IAMTestPermissionAdmitted(permission string) bool {
	if IAMPermissionExcluded(permission) {
		return false
	}
	for _, set := range [][]string{iamTestOperatorPermissions[:], iamTestDestructivePermissions[:]} {
		for _, candidate := range set {
			if candidate == permission {
				return true
			}
		}
	}
	return false
}

// ValidateIAMRoleDefinition rejects a definition that is not exactly one of
// the catalog roles or the environment escrow role.
func ValidateIAMRoleDefinition(definition IAMRoleDefinition) error {
	if !iamRoleIDPattern.MatchString(definition.ID) || definition.Stage != IAMRoleStageGA ||
		strings.TrimSpace(definition.Title) == "" || strings.TrimSpace(definition.Description) == "" ||
		len(definition.Permissions) == 0 || !sort.StringsAreSorted(definition.Permissions) {
		return fmt.Errorf("%w: role %q is malformed", ErrIAMCatalog, definition.ID)
	}
	for index, permission := range definition.Permissions {
		if !iamPermissionPattern.MatchString(permission) || (index > 0 && permission == definition.Permissions[index-1]) {
			return fmt.Errorf("%w: role %q permission %q is malformed or duplicated", ErrIAMCatalog, definition.ID, permission)
		}
	}
	var expected IAMRoleDefinition
	switch {
	case definition.ID == IAMTestOperatorRoleID:
		expected = IAMTestOperatorRole()
	case definition.ID == IAMTestDestructiveRoleID:
		expected = IAMTestDestructiveRole()
	case strings.HasPrefix(definition.ID, IAMEscrowWriterRoleBase+"_"):
		environment := strings.ReplaceAll(strings.TrimPrefix(definition.ID, IAMEscrowWriterRoleBase+"_"), "_", "-")
		escrow, err := IAMEscrowWriterRole(environment)
		if err != nil {
			return err
		}
		expected = escrow
	default:
		return fmt.Errorf("%w: role %q is outside the closed catalog", ErrIAMCatalog, definition.ID)
	}
	if !iamEqualRoleDefinition(definition, expected) {
		return fmt.Errorf("%w: role %q does not equal its catalog definition", ErrIAMCatalog, definition.ID)
	}
	return nil
}

func iamEqualRoleDefinition(first, second IAMRoleDefinition) bool {
	return first.ID == second.ID && first.Title == second.Title && first.Description == second.Description &&
		first.Stage == second.Stage && equalStrings(first.Permissions, second.Permissions)
}

// IAMPrincipalRole names one harness principal slot.
type IAMPrincipalRole string

const (
	IAMPrincipalHuman           IAMPrincipalRole = "human"
	IAMPrincipalCI              IAMPrincipalRole = "ci"
	IAMPrincipalTestOperator    IAMPrincipalRole = "test-operator"
	IAMPrincipalTestDestructive IAMPrincipalRole = "test-destructive"
	IAMPrincipalTestVM          IAMPrincipalRole = "test-vm"
	IAMPrincipalTestWipe        IAMPrincipalRole = "test-wipe"
)

// IAMPrincipal is one exact identity. Member is the IAM binding member form;
// Email is the troubleshooter principal form and is empty for a workload
// identity principal, which the troubleshooter does not support.
type IAMPrincipal struct {
	Role   IAMPrincipalRole `json:"role"`
	Member string           `json:"member"`
	Email  string           `json:"email,omitempty"`
}

// IAMPrincipalSet is the complete harness principal set for one project.
type IAMPrincipalSet struct {
	Project         string       `json:"project"`
	Human           IAMPrincipal `json:"human"`
	CI              IAMPrincipal `json:"ci"`
	TestOperator    IAMPrincipal `json:"testOperator"`
	TestDestructive IAMPrincipal `json:"testDestructive"`
	TestVM          IAMPrincipal `json:"testVm"`
	TestWipe        IAMPrincipal `json:"testWipe"`
}

// ServiceAccounts returns the four harness service accounts in creation order.
func (set IAMPrincipalSet) ServiceAccounts() []IAMPrincipal {
	return []IAMPrincipal{set.TestOperator, set.TestDestructive, set.TestVM, set.TestWipe}
}

// IAMHarnessPrincipals derives the principal set from the validated manifest
// projection and the explicit human bootstrap account. Nothing is defaulted.
func IAMHarnessPrincipals(configuration config.HarnessConfiguration, humanAccount string) (IAMPrincipalSet, error) {
	if !iamHumanAccountPattern.MatchString(humanAccount) {
		return IAMPrincipalSet{}, fmt.Errorf("%w: human account must be an explicit lowercase account", ErrIAMCatalog)
	}
	project := configuration.Project()
	if err := config.ValidateHarnessPrincipalSet(project, configuration.OperatorPrincipal(), configuration.DestructivePrincipal(),
		configuration.VMPrincipal(), configuration.WipeServiceAccount(), configuration.CIPrincipal()); err != nil {
		return IAMPrincipalSet{}, fmt.Errorf("%w: %w", ErrIAMCatalog, err)
	}
	serviceAccount := func(role IAMPrincipalRole, email string) IAMPrincipal {
		return IAMPrincipal{Role: role, Member: "serviceAccount:" + email, Email: email}
	}
	return IAMPrincipalSet{
		Project:         project,
		Human:           IAMPrincipal{Role: IAMPrincipalHuman, Member: "user:" + humanAccount, Email: humanAccount},
		CI:              IAMPrincipal{Role: IAMPrincipalCI, Member: configuration.CIPrincipal()},
		TestOperator:    serviceAccount(IAMPrincipalTestOperator, configuration.OperatorPrincipal()),
		TestDestructive: serviceAccount(IAMPrincipalTestDestructive, configuration.DestructivePrincipal()),
		TestVM:          serviceAccount(IAMPrincipalTestVM, configuration.VMPrincipal()),
		TestWipe:        serviceAccount(IAMPrincipalTestWipe, configuration.WipeServiceAccount()),
	}, nil
}

// IAMBindingTarget is the closed set of resources that receive bindings.
type IAMBindingTarget string

const (
	IAMBindingTargetProject        IAMBindingTarget = "project"
	IAMBindingTargetServiceAccount IAMBindingTarget = "service-account"
	IAMBindingTargetBucket         IAMBindingTarget = "bucket"
	IAMBindingTargetRunJob         IAMBindingTarget = "run-job"
)

// IAMCondition is one exact IAM condition. Title identifies the binding.
type IAMCondition struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Expression  string `json:"expression"`
}

// IAMBindingSpec is one exact (target, role, member, condition) binding.
// Resource is the project ID, service-account email, bucket name, or Cloud
// Run job name; Location is set only for regional targets.
type IAMBindingSpec struct {
	Target    IAMBindingTarget `json:"target"`
	Project   string           `json:"project"`
	Resource  string           `json:"resource"`
	Location  string           `json:"location,omitempty"`
	Role      string           `json:"role"`
	Member    string           `json:"member"`
	Condition *IAMCondition    `json:"condition,omitempty"`
}

// IAMCustomRoleName returns the full project custom role name.
func IAMCustomRoleName(project, roleID string) string {
	return "projects/" + project + "/roles/" + roleID
}

type iamConditionClause struct {
	title      string
	expression string
}

func iamComputeResourceName(project, scope, collection, name string) string {
	return "projects/" + project + "/" + scope + "/" + collection + "/" + name
}

func iamRunScopedClauses(configuration config.HarnessConfiguration, includeSubnet bool) []iamConditionClause {
	project, zone, region := configuration.Project(), configuration.Zone(), configuration.Region()
	firewall := func(name string) string { return iamComputeResourceName(project, "global", "firewalls", name) }
	clauses := []iamConditionClause{
		{title: "instances", expression: `resource.type == "compute.googleapis.com/Instance" && resource.name.startsWith("` +
			iamComputeResourceName(project, "zones/"+zone, "instances", IAMTestResourcePrefix) + `")`},
		{title: "disks", expression: `resource.type == "compute.googleapis.com/Disk" && (resource.name.startsWith("` +
			iamComputeResourceName(project, "zones/"+zone, "disks", IAMTestResourcePrefix) + `") || resource.name.startsWith("` +
			iamComputeResourceName(project, "regions/"+region, "disks", IAMTestResourcePrefix) + `"))`},
		{title: "firewalls", expression: `resource.type == "compute.googleapis.com/Firewall" && resource.name.startsWith("` +
			firewall(IAMTestResourcePrefix) + `") && resource.name != "` + firewall(iamPermanentIAPFirewall) +
			`" && resource.name != "` + firewall(iamPermanentInternalFirewall) + `"`},
		{title: "network", expression: `resource.type == "compute.googleapis.com/Network" && resource.name == "` +
			iamComputeResourceName(project, "global", "networks", configuration.VPC()) + `"`},
	}
	if includeSubnet {
		clauses = append(clauses, iamConditionClause{title: "subnetwork", expression: `resource.type == "compute.googleapis.com/Subnetwork" && resource.name == "` +
			iamComputeResourceName(project, "regions/"+region, "subnetworks", configuration.Subnet()) + `"`})
	}
	return append(clauses,
		iamConditionClause{title: "collections", expression: `(resource.type == "cloudresourcemanager.googleapis.com/Project" && resource.name == "projects/` +
			project + `") || resource.name == "projects/` + project + `/zones/` + zone + `" || resource.name == "projects/` + project + `/regions/` + region + `"`},
		iamConditionClause{title: "operations", expression: `resource.name.startsWith("projects/` + project + `/zones/` + zone +
			`/operations/") || resource.name.startsWith("projects/` + project + `/regions/` + region +
			`/operations/") || resource.name.startsWith("projects/` + project + `/global/operations/")`},
	)
}

// IAMProjectBindings renders the T5 project-level conditioned bindings: the
// test operator, test destructive, and wipe principals each receive their
// catalog role only on run-scoped resource names.
func IAMProjectBindings(principals IAMPrincipalSet, configuration config.HarnessConfiguration) ([]IAMBindingSpec, error) {
	if err := iamValidatePrincipalSet(principals, configuration); err != nil {
		return nil, err
	}
	grants := []struct {
		principal IAMPrincipal
		role      string
		subnet    bool
	}{
		{principals.TestOperator, IAMTestOperatorRoleID, true},
		{principals.TestDestructive, IAMTestDestructiveRoleID, false},
		{principals.TestWipe, IAMTestDestructiveRoleID, false},
	}
	result := make([]IAMBindingSpec, 0)
	for _, grant := range grants {
		for _, clause := range iamRunScopedClauses(configuration, grant.subnet) {
			condition := &IAMCondition{
				Title:       string(grant.principal.Role) + "/" + clause.title,
				Description: "CtrlDB " + IAMCatalogVersion,
				Expression:  clause.expression,
			}
			result = append(result, IAMBindingSpec{
				Target: IAMBindingTargetProject, Project: principals.Project, Resource: principals.Project,
				Role: IAMCustomRoleName(principals.Project, grant.role), Member: grant.principal.Member, Condition: condition,
			})
		}
	}
	return result, iamValidateBindingSpecs(result)
}

// IAMServiceAccountBindings renders the T5 service-account-level bindings:
// token creator for the human and CI principals on the two impersonated test
// identities, and actAs for the test operator on the VM identity only.
func IAMServiceAccountBindings(principals IAMPrincipalSet, configuration config.HarnessConfiguration) ([]IAMBindingSpec, error) {
	if err := iamValidatePrincipalSet(principals, configuration); err != nil {
		return nil, err
	}
	binding := func(target IAMPrincipal, role string, member IAMPrincipal) IAMBindingSpec {
		return IAMBindingSpec{Target: IAMBindingTargetServiceAccount, Project: principals.Project, Resource: target.Email, Role: role, Member: member.Member}
	}
	result := []IAMBindingSpec{
		binding(principals.TestOperator, IAMTokenCreatorRole, principals.Human),
		binding(principals.TestOperator, IAMTokenCreatorRole, principals.CI),
		binding(principals.TestDestructive, IAMTokenCreatorRole, principals.Human),
		binding(principals.TestDestructive, IAMTokenCreatorRole, principals.CI),
		binding(principals.TestVM, IAMServiceAccountUserRole, principals.TestOperator),
	}
	return result, iamValidateBindingSpecs(result)
}

// IAMControlPrefixBindings renders the T6 bucket-level conditioned bindings
// on the control bucket's objects/test/ subtree for the two impersonated test
// identities. Thread A's storage client applies them (and renders the K3
// wipe/VM bindings); this catalog owns the T6 content. The condition form
// matches A's resource-scoped object condition exactly.
func IAMControlPrefixBindings(principals IAMPrincipalSet, configuration config.HarnessConfiguration) ([]IAMBindingSpec, error) {
	if err := iamValidatePrincipalSet(principals, configuration); err != nil {
		return nil, err
	}
	bucket := configuration.ControlBucket()
	binding := func(member IAMPrincipal) IAMBindingSpec {
		return IAMBindingSpec{
			Target: IAMBindingTargetBucket, Project: principals.Project, Resource: bucket, Role: IAMObjectUserRole, Member: member.Member,
			Condition: &IAMCondition{
				Title:       string(member.Role) + "/control-test-prefix",
				Description: "CtrlDB " + IAMCatalogVersion,
				Expression: `resource.type == "storage.googleapis.com/Object" && resource.name.startsWith("projects/_/buckets/` +
					bucket + `/` + IAMControlTestPrefix + `")`,
			},
		}
	}
	result := []IAMBindingSpec{binding(principals.TestOperator), binding(principals.TestDestructive)}
	return result, iamValidateBindingSpecs(result)
}

// IAMWipeInvokerBindings renders the T7 Cloud Run job-level binding thread D
// applies: the wipe identity may invoke only the wipe job. The scheduler
// authenticates as the same wipe identity, so no other principal is bound.
func IAMWipeInvokerBindings(principals IAMPrincipalSet, configuration config.HarnessConfiguration) ([]IAMBindingSpec, error) {
	if err := iamValidatePrincipalSet(principals, configuration); err != nil {
		return nil, err
	}
	result := []IAMBindingSpec{{
		Target: IAMBindingTargetRunJob, Project: principals.Project, Resource: configuration.WipeRunJob(),
		Location: configuration.Region(), Role: IAMRunInvokerRole, Member: principals.TestWipe.Member,
	}}
	return result, iamValidateBindingSpecs(result)
}

// IAMBindingFingerprint returns the canonical SHA-256 of a binding set,
// independent of caller order.
func IAMBindingFingerprint(specs []IAMBindingSpec) (string, error) {
	if err := iamValidateBindingSpecs(specs); err != nil {
		return "", err
	}
	canonical := append([]IAMBindingSpec(nil), specs...)
	sort.SliceStable(canonical, func(i, j int) bool { return iamBindingKey(canonical[i]) < iamBindingKey(canonical[j]) })
	return iamHashCanonical(canonical)
}

// IAMRoleFingerprint returns the canonical SHA-256 of a role definition set.
func IAMRoleFingerprint(definitions []IAMRoleDefinition) (string, error) {
	canonical := append([]IAMRoleDefinition(nil), definitions...)
	for index, definition := range canonical {
		if err := ValidateIAMRoleDefinition(definition); err != nil {
			return "", err
		}
		canonical[index].Permissions = append([]string(nil), definition.Permissions...)
	}
	sort.SliceStable(canonical, func(i, j int) bool { return canonical[i].ID < canonical[j].ID })
	for index := 1; index < len(canonical); index++ {
		if canonical[index].ID == canonical[index-1].ID {
			return "", fmt.Errorf("%w: duplicate role %q", ErrIAMCatalog, canonical[index].ID)
		}
	}
	return iamHashCanonical(canonical)
}

func iamHashCanonical(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("%w: canonical encoding failed", ErrIAMCatalog)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func iamBindingKey(spec IAMBindingSpec) string {
	title := ""
	if spec.Condition != nil {
		title = spec.Condition.Title
	}
	return strings.Join([]string{string(spec.Target), spec.Project, spec.Location, spec.Resource, spec.Role, title, spec.Member}, "\x00")
}

func iamValidatePrincipalSet(principals IAMPrincipalSet, configuration config.HarnessConfiguration) error {
	expected, err := IAMHarnessPrincipals(configuration, principals.Human.Email)
	if err != nil {
		return err
	}
	if expected != principals {
		return fmt.Errorf("%w: principal set does not match the manifest projection", ErrIAMCatalog)
	}
	return nil
}

// ValidateIAMBindingSpecs rejects malformed, duplicate, or cross-project
// bindings and any condition above the provider operator limit.
func ValidateIAMBindingSpecs(specs []IAMBindingSpec) error { return iamValidateBindingSpecs(specs) }

func iamValidateBindingSpecs(specs []IAMBindingSpec) error {
	if len(specs) == 0 {
		return fmt.Errorf("%w: binding set must not be empty", ErrIAMCatalog)
	}
	project := specs[0].Project
	seen := make(map[string]struct{}, len(specs))
	for index, spec := range specs {
		if err := iamValidateBindingSpec(spec); err != nil {
			return fmt.Errorf("%w: bindings[%d] %w", ErrIAMCatalog, index, err)
		}
		if spec.Project != project {
			return fmt.Errorf("%w: bindings[%d] crosses projects", ErrIAMCatalog, index)
		}
		key := iamBindingKey(spec)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("%w: bindings[%d] duplicates an earlier binding", ErrIAMCatalog, index)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func iamValidateBindingSpec(spec IAMBindingSpec) error {
	switch spec.Target {
	case IAMBindingTargetProject:
		if spec.Resource != spec.Project || spec.Location != "" {
			return errors.New("project binding must target the binding project")
		}
	case IAMBindingTargetServiceAccount:
		if !strings.HasSuffix(spec.Resource, "@"+spec.Project+".iam.gserviceaccount.com") || spec.Location != "" {
			return errors.New("service-account binding must target a project service account")
		}
	case IAMBindingTargetBucket:
		if spec.Resource == "" || spec.Location != "" {
			return errors.New("bucket binding must name a bucket")
		}
	case IAMBindingTargetRunJob:
		if spec.Resource == "" || spec.Location == "" {
			return errors.New("run-job binding must name a job and region")
		}
	default:
		return errors.New("has an unknown target")
	}
	if !iamProjectIDPattern.MatchString(spec.Project) {
		return errors.New("must name a canonical project")
	}
	if !strings.HasPrefix(spec.Role, "roles/") && !strings.HasPrefix(spec.Role, "projects/"+spec.Project+"/roles/") {
		return errors.New("must use a predefined role or a custom role in the binding project")
	}
	if !iamValidMember(spec.Member) {
		return errors.New("must name a canonical member")
	}
	if spec.Condition != nil {
		if strings.TrimSpace(spec.Condition.Title) == "" || strings.TrimSpace(spec.Condition.Expression) == "" {
			return errors.New("condition must have a title and expression")
		}
		if iamContainsControl(spec.Condition.Expression) || iamContainsControl(spec.Condition.Title) || iamContainsControl(spec.Condition.Description) {
			return errors.New("condition contains control characters")
		}
		if iamConditionOperatorCount(spec.Condition.Expression) > iamMaxConditionOperators {
			return errors.New("condition exceeds the provider operator limit")
		}
	}
	return nil
}

var iamProjectIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

func iamValidMember(member string) bool {
	switch {
	case strings.HasPrefix(member, "user:"):
		return iamHumanAccountPattern.MatchString(strings.TrimPrefix(member, "user:"))
	case strings.HasPrefix(member, "serviceAccount:"):
		return iamServiceAccountEmailPattern.MatchString(strings.TrimPrefix(member, "serviceAccount:"))
	case strings.HasPrefix(member, "principal://iam.googleapis.com/"), strings.HasPrefix(member, "principalSet://iam.googleapis.com/"):
		return !iamContainsControlOrSpace(member)
	default:
		return false
	}
}

var iamServiceAccountEmailPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)

func iamConditionOperatorCount(expression string) int {
	return strings.Count(expression, "&&") + strings.Count(expression, "||") + strings.Count(expression, "!") - strings.Count(expression, "!=")
}

func iamContainsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func iamContainsControlOrSpace(value string) bool {
	return iamContainsControl(value) || strings.ContainsAny(value, " \t")
}
