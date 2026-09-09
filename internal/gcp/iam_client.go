// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/thelostorbital/ctrldb/internal/config"
	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation/bootstrap"
	"github.com/thelostorbital/ctrldb/internal/observation"
	"github.com/thelostorbital/ctrldb/internal/runner"
)

const (
	iamMaxCommandTimeout = 60 * time.Second
	iamStdoutLimit       = 8 << 20
	iamStderrLimit       = 64 << 10
	iamEtagAttempts      = 5
	iamDocumentMode      = os.FileMode(0o600)
)

// ErrIAMRejected is the sentinel every IAMError unwraps to.
var ErrIAMRejected = errors.New("gcp iam request rejected")

var (
	iamSHA256Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	iamOperationIDPattern = regexp.MustCompile(`^op-[0-9a-f]{16}$`)
)

// IAMFailureKind classifies why an IAM operation stopped.
type IAMFailureKind string

const (
	IAMFailureInvalid       IAMFailureKind = "invalid"
	IAMFailureAuthorization IAMFailureKind = "authorization"
	IAMFailureProcess       IAMFailureKind = "process"
	IAMFailureSchema        IAMFailureKind = "schema"
	IAMFailureConflict      IAMFailureKind = "conflict"
	IAMFailureDrift         IAMFailureKind = "drift"
	IAMFailureVerification  IAMFailureKind = "verification"
)

// IAMError carries a classification and the schema or field that failed. It
// never carries provider output.
type IAMError struct {
	kind   IAMFailureKind
	source string
}

func (failure *IAMError) Error() string {
	if failure == nil || failure.source == "" {
		return "gcp iam operation failed"
	}
	return "gcp iam operation failed: " + string(failure.kind) + " " + failure.source
}

func (failure *IAMError) Unwrap() error { return ErrIAMRejected }

// Kind returns the failure classification.
func (failure *IAMError) Kind() IAMFailureKind {
	if failure == nil {
		return ""
	}
	return failure.kind
}

func iamError(kind IAMFailureKind, source string) error { return &IAMError{kind: kind, source: source} }

// IAMClientOptions mirrors ReadClientOptions and adds the run-owned scratch
// directory that holds the transient role and policy documents gcloud reads.
type IAMClientOptions struct {
	GcloudPath       string
	SearchPath       string
	Home             string
	CloudSDKConfig   string
	Locale           string
	CommandTimeout   time.Duration
	ScratchDirectory string
	Clock            func() time.Time
}

// IAMClient exposes only typed WF-TEST-01 identity operations. It has no
// generic command, key, impersonation, or arbitrary-policy method.
type IAMClient struct {
	runner         runner.Runner
	executable     string
	environment    []runner.EnvironmentVariable
	commandTimeout time.Duration
	scratch        string
	clock          func() time.Time
}

// NewIAMClient seals gcloud into the process boundary exactly as
// NewReadClient does. It accepts no runner, argv, or environment injection.
func NewIAMClient(options IAMClientOptions) (*IAMClient, error) {
	if options.CommandTimeout <= 0 || options.CommandTimeout > iamMaxCommandTimeout || options.Clock == nil {
		return nil, iamError(IAMFailureInvalid, "client options")
	}
	if options.Locale != "C.UTF-8" && options.Locale != "en_US.UTF-8" {
		return nil, iamError(IAMFailureInvalid, "client options")
	}
	if err := iamValidateScratchDirectory(options.ScratchDirectory); err != nil {
		return nil, err
	}
	environment := []runner.EnvironmentVariable{
		{Name: "PATH", Value: options.SearchPath},
		{Name: "HOME", Value: options.Home},
		{Name: "CLOUDSDK_CONFIG", Value: options.CloudSDKConfig},
		{Name: "CLOUDSDK_CORE_DISABLE_PROMPTS", Value: "1"},
		{Name: "CLOUDSDK_CORE_DISABLE_USAGE_REPORTING", Value: "1"},
		{Name: "NO_COLOR", Value: "1"},
		{Name: "LC_ALL", Value: options.Locale},
	}
	boundary, err := newProcessBoundary(options.GcloudPath, environment)
	if err != nil {
		return nil, iamError(IAMFailureInvalid, "process boundary")
	}
	return &IAMClient{
		runner: boundary, executable: options.GcloudPath, environment: append([]runner.EnvironmentVariable(nil), environment...),
		commandTimeout: options.CommandTimeout, scratch: options.ScratchDirectory, clock: options.Clock,
	}, nil
}

func iamValidateScratchDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return iamError(IAMFailureInvalid, "scratch directory")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return iamError(IAMFailureInvalid, "scratch directory")
	}
	return nil
}

// IAMMutationAuthorization carries the uniform board fields the central
// gateway derives from the approved plan, durable claim, and fresh
// observation. Every entry point validates it against the typed intent
// before any process runs.
type IAMMutationAuthorization struct {
	PlanDocumentSHA256    string
	PlanV1Hash            string
	EnvelopeBindingSHA256 string
	OperationID           string
	StepID                string
	Attempt               uint32
	ClaimGeneration       uint64
	ExecutingIdentity     domain.ExecutionIdentity
	ObservationRevision   string
	ObservedAt            time.Time
	ValidUntil            time.Time
	Now                   time.Time
}

func (authorization IAMMutationAuthorization) validate(intent bootstrap.StepIntent, kind bootstrap.IntentKind) error {
	switch {
	case !iamSHA256Pattern.MatchString(authorization.PlanDocumentSHA256),
		!iamSHA256Pattern.MatchString(authorization.PlanV1Hash),
		!iamSHA256Pattern.MatchString(authorization.EnvelopeBindingSHA256),
		!iamSHA256Pattern.MatchString(authorization.ObservationRevision),
		!iamOperationIDPattern.MatchString(authorization.OperationID),
		authorization.Attempt <= 0, authorization.ClaimGeneration <= 0:
		return iamError(IAMFailureAuthorization, "authorization fields")
	case !authorization.ExecutingIdentity.Valid(), authorization.ExecutingIdentity != domain.IdentityHuman:
		return iamError(IAMFailureAuthorization, "executing identity")
	case !iamValidUTC(authorization.ObservedAt), !iamValidUTC(authorization.ValidUntil), !iamValidUTC(authorization.Now),
		!authorization.ObservedAt.Before(authorization.ValidUntil),
		authorization.ValidUntil.Sub(authorization.ObservedAt) > observation.MaxEvidenceLifetime,
		authorization.Now.Before(authorization.ObservedAt), !authorization.Now.Before(authorization.ValidUntil):
		return iamError(IAMFailureAuthorization, "observation freshness")
	case intent.Kind != kind, intent.StepID != authorization.StepID:
		return iamError(IAMFailureAuthorization, "intent kind")
	case intent.EnvelopeBindingSHA256 != authorization.EnvelopeBindingSHA256, intent.ExecutingIdentity != authorization.ExecutingIdentity:
		return iamError(IAMFailureAuthorization, "intent binding")
	}
	return nil
}

func iamValidUTC(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

// IAMIdentitiesDesired is the complete T5 desired state. It is derived from
// the catalog and the manifest projection; the adapter validates it again.
type IAMIdentitiesDesired struct {
	Principals             IAMPrincipalSet     `json:"principals"`
	Roles                  []IAMRoleDefinition `json:"roles"`
	ProjectBindings        []IAMBindingSpec    `json:"projectBindings"`
	ServiceAccountBindings []IAMBindingSpec    `json:"serviceAccountBindings"`
}

// IAMDesiredIdentities derives the exact T5 desired state.
func IAMDesiredIdentities(configuration config.HarnessConfiguration, humanAccount string) (IAMIdentitiesDesired, error) {
	principals, err := IAMHarnessPrincipals(configuration, humanAccount)
	if err != nil {
		return IAMIdentitiesDesired{}, err
	}
	projectBindings, err := IAMProjectBindings(principals, configuration)
	if err != nil {
		return IAMIdentitiesDesired{}, err
	}
	serviceAccountBindings, err := IAMServiceAccountBindings(principals, configuration)
	if err != nil {
		return IAMIdentitiesDesired{}, err
	}
	return IAMIdentitiesDesired{
		Principals: principals, Roles: []IAMRoleDefinition{IAMTestOperatorRole(), IAMTestDestructiveRole()},
		ProjectBindings: projectBindings, ServiceAccountBindings: serviceAccountBindings,
	}, nil
}

func (desired IAMIdentitiesDesired) validate() error {
	principals := desired.Principals
	if !iamProjectIDPattern.MatchString(principals.Project) || !iamValidMember(principals.Human.Member) ||
		principals.Human.Role != IAMPrincipalHuman || principals.CI.Role != IAMPrincipalCI || !iamValidMember(principals.CI.Member) {
		return iamError(IAMFailureInvalid, "principals")
	}
	seen := make(map[string]struct{}, 4)
	for _, account := range principals.ServiceAccounts() {
		if !iamServiceAccountEmailPattern.MatchString(account.Email) || account.Member != "serviceAccount:"+account.Email ||
			!iamServiceAccountBelongsToProject(account.Email, principals.Project) {
			return iamError(IAMFailureInvalid, "service accounts")
		}
		if _, duplicate := seen[account.Email]; duplicate {
			return iamError(IAMFailureInvalid, "service accounts")
		}
		seen[account.Email] = struct{}{}
	}
	if len(desired.Roles) != 2 {
		return iamError(IAMFailureInvalid, "roles")
	}
	roles := make(map[string]struct{}, 2)
	for _, definition := range desired.Roles {
		if err := ValidateIAMRoleDefinition(definition); err != nil || (definition.ID != IAMTestOperatorRoleID && definition.ID != IAMTestDestructiveRoleID) {
			return iamError(IAMFailureInvalid, "roles")
		}
		roles[IAMCustomRoleName(principals.Project, definition.ID)] = struct{}{}
	}
	if len(roles) != 2 {
		return iamError(IAMFailureInvalid, "roles")
	}
	return desired.validateBindings(roles, seen)
}

func (desired IAMIdentitiesDesired) validateBindings(roles map[string]struct{}, accounts map[string]struct{}) error {
	principals := desired.Principals
	members := map[string]struct{}{principals.Human.Member: {}, principals.CI.Member: {}}
	for _, account := range principals.ServiceAccounts() {
		members[account.Member] = struct{}{}
	}
	if err := iamValidateBindingSpecs(desired.ProjectBindings); err != nil {
		return iamError(IAMFailureInvalid, "project bindings")
	}
	for _, spec := range desired.ProjectBindings {
		_, catalogRole := roles[spec.Role]
		_, knownMember := members[spec.Member]
		if spec.Target != IAMBindingTargetProject || spec.Project != principals.Project || !catalogRole || !knownMember ||
			spec.Condition == nil || spec.Member == principals.Human.Member || spec.Member == principals.CI.Member {
			return iamError(IAMFailureInvalid, "project bindings")
		}
	}
	if err := iamValidateBindingSpecs(desired.ServiceAccountBindings); err != nil {
		return iamError(IAMFailureInvalid, "service-account bindings")
	}
	for _, spec := range desired.ServiceAccountBindings {
		_, knownAccount := accounts[spec.Resource]
		_, knownMember := members[spec.Member]
		if spec.Target != IAMBindingTargetServiceAccount || spec.Project != principals.Project || !knownAccount || !knownMember ||
			(spec.Role != IAMTokenCreatorRole && spec.Role != IAMServiceAccountUserRole) || spec.Condition != nil {
			return iamError(IAMFailureInvalid, "service-account bindings")
		}
	}
	return nil
}

func iamServiceAccountBelongsToProject(email, project string) bool {
	return len(email) > len(project)+len("@.iam.gserviceaccount.com") &&
		email[len(email)-len(project)-len(".iam.gserviceaccount.com")-1:] == "@"+project+".iam.gserviceaccount.com"
}

// IAMRoleRevision records one role this operation changed so rollback can
// restore exactly the prior observed definition.
type IAMRoleRevision struct {
	ID    string             `json:"id"`
	Prior IAMRoleObservation `json:"prior"`
	After IAMRoleObservation `json:"after"`
}

// IAMIdentitiesRecord is the durable, non-secret result of ApplyIdentities.
// Created and Added fields list only what this operation changed.
type IAMIdentitiesRecord struct {
	OperationID            string                         `json:"operationId"`
	StepID                 string                         `json:"stepId"`
	Attempt                uint32                         `json:"attempt"`
	Project                string                         `json:"project"`
	ServiceAccounts        []IAMServiceAccountObservation `json:"serviceAccounts"`
	CreatedServiceAccounts []string                       `json:"createdServiceAccounts"`
	UserManagedKeys        int                            `json:"userManagedKeys"`
	Roles                  []IAMRoleObservation           `json:"roles"`
	CreatedRoles           []string                       `json:"createdRoles"`
	UpdatedRoles           []IAMRoleRevision              `json:"updatedRoles"`
	AddedBindings          []IAMBindingSpec               `json:"addedBindings"`
	RoleFingerprint        string                         `json:"roleFingerprint"`
	BindingFingerprint     string                         `json:"bindingFingerprint"`
	ObservedAt             time.Time                      `json:"observedAt"`
}

// ApplyIdentities performs T5: describe-before-create of the four service
// accounts, exact create/update of the two catalog roles, and etag-safe
// read-modify-write of the project and service-account policies. It fails
// closed before any process runs when the authorization, intent, or desired
// state is not exactly admissible.
func (client *IAMClient) ApplyIdentities(ctx context.Context, authorization IAMMutationAuthorization, intent bootstrap.StepIntent, desired IAMIdentitiesDesired) (IAMIdentitiesRecord, error) {
	if client == nil || ctx == nil {
		return IAMIdentitiesRecord{}, iamError(IAMFailureInvalid, "client")
	}
	if err := authorization.validate(intent, bootstrap.IntentIdentities); err != nil {
		return IAMIdentitiesRecord{}, err
	}
	if err := desired.validate(); err != nil {
		return IAMIdentitiesRecord{}, err
	}
	record := IAMIdentitiesRecord{
		OperationID: authorization.OperationID, StepID: authorization.StepID, Attempt: authorization.Attempt,
		Project: desired.Principals.Project, ObservedAt: client.clock().UTC(),
		CreatedServiceAccounts: []string{}, CreatedRoles: []string{}, UpdatedRoles: []IAMRoleRevision{}, AddedBindings: []IAMBindingSpec{},
	}
	command := commandContext{account: desired.Principals.Human.Email, project: desired.Principals.Project}
	if err := client.applyServiceAccounts(ctx, command, desired, &record); err != nil {
		return IAMIdentitiesRecord{}, err
	}
	if err := client.applyRoles(ctx, command, desired, &record); err != nil {
		return IAMIdentitiesRecord{}, err
	}
	documentPrefix := authorization.OperationID + "-" + authorization.StepID + "-" + iamAttemptSuffix(uint64(authorization.Attempt))
	added, err := client.applyPolicy(ctx, command, iamProjectPolicyGetArguments(command), func(path string) iamCommand {
		return iamProjectPolicySetArguments(command, path)
	}, documentPrefix+"-project", desired.ProjectBindings)
	if err != nil {
		return IAMIdentitiesRecord{}, err
	}
	record.AddedBindings = append(record.AddedBindings, added...)
	for _, account := range desired.Principals.ServiceAccounts() {
		specs := iamBindingsForResource(desired.ServiceAccountBindings, account.Email)
		if len(specs) == 0 {
			continue
		}
		email := account.Email
		added, err := client.applyPolicy(ctx, command, iamServiceAccountPolicyGetArguments(command, email), func(path string) iamCommand {
			return iamServiceAccountPolicySetArguments(command, email, path)
		}, documentPrefix+"-"+iamDocumentToken(email), specs)
		if err != nil {
			return IAMIdentitiesRecord{}, err
		}
		record.AddedBindings = append(record.AddedBindings, added...)
	}
	return client.finishRecord(desired, record)
}

func (client *IAMClient) finishRecord(desired IAMIdentitiesDesired, record IAMIdentitiesRecord) (IAMIdentitiesRecord, error) {
	roleFingerprint, err := IAMRoleFingerprint(desired.Roles)
	if err != nil {
		return IAMIdentitiesRecord{}, iamError(IAMFailureInvalid, "roles")
	}
	bindingFingerprint, err := IAMBindingFingerprint(append(append([]IAMBindingSpec(nil), desired.ProjectBindings...), desired.ServiceAccountBindings...))
	if err != nil {
		return IAMIdentitiesRecord{}, iamError(IAMFailureInvalid, "bindings")
	}
	record.RoleFingerprint, record.BindingFingerprint = roleFingerprint, bindingFingerprint
	return record, nil
}

func (client *IAMClient) applyServiceAccounts(ctx context.Context, command commandContext, desired IAMIdentitiesDesired, record *IAMIdentitiesRecord) error {
	existing, err := client.listServiceAccounts(ctx, command)
	if err != nil {
		return err
	}
	// Observe every preexisting account before any create so a key or
	// disabled state on one account blocks the whole step without mutation.
	for _, account := range desired.Principals.ServiceAccounts() {
		if _, present := existing[account.Email]; present {
			if _, verifyErr := client.verifyServiceAccount(ctx, command, account.Email); verifyErr != nil {
				return verifyErr
			}
		}
	}
	for _, account := range desired.Principals.ServiceAccounts() {
		if _, present := existing[account.Email]; !present {
			if createErr := client.createServiceAccount(ctx, command, account); createErr != nil {
				return createErr
			}
			record.CreatedServiceAccounts = append(record.CreatedServiceAccounts, account.Email)
		}
		observed, verifyErr := client.verifyServiceAccount(ctx, command, account.Email)
		if verifyErr != nil {
			return verifyErr
		}
		record.ServiceAccounts = append(record.ServiceAccounts, observed)
	}
	return nil
}

func (client *IAMClient) createServiceAccount(ctx context.Context, command commandContext, account IAMPrincipal) error {
	accountID, ok := iamServiceAccountID(account.Email)
	if !ok {
		return iamError(IAMFailureInvalid, "service accounts")
	}
	output, runErr := client.run(ctx, iamServiceAccountCreateArguments(command, accountID, "CtrlDB "+string(account.Role),
		"CtrlDB WF-TEST-01 "+string(account.Role)+" ("+IAMCatalogVersion+")"), false)
	if runErr != nil {
		return runErr
	}
	if _, parseErr := iamParseServiceAccount(output, command.project, account.Email); parseErr != nil {
		return iamError(IAMFailureSchema, iamSchemaServiceAccountCreate)
	}
	return nil
}

// verifyServiceAccount proves the exact account exists in the project, is
// enabled, and has no user-managed key.
func (client *IAMClient) verifyServiceAccount(ctx context.Context, command commandContext, email string) (IAMServiceAccountObservation, error) {
	output, runErr := client.run(ctx, iamServiceAccountDescribeArguments(command, email), true)
	if runErr != nil {
		return IAMServiceAccountObservation{}, runErr
	}
	observed, parseErr := iamParseServiceAccount(output, command.project, email)
	if parseErr != nil {
		return IAMServiceAccountObservation{}, iamError(IAMFailureSchema, iamSchemaServiceAccountDescribe)
	}
	if observed.Disabled {
		return IAMServiceAccountObservation{}, iamError(IAMFailureDrift, "service account disabled")
	}
	keysOutput, runErr := client.run(ctx, iamServiceAccountKeysArguments(command, email), true)
	if runErr != nil {
		return IAMServiceAccountObservation{}, runErr
	}
	keys, parseErr := iamParseUserManagedKeyCount(keysOutput)
	if parseErr != nil {
		return IAMServiceAccountObservation{}, iamError(IAMFailureSchema, iamSchemaServiceAccountKeys)
	}
	if keys != 0 {
		return IAMServiceAccountObservation{}, iamError(IAMFailureVerification, "service account has user-managed keys")
	}
	return observed, nil
}

type iamServiceAccountListWire struct {
	Email     string `json:"email"`
	ProjectID string `json:"projectId"`
	UniqueID  string `json:"uniqueId"`
}

func (client *IAMClient) listServiceAccounts(ctx context.Context, command commandContext) (map[string]struct{}, error) {
	output, err := client.run(ctx, iamCommand{schemaServiceAccounts, globalArguments(command, "iam", "service-accounts", "list", "--format=json(email,projectId,uniqueId)")}, true)
	if err != nil {
		return nil, err
	}
	var wire []iamServiceAccountListWire
	if err := decodeProviderJSON(output, &wire, false); err != nil {
		return nil, iamError(IAMFailureSchema, schemaServiceAccounts)
	}
	result := make(map[string]struct{}, len(wire))
	for _, item := range wire {
		if item.ProjectID != command.project || !iamUniqueIDPattern.MatchString(item.UniqueID) || item.Email == "" {
			return nil, iamError(IAMFailureSchema, schemaServiceAccounts)
		}
		if _, duplicate := result[item.Email]; duplicate {
			return nil, iamError(IAMFailureSchema, schemaServiceAccounts)
		}
		result[item.Email] = struct{}{}
	}
	return result, nil
}

type iamRoleListWire struct {
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
}

func (client *IAMClient) listRoles(ctx context.Context, command commandContext) (map[string]bool, error) {
	output, err := client.run(ctx, iamCommand{schemaRoles, globalArguments(command, "iam", "roles", "list", "--show-deleted", "--format=json(name,deleted)")}, true)
	if err != nil {
		return nil, err
	}
	var wire []iamRoleListWire
	if err := decodeProviderJSON(output, &wire, false); err != nil {
		return nil, iamError(IAMFailureSchema, schemaRoles)
	}
	result := make(map[string]bool, len(wire))
	for _, item := range wire {
		if !iamRoleNamePattern.MatchString(item.Name) {
			return nil, iamError(IAMFailureSchema, schemaRoles)
		}
		if _, duplicate := result[item.Name]; duplicate {
			return nil, iamError(IAMFailureSchema, schemaRoles)
		}
		result[item.Name] = item.Deleted
	}
	return result, nil
}

func (client *IAMClient) applyRoles(ctx context.Context, command commandContext, desired IAMIdentitiesDesired, record *IAMIdentitiesRecord) error {
	existing, err := client.listRoles(ctx, command)
	if err != nil {
		return err
	}
	// Observe every role before any mutation so a deleted reserved ID blocks
	// the whole step without creating or updating anything.
	priors := make(map[string]*IAMRoleObservation, len(desired.Roles))
	for _, definition := range desired.Roles {
		deleted, present := existing[IAMCustomRoleName(command.project, definition.ID)]
		if deleted {
			return iamError(IAMFailureDrift, "deleted role with the reserved ID exists")
		}
		if present {
			observed, describeErr := client.describeRole(ctx, command, definition.ID)
			if describeErr != nil {
				return describeErr
			}
			priors[definition.ID] = &observed
		}
	}
	documentPrefix := record.OperationID + "-" + record.StepID + "-" + iamAttemptSuffix(uint64(record.Attempt))
	for _, definition := range desired.Roles {
		prior := priors[definition.ID]
		if prior != nil && iamRoleMatches(*prior, definition) {
			record.Roles = append(record.Roles, *prior)
			continue
		}
		etag, render := "", iamRoleCreateArguments
		if prior != nil {
			etag, render = prior.Etag, iamRoleUpdateArguments
		}
		if _, mutateErr := client.mutateRole(ctx, command, definition, etag, documentPrefix+"-"+definition.ID, render); mutateErr != nil {
			return mutateErr
		}
		observed, describeErr := client.describeRole(ctx, command, definition.ID)
		if describeErr != nil {
			return describeErr
		}
		if !iamRoleMatches(observed, definition) {
			return iamError(IAMFailureVerification, "role does not match its definition after mutation")
		}
		record.Roles = append(record.Roles, observed)
		if prior != nil {
			record.UpdatedRoles = append(record.UpdatedRoles, IAMRoleRevision{ID: definition.ID, Prior: *prior, After: observed})
		} else {
			record.CreatedRoles = append(record.CreatedRoles, definition.ID)
		}
	}
	return nil
}

func (client *IAMClient) describeRole(ctx context.Context, command commandContext, roleID string) (IAMRoleObservation, error) {
	output, err := client.run(ctx, iamRoleDescribeArguments(command, roleID), true)
	if err != nil {
		return IAMRoleObservation{}, err
	}
	observed, parseErr := iamParseRole(output, command.project, roleID)
	if parseErr != nil {
		return IAMRoleObservation{}, iamError(IAMFailureSchema, iamSchemaRoleDescribe)
	}
	return observed, nil
}

func (client *IAMClient) mutateRole(ctx context.Context, command commandContext, definition IAMRoleDefinition, etag, documentName string, render func(commandContext, string, string) iamCommand) (IAMRoleObservation, error) {
	document, err := iamRenderRoleDocument(definition, etag)
	if err != nil {
		return IAMRoleObservation{}, iamError(IAMFailureInvalid, "role document")
	}
	path, cleanup, err := client.writeDocument(documentName, document)
	if err != nil {
		return IAMRoleObservation{}, err
	}
	defer cleanup()
	rendered := render(command, definition.ID, path)
	output, runErr := client.run(ctx, rendered, false)
	if runErr != nil {
		return IAMRoleObservation{}, runErr
	}
	observed, parseErr := iamParseRole(output, command.project, definition.ID)
	if parseErr != nil {
		return IAMRoleObservation{}, iamError(IAMFailureSchema, rendered.schema)
	}
	return observed, nil
}

// applyPolicy converges one policy on the desired bindings with bounded
// etag-conflict retries. It returns the bindings that were absent before
// this operation added them. A set failure whose re-read shows an unchanged
// etag is terminal; only an observed etag change is retried.
func (client *IAMClient) applyPolicy(ctx context.Context, command commandContext, get iamCommand, set func(string) iamCommand, documentName string, specs []IAMBindingSpec) ([]IAMBindingSpec, error) {
	for attempt := 1; attempt <= iamEtagAttempts; attempt++ {
		current, err := client.readPolicy(ctx, get)
		if err != nil {
			return nil, err
		}
		merged, added := iamPolicyWithBindings(current, specs)
		if len(added) == 0 {
			return []IAMBindingSpec{}, nil
		}
		result, err := client.setPolicy(ctx, command, get, set, documentName+"-"+iamAttemptSuffix(uint64(attempt)), merged, current.Etag)
		if err != nil {
			var failure *IAMError
			if errors.As(err, &failure) && failure.kind == IAMFailureConflict {
				continue
			}
			return nil, err
		}
		if !iamEqualPolicyBindings(result, merged) {
			return nil, iamError(IAMFailureVerification, "policy does not equal the rendered policy after set")
		}
		return added, nil
	}
	return nil, iamError(IAMFailureConflict, "etag retries exhausted")
}

func (client *IAMClient) readPolicy(ctx context.Context, get iamCommand) (iamPolicy, error) {
	output, err := client.run(ctx, get, true)
	if err != nil {
		return iamPolicy{}, err
	}
	policy, parseErr := iamParsePolicy(output)
	if parseErr != nil {
		return iamPolicy{}, iamError(IAMFailureSchema, get.schema)
	}
	return policy, nil
}

func (client *IAMClient) setPolicy(ctx context.Context, command commandContext, get iamCommand, set func(string) iamCommand, documentName string, policy iamPolicy, sentEtag string) (iamPolicy, error) {
	document, err := iamRenderPolicyDocument(policy)
	if err != nil {
		return iamPolicy{}, iamError(IAMFailureInvalid, "policy document")
	}
	path, cleanup, err := client.writeDocument(documentName, document)
	if err != nil {
		return iamPolicy{}, err
	}
	defer cleanup()
	rendered := set(path)
	output, runErr := client.run(ctx, rendered, false)
	if runErr != nil {
		observed, readErr := client.readPolicy(ctx, get)
		if readErr == nil && observed.Etag != sentEtag {
			return iamPolicy{}, iamError(IAMFailureConflict, rendered.schema)
		}
		return iamPolicy{}, runErr
	}
	result, parseErr := iamParsePolicy(output)
	if parseErr != nil {
		return iamPolicy{}, iamError(IAMFailureSchema, rendered.schema)
	}
	_ = command
	return result, nil
}

// IAMRollbackRecord lists exactly what a rollback removed or restored.
type IAMRollbackRecord struct {
	OperationID            string            `json:"operationId"`
	StepID                 string            `json:"stepId"`
	RemovedBindings        []IAMBindingSpec  `json:"removedBindings"`
	RestoredRoles          []string          `json:"restoredRoles"`
	DeletedRoles           []string          `json:"deletedRoles"`
	DeletedServiceAccounts []string          `json:"deletedServiceAccounts"`
	Untouched              []IAMRoleRevision `json:"untouched"`
}

// RollbackIdentities removes only the bindings, roles, and service accounts
// the recorded ApplyIdentities operation created and restores the prior
// definition of any role it updated. Preexisting resources are never touched.
func (client *IAMClient) RollbackIdentities(ctx context.Context, authorization IAMMutationAuthorization, intent bootstrap.StepIntent, desired IAMIdentitiesDesired, record IAMIdentitiesRecord) (IAMRollbackRecord, error) {
	if client == nil || ctx == nil {
		return IAMRollbackRecord{}, iamError(IAMFailureInvalid, "client")
	}
	if err := authorization.validate(intent, bootstrap.IntentIdentities); err != nil {
		return IAMRollbackRecord{}, err
	}
	if err := desired.validate(); err != nil {
		return IAMRollbackRecord{}, err
	}
	if record.OperationID != authorization.OperationID || record.StepID != authorization.StepID || record.Project != desired.Principals.Project {
		return IAMRollbackRecord{}, iamError(IAMFailureAuthorization, "record binding")
	}
	if err := iamValidateRollbackRecord(desired, record); err != nil {
		return IAMRollbackRecord{}, err
	}
	command := commandContext{account: desired.Principals.Human.Email, project: desired.Principals.Project}
	result := IAMRollbackRecord{OperationID: record.OperationID, StepID: record.StepID, RemovedBindings: []IAMBindingSpec{},
		RestoredRoles: []string{}, DeletedRoles: []string{}, DeletedServiceAccounts: []string{}, Untouched: []IAMRoleRevision{}}
	documentPrefix := authorization.OperationID + "-" + authorization.StepID + "-rollback-" + iamAttemptSuffix(uint64(authorization.Attempt))
	if err := client.rollbackBindings(ctx, command, desired, record, documentPrefix, &result); err != nil {
		return IAMRollbackRecord{}, err
	}
	for _, revision := range record.UpdatedRoles {
		prior := IAMRoleDefinition{ID: revision.ID, Title: revision.Prior.Title, Description: revision.Prior.Description,
			Stage: revision.Prior.Stage, Permissions: append([]string(nil), revision.Prior.Permissions...)}
		sort.Strings(prior.Permissions)
		if err := client.restoreRole(ctx, command, prior, documentPrefix+"-"+revision.ID); err != nil {
			return IAMRollbackRecord{}, err
		}
		result.RestoredRoles = append(result.RestoredRoles, revision.ID)
	}
	for _, roleID := range record.CreatedRoles {
		if _, err := client.run(ctx, iamRoleDeleteArguments(command, roleID), false); err != nil {
			return IAMRollbackRecord{}, err
		}
		result.DeletedRoles = append(result.DeletedRoles, roleID)
	}
	for _, email := range record.CreatedServiceAccounts {
		if _, err := client.run(ctx, iamServiceAccountDeleteArguments(command, email), false); err != nil {
			return IAMRollbackRecord{}, err
		}
		result.DeletedServiceAccounts = append(result.DeletedServiceAccounts, email)
	}
	return result, nil
}

func iamValidateRollbackRecord(desired IAMIdentitiesDesired, record IAMIdentitiesRecord) error {
	accounts := make(map[string]struct{}, 4)
	for _, account := range desired.Principals.ServiceAccounts() {
		accounts[account.Email] = struct{}{}
	}
	for _, email := range record.CreatedServiceAccounts {
		if _, ok := accounts[email]; !ok {
			return iamError(IAMFailureAuthorization, "record names a service account outside the desired set")
		}
	}
	for _, roleID := range record.CreatedRoles {
		if roleID != IAMTestOperatorRoleID && roleID != IAMTestDestructiveRoleID {
			return iamError(IAMFailureAuthorization, "record names a role outside the catalog")
		}
	}
	for _, revision := range record.UpdatedRoles {
		if (revision.ID != IAMTestOperatorRoleID && revision.ID != IAMTestDestructiveRoleID) || revision.Prior.Name != IAMCustomRoleName(record.Project, revision.ID) {
			return iamError(IAMFailureAuthorization, "record names a role outside the catalog")
		}
	}
	all := append(append([]IAMBindingSpec(nil), desired.ProjectBindings...), desired.ServiceAccountBindings...)
	for _, added := range record.AddedBindings {
		found := false
		for _, spec := range all {
			if iamBindingKey(spec) == iamBindingKey(added) && iamConditionKey(spec.Condition) == iamConditionKey(added.Condition) {
				found = true
			}
		}
		if !found {
			return iamError(IAMFailureAuthorization, "record names a binding outside the desired set")
		}
	}
	return nil
}

func (client *IAMClient) rollbackBindings(ctx context.Context, command commandContext, desired IAMIdentitiesDesired, record IAMIdentitiesRecord, documentPrefix string, result *IAMRollbackRecord) error {
	for _, account := range desired.Principals.ServiceAccounts() {
		specs := iamBindingsForResource(record.AddedBindings, account.Email)
		if len(specs) == 0 {
			continue
		}
		email := account.Email
		removed, err := client.removePolicyBindings(ctx, iamServiceAccountPolicyGetArguments(command, email), func(path string) iamCommand {
			return iamServiceAccountPolicySetArguments(command, email, path)
		}, documentPrefix+"-"+iamDocumentToken(email), specs)
		if err != nil {
			return err
		}
		result.RemovedBindings = append(result.RemovedBindings, removed...)
	}
	projectSpecs := iamBindingsForTarget(record.AddedBindings, IAMBindingTargetProject)
	if len(projectSpecs) == 0 {
		return nil
	}
	removed, err := client.removePolicyBindings(ctx, iamProjectPolicyGetArguments(command), func(path string) iamCommand {
		return iamProjectPolicySetArguments(command, path)
	}, documentPrefix+"-project", projectSpecs)
	if err != nil {
		return err
	}
	result.RemovedBindings = append(result.RemovedBindings, removed...)
	return nil
}

func (client *IAMClient) removePolicyBindings(ctx context.Context, get iamCommand, set func(string) iamCommand, documentName string, specs []IAMBindingSpec) ([]IAMBindingSpec, error) {
	for attempt := 1; attempt <= iamEtagAttempts; attempt++ {
		current, err := client.readPolicy(ctx, get)
		if err != nil {
			return nil, err
		}
		removed := make([]IAMBindingSpec, 0, len(specs))
		for _, spec := range specs {
			if iamPolicyContains(current, spec) {
				removed = append(removed, spec)
			}
		}
		if len(removed) == 0 {
			return []IAMBindingSpec{}, nil
		}
		reduced := iamPolicyWithoutBindings(current, removed)
		result, err := client.setPolicy(ctx, commandContext{}, get, set, documentName+"-"+iamAttemptSuffix(uint64(attempt)), reduced, current.Etag)
		if err != nil {
			var failure *IAMError
			if errors.As(err, &failure) && failure.kind == IAMFailureConflict {
				continue
			}
			return nil, err
		}
		if !iamEqualPolicyBindings(result, reduced) {
			return nil, iamError(IAMFailureVerification, "policy does not equal the rendered policy after set")
		}
		return removed, nil
	}
	return nil, iamError(IAMFailureConflict, "etag retries exhausted")
}

func (client *IAMClient) restoreRole(ctx context.Context, command commandContext, prior IAMRoleDefinition, documentName string) error {
	current, err := client.describeRole(ctx, command, prior.ID)
	if err != nil {
		return err
	}
	document, err := json.Marshal(iamRoleDocument{Title: prior.Title, Description: prior.Description,
		IncludedPermissions: prior.Permissions, Stage: prior.Stage, Etag: current.Etag})
	if err != nil {
		return iamError(IAMFailureInvalid, "role document")
	}
	path, cleanup, err := client.writeDocument(documentName, document)
	if err != nil {
		return err
	}
	defer cleanup()
	if _, runErr := client.run(ctx, iamRoleUpdateArguments(command, prior.ID, path), false); runErr != nil {
		return runErr
	}
	return nil
}

func iamBindingsForResource(specs []IAMBindingSpec, resource string) []IAMBindingSpec {
	result := make([]IAMBindingSpec, 0)
	for _, spec := range specs {
		if spec.Target == IAMBindingTargetServiceAccount && spec.Resource == resource {
			result = append(result, spec)
		}
	}
	return result
}

func iamBindingsForTarget(specs []IAMBindingSpec, target IAMBindingTarget) []IAMBindingSpec {
	result := make([]IAMBindingSpec, 0)
	for _, spec := range specs {
		if spec.Target == target {
			result = append(result, spec)
		}
	}
	return result
}

func iamAttemptSuffix(attempt uint64) string { return "a" + strconv.FormatUint(attempt, 10) }

func iamDocumentToken(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:8])
}

// writeDocument creates one exclusive mode-0600 document in the scratch
// directory. The name is deterministic for the operation, step, attempt, and
// content so the rendered argv is reproducible.
func (client *IAMClient) writeDocument(name string, content []byte) (string, func(), error) {
	digest := sha256.Sum256(content)
	path := filepath.Join(client.scratch, "iam-"+name+"-"+hex.EncodeToString(digest[:8])+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, iamDocumentMode)
	if err != nil {
		return "", nil, iamError(IAMFailureInvalid, "scratch document")
	}
	cleanup := func() { _ = os.Remove(path) }
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		cleanup()
		return "", nil, iamError(IAMFailureInvalid, "scratch document")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return "", nil, iamError(IAMFailureInvalid, "scratch document")
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, iamError(IAMFailureInvalid, "scratch document")
	}
	return path, cleanup, nil
}

// run executes one rendered command through the sealed boundary. Read-only
// commands must produce no diagnostics; mutation commands may print status
// text, which is discarded.
func (client *IAMClient) run(ctx context.Context, command iamCommand, strictStderr bool) ([]byte, error) {
	result, err := client.runner.Run(ctx, runner.Request{
		Executable: client.executable, Arguments: append([]string(nil), command.arguments...),
		Environment: append([]runner.EnvironmentVariable(nil), client.environment...),
		Timeout:     client.commandTimeout, StdoutLimitBytes: iamStdoutLimit, StderrLimitBytes: iamStderrLimit,
	})
	if err != nil {
		return nil, iamError(IAMFailureProcess, command.schema)
	}
	if strictStderr && result.Stderr.String() != "" {
		return nil, iamError(IAMFailureProcess, command.schema)
	}
	return append([]byte(nil), result.Stdout...), nil
}
