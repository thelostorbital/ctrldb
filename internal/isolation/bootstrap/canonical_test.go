// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/thelostorbital/ctrldb/internal/domain"
	"github.com/thelostorbital/ctrldb/internal/isolation"
)

func TestParseCompiledPlanRejectsMalformedOrNoncanonicalDocuments(t *testing.T) {
	t.Parallel()

	valid := mustCanonical(t, mustCompile(t, validCompileRequest(t)))
	tests := []struct {
		name    string
		encoded []byte
	}{
		{name: "empty", encoded: nil},
		{name: "malformed", encoded: []byte(`{"schemaVersion":`)},
		{name: "null", encoded: []byte(`null`)},
		{name: "trailing object", encoded: append(append([]byte{}, valid...), []byte(`{}`)...)},
		{name: "noncanonical whitespace", encoded: append([]byte("\n"), valid...)},
		{name: "duplicate top level", encoded: []byte(`{"schemaVersion":"a","schemaVersion":"b","payload":{},"documentSha256":"` + repeatedHex("a") + `"}`)},
		{name: "unknown top level", encoded: addTopLevelField(t, valid, "unknown", true)},
		{name: "wrong schema", encoded: rewriteWire(t, valid, func(wire *compiledWireV1) { wire.SchemaVersion = "wf-test-plan/v2" })},
		{name: "outer hash mismatch", encoded: rewriteWire(t, valid, func(wire *compiledWireV1) { wire.DocumentSHA256 = repeatedHex("f") })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseCompiledPlan(test.encoded); !errors.Is(err, ErrInvalidCompiledPlan) {
				t.Fatalf("ParseCompiledPlan() error = %v; want ErrInvalidCompiledPlan", err)
			}
		})
	}
}

func TestParseCompiledPlanRejectsRehashedSemanticTampering(t *testing.T) {
	t.Parallel()

	compiled := mustCompile(t, validCompileRequest(t))
	tests := []struct {
		name   string
		mutate func(*compiledPayloadV1)
	}{
		{name: "prefix without reserved value", mutate: func(value *compiledPayloadV1) { value.Desired.NamePrefix = "other-test-" }},
		{name: "labels without prefix", mutate: func(value *compiledPayloadV1) { value.Desired.Labels["managed-by"] = "other" }},
		{name: "unsafe CI principal", mutate: func(value *compiledPayloadV1) { value.Desired.CIPrincipal = "allUsers" }},
		{name: "foreign service account", mutate: func(value *compiledPayloadV1) {
			value.Desired.VMPrincipal = "ctrldb-test-vm@foreign-project.iam.gserviceaccount.com"
		}},
		{name: "duplicate service account", mutate: func(value *compiledPayloadV1) { value.Desired.VMPrincipal = value.Desired.OperatorPrincipal }},
		{name: "plan validity bypass", mutate: func(value *compiledPayloadV1) { value.Desired.PlanValiditySeconds++ }},
		{name: "unsupported cleanup kind", mutate: func(value *compiledPayloadV1) {
			value.CleanupCapabilities[0] = isolation.CleanupCapability("compute.snapshots")
		}},
		{name: "reordered cleanup set", mutate: func(value *compiledPayloadV1) {
			value.CleanupCapabilities[0], value.CleanupCapabilities[1] = value.CleanupCapabilities[1], value.CleanupCapabilities[0]
		}},
		{name: "disposable permanent singleton", mutate: func(value *compiledPayloadV1) { value.DesiredResources[0].Permanence = DisposableRun }},
		{name: "unknown mutation intent", mutate: func(value *compiledPayloadV1) { value.Intents[0].Kind = IntentKind("test-instance-create") }},
		{name: "reordered steps", mutate: func(value *compiledPayloadV1) {
			value.Intents[0], value.Intents[1] = value.Intents[1], value.Intents[0]
		}},
		{name: "duplicate step ID", mutate: func(value *compiledPayloadV1) { value.Intents[1].StepID = value.Intents[0].StepID }},
		{name: "wrong identity", mutate: func(value *compiledPayloadV1) { value.Intents[0].ExecutingIdentity = domain.IdentityOperator }},
		{name: "missing permission", mutate: func(value *compiledPayloadV1) { value.Plan.Permissions = value.Plan.Permissions[1:] }},
		{name: "missing verification", mutate: func(value *compiledPayloadV1) { value.Intents[0].Verification = []string{} }},
		{name: "missing compensation", mutate: func(value *compiledPayloadV1) { value.Intents[0].Compensation = "" }},
		{name: "missing dependency", mutate: func(value *compiledPayloadV1) { value.Intents[1].Dependencies = []string{} }},
		{name: "zero timeout", mutate: func(value *compiledPayloadV1) { value.Intents[0].TimeoutSeconds = 0 }},
		{name: "forged open transition", mutate: func(value *compiledPayloadV1) {
			value.Intents[len(value.Intents)-1].Transition.FromBootstrapPhase = "open"
		}},
		{name: "cost cap bypass", mutate: func(value *compiledPayloadV1) { value.Limits.MaximumCostMicros++ }},
		{name: "estimated cost mismatch", mutate: func(value *compiledPayloadV1) { value.Limits.EstimatedCostMicros++ }},
		{name: "pricing cost driver", mutate: func(value *compiledPayloadV1) { value.Pricing.DiskGiB-- }},
		{name: "permission proof", mutate: func(value *compiledPayloadV1) { value.Permissions.Grants[0].Granted = false }},
		{name: "machine shape bypass", mutate: func(value *compiledPayloadV1) { value.Limits.MaximumGuestCPUs++ }},
		{name: "resource fingerprint", mutate: func(value *compiledPayloadV1) { value.DesiredResources[0].DesiredStateFingerprint = repeatedHex("c") }},
		{name: "plan envelope", mutate: func(value *compiledPayloadV1) { value.Binding.PlanHash = repeatedHex("d") }},
		{name: "observation envelope", mutate: func(value *compiledPayloadV1) { value.Binding.ObservationRevision = repeatedHex("e") }},
		{name: "risk summary", mutate: func(value *compiledPayloadV1) { value.Risks.ExpectedDowntimeSeconds = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded := rehashedMutation(t, compiled, test.mutate)
			if _, err := ParseCompiledPlan(encoded); !errors.Is(err, ErrInvalidCompiledPlan) {
				t.Fatalf("ParseCompiledPlan() error = %v; want ErrInvalidCompiledPlan", err)
			}
		})
	}
}

func TestCapacityChangesCannotRetainTheApprovedPlan(t *testing.T) {
	t.Parallel()

	compiled := mustCompile(t, validCompileRequest(t))
	tests := []struct {
		name   string
		mutate func(*compiledPayloadV1)
	}{
		{name: "disk", mutate: func(value *compiledPayloadV1) { value.Limits.MaximumDiskGiB++ }},
		{name: "instances", mutate: func(value *compiledPayloadV1) { value.Limits.MaximumInstances++ }},
		{name: "lifetime", mutate: func(value *compiledPayloadV1) { value.Limits.MaximumLifetimeSec++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded := rehashedMutation(t, compiled, test.mutate)
			if _, err := ParseCompiledPlan(encoded); !errors.Is(err, ErrInvalidCompiledPlan) {
				t.Fatalf("ParseCompiledPlan(rehashed cap) error = %v; want ErrInvalidCompiledPlan", err)
			}
		})
	}
}

func TestCompiledPlanHashBindsManifestObservationAndEnvelope(t *testing.T) {
	t.Parallel()

	compiled := mustCompile(t, validCompileRequest(t))
	original := mustCanonical(t, compiled)
	wire := decodeWire(t, original)
	wire.Payload.Binding.ManifestHash = repeatedHex("c")
	wire.Payload.Binding.ObservationRevision = repeatedHex("d")
	wire.Payload.Binding.BindingSHA256 = ""
	bindingHash, err := hashJSON(wire.Payload.Binding)
	if err != nil {
		t.Fatalf("hashJSON(binding) unexpected error: %v", err)
	}
	wire.Payload.Binding.BindingSHA256 = bindingHash
	for index := range wire.Payload.Intents {
		wire.Payload.Intents[index].EnvelopeBindingSHA256 = bindingHash
	}
	wire.DocumentSHA256, err = hashJSON(wire.Payload)
	if err != nil {
		t.Fatalf("hashJSON(payload) unexpected error: %v", err)
	}
	changed, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal(wire) unexpected error: %v", err)
	}
	if bytes.Equal(original, changed) || compiled.DocumentHash() == wire.DocumentSHA256 {
		t.Fatal("manifest and observation substitutions did not change the approval artifact")
	}
}

func TestCompiledPlanContainsNoCommandOrSecretBearingFields(t *testing.T) {
	t.Parallel()

	encoded := mustCanonical(t, mustCompile(t, validCompileRequest(t)))
	for _, forbidden := range []string{`"argv"`, `"command"`, `"token"`, `"credential"`, `"mongoUri"`, `"password"`} {
		if bytes.Contains(bytes.ToLower(encoded), bytes.ToLower([]byte(forbidden))) {
			t.Fatalf("canonical plan contains forbidden provider or secret-bearing field %q", forbidden)
		}
	}
	if !bytes.Contains(encoded, []byte(`"executingIdentity":"human"`)) ||
		!bytes.Contains(encoded, []byte(`"boundary":"audit-retention-lock"`)) {
		t.Fatal("canonical plan omitted required identity or irreversible-boundary metadata")
	}
}

func rehashedMutation(t *testing.T, compiled CompiledPlan, mutate func(*compiledPayloadV1)) []byte {
	t.Helper()

	payload := clonePayload(compiled.payload)
	mutate(&payload)
	hash, err := hashJSON(payload)
	if err != nil {
		t.Fatalf("hashJSON(payload) unexpected error: %v", err)
	}
	encoded, err := json.Marshal(compiledWireV1{SchemaVersion: CompiledPlanSchemaV1, Payload: payload, DocumentSHA256: hash})
	if err != nil {
		t.Fatalf("json.Marshal(wire) unexpected error: %v", err)
	}
	return encoded
}

func decodeWire(t *testing.T, encoded []byte) compiledWireV1 {
	t.Helper()

	var wire compiledWireV1
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("json.Unmarshal(wire) unexpected error: %v", err)
	}
	return wire
}

func rewriteWire(t *testing.T, encoded []byte, mutate func(*compiledWireV1)) []byte {
	t.Helper()

	wire := decodeWire(t, encoded)
	mutate(&wire)
	result, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal(wire) unexpected error: %v", err)
	}
	return result
}

func addTopLevelField(t *testing.T, encoded []byte, key string, value any) []byte {
	t.Helper()

	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatalf("json.Unmarshal(document) unexpected error: %v", err)
	}
	document[key] = value
	result, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal(document) unexpected error: %v", err)
	}
	return result
}

func TestCanonicalParserRejectsNestedDuplicateFields(t *testing.T) {
	t.Parallel()

	valid := string(mustCanonical(t, mustCompile(t, validCompileRequest(t))))
	needle := `"workflowId":"WF-TEST-01"`
	duplicated := strings.Replace(valid, needle, needle+`,`+needle, 1)
	if duplicated == valid {
		t.Fatal("test fixture did not insert a duplicate field")
	}
	if _, err := ParseCompiledPlan([]byte(duplicated)); !errors.Is(err, ErrInvalidCompiledPlan) {
		t.Fatalf("ParseCompiledPlan(duplicate nested field) error = %v; want ErrInvalidCompiledPlan", err)
	}
}
