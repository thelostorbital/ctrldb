// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindArchitectureViolations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		filename string
		source   string
		want     int
		message  string
	}{
		{
			name:   "default import",
			source: "package fixture\nimport \"os\"\nvar _ = os.StartProcess\n",
			want:   1,
		},
		{
			name:   "interpreted alias",
			source: "package fixture\nimport system \"os\"\nvar _ = system.StartProcess\n",
			want:   1,
		},
		{
			name:   "raw alias",
			source: "package fixture\nimport system `os`\nvar _ = system.StartProcess\n",
			want:   1,
		},
		{
			name:   "interpreted dot import",
			source: "package fixture\nimport . \"os\"\nvar _ = StartProcess\n",
			want:   1,
		},
		{
			name:   "raw dot import",
			source: "package fixture\nimport . `os`\nvar _ = StartProcess\n",
			want:   1,
		},
		{
			name:   "os exec import",
			source: "package fixture\nimport _ \"os/exec\"\n",
			want:   1,
		},
		{
			name:   "CGI import",
			source: "package fixture\nimport _ \"net/http/cgi\"\n",
			want:   1,
		},
		{
			name:   "go build import",
			source: "package fixture\nimport _ \"go/build\"\n",
			want:   1,
		},
		{
			name:   "go importer import",
			source: "package fixture\nimport _ \"go/importer\"\n",
			want:   1,
		},
		{
			name:     "source importer in archcheck implementation",
			filename: "internal/archcheck/main.go",
			source:   "package main\nimport _ \"go/importer\"\n",
		},
		{
			name:     "build matcher in archcheck implementation",
			filename: "internal/archcheck/main.go",
			source:   "package main\nimport _ \"go/build\"\n",
		},
		{
			name:     "default importer in archcheck implementation",
			filename: "internal/archcheck/main.go",
			source:   "package main\nimport \"go/importer\"\nfunc load() { importer.Default() }\n",
			want:     1,
			message:  "go/importer.Default is forbidden",
		},
		{
			name:   "go packages import",
			source: "package fixture\nimport _ \"golang.org/x/tools/go/packages\"\n",
			want:   1,
		},
		{
			name:   "go packages subpackage import",
			source: "package fixture\nimport _ \"golang.org/x/tools/go/packages/packagestest\"\n",
			want:   1,
		},
		{
			name:   "plugin import",
			source: "package fixture\nimport _ \"plugin\"\n",
			want:   1,
		},
		{
			name:   "cgo import",
			source: "package fixture\nimport \"C\"\n",
			want:   1,
		},
		{
			name:   "raw os exec import",
			source: "package fixture\nimport _ `os/exec`\n",
			want:   1,
		},
		{
			name:   "escaped os exec import",
			source: "package fixture\nimport _ \"o\\x73/ex\\x65c\"\n",
			want:   2,
		},
		{
			name:   "syscall import",
			source: "package fixture\nimport _ \"syscall\"\n",
			want:   1,
		},
		{
			name: "syscall js import in WebAssembly source",
			source: `//go:build js && wasm

package fixture

import _ "syscall/js"
`,
			want: 1,
		},
		{
			name:   "execabs import",
			source: "package fixture\nimport _ \"golang.org/x/sys/execabs\"\n",
			want:   1,
		},
		{
			name:   "unix import",
			source: "package fixture\nimport _ \"golang.org/x/sys/unix\"\n",
			want:   1,
		},
		{
			name:   "windows import",
			source: "package fixture\nimport _ `golang.org/x/sys/windows`\n",
			want:   1,
		},
		{
			name:   "windows process subpackage",
			source: "package fixture\nimport _ \"golang.org/x/sys/windows/svc/mgr\"\n",
			want:   1,
		},
		{
			name: "linkname directive",
			source: `package fixture
import _ "unsafe"
//go:linkname startProcess os.StartProcess
func startProcess()
`,
			want: 2,
		},
		{
			name:   "production reflection",
			source: "package fixture\nimport _ \"reflect\"\n",
			want:   1,
		},
		{
			name:   "production unsafe",
			source: "package fixture\nimport _ \"unsafe\"\n",
			want:   1,
		},
		{
			name:     "test reflection",
			filename: "internal/example/fixture_test.go",
			source:   "package fixture\nimport _ \"reflect\"\n",
		},
		{
			name:     "test unsafe",
			filename: "internal/example/fixture_test.go",
			source:   "package fixture\nimport _ \"unsafe\"\n",
		},
		{
			name: "cgo import directive",
			source: `package fixture
//go:cgo_import_dynamic _ _ "./evil.so"
`,
			want: 1,
		},
		{
			name: "shadowed package name",
			source: `package fixture
import "os"
type processAPI struct{}
func (processAPI) StartProcess() {}
func useLocalProcessAPI() {
	os := processAPI{}
	os.StartProcess()
}
var _ = os.Args
`,
		},
		{
			name: "unrelated method",
			source: `package fixture
type processAPI struct{}
func (processAPI) StartProcess() {}
func useLocalProcessAPI() {
	api := processAPI{}
	api.StartProcess()
}
`,
		},
		{
			name:   "local package named os",
			source: "package os\nfunc StartProcess() {}\nvar _ = StartProcess\n",
		},
		{
			name:   "Bubble Tea outside TUI",
			source: "package fixture\nimport _ \"charm.land/bubbletea/v2\"\n",
			want:   1,
		},
		{
			name:     "Bubble Tea inside TUI",
			filename: "internal/tui/fixture.go",
			source:   "package fixture\nimport _ \"charm.land/bubbletea/v2\"\n",
		},
		{
			name:   "test infrastructure in production",
			source: "package fixture\nimport _ \"net/http/httptest\"\n",
			want:   1,
		},
		{
			name:   "testdata package in production",
			source: "package fixture\nimport _ \"example.com/project/testdata/support\"\n",
			want:   1,
		},
		{
			name:   "mock infrastructure in production",
			source: "package fixture\nimport _ \"github.com/stretchr/testify/mock\"\n",
			want:   1,
		},
		{
			name:   "testify assert in production",
			source: "package fixture\nimport _ \"github.com/stretchr/testify/assert\"\n",
			want:   1,
		},
		{
			name:   "testify require in production",
			source: "package fixture\nimport _ \"github.com/stretchr/testify/require\"\n",
			want:   1,
		},
		{
			name:   "testify suite in production",
			source: "package fixture\nimport _ \"github.com/stretchr/testify/suite\"\n",
			want:   1,
		},
		{
			name:     "test infrastructure in test",
			filename: "internal/example/fixture_test.go",
			source:   "package fixture\nimport _ \"net/http/httptest\"\n",
		},
		{
			name:     "test infrastructure in testdata",
			filename: "internal/example/testdata/fixture.go",
			source:   "package fixture\nimport _ \"net/http/httptest\"\n",
		},
		{
			name:   "escaped import path",
			source: "package fixture\nimport _ \"example.com/\\x66oo\"\n",
			want:   1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			filename := test.filename
			if filename == "" {
				filename = "fixture.go"
			}
			findings, err := findArchitectureViolations(filename, []byte(test.source), policyForSource(filename))
			if err != nil {
				t.Fatalf("find architecture violations: %v", err)
			}
			if len(findings) != test.want {
				t.Fatalf("got %d findings (%v), want %d", len(findings), findings, test.want)
			}
			if test.message != "" && !strings.Contains(findings[0].message, test.message) {
				t.Fatalf("finding message = %q, want it to contain %q", findings[0].message, test.message)
			}
		})
	}
}

func TestVerifierImportBoundaryFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want int
	}{
		{name: "allowed.go.txt"},
		{name: "forbidden-app.go.txt", want: 1},
		{name: "forbidden-executor-step.go.txt", want: 1},
		{name: "forbidden-external-provider.go.txt", want: 1},
		{name: "forbidden-internal-package.go.txt", want: 1},
		{name: "forbidden-observation-subpackage.go.txt", want: 1},
		{name: "forbidden-runner.go.txt", want: 1},
		{name: "forbidden-stdlib-lookalike.go.txt", want: 1},
		{name: "forbidden-stdlib-network.go.txt", want: 1},
		{name: "forbidden-stdlib-reflect.go.txt", want: 1},
		{name: "forbidden-stdlib-tls.go.txt", want: 1},
		{name: "forbidden-workflow.go.txt", want: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixturePath := filepath.Join("testdata", "verify-boundary", test.name)
			contents, err := os.ReadFile(fixturePath)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			filename := filepath.ToSlash(filepath.Join("internal", "verify", strings.TrimSuffix(test.name, ".txt")))
			findings, err := findArchitectureViolations(filename, contents, policyForSource(filename))
			if err != nil {
				t.Fatalf("find architecture violations: %v", err)
			}
			if len(findings) != test.want {
				t.Fatalf("got %d findings (%v), want %d", len(findings), findings, test.want)
			}
			for _, result := range findings {
				if !strings.Contains(result.message, "C-VERIFY") {
					t.Fatalf("finding message = %q, want C-VERIFY boundary", result.message)
				}
			}
		})
	}
}

func TestScanIncludesImportableSpecialDirectories(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	files := map[string]string{
		"testdata/process/forbidden.go":  "package process\nimport _ \"os/exec\"\n",
		"generated/process/forbidden.go": "package process\nimport _ \"syscall\"\n",
		"assembly/launch_amd64.s":        "TEXT ·launch(SB),$0-0\nRET\n",
		"native/launch_linux_amd64.syso": "native object fixture\n",
		"native/launch.swig":             "%inline %{ void launch(void); %}\n",
		"native/launch.swigcxx":          "%inline %{ void launch(void); %}\n",
	}
	for name, contents := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	findings, err := scan(root)
	if err != nil {
		t.Fatalf("scan special directories: %v", err)
	}
	if len(findings) != len(files) {
		t.Fatalf("got %d findings, want %d", len(findings), len(files))
	}
	foundByPath := make(map[string]int, len(findings))
	for _, result := range findings {
		foundByPath[result.filename]++
	}
	for name := range files {
		path := filepath.Join(root, name)
		if foundByPath[path] != 1 {
			t.Errorf("got %d findings for %s, want 1", foundByPath[path], name)
		}
	}
}

func TestScanChecksVendoredNativeBoundariesWithoutApplyingFirstPartyImportPolicy(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	files := map[string]string{
		"vendor/example.test/dependency/ordinary.go": `package dependency

import _ "os/exec"
`,
		"vendor/example.test/dependency/native.s":    "TEXT ·launch(SB),$0-0\nRET\n",
		"vendor/example.test/dependency/native.syso": "native object fixture\n",
		"vendor/example.test/dependency/cgo.go": `package dependency

import "C"
`,
		"vendor/example.test/dependency/directive.go": `package dependency

//go:linkname launch os.StartProcess
func launch()
`,
	}
	writeScanFixtureFiles(t, root, files)

	findings, err := scan(root)
	if err != nil {
		t.Fatalf("scan vendor fixtures: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("got %d findings (%v), want four vendor native-boundary findings", len(findings), findings)
	}
	foundByPath := make(map[string]int, len(findings))
	for _, result := range findings {
		foundByPath[filepath.ToSlash(result.filename)]++
	}
	for _, name := range []string{
		"vendor/example.test/dependency/native.s",
		"vendor/example.test/dependency/native.syso",
		"vendor/example.test/dependency/cgo.go",
		"vendor/example.test/dependency/directive.go",
	} {
		path := filepath.ToSlash(filepath.Join(root, name))
		if foundByPath[path] != 1 {
			t.Errorf("got %d findings for %s, want 1", foundByPath[path], name)
		}
	}
	ordinary := filepath.ToSlash(filepath.Join(root, "vendor/example.test/dependency/ordinary.go"))
	if foundByPath[ordinary] != 0 {
		t.Errorf("ordinary vendored Go dependency received %d first-party findings", foundByPath[ordinary])
	}
}

const validSecretValueSource = `package secret
import "fmt"
type Value struct { access func(func(*[]byte)) }
func New(value []byte) *Value {
	return &Value{access: func(operation func(*[]byte)) { operation(&value) }}
}
func (*Value) Zero() {}
func (*Value) Empty() bool { return false }
func (*Value) String() string { return "[redacted]" }
func (*Value) GoString() string { return "[redacted]" }
func (*Value) Format(fmt.State, rune) {}
func (*Value) MarshalJSON() ([]byte, error) { return nil, nil }
func (*Value) MarshalText() ([]byte, error) { return nil, nil }
`

const primitiveSecretValueSource = `package secret
import "fmt"
type Value struct { bytes []byte }
func New(value []byte) *Value { return &Value{bytes: value} }
func (*Value) Zero() {}
func (*Value) Empty() bool { return false }
func (*Value) String() string { return "[redacted]" }
func (*Value) GoString() string { return "[redacted]" }
func (*Value) Format(fmt.State, rune) {}
func (*Value) MarshalJSON() ([]byte, error) { return nil, nil }
func (*Value) MarshalText() ([]byte, error) { return nil, nil }
`

func TestScanEnforcesSecretAPISurface(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		extra map[string]string
		want  int
	}{
		{name: "approved surface", value: validSecretValueSource},
		{
			name:  "exported raw method",
			value: validSecretValueSource,
			extra: map[string]string{"reveal.go": "package secret\nfunc (*Value) Reveal() []byte { return nil }\n"},
			want:  1,
		},
		{
			name:  "exported raw function",
			value: validSecretValueSource,
			extra: map[string]string{"raw.go": "package secret\nfunc Raw(*Value) []byte { return nil }\n"},
			want:  1,
		},
		{
			name:  "exported callback escape",
			value: validSecretValueSource,
			extra: map[string]string{"with.go": "package secret\nfunc (*Value) WithBytes(func([]byte)) {}\n"},
			want:  1,
		},
		{
			name:  "exported writer escape",
			value: validSecretValueSource,
			extra: map[string]string{"write.go": "package secret\nimport \"io\"\nfunc (*Value) WriteTo(io.Writer) error { return nil }\n"},
			want:  1,
		},
		{
			name:  "alternate constructor",
			value: validSecretValueSource,
			extra: map[string]string{"constructor.go": "package secret\nfunc FromString(string) *Value { return nil }\n"},
			want:  1,
		},
		{
			name:  "exported field",
			value: strings.Replace(validSecretValueSource, "access func(func(*[]byte))", "access func(func(*[]byte)); Bytes []byte", 1),
			want:  1,
		},
		{
			name:  "primitive raw storage",
			value: primitiveSecretValueSource,
			want:  1,
		},
		{
			name:  "wrong constructor signature",
			value: strings.Replace(validSecretValueSource, "func New(value []byte) *Value {\n\treturn &Value{access: func(operation func(*[]byte)) { operation(&value) }}\n}", "func New(string) *Value { return nil }", 1),
			want:  1,
		},
		{
			name:  "wrong approved method signature",
			value: strings.Replace(validSecretValueSource, "func (*Value) Empty() bool { return false }", "func (*Value) Empty() []byte { return nil }", 1),
			want:  1,
		},
		{
			name:  "darwin-only exported accessor",
			value: validSecretValueSource,
			extra: map[string]string{
				"reveal_darwin.go": "package secret\nfunc (*Value) Reveal() []byte { return nil }\n",
			},
			want: 2,
		},
		{
			name:  "custom-tag exported accessor",
			value: validSecretValueSource,
			extra: map[string]string{
				"reveal_custom.go": "//go:build raw_secret_test\n\npackage secret\nfunc (*Value) Reveal() []byte { return nil }\n",
			},
			want: 1,
		},
		{
			name:  "legacy custom-tag exported accessor",
			value: validSecretValueSource,
			extra: map[string]string{
				"reveal_legacy.go": "// +build raw_secret_test\n\npackage secret\nfunc (*Value) Reveal() []byte { return nil }\n",
			},
			want: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			fixtureFiles := map[string]string{"internal/secret/value.go": test.value}
			for name, contents := range test.extra {
				fixtureFiles[filepath.Join("internal/secret", name)] = contents
			}
			writeScanFixtureFiles(t, root, fixtureFiles)
			findings, err := scan(root)
			if err != nil {
				t.Fatalf("scan secret API fixture: %v", err)
			}
			if len(findings) != test.want {
				t.Fatalf("got %d findings (%v), want %d", len(findings), findings, test.want)
			}
		})
	}
}

func TestSecretRawExtractionFormsDoNotCompile(t *testing.T) {
	t.Parallel()

	secretPackage := loadSecretPackage(t)
	tests := []struct {
		name   string
		source string
	}{
		{
			name: "direct call",
			source: `package consumer
import "github.com/thelostorbital/ctrldb/internal/secret"
func expose(value *secret.Value) { _ = value.Reveal() }
`,
		},
		{
			name: "import alias",
			source: `package consumer
import secrets "github.com/thelostorbital/ctrldb/internal/secret"
func expose(value *secrets.Value) { _ = value.Reveal() }
`,
		},
		{
			name: "method value",
			source: `package consumer
import "github.com/thelostorbital/ctrldb/internal/secret"
func expose(value *secret.Value) { reveal := value.Reveal; _ = reveal }
`,
		},
		{
			name: "method expression",
			source: `package consumer
import "github.com/thelostorbital/ctrldb/internal/secret"
var reveal = (*secret.Value).Reveal
`,
		},
		{
			name: "interface indirection",
			source: `package consumer
import "github.com/thelostorbital/ctrldb/internal/secret"
type revealer interface { Reveal() []byte }
func expose(value *secret.Value) { var indirect revealer = value; _ = indirect.Reveal() }
`,
		},
		{
			name: "generic constraint",
			source: `package consumer
import "github.com/thelostorbital/ctrldb/internal/secret"
type revealer interface { Reveal() []byte }
func reveal[T revealer](value T) []byte { return value.Reveal() }
func expose(value *secret.Value) { _ = reveal(value) }
`,
		},
		{
			name: "returned method value",
			source: `package consumer
import "github.com/thelostorbital/ctrldb/internal/secret"
func expose(value *secret.Value) func() []byte { return value.Reveal }
`,
		},
		{
			name: "captured call",
			source: `package consumer
import "github.com/thelostorbital/ctrldb/internal/secret"
func expose(value *secret.Value) func() []byte { return func() []byte { return value.Reveal() } }
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := typeCheckSecretConsumer(test.source, secretPackage); err == nil {
				t.Fatal("raw extraction form compiled without an exported secret accessor")
			}
		})
	}
}

func TestSecretSafeSurfaceAndUnrelatedLookalikeCompile(t *testing.T) {
	t.Parallel()

	secretPackage := loadSecretPackage(t)
	source := `package consumer
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
type lookalike struct{}
func (*lookalike) Reveal() []byte { return nil }
func safe(value *secret.Value, local *lookalike) {
	fmt.Print(value)
	_, _, _ = value.String(), value.GoString(), value.Empty()
	_, _ = value.MarshalJSON()
	_, _ = value.MarshalText()
	value.Zero()
	_ = local.Reveal()
}
`
	if err := typeCheckSecretConsumer(source, secretPackage); err != nil {
		t.Fatalf("safe secret surface did not compile: %v", err)
	}
}

func loadSecretPackage(t *testing.T) *types.Package {
	t.Helper()
	filename := filepath.Join("..", "secret", "value.go")
	contents, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read secret source: %v", err)
	}
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, filename, contents, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse secret source: %v", err)
	}
	checked, err := (&types.Config{Importer: newArchitectureImporter(true)}).Check(secretPackagePath, files, []*ast.File{parsed}, nil)
	if err != nil {
		t.Fatalf("type-check secret package: %v", err)
	}
	return checked
}

type secretConsumerImporter struct {
	secret   *types.Package
	fallback types.Importer
}

func (loader secretConsumerImporter) Import(importPath string) (*types.Package, error) {
	if importPath == secretPackagePath {
		return loader.secret, nil
	}
	return loader.fallback.Import(importPath)
}

func typeCheckSecretConsumer(source string, secretPackage *types.Package) error {
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, "consumer.go", source, parser.SkipObjectResolution)
	if err != nil {
		return err
	}
	loader := secretConsumerImporter{secret: secretPackage, fallback: newArchitectureImporter(true)}
	_, err = (&types.Config{Importer: loader}).Check(modulePath+"/internal/consumer", files, []*ast.File{parsed}, nil)
	return err
}

func TestScanEnforcesVerifierBoundaryThroughObservationContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		observation string
		want        int
	}{
		{
			name:        "safe observation contract",
			observation: "package observation\nimport \"context\"\ntype Observer interface { Observe(context.Context) error }\n",
		},
		{
			name:        "network client hidden behind observation contract",
			observation: "package observation\nimport _ \"net/http\"\ntype Observer interface{}\n",
			want:        1,
		},
		{
			name:        "TLS dialer hidden behind observation contract",
			observation: "package observation\nimport _ \"crypto/tls\"\ntype Observer interface{}\n",
			want:        1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeScanFixtureFiles(t, root, map[string]string{
				"internal/observation/contract.go": test.observation,
				"internal/verify/check.go":         "package verify\nimport _ \"github.com/thelostorbital/ctrldb/internal/observation\"\n",
			})
			findings, err := scan(root)
			if err != nil {
				t.Fatalf("scan transitive verifier boundary: %v", err)
			}
			if len(findings) != test.want {
				t.Fatalf("got %d findings (%v), want %d", len(findings), findings, test.want)
			}
			if test.want != 0 && !strings.HasSuffix(filepath.ToSlash(findings[0].filename), "internal/observation/contract.go") {
				t.Fatalf("finding path = %q, want observation contract", findings[0].filename)
			}
		})
	}
}

func TestScanEnforcesVerifierBoundaryAcrossFirstPartyImportClosure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		files         map[string]string
		findingSuffix string
		wantFinding   bool
	}{
		{
			name: "safe domain dependency",
			files: map[string]string{
				"internal/domain/model.go": "package domain\nimport _ \"context\"\n",
			},
		},
		{
			name: "nested domain TLS dependency",
			files: map[string]string{
				"internal/domain/model.go":       "package domain\nimport _ \"github.com/thelostorbital/ctrldb/internal/domain/support\"\n",
				"internal/domain/support/tls.go": "package support\nimport _ \"crypto/tls\"\n",
			},
			findingSuffix: "internal/domain/support/tls.go",
			wantFinding:   true,
		},
		{
			name: "domain reflection dependency",
			files: map[string]string{
				"internal/domain/model.go": "package domain\nimport _ \"reflect\"\n",
			},
			findingSuffix: "internal/domain/model.go",
			wantFinding:   true,
		},
		{
			name: "domain unsafe dependency",
			files: map[string]string{
				"internal/domain/model.go": "package domain\nimport _ \"unsafe\"\n",
			},
			findingSuffix: "internal/domain/model.go",
			wantFinding:   true,
		},
		{
			name: "domain network dependency",
			files: map[string]string{
				"internal/domain/model.go": "package domain\nimport _ \"net\"\n",
			},
			findingSuffix: "internal/domain/model.go",
			wantFinding:   true,
		},
		{
			name: "domain runner dependency",
			files: map[string]string{
				"internal/domain/model.go": "package domain\nimport _ \"github.com/thelostorbital/ctrldb/internal/runner\"\n",
			},
			findingSuffix: "internal/domain/model.go",
			wantFinding:   true,
		},
		{
			name: "domain workflow dependency",
			files: map[string]string{
				"internal/domain/model.go": "package domain\nimport _ \"github.com/thelostorbital/ctrldb/internal/workflow\"\n",
			},
			findingSuffix: "internal/domain/model.go",
			wantFinding:   true,
		},
		{
			name: "domain provider dependency",
			files: map[string]string{
				"internal/domain/model.go": "package domain\nimport _ \"github.com/thelostorbital/ctrldb/internal/provider\"\n",
			},
			findingSuffix: "internal/domain/model.go",
			wantFinding:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			test.files["internal/verify/check.go"] = "package verify\nimport _ \"github.com/thelostorbital/ctrldb/internal/domain\"\n"
			writeScanFixtureFiles(t, root, test.files)

			findings, err := scan(root)
			if err != nil {
				t.Fatalf("scan verifier import closure: %v", err)
			}
			found := false
			for _, result := range findings {
				if strings.Contains(result.message, "C-VERIFY") && strings.HasSuffix(filepath.ToSlash(result.filename), test.findingSuffix) {
					found = true
				}
			}
			if found != test.wantFinding {
				t.Fatalf("C-VERIFY closure finding = %v, want %v; all findings: %v", found, test.wantFinding, findings)
			}
		})
	}
}

func TestScanChecksUniversalRulesInInactiveDarwinSources(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	files := map[string]string{
		"internal/example/launch_darwin.go": `//go:build !darwin

package example

import _ "os/exec"
`,
		"internal/observation/network_darwin.go": `//go:build !darwin

package observation

import _ "net/http"
`,
	}
	writeScanFixtureFiles(t, root, files)

	findings, err := scan(root)
	if err != nil {
		t.Fatalf("scan inactive Darwin sources: %v", err)
	}
	if len(findings) != len(files) {
		t.Fatalf("got %d findings (%v), want %d universal-rule findings", len(findings), findings, len(files))
	}
	foundByPath := make(map[string]bool, len(findings))
	for _, finding := range findings {
		foundByPath[filepath.ToSlash(finding.filename)] = true
	}
	for name := range files {
		if !foundByPath[filepath.ToSlash(filepath.Join(root, name))] {
			t.Errorf("missing universal-rule finding for %s", name)
		}
	}
}

func writeScanFixtureFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, contents := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
}
