// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package main

import (
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
			want: 1,
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
		{
			name: "direct secret formatting",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose() { fmt.Printf("%v", secret.New([]byte("fixture"))) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "aliased secret Errorf",
			source: `package fixture
import (
	f "fmt"
	s "github.com/thelostorbital/ctrldb/internal/secret"
)
type credential = s.Value
func expose(value *credential) error { return f.Errorf("credential: %v", value) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "package log",
			source: `package fixture
import (
	"log"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { log.Print(value) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "logger method",
			source: `package fixture
import (
	"log"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { logger := log.Default(); logger.Printf("%v", value) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret nested in struct",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
type envelope struct { value *secret.Value }
func expose(value *secret.Value) { fmt.Print(envelope{value: value}) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret wrapped in interface variable",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { var wrapped any = value; fmt.Print(wrapped) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret wrapped in variadic slice",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { arguments := []any{value}; fmt.Print(arguments...) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "defined secret wrapper",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
type wrapped secret.Value
func expose(value *wrapped) { fmt.Print(value) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "explicit redacted string",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func safe(value *secret.Value) { fmt.Print(value.String()) }
`,
		},
		{
			name: "local secret lookalike",
			source: `package fixture
import "fmt"
type Value struct { bytes []byte }
func safe(value *Value) { fmt.Print(value) }
`,
		},
		{
			name: "shadowed fmt",
			source: `package fixture
type formatter struct{}
func (formatter) Print(...any) {}
func safe() { fmt := formatter{}; fmt.Print(struct{ Value string }{Value: "safe"}) }
`,
		},
		{
			name:     "secret formatting in tests",
			filename: "internal/example/example_test.go",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func exercise(value *secret.Value) { fmt.Print(value) }
`,
		},
		{
			name:     "secret package implementation",
			filename: "internal/secret/format.go",
			source: `package secret
import "fmt"
type Value struct{}
func safe(value *Value) { fmt.Print(value) }
`,
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
		{name: "forbidden-runner.go.txt", want: 1},
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

func TestScanResolvesSecretAliasesAcrossFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	files := map[string]string{
		"types.go": `package fixture
import "github.com/thelostorbital/ctrldb/internal/secret"
type credential = secret.Value
`,
		"format.go": `package fixture
import "fmt"
func expose(value *credential) { fmt.Printf("%v", value) }
`,
	}
	for name, contents := range files {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	findings, err := scan(root)
	if err != nil {
		t.Fatalf("scan cross-file alias: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings (%v), want 1", len(findings), findings)
	}
	if !strings.Contains(findings[0].message, "secret.Value") {
		t.Fatalf("finding message = %q, want secret.Value", findings[0].message)
	}
}
