// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"runtime"
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
			name: "structured logger package function",
			source: `package fixture
import (
	"log/slog"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { slog.Info("credential", "value", value.Reveal()) }
`,
			want:    1,
			message: "including slog",
		},
		{
			name: "structured logger method",
			source: `package fixture
import (
	"log/slog"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { logger := slog.Default(); logger.Error("credential", "value", value.Reveal()) }
`,
			want:    1,
			message: "including slog",
		},
		{
			name: "structured logger safe values",
			source: `package fixture
import "log/slog"
func safe() { slog.Info("status", "value", "redacted") }
`,
		},
		{
			name: "structured logger attached attribute",
			source: `package fixture
import (
	"log/slog"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { _ = slog.With("credential", value.Reveal()) }
`,
			want:    1,
			message: "including slog",
		},
		{
			name: "formatter function alias",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { printer := fmt.Printf; printer("%v", value) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "formatter function alias reassignment",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) {
	var printer func(string, ...any) (int, error)
	printer = fmt.Printf
	printer("%v", value)
}
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "formatter alias through variable indirection",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { first := fmt.Printf; second := first; second("%v", value) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "formatter alias written into container",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) {
	printers := make([]func(string, ...any) (int, error), 1)
	printers[0] = fmt.Printf
	_, _ = printers[0]("%v", value)
}
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "formatter returned by helper",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func printer() func(string, ...any) (int, error) { return fmt.Printf }
func expose(value *secret.Value) { _, _ = printer()("%v", value) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "logger method function alias",
			source: `package fixture
import (
	"log"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { logger := log.Default(); printer := logger.Printf; printer("%v", value) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "formatter passed through helper parameter",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func invoke(printer func(string, ...any) (int, error), value any) { _, _ = printer("%v", value) }
func expose(value *secret.Value) { invoke(fmt.Printf, value) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "formatter function literal alias",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) {
	printer := func(argument any) { fmt.Print(argument) }
	printer(value)
}
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "ordinary formatting helper function alias",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func printValue(value any) { fmt.Print(value) }
func expose(value *secret.Value) { printer := printValue; printer(value) }
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
			name: "secret written into interface field",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
type holder struct { value any }
func expose(value *secret.Value) { var wrapped holder; wrapped.value = value; fmt.Print(wrapped) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret written into interface slice",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { wrapped := make([]any, 1); wrapped[0] = value; fmt.Print(wrapped) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret written into interface map",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { wrapped := map[string]any{}; wrapped["credential"] = value; fmt.Print(wrapped) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret used as interface map key",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { wrapped := map[any]string{}; wrapped[value] = "credential"; fmt.Print(wrapped) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret written through pointer alias",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
type holder struct { value any }
func expose(value *secret.Value) { var wrapped holder; alias := &wrapped; alias.value = value; fmt.Print(wrapped) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret written through ordinary helper",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
type holder struct { value any }
func store(target *holder, value any) { target.value = value }
func expose(value *secret.Value) { var wrapped holder; store(&wrapped, value); fmt.Print(wrapped) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret formatted by interface-dispatched helper",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
type printer interface { Print(any) }
type output struct{}
func (output) Print(value any) { fmt.Print(value) }
func expose(value *secret.Value) { var destination printer = output{}; destination.Print(value) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret copied into interface slice",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { wrapped := make([]any, 1); copy(wrapped, []any{value}); fmt.Print(wrapped) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret sent through interface channel",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { wrapped := make(chan any, 1); wrapped <- value; fmt.Print(<-wrapped) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret propagated through ordinary wrapper",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func wrap(value any) any { return value }
func expose(value *secret.Value) { fmt.Print(wrap(value)) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret returned by assigned closure",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { reveal := func() []byte { return value.Reveal() }; fmt.Print(reveal()) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "safe value returned by assigned closure",
			source: `package fixture
import "fmt"
func safe() { redacted := func() string { return "[redacted]" }; fmt.Print(redacted()) }
`,
		},
		{
			name: "formatter returned as closure",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func Printer() func(any) { return func(value any) { fmt.Print(value) } }
func expose(value *secret.Value) { Printer()(value.Reveal()) }
`,
			want:    2,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "secret-returning closure returned by function",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func Revealer(value *secret.Value) func() []byte { return func() []byte { return value.Reveal() } }
func expose(value *secret.Value) { fmt.Print(Revealer(value)()) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "function literal passed as argument",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func invoke(printer func(any), value any) { printer(value) }
func expose(value *secret.Value) { invoke(func(argument any) { fmt.Print(argument) }, value.Reveal()) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "function literal stored in composite",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) {
	printers := []func(any){func(argument any) { fmt.Print(argument) }}
	printers[0](value.Reveal())
}
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "returned closure accepts safe value",
			source: `package fixture
import "fmt"
func Printer() func(any) { return func(value any) { fmt.Print(value) } }
func safe() { Printer()("[redacted]") }
`,
		},
		{
			name: "formatter closure preserved across tuple destructuring",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func Printer() (func(any), error) { return func(value any) { fmt.Print(value) }, nil }
func expose(value *secret.Value) { printer, _ := Printer(); printer(value.Reveal()) }
`,
			want:    2,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "method receiver retains stored secret",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
type box struct { value any }
func (receiver *box) Put(value any) { receiver.value = value }
func expose(value *secret.Value) { var stored box; stored.Put(value.Reveal()); fmt.Print(stored) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "method receiver retains safe value",
			source: `package fixture
import "fmt"
type box struct { value any }
func (receiver *box) Put(value any) { receiver.value = value }
func safe() { var stored box; stored.Put("[redacted]"); fmt.Print(stored) }
`,
		},
		{
			name: "secret preserved across tuple destructuring",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func pair(value *secret.Value) (any, any) { return value.Reveal(), "safe" }
func expose(value *secret.Value) { revealed, _ := pair(value); fmt.Print(revealed) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name: "safe tuple destructuring",
			source: `package fixture
import "fmt"
func pair() (any, any) { return "safe", 1 }
func safe() { value, _ := pair(); fmt.Print(value) }
`,
		},
		{
			name: "unresolved formatting argument fails closed",
			source: `package fixture
import (
	"fmt"
	"example.test/provider"
)
func expose() { fmt.Print(provider.Credential()) }
`,
			want:    1,
			message: "formatting argument type could not be resolved",
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
			name: "local formatter function alias",
			source: `package fixture
func Print(...any) {}
func safe() { printer := Print; printer("safe") }
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
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name:     "revealed secret formatting in tests",
			filename: "internal/example/example_test.go",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func exercise(value *secret.Value) { fmt.Print(value.Reveal()) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name:     "redacted secret formatting in tests",
			filename: "internal/example/example_test.go",
			source: `package fixture
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func exercise(value *secret.Value) { fmt.Print(value.String()) }
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
		{
			name:     "secret redaction contract assertion",
			filename: "internal/secret/value_test.go",
			source: `package secret_test
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func assertRedacted(value *secret.Value) { _ = fmt.Sprint(value) }
`,
		},
		{
			name:     "secret redaction test cannot output value",
			filename: "internal/secret/value_test.go",
			source: `package secret_test
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { fmt.Print(value) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
		},
		{
			name:     "secret redaction test cannot print reveal",
			filename: "internal/secret/value_test.go",
			source: `package secret_test
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func expose(value *secret.Value) { fmt.Print(value.Reveal()) }
`,
			want:    1,
			message: "secret.Value must not be passed to fmt or log",
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

func TestScanResolvesSecretReturnedByRepositoryPackage(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	files := map[string]string{
		"provider/credential.go": `package provider
import "github.com/thelostorbital/ctrldb/internal/secret"
func Credential() *secret.Value { return nil }
`,
		"consumer/expose.go": `package consumer
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/provider"
)
func expose() { fmt.Printf("%v", provider.Credential()) }
`,
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
		t.Fatalf("scan imported secret result: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings (%v), want 1", len(findings), findings)
	}
	if !strings.Contains(findings[0].message, "secret.Value") || strings.Contains(findings[0].message, "could not be resolved") {
		t.Fatalf("finding message = %q, want resolved secret.Value flow", findings[0].message)
	}
}

func TestScanPropagatesRepositoryPackageFlowSummaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		provider string
		consumer string
		want     int
	}{
		{
			name: "formatting wrapper rejects revealed secret",
			provider: `package provider
import "fmt"
func Print(value any) { fmt.Print(value) }
`,
			consumer: `package consumer
import (
	"github.com/thelostorbital/ctrldb/internal/secret"
	"github.com/thelostorbital/ctrldb/provider"
)
func expose(value *secret.Value) { provider.Print(value.Reveal()) }
`,
			want: 1,
		},
		{
			name: "formatting wrapper accepts safe value",
			provider: `package provider
import "fmt"
func Print(value any) { fmt.Print(value) }
`,
			consumer: `package consumer
import "github.com/thelostorbital/ctrldb/provider"
func safe() { provider.Print("[redacted]") }
`,
		},
		{
			name: "exported formatting closure rejects revealed secret",
			provider: `package provider
import "fmt"
var Print = func(value any) { fmt.Print(value) }
`,
			consumer: `package consumer
import (
	"github.com/thelostorbital/ctrldb/internal/secret"
	"github.com/thelostorbital/ctrldb/provider"
)
func expose(value *secret.Value) { provider.Print(value.Reveal()) }
`,
			want: 1,
		},
		{
			name: "returned formatting closure rejects revealed secret",
			provider: `package provider
import "fmt"
func Printer() func(any) { return func(value any) { fmt.Print(value) } }
`,
			consumer: `package consumer
import (
	"github.com/thelostorbital/ctrldb/internal/secret"
	"github.com/thelostorbital/ctrldb/provider"
)
func expose(value *secret.Value) { provider.Printer()(value.Reveal()) }
`,
			want: 1,
		},
		{
			name: "returned secret closure remains tainted",
			provider: `package provider
import "github.com/thelostorbital/ctrldb/internal/secret"
func Revealer(value *secret.Value) func() []byte { return func() []byte { return value.Reveal() } }
`,
			consumer: `package consumer
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
	"github.com/thelostorbital/ctrldb/provider"
)
func expose(value *secret.Value) { fmt.Print(provider.Revealer(value)()) }
`,
			want: 1,
		},
		{
			name: "typed repository logger rejects revealed secret",
			provider: `package provider
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/internal/secret"
)
func Print(value *secret.Value) { fmt.Print(value.Reveal()) }
`,
			consumer: `package consumer
import (
	"github.com/thelostorbital/ctrldb/internal/secret"
	"github.com/thelostorbital/ctrldb/provider"
)
func expose(value *secret.Value) { provider.Print(value) }
`,
			want: 2,
		},
		{
			name: "erased secret return remains tainted",
			provider: `package provider
import "github.com/thelostorbital/ctrldb/internal/secret"
func Credential() any { return secret.New([]byte("fixture")) }
`,
			consumer: `package consumer
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/provider"
)
func expose() { fmt.Print(provider.Credential()) }
`,
			want: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeScanFixtureFiles(t, root, map[string]string{
				"provider/provider.go": test.provider,
				"consumer/consumer.go": test.consumer,
			})
			findings, err := scan(root)
			if err != nil {
				t.Fatalf("scan repository flow summary: %v", err)
			}
			if len(findings) != test.want {
				t.Fatalf("got %d findings (%v), want %d", len(findings), findings, test.want)
			}
		})
	}
}

func TestScanFailsClosedWhenRepositorySummaryCannotBeResolved(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeScanFixtureFiles(t, root, map[string]string{
		"provider/provider.go": `package provider
func Print(value any) { missingFormatter(value) }
`,
		"consumer/consumer.go": `package consumer
import (
	"github.com/thelostorbital/ctrldb/internal/secret"
	"github.com/thelostorbital/ctrldb/provider"
)
func expose(value *secret.Value) { provider.Print(value.Reveal()) }
`,
	})

	findings, err := scan(root)
	if err != nil {
		t.Fatalf("scan unresolved repository package: %v", err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0].message, "secret.Value") {
		t.Fatalf("findings = %v, want one fail-closed secret-flow finding", findings)
	}
}

func TestScanHonorsRepositoryPackageBuildConstraints(t *testing.T) {
	t.Parallel()

	inactiveGOOS := "windows"
	if runtime.GOOS == inactiveGOOS {
		inactiveGOOS = "linux"
	}
	tests := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{
			name: "filename constraints exclude inactive secret source",
			files: map[string]string{
				"provider/value_" + runtime.GOOS + ".go": `package provider
func Value() string { return "safe" }
`,
				"provider/value_" + inactiveGOOS + ".go": `package provider
import "github.com/thelostorbital/ctrldb/internal/secret"
func Value() *secret.Value { return nil }
`,
			},
		},
		{
			name: "filename constraints include active secret source",
			files: map[string]string{
				"provider/value_" + runtime.GOOS + ".go": `package provider
import "github.com/thelostorbital/ctrldb/internal/secret"
func Value() *secret.Value { return nil }
`,
				"provider/value_" + inactiveGOOS + ".go": `package provider
func Value() string { return "safe" }
`,
			},
			want: 1,
		},
		{
			name: "tag constraints exclude inactive secret source",
			files: map[string]string{
				"provider/value_active.go":   "//go:build " + runtime.GOOS + "\n\npackage provider\nfunc Value() string { return \"safe\" }\n",
				"provider/value_inactive.go": "//go:build !" + runtime.GOOS + "\n\npackage provider\nimport \"github.com/thelostorbital/ctrldb/internal/secret\"\nfunc Value() *secret.Value { return nil }\n",
			},
		},
		{
			name: "tag constraints include active secret source",
			files: map[string]string{
				"provider/value_active.go":   "//go:build " + runtime.GOOS + "\n\npackage provider\nimport \"github.com/thelostorbital/ctrldb/internal/secret\"\nfunc Value() *secret.Value { return nil }\n",
				"provider/value_inactive.go": "//go:build !" + runtime.GOOS + "\n\npackage provider\nfunc Value() string { return \"safe\" }\n",
			},
			want: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			test.files["consumer/consumer.go"] = `package consumer
import (
	"fmt"
	"github.com/thelostorbital/ctrldb/provider"
)
func safe() { fmt.Print(provider.Value()) }
`
			writeScanFixtureFiles(t, root, test.files)
			findings, err := scan(root)
			if err != nil {
				t.Fatalf("scan build-constrained package: %v", err)
			}
			if len(findings) != test.want {
				t.Fatalf("got %d findings (%v), want %d for active build", len(findings), findings, test.want)
			}
		})
	}
}

func TestScanHonorsTopLevelBuildConstraints(t *testing.T) {
	t.Parallel()

	inactiveGOOS := "windows"
	if runtime.GOOS == inactiveGOOS {
		inactiveGOOS = "linux"
	}
	tests := []struct {
		name         string
		activeBody   string
		inactiveBody string
		want         int
	}{
		{
			name:         "inactive formatter is excluded",
			activeBody:   `func emit(value *secret.Value) { _ = value.String() }`,
			inactiveBody: `func emit(value *secret.Value) { fmt.Print(value.Reveal()) }`,
		},
		{
			name:         "active formatter is reported",
			activeBody:   `func emit(value *secret.Value) { fmt.Print(value.Reveal()) }`,
			inactiveBody: `func emit(value *secret.Value) { _ = value.String() }`,
			want:         1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			activePath := "fixture_" + runtime.GOOS + ".go"
			writeScanFixtureFiles(t, root, map[string]string{
				activePath:                        "package fixture\nimport (\n\t\"fmt\"\n\t\"github.com/thelostorbital/ctrldb/internal/secret\"\n)\n" + test.activeBody + "\n",
				"fixture_" + inactiveGOOS + ".go": "package fixture\nimport (\n\t\"fmt\"\n\t\"github.com/thelostorbital/ctrldb/internal/secret\"\n)\n" + test.inactiveBody + "\n",
			})
			findings, err := scan(root)
			if err != nil {
				t.Fatalf("scan build-constrained source set: %v", err)
			}
			if len(findings) != test.want {
				t.Fatalf("got %d findings (%v), want %d", len(findings), findings, test.want)
			}
			if test.want != 0 && filepath.Base(findings[0].filename) != activePath {
				t.Fatalf("finding path = %q, want active file %q", findings[0].filename, activePath)
			}
		})
	}
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
