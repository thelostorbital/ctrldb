// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindArchitectureViolations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		filename string
		source   string
		want     int
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
			name: "linkname directive",
			source: `package fixture
import _ "unsafe"
//go:linkname startProcess os.StartProcess
func startProcess()
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
			name:     "test infrastructure in test",
			filename: "internal/example/fixture_test.go",
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
				t.Fatalf("got %d findings, want %d", len(findings), test.want)
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
