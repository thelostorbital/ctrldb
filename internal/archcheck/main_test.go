// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindProcessBoundaryViolations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		want   int
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
			name:   "raw os exec import",
			source: "package fixture\nimport _ `os/exec`\n",
			want:   1,
		},
		{
			name:   "escaped os exec import",
			source: "package fixture\nimport _ \"o\\x73/ex\\x65c\"\n",
			want:   1,
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			findings, err := findProcessBoundaryViolations("fixture.go", []byte(test.source))
			if err != nil {
				t.Fatalf("find process boundary violations: %v", err)
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
}
