// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Command archcheck enforces architecture constraints that require Go's type
// information and therefore cannot be expressed reliably as syntax patterns.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type finding struct {
	filename string
	line     int
	column   int
	message  string
}

type sourcePolicy struct {
	allowBubbleTeaImport    bool
	allowTestInfrastructure bool
}

var forbiddenProcessImports = map[string]string{
	"C":                        "cgo is forbidden until an exact validated native boundary is introduced",
	"go/build":                 "go/build is forbidden because it can launch the Go tool outside the validated runner adapter",
	"net/http/cgi":             "net/http/cgi is forbidden because it launches executables outside the validated runner adapter",
	"os/exec":                  "os/exec is forbidden until an exact validated adapter boundary is introduced",
	"plugin":                   "dynamic Go plugins are forbidden until an exact validated loading boundary is introduced",
	"syscall":                  "low-level process packages are forbidden; use the validated runner adapter",
	"golang.org/x/sys/execabs": "low-level process packages are forbidden; use the validated runner adapter",
	"golang.org/x/sys/unix":    "low-level process packages are forbidden; use the validated runner adapter",
	"golang.org/x/sys/windows": "low-level process packages are forbidden; use the validated runner adapter",
}

func main() {
	findings, err := scan(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "archcheck: %v\n", err)
		os.Exit(2)
	}

	for _, result := range findings {
		fmt.Fprintf(os.Stderr, "%s:%d:%d: %s\n", result.filename, result.line, result.column, result.message)
	}
	if len(findings) != 0 {
		os.Exit(1)
	}
}

func scan(root string) ([]finding, error) {
	var findings []finding
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		extension := filepath.Ext(path)
		var nativeArtifactMessage string
		switch extension {
		case ".s":
			nativeArtifactMessage = "Go assembly is forbidden until an exact validated native boundary is introduced"
		case ".syso":
			nativeArtifactMessage = "precompiled native object files are forbidden until an exact validated native boundary is introduced"
		case ".swig", ".swigcxx":
			nativeArtifactMessage = "SWIG inputs are forbidden until an exact validated native boundary is introduced"
		case ".go":
		default:
			return nil
		}
		if nativeArtifactMessage != "" {
			findings = append(findings, finding{
				filename: path,
				line:     1,
				column:   1,
				message:  nativeArtifactMessage,
			})
			return nil
		}

		contents, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		relativePath, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("locate %s beneath %s: %w", path, root, err)
		}
		fileFindings, err := findArchitectureViolations(path, contents, policyForSource(relativePath))
		if err != nil {
			return err
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].filename != findings[j].filename {
			return findings[i].filename < findings[j].filename
		}
		if findings[i].line != findings[j].line {
			return findings[i].line < findings[j].line
		}
		return findings[i].column < findings[j].column
	})
	return findings, nil
}

func findArchitectureViolations(filename string, contents []byte, policy sourcePolicy) ([]finding, error) {
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, filename, contents, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filename, err)
	}

	var findings []finding
	for _, group := range parsed.Comments {
		for _, comment := range group.List {
			message, forbidden := forbiddenCompilerDirective(comment.Text)
			if !forbidden {
				continue
			}
			position := files.Position(comment.Pos())
			findings = append(findings, finding{
				filename: position.Filename,
				line:     position.Line,
				column:   position.Column,
				message:  message,
			})
		}
	}
	for _, imported := range parsed.Imports {
		if strings.HasPrefix(imported.Path.Value, "\"") && strings.Contains(imported.Path.Value, `\`) {
			position := files.Position(imported.Path.Pos())
			findings = append(findings, finding{
				filename: position.Filename,
				line:     position.Line,
				column:   position.Column,
				message:  "Go import paths must use their literal spelling; escape sequences are forbidden",
			})
		}
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("decode import in %s: %w", filename, err)
		}
		var messages []string
		if message, forbidden := forbiddenProcessImportMessage(importPath); forbidden {
			messages = append(messages, message)
		}
		if isBubbleTeaImport(importPath) && !policy.allowBubbleTeaImport {
			messages = append(messages, "Bubble Tea is restricted to internal/tui")
		}
		if isTestInfrastructureImport(importPath) && !policy.allowTestInfrastructure {
			messages = append(messages, "production code must not import test-only or fake infrastructure")
		}
		for _, message := range messages {
			position := files.Position(imported.Path.Pos())
			findings = append(findings, finding{
				filename: position.Filename,
				line:     position.Line,
				column:   position.Column,
				message:  message,
			})
		}
	}

	uses := make(map[*ast.Ident]types.Object)
	configuration := types.Config{
		Importer:                 architectureImporter{},
		DisableUnusedImportCheck: true,
		Error:                    func(error) {},
	}
	checkedPackagePath := "github.com/thelostorbital/ctrldb/.archcheck/" + parsed.Name.Name
	_, _ = configuration.Check(checkedPackagePath, files, []*ast.File{parsed}, &types.Info{Uses: uses})

	ast.Inspect(parsed, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		object, ok := uses[identifier].(*types.Func)
		if !ok || object.Name() != "StartProcess" || object.Pkg() == nil || object.Pkg().Path() != "os" {
			return true
		}
		position := files.Position(identifier.Pos())
		findings = append(findings, finding{
			filename: position.Filename,
			line:     position.Line,
			column:   position.Column,
			message:  "os.StartProcess is forbidden; process creation belongs to the validated adapter boundary",
		})
		return true
	})
	return findings, nil
}

// architectureImporter supplies the minimum package metadata needed to
// distinguish the real os.StartProcess symbol from local lookalikes. Unlike
// go/importer.Default, it never invokes the Go tool or any other subprocess.
type architectureImporter struct{}

func (architectureImporter) Import(importPath string) (*types.Package, error) {
	packageName := importPath
	if separator := strings.LastIndexByte(importPath, '/'); separator >= 0 {
		packageName = importPath[separator+1:]
	}
	imported := types.NewPackage(importPath, packageName)
	if importPath == "os" {
		signature := types.NewSignatureType(nil, nil, nil, nil, nil, false)
		imported.Scope().Insert(types.NewFunc(token.NoPos, imported, "StartProcess", signature))
	}
	imported.MarkComplete()
	return imported, nil
}

func policyForSource(relativePath string) sourcePolicy {
	normalized := filepath.ToSlash(filepath.Clean(relativePath))
	policy := sourcePolicy{
		allowBubbleTeaImport:    strings.HasPrefix(normalized, "internal/tui/"),
		allowTestInfrastructure: strings.HasSuffix(normalized, "_test.go"),
	}
	if policy.allowTestInfrastructure {
		return policy
	}

	for _, directory := range strings.Split(filepath.ToSlash(filepath.Dir(relativePath)), "/") {
		switch directory {
		case "test", "tests", "testutil", "testutils", "fake", "fakes", "mock", "mocks", "gomock":
			policy.allowTestInfrastructure = true
			return policy
		}
	}
	return policy
}

func isBubbleTeaImport(importPath string) bool {
	if importPath == "charm.land/bubbletea/v2" || importPath == "github.com/charmbracelet/bubbletea" {
		return true
	}
	version, versioned := strings.CutPrefix(importPath, "github.com/charmbracelet/bubbletea/v")
	if !versioned || version == "" {
		return false
	}
	for _, character := range version {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func isTestInfrastructureImport(importPath string) bool {
	for _, component := range strings.Split(importPath, "/") {
		switch component {
		case "test", "tests", "testing", "httptest", "testutil", "testutils", "fake", "fakes", "mock", "mocks", "gomock":
			return true
		}
	}
	return false
}

func forbiddenProcessImportMessage(importPath string) (string, bool) {
	if message, forbidden := forbiddenProcessImports[importPath]; forbidden {
		return message, true
	}
	if strings.HasPrefix(importPath, "golang.org/x/sys/unix/") ||
		strings.HasPrefix(importPath, "golang.org/x/sys/windows/") {
		return "low-level process packages are forbidden; use the validated runner adapter", true
	}
	return "", false
}

func forbiddenCompilerDirective(comment string) (string, bool) {
	linknameArguments, isLinkname := strings.CutPrefix(comment, "//go:linkname")
	if isLinkname && (linknameArguments == "" || linknameArguments[0] == ' ' || linknameArguments[0] == '\t') {
		return "go:linkname is forbidden; it can bypass validated package boundaries", true
	}
	if strings.HasPrefix(comment, "//go:cgo_") {
		return "go:cgo compiler directives are forbidden; they can link native code outside the validated boundary", true
	}
	return "", false
}
