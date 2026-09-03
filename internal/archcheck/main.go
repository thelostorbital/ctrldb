// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Command archcheck enforces architecture constraints that require Go's type
// information and therefore cannot be expressed reliably as syntax patterns.
package main

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

type finding struct {
	filename string
	line     int
	column   int
	message  string
}

var forbiddenProcessImports = map[string]string{
	"os/exec":                  "os/exec is forbidden until an exact validated adapter boundary is introduced",
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
		if filepath.Ext(path) != ".go" {
			return nil
		}

		contents, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		fileFindings, err := findProcessBoundaryViolations(path, contents)
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

func findProcessBoundaryViolations(filename string, contents []byte) ([]finding, error) {
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, filename, contents, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filename, err)
	}

	var findings []finding
	for _, imported := range parsed.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("decode import in %s: %w", filename, err)
		}
		message, forbidden := forbiddenProcessImports[importPath]
		if !forbidden {
			continue
		}
		position := files.Position(imported.Path.Pos())
		findings = append(findings, finding{
			filename: position.Filename,
			line:     position.Line,
			column:   position.Column,
			message:  message,
		})
	}

	uses := make(map[*ast.Ident]types.Object)
	configuration := types.Config{
		Importer:                 importer.Default(),
		DisableUnusedImportCheck: true,
		Error:                    func(error) {},
	}
	_, _ = configuration.Check(parsed.Name.Name, files, []*ast.File{parsed}, &types.Info{Uses: uses})

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
