// Copyright 2026 CtrlBoard.dev
// SPDX-License-Identifier: Apache-2.0

// Command archcheck enforces architecture constraints that require Go's type
// information and therefore cannot be expressed reliably as syntax patterns.
package main

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type finding struct {
	filename string
	line     int
	column   int
	message  string
}

type sourceFile struct {
	filename string
	contents []byte
	policy   sourcePolicy
}

type sourcePolicy struct {
	allowBubbleTeaImport    bool
	allowSecretFormatting   bool
	allowRedactionAssertion bool
	allowSourceImporter     bool
	allowTestInfrastructure bool
	enforceVerifierBoundary bool
}

const (
	modulePath        = "github.com/thelostorbital/ctrldb"
	secretPackagePath = modulePath + "/internal/secret"
)

var formattingFunctions = map[string]map[string]struct{}{
	"fmt": {
		"Append": {}, "Appendf": {}, "Appendln": {},
		"Errorf": {},
		"Fprint": {}, "Fprintf": {}, "Fprintln": {},
		"Print": {}, "Printf": {}, "Println": {},
		"Sprint": {}, "Sprintf": {}, "Sprintln": {},
	},
	"log": {
		"Fatal": {}, "Fatalf": {}, "Fatalln": {},
		"Output": {},
		"Panic":  {}, "Panicf": {}, "Panicln": {},
		"Print": {}, "Printf": {}, "Println": {},
	},
	"log/slog": {
		"Debug": {}, "DebugContext": {},
		"Error": {}, "ErrorContext": {},
		"Info": {}, "InfoContext": {},
		"Log": {}, "LogAttrs": {},
		"With": {},
		"Warn": {}, "WarnContext": {},
	},
}

var verifierSafeStandardImports = map[string]struct{}{
	"bytes": {}, "cmp": {}, "context": {}, "errors": {}, "fmt": {},
	"io": {}, "io/fs": {}, "iter": {}, "log": {}, "log/slog": {},
	"maps": {}, "net/netip": {}, "net/url": {}, "path": {},
	"path/filepath": {}, "reflect": {}, "regexp": {}, "slices": {},
	"sort": {}, "strconv": {}, "strings": {}, "sync": {},
	"sync/atomic": {}, "time": {},
}

var verifierSafeStandardPrefixes = []string{
	"archive/", "compress/", "crypto/", "encoding/", "hash/", "math/", "text/", "unicode/",
}

var forbiddenProcessImports = map[string]string{
	"C":                              "cgo is forbidden until an exact validated native boundary is introduced",
	"go/build":                       "go/build is forbidden because it can launch the Go tool outside the validated runner adapter",
	"go/importer":                    "go/importer is forbidden because its default importer can launch the Go tool outside the validated runner adapter",
	"golang.org/x/tools/go/packages": "go/packages is forbidden because its default driver can launch the Go tool outside the validated runner adapter",
	"net/http/cgi":                   "net/http/cgi is forbidden because it launches executables outside the validated runner adapter",
	"os/exec":                        "os/exec is forbidden until an exact validated adapter boundary is introduced",
	"plugin":                         "dynamic Go plugins are forbidden until an exact validated loading boundary is introduced",
	"syscall":                        "low-level process packages are forbidden; use the validated runner adapter",
	"golang.org/x/sys/execabs":       "low-level process packages are forbidden; use the validated runner adapter",
	"golang.org/x/sys/unix":          "low-level process packages are forbidden; use the validated runner adapter",
	"golang.org/x/sys/windows":       "low-level process packages are forbidden; use the validated runner adapter",
}

var standardLibraryPackages = struct {
	sync.Mutex
	importer types.Importer
	known    map[string]bool
}{
	importer: importer.ForCompiler(token.NewFileSet(), "source", nil),
	known:    make(map[string]bool),
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
	sourcesByDirectory := make(map[string][]sourceFile)
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
		policy := policyForSource(relativePath)
		syntaxPolicy := policy
		syntaxPolicy.allowSecretFormatting = true
		fileFindings, err := findArchitectureViolations(path, contents, syntaxPolicy)
		if err != nil {
			return err
		}
		findings = append(findings, fileFindings...)
		matches, matchErr := build.Default.MatchFile(filepath.Dir(path), filepath.Base(path))
		if matchErr != nil {
			return fmt.Errorf("evaluate build constraints for %s: %w", path, matchErr)
		}
		if !matches {
			return nil
		}
		sourcesByDirectory[filepath.Dir(path)] = append(sourcesByDirectory[filepath.Dir(path)], sourceFile{
			filename: path,
			contents: contents,
			policy:   policy,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	packageImporter := newArchitectureImporter(root)
	for _, directorySources := range sourcesByDirectory {
		packageFindings, err := findPackageSecretViolations(directorySources, packageImporter)
		if err != nil {
			return nil, err
		}
		findings = append(findings, packageFindings...)
	}
	findings = uniqueFindings(findings)

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

func findPackageSecretViolations(sources []sourceFile, packageImporter *architectureImporter) ([]finding, error) {
	parsedByPackage := make(map[string][]*ast.File)
	policies := make(map[*ast.File]sourcePolicy, len(sources))
	files := token.NewFileSet()
	for _, source := range sources {
		parsed, err := parser.ParseFile(files, source.filename, source.contents, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", source.filename, err)
		}
		parsedByPackage[parsed.Name.Name] = append(parsedByPackage[parsed.Name.Name], parsed)
		policies[parsed] = source.policy
	}

	var findings []finding
	for packageName, parsedFiles := range parsedByPackage {
		uses := make(map[*ast.Ident]types.Object)
		definitions := make(map[*ast.Ident]types.Object)
		expressionTypes := make(map[ast.Expr]types.TypeAndValue)
		selections := make(map[*ast.SelectorExpr]*types.Selection)
		information := &types.Info{Defs: definitions, Selections: selections, Types: expressionTypes, Uses: uses}
		configuration := types.Config{
			Importer:                 packageImporter,
			DisableUnusedImportCheck: true,
			Error:                    func(error) {},
		}
		checkedPackage, _ := configuration.Check(modulePath+"/.archcheck/package/"+packageName, files, parsedFiles, information)
		facts := findFlowFacts(parsedFiles, information, checkedPackage, packageImporter.summaries, nil)

		for _, parsed := range parsedFiles {
			if policies[parsed].allowSecretFormatting {
				continue
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || !isFormattingCall(call, information, facts) {
					return true
				}
				allowRedactionAssertion := policies[parsed].allowRedactionAssertion && isRedactionAssertionCall(call, information)
				for _, argument := range call.Args {
					message := formattingArgumentViolationMessage(argument, information, facts, allowRedactionAssertion)
					if message == "" {
						continue
					}
					position := files.Position(call.Fun.Pos())
					findings = append(findings, finding{
						filename: position.Filename,
						line:     position.Line,
						column:   position.Column,
						message:  message,
					})
					break
				}
				return true
			})
		}
	}
	return findings, nil
}

func uniqueFindings(findings []finding) []finding {
	seen := make(map[finding]struct{}, len(findings))
	unique := make([]finding, 0, len(findings))
	for _, result := range findings {
		if _, duplicate := seen[result]; duplicate {
			continue
		}
		seen[result] = struct{}{}
		unique = append(unique, result)
	}
	return unique
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
		if message, forbidden := forbiddenProcessImportMessage(importPath, policy); forbidden {
			messages = append(messages, message)
		}
		if isBubbleTeaImport(importPath) && !policy.allowBubbleTeaImport {
			messages = append(messages, "Bubble Tea is restricted to internal/tui")
		}
		if isTestInfrastructureImport(importPath) && !policy.allowTestInfrastructure {
			messages = append(messages, "production code must not import test-only or fake infrastructure")
		}
		if policy.enforceVerifierBoundary {
			if message, forbidden := forbiddenVerifierImportMessage(importPath); forbidden {
				messages = append(messages, message)
			}
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
	definitions := make(map[*ast.Ident]types.Object)
	expressionTypes := make(map[ast.Expr]types.TypeAndValue)
	selections := make(map[*ast.SelectorExpr]*types.Selection)
	packageImporter := newArchitectureImporter("")
	configuration := types.Config{
		Importer:                 packageImporter,
		DisableUnusedImportCheck: true,
		Error:                    func(error) {},
	}
	checkedPackagePath := modulePath + "/.archcheck/" + parsed.Name.Name
	typeInformation := &types.Info{
		Defs:       definitions,
		Selections: selections,
		Types:      expressionTypes,
		Uses:       uses,
	}
	checkedPackage, _ := configuration.Check(checkedPackagePath, files, []*ast.File{parsed}, typeInformation)
	facts := findFlowFacts([]*ast.File{parsed}, typeInformation, checkedPackage, packageImporter.summaries, nil)

	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && !policy.allowSecretFormatting && isFormattingCall(call, typeInformation, facts) {
			allowRedactionAssertion := policy.allowRedactionAssertion && isRedactionAssertionCall(call, typeInformation)
			for _, argument := range call.Args {
				message := formattingArgumentViolationMessage(argument, typeInformation, facts, allowRedactionAssertion)
				if message == "" {
					continue
				}
				position := files.Position(call.Fun.Pos())
				findings = append(findings, finding{
					filename: position.Filename,
					line:     position.Line,
					column:   position.Column,
					message:  message,
				})
				break
			}
		}

		identifier, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		object, ok := uses[identifier].(*types.Func)
		if !ok || object.Pkg() == nil {
			return true
		}
		if object.Pkg().Path() == "go/importer" && object.Name() == "Default" {
			position := files.Position(identifier.Pos())
			findings = append(findings, finding{
				filename: position.Filename,
				line:     position.Line,
				column:   position.Column,
				message:  "go/importer.Default is forbidden; use the source importer without invoking the Go tool",
			})
			return true
		}
		if object.Name() != "StartProcess" || object.Pkg().Path() != "os" {
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

// architectureImporter resolves repository packages from source and standard
// library packages through the source importer. It never invokes the Go tool.
// Third-party packages are represented by closed stubs: they cannot import the
// repository's internal secret package, and any unresolved value reaching a
// formatting boundary is rejected separately.
type architectureImporter struct {
	root      string
	files     *token.FileSet
	standard  types.Importer
	packages  map[string]*types.Package
	loading   map[string]bool
	summaries *flowSummaries
}

func newArchitectureImporter(root string) *architectureImporter {
	files := token.NewFileSet()
	loader := &architectureImporter{
		root:      root,
		files:     files,
		packages:  make(map[string]*types.Package),
		loading:   make(map[string]bool),
		summaries: newFlowSummaries(),
	}
	if root != "" {
		loader.standard = importer.ForCompiler(files, "source", nil)
	}
	return loader
}

func (loader *architectureImporter) Import(importPath string) (*types.Package, error) {
	if imported, ok := loader.packages[importPath]; ok {
		return imported, nil
	}
	if importPath != secretPackagePath && loader.root != "" && strings.HasPrefix(importPath, modulePath+"/") {
		return loader.importRepositoryPackage(importPath)
	}
	if importPath != secretPackagePath && loader.standard != nil && isStandardLibraryImport(importPath) {
		if imported, err := loader.standard.Import(importPath); err == nil {
			loader.packages[importPath] = imported
			return imported, nil
		}
	}

	packageName := importPath
	if separator := strings.LastIndexByte(importPath, '/'); separator >= 0 {
		packageName = importPath[separator+1:]
	}
	imported := types.NewPackage(importPath, packageName)
	switch importPath {
	case "fmt":
		for name := range formattingFunctions["fmt"] {
			var results []types.Type
			switch name {
			case "Errorf":
				results = []types.Type{types.Universe.Lookup("error").Type()}
			case "Sprint", "Sprintf", "Sprintln":
				results = []types.Type{types.Typ[types.String]}
			case "Append", "Appendf", "Appendln":
				results = []types.Type{types.NewSlice(types.Typ[types.Byte])}
			}
			addFunction(imported, name, results)
		}
	case "log":
		addVariadicFunctions(imported, formattingFunctions["log"])
		addLoggerType(imported, formattingFunctions["log"])
	case "log/slog":
		addVariadicFunctions(imported, formattingFunctions["log/slog"])
		addLoggerType(imported, formattingFunctions["log/slog"])
	case "go/importer":
		// The syntax-only unit-test importer needs enough metadata to prove
		// importer.Default is rejected even where importing go/importer itself
		// is explicitly permitted.
		addFunction(imported, "Default", nil)
		addFunction(imported, "ForCompiler", nil)
	case "os":
		signature := types.NewSignatureType(nil, nil, nil, nil, nil, false)
		imported.Scope().Insert(types.NewFunc(token.NoPos, imported, "StartProcess", signature))
	case secretPackagePath:
		secretValue := types.NewNamed(
			types.NewTypeName(token.NoPos, imported, "Value", nil),
			types.NewStruct([]*types.Var{types.NewField(token.NoPos, imported, "bytes", types.NewSlice(types.Typ[types.Byte]), false)}, nil),
			nil,
		)
		imported.Scope().Insert(secretValue.Obj())
		receiver := types.NewVar(token.NoPos, imported, "value", types.NewPointer(secretValue))
		for _, name := range []string{"String", "GoString"} {
			secretValue.AddMethod(types.NewFunc(token.NoPos, imported, name, fixedSignature(receiver, []types.Type{types.Typ[types.String]})))
		}
		secretValue.AddMethod(types.NewFunc(token.NoPos, imported, "Reveal", fixedSignature(receiver, []types.Type{types.NewSlice(types.Typ[types.Byte])})))
		secretValue.AddMethod(types.NewFunc(token.NoPos, imported, "Empty", fixedSignature(receiver, []types.Type{types.Typ[types.Bool]})))
		secretValue.AddMethod(types.NewFunc(token.NoPos, imported, "Zero", fixedSignature(receiver, nil)))
		for _, name := range []string{"MarshalJSON", "MarshalText"} {
			secretValue.AddMethod(types.NewFunc(token.NoPos, imported, name, fixedSignature(receiver, []types.Type{
				types.NewSlice(types.Typ[types.Byte]),
				types.Universe.Lookup("error").Type(),
			})))
		}
		addFunction(imported, "New", []types.Type{types.NewPointer(secretValue)})
	}
	imported.MarkComplete()
	loader.packages[importPath] = imported
	return imported, nil
}

func addLoggerType(imported *types.Package, methods map[string]struct{}) {
	logger := types.NewNamed(types.NewTypeName(token.NoPos, imported, "Logger", nil), types.NewStruct(nil, nil), nil)
	imported.Scope().Insert(logger.Obj())
	for name := range methods {
		receiver := types.NewVar(token.NoPos, imported, "logger", types.NewPointer(logger))
		logger.AddMethod(types.NewFunc(token.NoPos, imported, name, variadicSignature(receiver, nil)))
	}
	addFunction(imported, "Default", []types.Type{types.NewPointer(logger)})
	addFunction(imported, "New", []types.Type{types.NewPointer(logger)})
}

func (loader *architectureImporter) importRepositoryPackage(importPath string) (*types.Package, error) {
	if loader.loading[importPath] {
		return nil, fmt.Errorf("repository import cycle involving %s", importPath)
	}
	loader.loading[importPath] = true
	defer delete(loader.loading, importPath)

	relative := strings.TrimPrefix(importPath, modulePath+"/")
	directory := filepath.Join(loader.root, filepath.FromSlash(relative))
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read repository package %s: %w", importPath, err)
	}
	var parsedFiles []*ast.File
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		filename := filepath.Join(directory, entry.Name())
		matches, matchErr := build.Default.MatchFile(directory, entry.Name())
		if matchErr != nil {
			return nil, fmt.Errorf("evaluate build constraints for %s: %w", filename, matchErr)
		}
		if !matches {
			continue
		}
		contents, readErr := os.ReadFile(filename)
		if readErr != nil {
			return nil, fmt.Errorf("read repository package %s: %w", importPath, readErr)
		}
		parsed, parseErr := parser.ParseFile(loader.files, filename, contents, parser.SkipObjectResolution)
		if parseErr != nil {
			return nil, fmt.Errorf("parse repository package %s: %w", importPath, parseErr)
		}
		parsedFiles = append(parsedFiles, parsed)
	}
	if len(parsedFiles) == 0 {
		return nil, fmt.Errorf("repository package %s has no source files", importPath)
	}

	uses := make(map[*ast.Ident]types.Object)
	definitions := make(map[*ast.Ident]types.Object)
	expressionTypes := make(map[ast.Expr]types.TypeAndValue)
	selections := make(map[*ast.SelectorExpr]*types.Selection)
	information := &types.Info{Defs: definitions, Selections: selections, Types: expressionTypes, Uses: uses}
	configuration := types.Config{
		Importer:                 loader,
		DisableUnusedImportCheck: true,
		Error:                    func(error) {},
	}
	imported, checkErr := configuration.Check(importPath, loader.files, parsedFiles, information)
	loader.packages[importPath] = imported
	if checkErr != nil {
		// A repository package may depend on an intentionally opaque third-party
		// stub. Preserve the usable partial type information, but conservatively
		// treat every exported object from that package as a potential formatter
		// so an unresolved check cannot hide a secret-bearing call.
		for _, object := range information.Defs {
			if object != nil && object.Pkg() == imported && ast.IsExported(object.Name()) {
				loader.summaries.formattingFunctions[object] = true
			}
		}
	}
	loader.summarizeRepositoryPackage(parsedFiles, information, imported)
	return imported, nil
}

func (loader *architectureImporter) summarizeRepositoryPackage(parsedFiles []*ast.File, information *types.Info, imported *types.Package) {
	actual := findFlowFacts(parsedFiles, information, imported, loader.summaries, nil)
	summarizeParameterFlows(parsedFiles, information, actual, loader.summaries)
	for object := range actual.secretObjects {
		if object.Pkg() == imported {
			loader.summaries.secretObjects[object] = true
		}
	}
	for object := range actual.secretReturns {
		if object.Pkg() == imported {
			loader.summaries.secretReturns[object] = true
		}
	}
	for object := range actual.formatterReturns {
		if object.Pkg() == imported {
			loader.summaries.formatterReturns[object] = true
		}
	}
	for object := range actual.formatterObjects {
		if object.Pkg() == imported {
			loader.summaries.formattingFunctions[object] = true
		}
	}

	var parameters []types.Object
	for function, functionParameters := range actual.functionParameters {
		if function.Pkg() != imported {
			continue
		}
		for _, parameter := range functionParameters {
			if parameter != nil {
				parameters = append(parameters, parameter)
			}
		}
	}
	for _, literalParameters := range actual.literalParameters {
		for _, parameter := range literalParameters {
			if parameter != nil {
				parameters = append(parameters, parameter)
			}
		}
	}
	for changed := true; changed; {
		changed = false
		symbolic := findFlowFacts(parsedFiles, information, imported, loader.summaries, parameters)
		for object := range symbolic.formatterReturns {
			if object.Pkg() == imported && !loader.summaries.formatterReturns[object] {
				loader.summaries.formatterReturns[object] = true
				changed = true
			}
		}
		for _, parsed := range parsedFiles {
			for _, declaration := range parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}
				object := information.Defs[function.Name]
				if functionBodyFormatsSecret(function.Body, information, symbolic) && !loader.summaries.formattingFunctions[object] {
					loader.summaries.formattingFunctions[object] = true
					changed = true
				}
			}
		}
		for object, literals := range symbolic.functionLiterals {
			if object.Pkg() != imported || loader.summaries.formattingFunctions[object] {
				continue
			}
			for literal := range literals {
				if functionBodyFormatsSecret(literal.Body, information, symbolic) {
					loader.summaries.formattingFunctions[object] = true
					changed = true
					break
				}
			}
		}
	}
}

func summarizeParameterFlows(parsedFiles []*ast.File, information *types.Info, facts *flowFacts, summaries *flowSummaries) {
	for _, parsed := range parsedFiles {
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			object := information.Defs[function.Name]
			parameters := facts.functionParameters[object]
			parameterIndexes := make(map[types.Object]int, len(parameters))
			for index, parameter := range parameters {
				if parameter != nil {
					parameterIndexes[parameter] = index
				}
			}
			parameterDependencies := functionParameterDependencies(function.Body, information, parameterIndexes, facts.aliases)
			receiver := facts.functionReceivers[object]
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if _, nested := node.(*ast.FuncLit); nested {
					return false
				}
				switch statement := node.(type) {
				case *ast.CallExpr:
					for _, callbackIndex := range directParameterIndexes(statement.Fun, information, parameterDependencies, facts.aliases) {
						invocation := callbackInvocation{callbackParameter: callbackIndex, argumentParameters: make([][]int, len(statement.Args))}
						for index, argument := range statement.Args {
							invocation.argumentParameters[index] = expressionParameterIndexes(argument, information, parameterDependencies, facts.aliases)
						}
						summaries.callbackInvocations[object] = appendUniqueCallbackInvocation(summaries.callbackInvocations[object], invocation)
					}
				case *ast.AssignStmt:
					if receiver == nil || len(statement.Lhs) != len(statement.Rhs) {
						return true
					}
					for index, target := range statement.Lhs {
						if !objectsRelated(flowRootObject(target, information), receiver, facts.aliases) ||
							!receiverMutationObservable(target, information) {
							continue
						}
						for _, parameterIndex := range expressionParameterIndexes(statement.Rhs[index], information, parameterDependencies, facts.aliases) {
							summaries.receiverMutations[object] = appendUniqueInt(summaries.receiverMutations[object], parameterIndex)
						}
					}
				}
				return true
			})
		}
	}
}

func functionParameterDependencies(body *ast.BlockStmt, information *types.Info, indexes map[types.Object]int, aliases map[types.Object]map[types.Object]bool) map[types.Object][]int {
	dependencies := make(map[types.Object][]int, len(indexes))
	for object, index := range indexes {
		dependencies[object] = []int{index}
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			switch statement := node.(type) {
			case *ast.AssignStmt:
				if propagateParameterDependencies(statement.Lhs, statement.Rhs, information, dependencies, aliases) {
					changed = true
				}
			case *ast.ValueSpec:
				left := make([]ast.Expr, 0, len(statement.Names))
				for _, name := range statement.Names {
					left = append(left, name)
				}
				if propagateParameterDependencies(left, statement.Values, information, dependencies, aliases) {
					changed = true
				}
			}
			return true
		})
	}
	return dependencies
}

func propagateParameterDependencies(left, right []ast.Expr, information *types.Info, dependencies map[types.Object][]int, aliases map[types.Object]map[types.Object]bool) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	if len(left) == len(right) {
		changed := false
		for index := range left {
			changed = addParameterDependencies(flowRootObject(left[index], information), expressionParameterIndexes(right[index], information, dependencies, aliases), dependencies) || changed
		}
		return changed
	}
	var combined []int
	for _, expression := range right {
		combined = appendUniqueInts(combined, expressionParameterIndexes(expression, information, dependencies, aliases)...)
	}
	changed := false
	for _, target := range left {
		changed = addParameterDependencies(flowRootObject(target, information), combined, dependencies) || changed
	}
	return changed
}

func addParameterDependencies(object types.Object, indexes []int, dependencies map[types.Object][]int) bool {
	if object == nil || len(indexes) == 0 {
		return false
	}
	updated := appendUniqueInts(dependencies[object], indexes...)
	if len(updated) == len(dependencies[object]) {
		return false
	}
	dependencies[object] = updated
	return true
}

func directParameterIndexes(expression ast.Expr, information *types.Info, dependencies map[types.Object][]int, aliases map[types.Object]map[types.Object]bool) []int {
	var indexes []int
	for _, object := range []types.Object{expressionObject(expression, information), flowRootObject(expression, information)} {
		indexes = appendUniqueInts(indexes, relatedParameterIndexes(object, dependencies, aliases)...)
	}
	return indexes
}

func expressionParameterIndexes(expression ast.Expr, information *types.Info, dependencies map[types.Object][]int, aliases map[types.Object]map[types.Object]bool) []int {
	var indexes []int
	ast.Inspect(expression, func(node ast.Node) bool {
		value, ok := node.(ast.Expr)
		if !ok {
			return true
		}
		indexes = appendUniqueInts(indexes, relatedParameterIndexes(expressionObject(value, information), dependencies, aliases)...)
		return true
	})
	return indexes
}

func relatedParameterIndexes(root types.Object, dependencies map[types.Object][]int, aliases map[types.Object]map[types.Object]bool) []int {
	var indexes []int
	seen := make(map[types.Object]bool)
	pending := []types.Object{root}
	for len(pending) != 0 {
		object := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if object == nil || seen[object] {
			continue
		}
		seen[object] = true
		indexes = appendUniqueInts(indexes, dependencies[object]...)
		for alias := range aliases[object] {
			pending = append(pending, alias)
		}
	}
	return indexes
}

func objectsRelated(left, right types.Object, aliases map[types.Object]map[types.Object]bool) bool {
	if left == nil || right == nil {
		return false
	}
	return len(relatedParameterIndexes(left, map[types.Object][]int{right: []int{0}}, aliases)) != 0
}

func receiverMutationObservable(target ast.Expr, information *types.Info) bool {
	switch value := target.(type) {
	case *ast.ParenExpr:
		return receiverMutationObservable(value.X, information)
	case *ast.SelectorExpr:
		return isReferenceLike(information.TypeOf(value.X)) || receiverMutationObservable(value.X, information)
	case *ast.IndexExpr:
		return isReferenceLike(information.TypeOf(value.X)) || receiverMutationObservable(value.X, information)
	case *ast.StarExpr:
		return isReferenceLike(information.TypeOf(value.X))
	default:
		return false
	}
}

func appendUniqueCallbackInvocation(existing []callbackInvocation, candidate callbackInvocation) []callbackInvocation {
	for _, invocation := range existing {
		if invocation.callbackParameter != candidate.callbackParameter || len(invocation.argumentParameters) != len(candidate.argumentParameters) {
			continue
		}
		equal := true
		for index := range invocation.argumentParameters {
			if !equalInts(invocation.argumentParameters[index], candidate.argumentParameters[index]) {
				equal = false
				break
			}
		}
		if equal {
			return existing
		}
	}
	return append(existing, candidate)
}

func appendUniqueInts(existing []int, candidates ...int) []int {
	for _, candidate := range candidates {
		existing = appendUniqueInt(existing, candidate)
	}
	sort.Ints(existing)
	return existing
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func appendUniqueInt(existing []int, candidate int) []int {
	for _, value := range existing {
		if value == candidate {
			return existing
		}
	}
	return append(existing, candidate)
}

func functionBodyFormatsSecret(body *ast.BlockStmt, information *types.Info, facts *flowFacts) bool {
	formatsSecret := false
	ast.Inspect(body, func(node ast.Node) bool {
		if formatsSecret {
			return false
		}
		if _, nestedFunction := node.(*ast.FuncLit); nestedFunction {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok || !isFormattingCall(call, information, facts) {
			return true
		}
		for _, argument := range call.Args {
			if expressionContainsSecret(argument, information, facts) {
				formatsSecret = true
				break
			}
		}
		return !formatsSecret
	})
	return formatsSecret
}

func addVariadicFunctions(imported *types.Package, names map[string]struct{}) {
	for name := range names {
		addFunction(imported, name, nil)
	}
}

func addFunction(imported *types.Package, name string, results []types.Type) {
	imported.Scope().Insert(types.NewFunc(token.NoPos, imported, name, variadicSignature(nil, results)))
}

func variadicSignature(receiver *types.Var, resultTypes []types.Type) *types.Signature {
	anyType := types.NewInterfaceType(nil, nil)
	anyType.Complete()
	parameters := types.NewTuple(types.NewVar(token.NoPos, nil, "arguments", types.NewSlice(anyType)))
	return types.NewSignatureType(receiver, nil, nil, parameters, tupleOf(resultTypes), true)
}

func fixedSignature(receiver *types.Var, resultTypes []types.Type) *types.Signature {
	return types.NewSignatureType(receiver, nil, nil, nil, tupleOf(resultTypes), false)
}

func tupleOf(typeList []types.Type) *types.Tuple {
	variables := make([]*types.Var, 0, len(typeList))
	for index, resultType := range typeList {
		variables = append(variables, types.NewVar(token.NoPos, nil, fmt.Sprintf("result%d", index), resultType))
	}
	return types.NewTuple(variables...)
}

func policyForSource(relativePath string) sourcePolicy {
	normalized := filepath.ToSlash(filepath.Clean(relativePath))
	policy := sourcePolicy{
		allowBubbleTeaImport:    strings.HasPrefix(normalized, "internal/tui/"),
		allowSecretFormatting:   strings.HasPrefix(normalized, "internal/secret/") && !strings.HasSuffix(normalized, "_test.go"),
		allowRedactionAssertion: normalized == "internal/secret/value_test.go",
		allowSourceImporter:     normalized == "internal/archcheck/main.go",
		allowTestInfrastructure: strings.HasSuffix(normalized, "_test.go"),
		enforceVerifierBoundary: strings.HasPrefix(normalized, "internal/verify/") || strings.HasPrefix(normalized, "internal/observation/"),
	}
	if policy.allowTestInfrastructure {
		return policy
	}

	for _, directory := range strings.Split(filepath.ToSlash(filepath.Dir(relativePath)), "/") {
		switch directory {
		case "test", "tests", "testdata", "testutil", "testutils", "fake", "fakes", "mock", "mocks", "gomock":
			policy.allowTestInfrastructure = true
			return policy
		}
	}
	return policy
}

func forbiddenVerifierImportMessage(importPath string) (string, bool) {
	if verifierSafeStandardImport(importPath) {
		return "", false
	}
	if internalPath, internal := strings.CutPrefix(importPath, modulePath+"/internal/"); internal {
		if internalPath == "observation" {
			return "", false
		}
		component := strings.Split(internalPath, "/")[0]
		switch component {
		case "domain", "verify":
			return "", false
		}
	}
	return "C-VERIFY may import only approved side-effect-free standard-library packages, internal/domain, internal/verify, and read-only observation contracts", true
}

func verifierSafeStandardImport(importPath string) bool {
	if _, allowed := verifierSafeStandardImports[importPath]; allowed {
		return isStandardLibraryImport(importPath)
	}
	for _, prefix := range verifierSafeStandardPrefixes {
		if strings.HasPrefix(importPath, prefix) {
			return isStandardLibraryImport(importPath)
		}
	}
	return false
}

type flowFacts struct {
	secretObjects           map[types.Object]bool
	formatterObjects        map[types.Object]bool
	secretReturns           map[types.Object]bool
	formatterReturns        map[types.Object]bool
	functionParameters      map[types.Object][]types.Object
	functionReceivers       map[types.Object]types.Object
	methodParameters        map[string][][]types.Object
	methodReceivers         map[string][]types.Object
	aliases                 map[types.Object]map[types.Object]bool
	functionLiterals        map[types.Object]map[*ast.FuncLit]bool
	functionLiteralReturns  map[types.Object]map[*ast.FuncLit]bool
	literalParameters       map[*ast.FuncLit][]types.Object
	literalSecretReturns    map[*ast.FuncLit]bool
	literalFormatterReturns map[*ast.FuncLit]bool
	literalLiteralReturns   map[*ast.FuncLit]map[*ast.FuncLit]bool
	formatterLiterals       map[*ast.FuncLit]bool
	callbackInvocations     map[types.Object][]callbackInvocation
	receiverMutations       map[types.Object][]int
	literals                []*ast.FuncLit
}

type callbackInvocation struct {
	callbackParameter  int
	argumentParameters [][]int
}

type flowSummaries struct {
	secretObjects       map[types.Object]bool
	secretReturns       map[types.Object]bool
	formatterReturns    map[types.Object]bool
	formattingFunctions map[types.Object]bool
	callbackInvocations map[types.Object][]callbackInvocation
	receiverMutations   map[types.Object][]int
}

func newFlowSummaries() *flowSummaries {
	return &flowSummaries{
		secretObjects:       make(map[types.Object]bool),
		secretReturns:       make(map[types.Object]bool),
		formatterReturns:    make(map[types.Object]bool),
		formattingFunctions: make(map[types.Object]bool),
		callbackInvocations: make(map[types.Object][]callbackInvocation),
		receiverMutations:   make(map[types.Object][]int),
	}
}

func newFlowFacts(summaries *flowSummaries) *flowFacts {
	facts := &flowFacts{
		secretObjects:           make(map[types.Object]bool),
		formatterObjects:        make(map[types.Object]bool),
		secretReturns:           make(map[types.Object]bool),
		formatterReturns:        make(map[types.Object]bool),
		functionParameters:      make(map[types.Object][]types.Object),
		functionReceivers:       make(map[types.Object]types.Object),
		methodParameters:        make(map[string][][]types.Object),
		methodReceivers:         make(map[string][]types.Object),
		aliases:                 make(map[types.Object]map[types.Object]bool),
		functionLiterals:        make(map[types.Object]map[*ast.FuncLit]bool),
		functionLiteralReturns:  make(map[types.Object]map[*ast.FuncLit]bool),
		literalParameters:       make(map[*ast.FuncLit][]types.Object),
		literalSecretReturns:    make(map[*ast.FuncLit]bool),
		literalFormatterReturns: make(map[*ast.FuncLit]bool),
		literalLiteralReturns:   make(map[*ast.FuncLit]map[*ast.FuncLit]bool),
		formatterLiterals:       make(map[*ast.FuncLit]bool),
		callbackInvocations:     make(map[types.Object][]callbackInvocation),
		receiverMutations:       make(map[types.Object][]int),
	}
	if summaries == nil {
		return facts
	}
	for object := range summaries.secretObjects {
		facts.secretObjects[object] = true
	}
	for object := range summaries.secretReturns {
		facts.secretReturns[object] = true
	}
	for object := range summaries.formatterReturns {
		facts.formatterReturns[object] = true
	}
	for object := range summaries.formattingFunctions {
		facts.formatterObjects[object] = true
	}
	for object, invocations := range summaries.callbackInvocations {
		facts.callbackInvocations[object] = append([]callbackInvocation(nil), invocations...)
	}
	for object, parameters := range summaries.receiverMutations {
		facts.receiverMutations[object] = append([]int(nil), parameters...)
	}
	return facts
}

func findFlowFacts(parsedFiles []*ast.File, information *types.Info, checkedPackage *types.Package, summaries *flowSummaries, seedSecrets []types.Object) *flowFacts {
	facts := newFlowFacts(summaries)
	for _, parsed := range parsedFiles {
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			object := information.Defs[function.Name]
			if object == nil || function.Type.Params == nil {
				continue
			}
			parameters := parameterObjects(function.Type.Params, information)
			facts.functionParameters[object] = parameters
			if function.Recv != nil {
				receivers := parameterObjects(function.Recv, information)
				if len(receivers) != 0 {
					facts.functionReceivers[object] = receivers[0]
					facts.methodReceivers[function.Name.Name] = append(facts.methodReceivers[function.Name.Name], receivers[0])
				}
				facts.methodParameters[function.Name.Name] = append(facts.methodParameters[function.Name.Name], parameters)
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			literal, ok := node.(*ast.FuncLit)
			if !ok {
				return true
			}
			facts.literals = append(facts.literals, literal)
			facts.literalParameters[literal] = parameterObjects(literal.Type.Params, information)
			return true
		})
	}
	for _, object := range seedSecrets {
		markObject(object, facts.secretObjects)
	}

	for changed := true; changed; {
		changed = false
		for _, parsed := range parsedFiles {
			ast.Inspect(parsed, func(node ast.Node) bool {
				switch statement := node.(type) {
				case *ast.AssignStmt:
					if propagateAssignments(statement.Lhs, statement.Rhs, information, facts) {
						changed = true
					}
				case *ast.ValueSpec:
					left := make([]ast.Expr, 0, len(statement.Names))
					for _, name := range statement.Names {
						left = append(left, name)
					}
					if propagateAssignments(left, statement.Values, information, facts) {
						changed = true
					}
				case *ast.CallExpr:
					if propagateCallArguments(statement, information, checkedPackage, facts) {
						changed = true
					}
					if propagateContainerCall(statement, information, facts) {
						changed = true
					}
				case *ast.SendStmt:
					if expressionContainsSecret(statement.Value, information, facts) &&
						markFlowTarget(statement.Chan, information, facts.secretObjects, facts.aliases) {
						changed = true
					}
				}
				return true
			})

			for _, declaration := range parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}
				object := information.Defs[function.Name]
				ast.Inspect(function.Body, func(node ast.Node) bool {
					if _, nestedFunction := node.(*ast.FuncLit); nestedFunction {
						return false
					}
					returned, ok := node.(*ast.ReturnStmt)
					if !ok {
						return true
					}
					for _, result := range returned.Results {
						if expressionContainsSecret(result, information, facts) && markObject(object, facts.secretReturns) {
							changed = true
						}
						if (expressionIsFormatter(result, information, facts) || expressionContainsFormatterClosure(result, information, facts)) &&
							markObject(object, facts.formatterReturns) {
							changed = true
						}
						if markReturnedFunctionLiterals(object, expressionFunctionLiterals(result, information, facts), facts.functionLiteralReturns) {
							changed = true
						}
					}
					return true
				})
			}
		}
		for _, literal := range facts.literals {
			if functionBodyFormatsSecret(literal.Body, information, facts) && !facts.formatterLiterals[literal] {
				facts.formatterLiterals[literal] = true
				changed = true
			}
			ast.Inspect(literal.Body, func(node ast.Node) bool {
				if nested, ok := node.(*ast.FuncLit); ok && nested != literal {
					return false
				}
				returned, ok := node.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, result := range returned.Results {
					if expressionContainsSecret(result, information, facts) && !facts.literalSecretReturns[literal] {
						facts.literalSecretReturns[literal] = true
						changed = true
					}
					if (expressionIsFormatter(result, information, facts) || expressionContainsFormatterClosure(result, information, facts)) &&
						!facts.literalFormatterReturns[literal] {
						facts.literalFormatterReturns[literal] = true
						changed = true
					}
					if markLiteralFunctionLiterals(literal, expressionFunctionLiterals(result, information, facts), facts.literalLiteralReturns) {
						changed = true
					}
				}
				return true
			})
		}
	}
	return facts
}

func parameterObjects(fields *ast.FieldList, information *types.Info) []types.Object {
	if fields == nil {
		return nil
	}
	var parameters []types.Object
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			parameters = append(parameters, nil)
			continue
		}
		for _, name := range field.Names {
			parameters = append(parameters, information.Defs[name])
		}
	}
	return parameters
}

func propagateAssignments(left, right []ast.Expr, information *types.Info, facts *flowFacts) bool {
	if len(left) == len(right) {
		changed := false
		for index := range left {
			changed = propagateAssignment(left[index], right[index], information, facts) || changed
		}
		return changed
	}
	if len(right) != 1 || len(left) == 0 {
		return false
	}

	rightType := information.TypeOf(right[0])
	tuple, _ := rightType.(*types.Tuple)
	secretResult := expressionContainsSecret(right[0], information, facts)
	formatterResult := expressionIsFormatter(right[0], information, facts)
	functionLiterals := expressionFunctionLiterals(right[0], information, facts)
	changed := false
	for index, target := range left {
		secretAtIndex := secretResult
		if tuple != nil && index < tuple.Len() {
			secretAtIndex = secretAtIndex || containsSecretType(tuple.At(index).Type(), make(map[types.Type]bool))
		}
		if secretAtIndex {
			changed = markFlowTarget(target, information, facts.secretObjects, facts.aliases) || changed
		}
		if formatterResult {
			changed = markFlowTarget(target, information, facts.formatterObjects, facts.aliases) || changed
		}
		changed = linkFunctionLiteralsToObject(flowRootObject(target, information), functionLiterals, facts) || changed
	}
	return changed
}

func propagateAssignment(left, right ast.Expr, information *types.Info, facts *flowFacts) bool {
	changed := linkFlowAliases(left, right, information, facts)
	changed = linkFunctionLiteralsToTarget(left, right, information, facts) || changed
	if expressionContainsSecret(right, information, facts) {
		changed = markFlowTarget(left, information, facts.secretObjects, facts.aliases) || changed
	}
	if expressionIsFormatter(right, information, facts) {
		changed = markFlowTarget(left, information, facts.formatterObjects, facts.aliases) || changed
	}
	if index, ok := left.(*ast.IndexExpr); ok && expressionContainsSecret(index.Index, information, facts) {
		changed = markFlowTarget(index.X, information, facts.secretObjects, facts.aliases) || changed
	}
	return changed
}

func propagateCallArguments(call *ast.CallExpr, information *types.Info, checkedPackage *types.Package, facts *flowFacts) bool {
	changed := false
	functions := calledFunctionCandidates(call.Fun, information, facts)
	receiverExpression, explicitArguments := callReceiverAndArguments(call, information)
	for _, function := range functions {
		if function.Pkg() != nil && checkedPackage != nil && function.Pkg() == checkedPackage {
			if receiver := facts.functionReceivers[function]; receiver != nil && receiverExpression != nil {
				changed = propagateReceiver(receiver, receiverExpression, information, facts) || changed
			}
			changed = propagateParameters(facts.functionParameters[function], explicitArguments, information, facts) || changed
		}

		for _, invocation := range facts.callbackInvocations[function] {
			if invocation.callbackParameter < 0 || invocation.callbackParameter >= len(explicitArguments) {
				continue
			}
			callback := explicitArguments[invocation.callbackParameter]
			for _, literal := range expressionFunctionLiterals(callback, information, facts) {
				changed = propagateCallbackParameters(facts.literalParameters[literal], invocation, explicitArguments, information, facts) || changed
			}
			for _, callbackFunction := range calledFunctionCandidates(callback, information, facts) {
				if callbackFunction.Pkg() == nil || checkedPackage == nil || callbackFunction.Pkg() != checkedPackage {
					continue
				}
				changed = propagateCallbackParameters(facts.functionParameters[callbackFunction], invocation, explicitArguments, information, facts) || changed
				if receiver := facts.functionReceivers[callbackFunction]; receiver != nil {
					if callbackReceiver := methodValueReceiver(callback, information); callbackReceiver != nil {
						changed = propagateReceiver(receiver, callbackReceiver, information, facts) || changed
					}
				}
			}
			if expressionIsFormatter(callback, information, facts) {
				for _, sourceParameters := range invocation.argumentParameters {
					for _, sourceParameter := range sourceParameters {
						if sourceParameter >= 0 && sourceParameter < len(explicitArguments) && expressionContainsSecret(explicitArguments[sourceParameter], information, facts) {
							changed = markObject(function, facts.formatterObjects) || changed
						}
					}
				}
			}
		}
		if receiverExpression != nil {
			for _, sourceParameter := range facts.receiverMutations[function] {
				if sourceParameter >= 0 && sourceParameter < len(explicitArguments) && expressionContainsSecret(explicitArguments[sourceParameter], information, facts) {
					changed = markFlowTarget(receiverExpression, information, facts.secretObjects, facts.aliases) || changed
				}
			}
		}
	}

	if len(functions) == 1 && checkedPackage != nil && functions[0].Pkg() == checkedPackage && facts.functionParameters[functions[0]] == nil {
		if _, selectorCall := call.Fun.(*ast.SelectorExpr); selectorCall {
			for index, parameters := range facts.methodParameters[functions[0].Name()] {
				if len(parameters) == len(explicitArguments) {
					changed = propagateParameters(parameters, explicitArguments, information, facts) || changed
					if receiverExpression != nil && index < len(facts.methodReceivers[functions[0].Name()]) {
						changed = propagateReceiver(facts.methodReceivers[functions[0].Name()][index], receiverExpression, information, facts) || changed
					}
				}
			}
		}
	}
	for _, literal := range calledFunctionLiterals(call.Fun, information, facts) {
		changed = propagateParameters(facts.literalParameters[literal], call.Args, information, facts) || changed
	}
	return changed
}

func propagateCallbackParameters(parameters []types.Object, invocation callbackInvocation, explicitArguments []ast.Expr, information *types.Info, facts *flowFacts) bool {
	changed := false
	for callbackArgument, sourceParameters := range invocation.argumentParameters {
		if callbackArgument >= len(parameters) {
			continue
		}
		for _, sourceParameter := range sourceParameters {
			if sourceParameter < 0 || sourceParameter >= len(explicitArguments) {
				continue
			}
			changed = propagateParameters(
				[]types.Object{parameters[callbackArgument]},
				[]ast.Expr{explicitArguments[sourceParameter]},
				information,
				facts,
			) || changed
		}
	}
	return changed
}

func methodValueReceiver(expression ast.Expr, information *types.Info) ast.Expr {
	for {
		switch value := expression.(type) {
		case *ast.ParenExpr:
			expression = value.X
			continue
		case *ast.SelectorExpr:
			selection := information.Selections[value]
			if selection != nil && selection.Kind() == types.MethodVal {
				return value.X
			}
		}
		return nil
	}
}

func callReceiverAndArguments(call *ast.CallExpr, information *types.Info) (ast.Expr, []ast.Expr) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, call.Args
	}
	selection := information.Selections[selector]
	if selection == nil {
		return nil, call.Args
	}
	switch selection.Kind() {
	case types.MethodVal:
		return selector.X, call.Args
	case types.MethodExpr:
		if len(call.Args) != 0 {
			return call.Args[0], call.Args[1:]
		}
	}
	return nil, call.Args
}

func propagateReceiver(receiver types.Object, expression ast.Expr, information *types.Info, facts *flowFacts) bool {
	changed := linkObjects(receiver, flowRootObject(expression, information), facts)
	changed = linkFunctionLiteralsToObject(receiver, expressionFunctionLiterals(expression, information, facts), facts) || changed
	if expressionContainsSecret(expression, information, facts) {
		changed = markObjectWithAliases(receiver, facts.secretObjects, facts.aliases) || changed
	}
	if expressionIsFormatter(expression, information, facts) {
		changed = markObjectWithAliases(receiver, facts.formatterObjects, facts.aliases) || changed
	}
	return changed
}

func propagateParameters(parameters []types.Object, arguments []ast.Expr, information *types.Info, facts *flowFacts) bool {
	if len(parameters) == 0 {
		return false
	}
	changed := false
	for index, argument := range arguments {
		parameterIndex := index
		if parameterIndex >= len(parameters) {
			parameterIndex = len(parameters) - 1
		}
		parameter := parameters[parameterIndex]
		changed = linkObjectToExpression(parameter, argument, information, facts) || changed
		if expressionContainsSecret(argument, information, facts) {
			changed = markObjectWithAliases(parameter, facts.secretObjects, facts.aliases) || changed
		}
		if expressionIsFormatter(argument, information, facts) {
			changed = markObjectWithAliases(parameter, facts.formatterObjects, facts.aliases) || changed
		}
	}
	return changed
}

func propagateContainerCall(call *ast.CallExpr, information *types.Info, facts *flowFacts) bool {
	identifier, ok := call.Fun.(*ast.Ident)
	if !ok || identifier.Name != "copy" || len(call.Args) != 2 {
		return false
	}
	if _, builtin := information.Uses[identifier].(*types.Builtin); !builtin {
		return false
	}
	if !expressionContainsSecret(call.Args[1], information, facts) {
		return false
	}
	return markFlowTarget(call.Args[0], information, facts.secretObjects, facts.aliases)
}

func markFlowTarget(expression ast.Expr, information *types.Info, marked map[types.Object]bool, aliases map[types.Object]map[types.Object]bool) bool {
	switch target := expression.(type) {
	case *ast.Ident:
		object := information.Defs[target]
		if object == nil {
			object = information.Uses[target]
		}
		return markObjectWithAliases(object, marked, aliases)
	case *ast.ParenExpr:
		return markFlowTarget(target.X, information, marked, aliases)
	case *ast.SelectorExpr:
		return markFlowTarget(target.X, information, marked, aliases)
	case *ast.IndexExpr:
		return markFlowTarget(target.X, information, marked, aliases)
	case *ast.IndexListExpr:
		return markFlowTarget(target.X, information, marked, aliases)
	case *ast.SliceExpr:
		return markFlowTarget(target.X, information, marked, aliases)
	case *ast.StarExpr:
		return markFlowTarget(target.X, information, marked, aliases)
	default:
		return false
	}
}

func markObjectWithAliases(object types.Object, marked map[types.Object]bool, aliases map[types.Object]map[types.Object]bool) bool {
	changed := false
	pending := []types.Object{object}
	for len(pending) != 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if current == nil || current.Name() == "_" || marked[current] {
			continue
		}
		marked[current] = true
		changed = true
		for alias := range aliases[current] {
			pending = append(pending, alias)
		}
	}
	return changed
}

func linkFlowAliases(left, right ast.Expr, information *types.Info, facts *flowFacts) bool {
	if !isReferenceLike(information.TypeOf(right)) {
		return false
	}
	return linkObjects(flowRootObject(left, information), flowRootObject(right, information), facts)
}

func linkFunctionLiteralsToTarget(left, right ast.Expr, information *types.Info, facts *flowFacts) bool {
	return linkFunctionLiteralsToObject(
		flowRootObject(left, information),
		expressionFunctionLiterals(right, information, facts),
		facts,
	)
}

func linkFunctionLiteralsToObject(object types.Object, literals []*ast.FuncLit, facts *flowFacts) bool {
	if object == nil {
		return false
	}
	if facts.functionLiterals[object] == nil {
		facts.functionLiterals[object] = make(map[*ast.FuncLit]bool)
	}
	return addFunctionLiterals(facts.functionLiterals[object], literals)
}

func markReturnedFunctionLiterals(object types.Object, literals []*ast.FuncLit, returned map[types.Object]map[*ast.FuncLit]bool) bool {
	if object == nil {
		return false
	}
	if returned[object] == nil {
		returned[object] = make(map[*ast.FuncLit]bool)
	}
	return addFunctionLiterals(returned[object], literals)
}

func markLiteralFunctionLiterals(literal *ast.FuncLit, returnedLiterals []*ast.FuncLit, returned map[*ast.FuncLit]map[*ast.FuncLit]bool) bool {
	if returned[literal] == nil {
		returned[literal] = make(map[*ast.FuncLit]bool)
	}
	return addFunctionLiterals(returned[literal], returnedLiterals)
}

func addFunctionLiterals(destination map[*ast.FuncLit]bool, literals []*ast.FuncLit) bool {
	changed := false
	for _, literal := range literals {
		if literal == nil || destination[literal] {
			continue
		}
		destination[literal] = true
		changed = true
	}
	return changed
}

func linkObjectToExpression(object types.Object, expression ast.Expr, information *types.Info, facts *flowFacts) bool {
	changed := linkFunctionLiteralsToObject(object, expressionFunctionLiterals(expression, information, facts), facts)
	if isReferenceLike(information.TypeOf(expression)) {
		changed = linkObjects(object, flowRootObject(expression, information), facts) || changed
	}
	return changed
}

func linkObjects(left, right types.Object, facts *flowFacts) bool {
	if left == nil || right == nil || left == right {
		return false
	}
	if facts.aliases[left] == nil {
		facts.aliases[left] = make(map[types.Object]bool)
	}
	if facts.aliases[left][right] {
		return false
	}
	if facts.aliases[right] == nil {
		facts.aliases[right] = make(map[types.Object]bool)
	}
	facts.aliases[left][right] = true
	facts.aliases[right][left] = true
	changed := true
	if facts.secretObjects[left] {
		changed = markObjectWithAliases(right, facts.secretObjects, facts.aliases) || changed
	} else if facts.secretObjects[right] {
		changed = markObjectWithAliases(left, facts.secretObjects, facts.aliases) || changed
	}
	if facts.formatterObjects[left] {
		changed = markObjectWithAliases(right, facts.formatterObjects, facts.aliases) || changed
	} else if facts.formatterObjects[right] {
		changed = markObjectWithAliases(left, facts.formatterObjects, facts.aliases) || changed
	}
	return changed
}

func flowRootObject(expression ast.Expr, information *types.Info) types.Object {
	switch value := expression.(type) {
	case *ast.Ident:
		return expressionObject(value, information)
	case *ast.ParenExpr:
		return flowRootObject(value.X, information)
	case *ast.UnaryExpr:
		return flowRootObject(value.X, information)
	case *ast.SelectorExpr:
		return flowRootObject(value.X, information)
	case *ast.IndexExpr:
		return flowRootObject(value.X, information)
	case *ast.IndexListExpr:
		return flowRootObject(value.X, information)
	case *ast.SliceExpr:
		return flowRootObject(value.X, information)
	case *ast.StarExpr:
		return flowRootObject(value.X, information)
	default:
		return nil
	}
}

func isReferenceLike(valueType types.Type) bool {
	if valueType == nil {
		return false
	}
	switch types.Unalias(valueType).Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map, *types.Chan, *types.Signature, *types.Interface:
		return true
	default:
		return false
	}
}

func markObject(object types.Object, marked map[types.Object]bool) bool {
	if object == nil || object.Name() == "_" || marked[object] {
		return false
	}
	marked[object] = true
	return true
}

func isFormattingCall(call *ast.CallExpr, information *types.Info, facts *flowFacts) bool {
	return expressionIsFormatter(call.Fun, information, facts)
}

func expressionIsFormatter(expression ast.Expr, information *types.Info, facts *flowFacts) bool {
	if object := expressionObject(expression, information); object != nil {
		if facts.formatterObjects[object] || isMonitoredFormattingFunction(object) {
			return true
		}
	}
	for _, literal := range expressionFunctionLiterals(expression, information, facts) {
		if facts.formatterLiterals[literal] {
			return true
		}
	}
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return expressionIsFormatter(value.X, information, facts)
	case *ast.SelectorExpr:
		return expressionIsFormatter(value.X, information, facts)
	case *ast.IndexExpr:
		return expressionIsFormatter(value.X, information, facts)
	case *ast.IndexListExpr:
		return expressionIsFormatter(value.X, information, facts)
	case *ast.TypeAssertExpr:
		return expressionIsFormatter(value.X, information, facts)
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			if expressionIsFormatter(element, information, facts) {
				return true
			}
		}
	case *ast.KeyValueExpr:
		return expressionIsFormatter(value.Value, information, facts)
	case *ast.CallExpr:
		if function := calledFunctionObject(value.Fun, information); function != nil && facts.formatterReturns[function] {
			return true
		}
		for _, literal := range calledFunctionLiterals(value.Fun, information, facts) {
			if facts.literalFormatterReturns[literal] {
				return true
			}
		}
		for _, argument := range value.Args {
			if expressionIsFormatter(argument, information, facts) {
				return true
			}
		}
	}
	return false
}

func expressionContainsFormatterClosure(expression ast.Expr, information *types.Info, facts *flowFacts) bool {
	for _, literal := range expressionFunctionLiterals(expression, information, facts) {
		if facts.formatterLiterals[literal] {
			return true
		}
	}
	return false
}

func expressionContainsSecret(expression ast.Expr, information *types.Info, facts *flowFacts) bool {
	if object := expressionObject(expression, information); object != nil && facts.secretObjects[object] {
		return true
	}
	if containsSecretType(information.TypeOf(expression), make(map[types.Type]bool)) {
		return true
	}

	switch value := expression.(type) {
	case *ast.ParenExpr:
		return expressionContainsSecret(value.X, information, facts)
	case *ast.UnaryExpr:
		return expressionContainsSecret(value.X, information, facts)
	case *ast.KeyValueExpr:
		return expressionContainsSecret(value.Value, information, facts)
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			if expressionContainsSecret(element, information, facts) {
				return true
			}
		}
	case *ast.IndexExpr:
		return expressionContainsSecret(value.X, information, facts)
	case *ast.IndexListExpr:
		return expressionContainsSecret(value.X, information, facts)
	case *ast.SelectorExpr:
		return expressionContainsSecret(value.X, information, facts)
	case *ast.SliceExpr:
		return expressionContainsSecret(value.X, information, facts)
	case *ast.StarExpr:
		return expressionContainsSecret(value.X, information, facts)
	case *ast.TypeAssertExpr:
		return expressionContainsSecret(value.X, information, facts)
	case *ast.FuncLit:
		return facts.literalSecretReturns[value]
	case *ast.CallExpr:
		if isExplicitRedactedStringCall(value, information) {
			return false
		}
		if function := calledFunctionObject(value.Fun, information); function != nil && facts.secretReturns[function] {
			return true
		}
		for _, literal := range calledFunctionLiterals(value.Fun, information, facts) {
			if facts.literalSecretReturns[literal] {
				return true
			}
		}
		if expressionContainsSecret(value.Fun, information, facts) {
			return true
		}
		if selector, ok := value.Fun.(*ast.SelectorExpr); ok && expressionContainsSecret(selector.X, information, facts) {
			return true
		}
		for _, argument := range value.Args {
			if expressionContainsSecret(argument, information, facts) {
				return true
			}
		}
	}
	return false
}

func expressionObject(expression ast.Expr, information *types.Info) types.Object {
	switch value := expression.(type) {
	case *ast.Ident:
		if object := information.Uses[value]; object != nil {
			return object
		}
		return information.Defs[value]
	case *ast.SelectorExpr:
		return information.Uses[value.Sel]
	default:
		return nil
	}
}

func calledFunctionObject(expression ast.Expr, information *types.Info) *types.Func {
	object, _ := expressionObject(expression, information).(*types.Func)
	return object
}

func calledFunctionCandidates(expression ast.Expr, information *types.Info, facts *flowFacts) []*types.Func {
	root := expressionObject(expression, information)
	if root == nil {
		return nil
	}
	var functions []*types.Func
	seen := make(map[types.Object]bool)
	pending := []types.Object{root}
	for len(pending) != 0 {
		object := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if object == nil || seen[object] {
			continue
		}
		seen[object] = true
		if function, ok := object.(*types.Func); ok {
			functions = append(functions, function)
		}
		for alias := range facts.aliases[object] {
			pending = append(pending, alias)
		}
	}
	return functions
}

func calledFunctionLiterals(expression ast.Expr, information *types.Info, facts *flowFacts) []*ast.FuncLit {
	return expressionFunctionLiterals(expression, information, facts)
}

func expressionFunctionLiterals(expression ast.Expr, information *types.Info, facts *flowFacts) []*ast.FuncLit {
	found := make(map[*ast.FuncLit]bool)
	collectExpressionFunctionLiterals(expression, information, facts, found)
	literals := make([]*ast.FuncLit, 0, len(found))
	for literal := range found {
		literals = append(literals, literal)
	}
	return literals
}

func collectExpressionFunctionLiterals(expression ast.Expr, information *types.Info, facts *flowFacts, found map[*ast.FuncLit]bool) {
	switch value := expression.(type) {
	case *ast.FuncLit:
		found[value] = true
		return
	case *ast.ParenExpr:
		collectExpressionFunctionLiterals(value.X, information, facts, found)
		return
	case *ast.KeyValueExpr:
		collectExpressionFunctionLiterals(value.Value, information, facts, found)
		return
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			collectExpressionFunctionLiterals(element, information, facts, found)
		}
		return
	case *ast.IndexExpr:
		collectExpressionFunctionLiterals(value.X, information, facts, found)
		return
	case *ast.IndexListExpr:
		collectExpressionFunctionLiterals(value.X, information, facts, found)
		return
	case *ast.SelectorExpr:
		collectExpressionFunctionLiterals(value.X, information, facts, found)
		return
	case *ast.SliceExpr:
		collectExpressionFunctionLiterals(value.X, information, facts, found)
		return
	case *ast.StarExpr:
		collectExpressionFunctionLiterals(value.X, information, facts, found)
		return
	case *ast.UnaryExpr:
		collectExpressionFunctionLiterals(value.X, information, facts, found)
		return
	case *ast.TypeAssertExpr:
		collectExpressionFunctionLiterals(value.X, information, facts, found)
		return
	case *ast.CallExpr:
		for _, function := range calledFunctionCandidates(value.Fun, information, facts) {
			for literal := range facts.functionLiteralReturns[function] {
				found[literal] = true
			}
		}
		for _, calledLiteral := range expressionFunctionLiterals(value.Fun, information, facts) {
			for returnedLiteral := range facts.literalLiteralReturns[calledLiteral] {
				found[returnedLiteral] = true
			}
		}
		return
	}

	collectObjectFunctionLiterals(expressionObject(expression, information), facts, found)
	collectObjectFunctionLiterals(flowRootObject(expression, information), facts, found)
}

func collectObjectFunctionLiterals(root types.Object, facts *flowFacts, found map[*ast.FuncLit]bool) {
	seenObjects := make(map[types.Object]bool)
	pending := []types.Object{root}
	for len(pending) != 0 {
		object := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if object == nil || seenObjects[object] {
			continue
		}
		seenObjects[object] = true
		for literal := range facts.functionLiterals[object] {
			found[literal] = true
		}
		for alias := range facts.aliases[object] {
			pending = append(pending, alias)
		}
	}
}

func isMonitoredFormattingFunction(object types.Object) bool {
	function, ok := object.(*types.Func)
	if !ok || function.Pkg() == nil {
		return false
	}
	names, monitoredPackage := formattingFunctions[function.Pkg().Path()]
	if !monitoredPackage {
		return false
	}
	_, monitoredFunction := names[function.Name()]
	return monitoredFunction
}

func isExplicitRedactedStringCall(call *ast.CallExpr, information *types.Info) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	function, ok := information.Uses[selector.Sel].(*types.Func)
	return ok && function.Pkg() != nil && function.Pkg().Path() == secretPackagePath &&
		(function.Name() == "String" || function.Name() == "GoString")
}

func isRedactionAssertionCall(call *ast.CallExpr, information *types.Info) bool {
	function := calledFunctionObject(call.Fun, information)
	if function == nil || function.Pkg() == nil || function.Pkg().Path() != "fmt" {
		return false
	}
	return function.Name() == "Sprint" || function.Name() == "Sprintf"
}

func hasUnresolvedType(expression ast.Expr, information *types.Info) bool {
	return containsInvalidType(information.TypeOf(expression), make(map[types.Type]bool))
}

func formattingArgumentViolationMessage(expression ast.Expr, information *types.Info, facts *flowFacts, allowRedactionAssertion bool) string {
	if expressionContainsSecret(expression, information, facts) {
		if allowRedactionAssertion && isDirectSecretValueType(information.TypeOf(expression)) {
			return ""
		}
		return "secret.Value must not be passed to fmt or log (including slog); output an explicit redacted string instead"
	}
	if hasUnresolvedType(expression, information) {
		return "formatting argument type could not be resolved; refusing a possible secret.Value flow"
	}
	return ""
}

func isDirectSecretValueType(valueType types.Type) bool {
	if valueType == nil {
		return false
	}
	valueType = types.Unalias(valueType)
	if pointer, ok := valueType.(*types.Pointer); ok {
		valueType = types.Unalias(pointer.Elem())
	}
	named, ok := valueType.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == secretPackagePath && named.Obj().Name() == "Value"
}

func containsInvalidType(valueType types.Type, seen map[types.Type]bool) bool {
	if valueType == nil {
		return true
	}
	if seen[valueType] {
		return false
	}
	seen[valueType] = true
	valueType = types.Unalias(valueType)
	switch typed := valueType.(type) {
	case *types.Basic:
		return typed.Kind() == types.Invalid
	case *types.Pointer:
		return containsInvalidType(typed.Elem(), seen)
	case *types.Array:
		return containsInvalidType(typed.Elem(), seen)
	case *types.Slice:
		return containsInvalidType(typed.Elem(), seen)
	case *types.Map:
		return containsInvalidType(typed.Key(), seen) || containsInvalidType(typed.Elem(), seen)
	case *types.Chan:
		return containsInvalidType(typed.Elem(), seen)
	case *types.Tuple:
		for index := 0; index < typed.Len(); index++ {
			if containsInvalidType(typed.At(index).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func containsSecretType(valueType types.Type, seen map[types.Type]bool) bool {
	if valueType == nil || seen[valueType] {
		return false
	}
	seen[valueType] = true
	valueType = types.Unalias(valueType)

	switch typed := valueType.(type) {
	case *types.Named:
		if object := typed.Obj(); object != nil && object.Pkg() != nil && object.Pkg().Path() == secretPackagePath && object.Name() == "Value" {
			return true
		}
		return containsSecretType(typed.Underlying(), seen)
	case *types.Pointer:
		return containsSecretType(typed.Elem(), seen)
	case *types.Array:
		return containsSecretType(typed.Elem(), seen)
	case *types.Slice:
		return containsSecretType(typed.Elem(), seen)
	case *types.Map:
		return containsSecretType(typed.Key(), seen) || containsSecretType(typed.Elem(), seen)
	case *types.Chan:
		return containsSecretType(typed.Elem(), seen)
	case *types.Tuple:
		for index := 0; index < typed.Len(); index++ {
			if containsSecretType(typed.At(index).Type(), seen) {
				return true
			}
		}
	case *types.Struct:
		for index := 0; index < typed.NumFields(); index++ {
			field := typed.Field(index)
			if field.Pkg() != nil && field.Pkg().Path() == secretPackagePath {
				return true
			}
			if containsSecretType(field.Type(), seen) {
				return true
			}
		}
	}
	return false
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
	if importPath == "github.com/stretchr/testify" || strings.HasPrefix(importPath, "github.com/stretchr/testify/") {
		return true
	}
	for _, component := range strings.Split(importPath, "/") {
		switch component {
		case "test", "tests", "testdata", "testing", "httptest", "testutil", "testutils", "fake", "fakes", "mock", "mocks", "gomock":
			return true
		}
	}
	return false
}

func forbiddenProcessImportMessage(importPath string, policy sourcePolicy) (string, bool) {
	if (importPath == "go/importer" || importPath == "go/build") && policy.allowSourceImporter {
		return "", false
	}
	if message, forbidden := forbiddenProcessImports[importPath]; forbidden {
		return message, true
	}
	if strings.HasPrefix(importPath, "syscall/") ||
		strings.HasPrefix(importPath, "golang.org/x/sys/unix/") ||
		strings.HasPrefix(importPath, "golang.org/x/sys/windows/") ||
		strings.HasPrefix(importPath, "golang.org/x/tools/go/packages/") {
		return "low-level process packages are forbidden; use the validated runner adapter", true
	}
	return "", false
}

func isStandardLibraryImport(importPath string) bool {
	if importPath == "" || strings.HasPrefix(importPath, ".") || strings.Contains(importPath, `\`) {
		return false
	}
	first, _, _ := strings.Cut(importPath, "/")
	if strings.Contains(first, ".") {
		return false
	}

	standardLibraryPackages.Lock()
	defer standardLibraryPackages.Unlock()
	if standard, checked := standardLibraryPackages.known[importPath]; checked {
		return standard
	}
	_, err := standardLibraryPackages.importer.Import(importPath)
	standardLibraryPackages.known[importPath] = err == nil
	return err == nil
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
