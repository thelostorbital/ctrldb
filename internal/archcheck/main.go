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

type sourceFile struct {
	filename string
	contents []byte
	policy   sourcePolicy
}

type sourcePolicy struct {
	allowBubbleTeaImport    bool
	allowSecretFormatting   bool
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
		fileFindings, err := findArchitectureViolations(path, contents, policyForSource(relativePath))
		if err != nil {
			return err
		}
		findings = append(findings, fileFindings...)
		sourcesByDirectory[filepath.Dir(path)] = append(sourcesByDirectory[filepath.Dir(path)], sourceFile{
			filename: path,
			contents: contents,
			policy:   policyForSource(relativePath),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, directorySources := range sourcesByDirectory {
		packageFindings, err := findPackageSecretViolations(directorySources)
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

func findPackageSecretViolations(sources []sourceFile) ([]finding, error) {
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
		information := &types.Info{Defs: definitions, Types: expressionTypes, Uses: uses}
		configuration := types.Config{
			Importer:                 architectureImporter{},
			DisableUnusedImportCheck: true,
			Error:                    func(error) {},
		}
		_, _ = configuration.Check(modulePath+"/.archcheck/package/"+packageName, files, parsedFiles, information)

		for _, parsed := range parsedFiles {
			if policies[parsed].allowSecretFormatting {
				continue
			}
			tainted := findTaintedObjects(parsed, information)
			ast.Inspect(parsed, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || !isFormattingCall(call, uses) {
					return true
				}
				for _, argument := range call.Args {
					if !expressionContainsSecret(argument, information, tainted) {
						continue
					}
					position := files.Position(call.Fun.Pos())
					findings = append(findings, finding{
						filename: position.Filename,
						line:     position.Line,
						column:   position.Column,
						message:  "secret.Value must not be passed to fmt or log; output an explicit redacted string instead",
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
		if message, forbidden := forbiddenProcessImportMessage(importPath); forbidden {
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
	configuration := types.Config{
		Importer:                 architectureImporter{},
		DisableUnusedImportCheck: true,
		Error:                    func(error) {},
	}
	checkedPackagePath := modulePath + "/.archcheck/" + parsed.Name.Name
	typeInformation := &types.Info{
		Defs:  definitions,
		Types: expressionTypes,
		Uses:  uses,
	}
	_, _ = configuration.Check(checkedPackagePath, files, []*ast.File{parsed}, typeInformation)
	tainted := findTaintedObjects(parsed, typeInformation)

	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && !policy.allowSecretFormatting && isFormattingCall(call, uses) {
			for _, argument := range call.Args {
				if !expressionContainsSecret(argument, typeInformation, tainted) {
					continue
				}
				position := files.Position(call.Fun.Pos())
				findings = append(findings, finding{
					filename: position.Filename,
					line:     position.Line,
					column:   position.Column,
					message:  "secret.Value must not be passed to fmt or log; output an explicit redacted string instead",
				})
				break
			}
		}

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
		logger := types.NewNamed(types.NewTypeName(token.NoPos, imported, "Logger", nil), types.NewStruct(nil, nil), nil)
		imported.Scope().Insert(logger.Obj())
		for name := range formattingFunctions["log"] {
			receiver := types.NewVar(token.NoPos, imported, "logger", types.NewPointer(logger))
			logger.AddMethod(types.NewFunc(token.NoPos, imported, name, variadicSignature(receiver, nil)))
		}
		addFunction(imported, "Default", []types.Type{types.NewPointer(logger)})
		addFunction(imported, "New", []types.Type{types.NewPointer(logger)})
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
		addFunction(imported, "New", []types.Type{types.NewPointer(secretValue)})
	}
	imported.MarkComplete()
	return imported, nil
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
		allowSecretFormatting:   strings.HasPrefix(normalized, "internal/secret/") || strings.HasSuffix(normalized, "_test.go"),
		allowTestInfrastructure: strings.HasSuffix(normalized, "_test.go"),
		enforceVerifierBoundary: strings.HasPrefix(normalized, "internal/verify/"),
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
	internalPath, internal := strings.CutPrefix(importPath, modulePath+"/internal/")
	if !internal {
		return "", false
	}

	components := strings.Split(internalPath, "/")
	if len(components) == 0 || components[0] == "verify" || components[0] == "domain" {
		return "", false
	}

	processAdapters := map[string]struct{}{
		"access": {}, "app": {}, "automation": {}, "gcp": {}, "hostagent": {},
		"mongodb": {}, "pbm": {}, "remote": {}, "runner": {}, "workflow": {},
	}
	if _, forbidden := processAdapters[components[0]]; forbidden {
		return "C-VERIFY must not import workflow, application, executor-step, or process-adapter packages", true
	}

	for _, component := range components {
		normalized := strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(component))
		switch normalized {
		case "executor", "executors", "executorstep", "executorsteps", "executionstep", "executionsteps", "process", "processadapter", "processadapters", "step", "steps":
			return "C-VERIFY must not import workflow, application, executor-step, or process-adapter packages", true
		}
	}
	return "", false
}

func isFormattingCall(call *ast.CallExpr, uses map[*ast.Ident]types.Object) bool {
	var identifier *ast.Ident
	switch called := call.Fun.(type) {
	case *ast.Ident:
		identifier = called
	case *ast.SelectorExpr:
		identifier = called.Sel
	default:
		return false
	}

	function, ok := uses[identifier].(*types.Func)
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

func findTaintedObjects(parsed *ast.File, information *types.Info) map[types.Object]bool {
	tainted := make(map[types.Object]bool)
	for changed := true; changed; {
		changed = false
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch statement := node.(type) {
			case *ast.AssignStmt:
				if len(statement.Lhs) != len(statement.Rhs) {
					return true
				}
				for index, right := range statement.Rhs {
					if expressionContainsSecret(right, information, tainted) && markTainted(statement.Lhs[index], information, tainted) {
						changed = true
					}
				}
			case *ast.ValueSpec:
				if len(statement.Names) != len(statement.Values) {
					return true
				}
				for index, value := range statement.Values {
					if expressionContainsSecret(value, information, tainted) && markIdentifierTainted(statement.Names[index], information, tainted) {
						changed = true
					}
				}
			}
			return true
		})
	}
	return tainted
}

func markTainted(expression ast.Expr, information *types.Info, tainted map[types.Object]bool) bool {
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return false
	}
	return markIdentifierTainted(identifier, information, tainted)
}

func markIdentifierTainted(identifier *ast.Ident, information *types.Info, tainted map[types.Object]bool) bool {
	object := information.Defs[identifier]
	if object == nil {
		object = information.Uses[identifier]
	}
	if object == nil || tainted[object] {
		return false
	}
	tainted[object] = true
	return true
}

func expressionContainsSecret(expression ast.Expr, information *types.Info, tainted map[types.Object]bool) bool {
	if identifier, ok := expression.(*ast.Ident); ok && tainted[information.Uses[identifier]] {
		return true
	}
	if containsSecretType(information.TypeOf(expression), make(map[types.Type]bool)) {
		return true
	}

	switch value := expression.(type) {
	case *ast.ParenExpr:
		return expressionContainsSecret(value.X, information, tainted)
	case *ast.UnaryExpr:
		return expressionContainsSecret(value.X, information, tainted)
	case *ast.KeyValueExpr:
		return expressionContainsSecret(value.Value, information, tainted)
	case *ast.CompositeLit:
		for _, element := range value.Elts {
			if expressionContainsSecret(element, information, tainted) {
				return true
			}
		}
	case *ast.IndexExpr:
		return expressionContainsSecret(value.X, information, tainted)
	case *ast.IndexListExpr:
		return expressionContainsSecret(value.X, information, tainted)
	case *ast.SelectorExpr:
		return expressionContainsSecret(value.X, information, tainted)
	case *ast.SliceExpr:
		return expressionContainsSecret(value.X, information, tainted)
	case *ast.StarExpr:
		return expressionContainsSecret(value.X, information, tainted)
	case *ast.TypeAssertExpr:
		return expressionContainsSecret(value.X, information, tainted)
	case *ast.CallExpr:
		if convertedType, ok := information.Types[value.Fun]; ok && convertedType.IsType() {
			for _, argument := range value.Args {
				if expressionContainsSecret(argument, information, tainted) {
					return true
				}
			}
		}
		if identifier, ok := value.Fun.(*ast.Ident); ok {
			if _, builtin := information.Uses[identifier].(*types.Builtin); builtin {
				for _, argument := range value.Args {
					if expressionContainsSecret(argument, information, tainted) {
						return true
					}
				}
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

func forbiddenProcessImportMessage(importPath string) (string, bool) {
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
