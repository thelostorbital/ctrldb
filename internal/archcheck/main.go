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
}

type sourcePolicy struct {
	allowBubbleTeaImport    bool
	allowSourceImporter     bool
	allowTestInfrastructure bool
	enforceVerifierBoundary bool
	enforceSecretAPISurface bool
}

const (
	modulePath        = "github.com/thelostorbital/ctrldb"
	secretPackagePath = modulePath + "/internal/secret"
)

var verifierSafeStandardImports = map[string]struct{}{
	"bytes": {}, "cmp": {}, "context": {}, "errors": {}, "fmt": {},
	"crypto": {}, "crypto/aes": {}, "crypto/cipher": {},
	"crypto/ed25519": {}, "crypto/hmac": {}, "crypto/rand": {},
	"crypto/rsa": {}, "crypto/sha256": {}, "crypto/sha512": {},
	"crypto/subtle": {}, "crypto/x509": {}, "crypto/x509/pkix": {},
	"io": {}, "io/fs": {}, "iter": {}, "log": {}, "log/slog": {},
	"maps": {}, "net/netip": {}, "net/url": {}, "path": {},
	"path/filepath": {}, "regexp": {}, "slices": {},
	"sort": {}, "strconv": {}, "strings": {}, "sync": {},
	"sync/atomic": {}, "time": {},
}

var verifierSafeStandardPrefixes = []string{
	"archive/", "compress/", "encoding/", "hash/", "math/", "text/", "unicode/",
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
	var secretSources []sourceFile
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git":
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
		if isVendoredPath(relativePath) {
			vendorFindings, err := findVendorNativeViolations(path, contents)
			if err != nil {
				return err
			}
			findings = append(findings, vendorFindings...)
			return nil
		}
		policy := policyForSource(relativePath)
		fileFindings, err := findArchitectureViolations(path, contents, policy)
		if err != nil {
			return err
		}
		findings = append(findings, fileFindings...)
		if policy.enforceSecretAPISurface {
			secretSources = append(secretSources, sourceFile{filename: path, contents: contents})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	secretFindings, err := findSecretAPIViolations(secretSources)
	if err != nil {
		return nil, err
	}
	findings = append(findings, secretFindings...)
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

func isVendoredPath(path string) bool {
	for _, component := range strings.Split(filepath.ToSlash(filepath.Clean(path)), "/") {
		if component == "vendor" {
			return true
		}
	}
	return false
}

func findVendorNativeViolations(filename string, contents []byte) ([]finding, error) {
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
			findings = append(findings, finding{filename: position.Filename, line: position.Line, column: position.Column, message: message})
		}
	}
	for _, imported := range parsed.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("decode import in %s: %w", filename, err)
		}
		if importPath != "C" {
			continue
		}
		position := files.Position(imported.Path.Pos())
		findings = append(findings, finding{
			filename: position.Filename,
			line:     position.Line,
			column:   position.Column,
			message:  forbiddenProcessImports["C"],
		})
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
	packageImporter := newArchitectureImporter(false)
	configuration := types.Config{
		Importer:                 packageImporter,
		DisableUnusedImportCheck: true,
		Error:                    func(error) {},
	}
	checkedPackagePath := modulePath + "/.archcheck/" + parsed.Name.Name
	typeInformation := &types.Info{Uses: uses}
	_, _ = configuration.Check(checkedPackagePath, files, []*ast.File{parsed}, typeInformation)

	ast.Inspect(parsed, func(node ast.Node) bool {
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

// architectureImporter resolves standard-library packages from source when
// exact API type information is required. Syntax-only checks use closed stubs
// and never invoke the Go tool.
type architectureImporter struct {
	standard types.Importer
	packages map[string]*types.Package
}

func newArchitectureImporter(loadStandard bool) *architectureImporter {
	loader := &architectureImporter{packages: make(map[string]*types.Package)}
	if loadStandard {
		loader.standard = importer.ForCompiler(token.NewFileSet(), "source", nil)
	}
	return loader
}

func (loader *architectureImporter) Import(importPath string) (*types.Package, error) {
	if imported, ok := loader.packages[importPath]; ok {
		return imported, nil
	}
	if loader.standard != nil && isStandardLibraryImport(importPath) {
		imported, err := loader.standard.Import(importPath)
		if err != nil {
			return nil, err
		}
		loader.packages[importPath] = imported
		return imported, nil
	}

	packageName := importPath
	if separator := strings.LastIndexByte(importPath, '/'); separator >= 0 {
		packageName = importPath[separator+1:]
	}
	imported := types.NewPackage(importPath, packageName)
	switch importPath {
	case "go/importer":
		addStubFunction(imported, "Default")
		addStubFunction(imported, "ForCompiler")
	case "os":
		addStubFunction(imported, "StartProcess")
	}
	imported.MarkComplete()
	loader.packages[importPath] = imported
	return imported, nil
}

func addStubFunction(imported *types.Package, name string) {
	signature := types.NewSignatureType(nil, nil, nil, nil, nil, false)
	imported.Scope().Insert(types.NewFunc(token.NoPos, imported, name, signature))
}

type secretBuildTarget struct {
	goos   string
	goarch string
}

var secretBuildTargets = []secretBuildTarget{
	{goos: "darwin", goarch: "amd64"},
	{goos: "darwin", goarch: "arm64"},
	{goos: "linux", goarch: "amd64"},
	{goos: "linux", goarch: "arm64"},
}

func findSecretAPIViolations(sources []sourceFile) ([]finding, error) {
	if len(sources) == 0 {
		return nil, nil
	}
	directory := filepath.Dir(sources[0].filename)
	var findings []finding
	for _, target := range secretBuildTargets {
		context := build.Default
		context.GOOS = target.goos
		context.GOARCH = target.goarch
		context.CgoEnabled = false

		files := token.NewFileSet()
		var parsedFiles []*ast.File
		for _, source := range sources {
			matches, err := context.MatchFile(directory, filepath.Base(source.filename))
			if err != nil {
				return nil, fmt.Errorf("evaluate build constraints for %s: %w", source.filename, err)
			}
			if !matches {
				continue
			}
			parsed, err := parser.ParseFile(files, source.filename, source.contents, parser.SkipObjectResolution)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", source.filename, err)
			}
			parsedFiles = append(parsedFiles, parsed)
		}
		if len(parsedFiles) == 0 {
			return nil, fmt.Errorf("internal/secret has no source files for %s/%s", target.goos, target.goarch)
		}

		configuration := types.Config{Importer: newArchitectureImporter(true)}
		checked, err := configuration.Check(secretPackagePath, files, parsedFiles, nil)
		if err != nil {
			return nil, fmt.Errorf("type-check internal/secret for %s/%s: %w", target.goos, target.goarch, err)
		}
		findings = append(findings, inspectSecretAPISurface(checked, files)...)
	}
	return uniqueFindings(findings), nil
}

func inspectSecretAPISurface(secretPackage *types.Package, files *token.FileSet) []finding {
	var findings []finding
	scope := secretPackage.Scope()
	for _, name := range scope.Names() {
		object := scope.Lookup(name)
		if !object.Exported() {
			continue
		}
		valid := false
		switch name {
		case "Value":
			valid = validSecretValueType(object)
		case "New":
			valid = validSecretNew(object, scope.Lookup("Value"))
		}
		if !valid {
			findings = append(findings, secretAPIFinding(files, object, "internal/secret exports only Value and the exact New constructor"))
		}
	}

	valueName, ok := scope.Lookup("Value").(*types.TypeName)
	if !ok {
		return findings
	}
	value, ok := types.Unalias(valueName.Type()).(*types.Named)
	if !ok {
		return findings
	}
	methods := types.NewMethodSet(types.NewPointer(value))
	for index := 0; index < methods.Len(); index++ {
		method := methods.At(index).Obj()
		if !method.Exported() {
			continue
		}
		if !validSecretValueMethod(method, value) {
			findings = append(findings, secretAPIFinding(files, method, "secret.Value exposes only the approved redacting, status, and zeroing methods"))
		}
	}
	return findings
}

func validSecretValueType(object types.Object) bool {
	name, ok := object.(*types.TypeName)
	if !ok || name.IsAlias() {
		return false
	}
	value, ok := types.Unalias(name.Type()).(*types.Named)
	if !ok {
		return false
	}
	structure, ok := value.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for index := 0; index < structure.NumFields(); index++ {
		if structure.Field(index).Exported() {
			return false
		}
	}
	return true
}

func validSecretNew(object, valueObject types.Object) bool {
	function, ok := object.(*types.Func)
	valueName, valueOK := valueObject.(*types.TypeName)
	if !ok || !valueOK {
		return false
	}
	signature := function.Type().(*types.Signature)
	return signature.Recv() == nil && signature.TypeParams().Len() == 0 && !signature.Variadic() &&
		signature.Params().Len() == 1 && isByteSlice(signature.Params().At(0).Type()) &&
		signature.Results().Len() == 1 && isPointerToNamed(signature.Results().At(0).Type(), valueName.Type())
}

func validSecretValueMethod(object types.Object, value *types.Named) bool {
	function, ok := object.(*types.Func)
	if !ok {
		return false
	}
	signature := function.Type().(*types.Signature)
	if signature.Recv() == nil || signature.TypeParams().Len() != 0 || signature.RecvTypeParams().Len() != 0 || signature.Variadic() ||
		!isPointerToNamed(signature.Recv().Type(), value) {
		return false
	}

	switch function.Name() {
	case "Zero":
		return signature.Params().Len() == 0 && signature.Results().Len() == 0
	case "Empty":
		return signature.Params().Len() == 0 && singleResultIdentical(signature, types.Typ[types.Bool])
	case "String", "GoString":
		return signature.Params().Len() == 0 && singleResultIdentical(signature, types.Typ[types.String])
	case "Format":
		return signature.Params().Len() == 2 && signature.Results().Len() == 0 &&
			isNamedType(signature.Params().At(0).Type(), "fmt", "State") &&
			types.Identical(signature.Params().At(1).Type(), types.Typ[types.Rune])
	case "MarshalJSON", "MarshalText":
		return signature.Params().Len() == 0 && signature.Results().Len() == 2 &&
			isByteSlice(signature.Results().At(0).Type()) &&
			types.Identical(signature.Results().At(1).Type(), types.Universe.Lookup("error").Type())
	default:
		return false
	}
}

func singleResultIdentical(signature *types.Signature, expected types.Type) bool {
	return signature.Results().Len() == 1 && types.Identical(signature.Results().At(0).Type(), expected)
}

func isByteSlice(valueType types.Type) bool {
	slice, ok := types.Unalias(valueType).(*types.Slice)
	return ok && types.Identical(slice.Elem(), types.Typ[types.Byte])
}

func isPointerToNamed(valueType, expected types.Type) bool {
	pointer, ok := types.Unalias(valueType).(*types.Pointer)
	return ok && types.Identical(types.Unalias(pointer.Elem()), types.Unalias(expected))
}

func isNamedType(valueType types.Type, packagePath, name string) bool {
	named, ok := types.Unalias(valueType).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == packagePath && named.Obj().Name() == name
}

func secretAPIFinding(files *token.FileSet, object types.Object, message string) finding {
	position := files.Position(object.Pos())
	return finding{filename: position.Filename, line: position.Line, column: position.Column, message: message}
}

func policyForSource(relativePath string) sourcePolicy {
	normalized := filepath.ToSlash(filepath.Clean(relativePath))
	policy := sourcePolicy{
		allowBubbleTeaImport:    strings.HasPrefix(normalized, "internal/tui/"),
		allowSourceImporter:     normalized == "internal/archcheck/main.go",
		allowTestInfrastructure: strings.HasSuffix(normalized, "_test.go"),
		enforceVerifierBoundary: strings.HasPrefix(normalized, "internal/verify/") || strings.HasPrefix(normalized, "internal/observation/"),
		enforceSecretAPISurface: strings.HasPrefix(normalized, "internal/secret/") && !strings.HasSuffix(normalized, "_test.go"),
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
