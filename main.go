package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// internalPrefixes lists package name prefixes that commonly indicate internal
// or organisation-scoped packages susceptible to dependency confusion.
var internalPrefixes = []struct {
	Pattern *regexp.Regexp
	Reason  string
}{
	{regexp.MustCompile(`^@internal/`), "Package uses @internal/ scope which may collide with public registry"},
	{regexp.MustCompile(`^@private/`), "Package uses @private/ scope which may collide with public registry"},
	{regexp.MustCompile(`^@corp/`), "Package uses @corp/ scope which may collide with public registry"},
	{regexp.MustCompile(`^@company/`), "Package uses @company/ scope which may collide with public registry"},
	{regexp.MustCompile(`^internal[-_]`), "Package name starts with 'internal-' prefix indicating private package"},
	{regexp.MustCompile(`^company[-_]`), "Package name starts with 'company-' prefix indicating private package"},
	{regexp.MustCompile(`^corp[-_]`), "Package name starts with 'corp-' prefix indicating private package"},
	{regexp.MustCompile(`^private[-_]`), "Package name starts with 'private-' prefix indicating private package"},
}

// manifestFiles maps package manifest filenames to their ecosystem.
var manifestFiles = map[string]string{
	"package.json":      "npm",
	"requirements.txt":  "pip",
	"setup.py":          "pip",
	"setup.cfg":         "pip",
	"pyproject.toml":    "pip",
	"Pipfile":           "pip",
	"Gemfile":           "gem",
	"go.mod":            "go",
	"pom.xml":           "maven",
	"build.gradle":      "gradle",
	"build.gradle.kts":  "gradle",
	"composer.json":     "composer",
	"Cargo.toml":        "cargo",
}

// privateRegistryConfigs maps ecosystems to their expected private registry
// configuration files.
var privateRegistryConfigs = map[string][]string{
	"npm":      {".npmrc", ".yarnrc", ".yarnrc.yml"},
	"pip":      {"pip.conf", ".pip/pip.conf", "pyproject.toml"},
	"gem":      {".gemrc"},
	"composer": {"auth.json"},
	"maven":    {"settings.xml", ".mvn/settings.xml"},
	"gradle":   {"gradle.properties", "init.gradle"},
}

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
}

// npmPackageJSON represents a minimal package.json structure.
type npmPackageJSON struct {
	Name            string            `json:"name"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// composerJSON represents a minimal composer.json structure.
type composerJSON struct {
	Name    string            `json:"name"`
	Require map[string]string `json:"require"`
}

// reScopedPackage matches npm scoped packages (@scope/name).
var reScopedPackage = regexp.MustCompile(`^@[a-z0-9][\w.-]*/`)

// rePipRequirement matches a pip requirement line (package==version or package>=version).
var rePipRequirement = regexp.MustCompile(`^([a-zA-Z0-9][\w.-]+)`)

// rePipExtraIndex matches pip --extra-index-url or --index-url configuration.
var rePipExtraIndex = regexp.MustCompile(`(?i)--?(extra-)?index-url`)

// reGoModule matches go.mod require directives.
var reGoModule = regexp.MustCompile(`^\s*([a-zA-Z0-9][\w./-]+)\s+v`)

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/depconfusion", version).
		Capability("depconfusion", "Dependency confusion detection and prevention").
		Tool("scan", "Scan for dependency confusion risks in package manifests", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	// Track which ecosystems have manifests and which have registry configs.
	ecosystemsFound := make(map[string]bool)
	registryConfigsFound := make(map[string]bool)

	// First pass: collect all manifest and config files.
	var manifestPaths []string

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()

		// Track manifest files.
		if ecosystem, ok := manifestFiles[name]; ok {
			ecosystemsFound[ecosystem] = true
			manifestPaths = append(manifestPaths, path)
		}

		// Track registry config files.
		for ecosystem, configs := range privateRegistryConfigs {
			for _, configName := range configs {
				if name == filepath.Base(configName) {
					registryConfigsFound[ecosystem] = true
				}
			}
		}

		return nil
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	// Second pass: scan manifests for confusion risks.
	for _, path := range manifestPaths {
		if ctx.Err() != nil {
			break
		}
		scanManifest(resp, path, workspaceRoot)
	}

	// Check for missing private registry configs.
	for ecosystem := range ecosystemsFound {
		if !registryConfigsFound[ecosystem] {
			if _, hasConfigs := privateRegistryConfigs[ecosystem]; hasConfigs {
				checkMissingRegistryConfig(resp, workspaceRoot, ecosystem)
			}
		}
	}

	return resp.Build(), nil
}

// scanManifest dispatches to the appropriate manifest scanner based on filename.
func scanManifest(resp *sdk.ResponseBuilder, path, workspaceRoot string) {
	name := filepath.Base(path)
	switch name {
	case "package.json":
		scanNPMManifest(resp, path)
	case "requirements.txt":
		scanPipManifest(resp, path)
	case "go.mod":
		scanGoMod(resp, path)
	case "composer.json":
		scanComposerManifest(resp, path)
	}
}

// scanNPMManifest checks package.json for dependency confusion risks.
func scanNPMManifest(resp *sdk.ResponseBuilder, filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	var pkg npmPackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return
	}

	// Check all dependencies for internal namespace collisions.
	allDeps := make(map[string]string)
	for k, v := range pkg.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		allDeps[k] = v
	}

	for depName, depVersion := range allDeps {
		// Check for internal package patterns.
		for _, prefix := range internalPrefixes {
			if prefix.Pattern.MatchString(depName) {
				resp.Finding(
					"DEPCONF-001",
					sdk.SeverityHigh,
					sdk.ConfidenceHigh,
					fmt.Sprintf("Namespace collision risk: %s@%s - %s", depName, depVersion, prefix.Reason),
				).
					At(filePath, 0, 0).
					WithMetadata("package", depName).
					WithMetadata("version", depVersion).
					WithMetadata("ecosystem", "npm").
					Done()
			}
		}

		// Check for scoped packages without explicit registry.
		if reScopedPackage.MatchString(depName) {
			checkScopedPackageSource(resp, filePath, depName, depVersion)
		}
	}
}

// checkScopedPackageSource reports scoped packages that lack explicit registry configuration.
func checkScopedPackageSource(resp *sdk.ResponseBuilder, filePath, depName, depVersion string) {
	// Extract scope from package name.
	parts := strings.SplitN(depName, "/", 2)
	if len(parts) != 2 {
		return
	}
	scope := parts[0]

	// Check if .npmrc exists in the same directory with a registry for this scope.
	dir := filepath.Dir(filePath)
	npmrcPath := filepath.Join(dir, ".npmrc")
	if _, err := os.Stat(npmrcPath); err != nil {
		resp.Finding(
			"DEPCONF-003",
			sdk.SeverityMedium,
			sdk.ConfidenceMedium,
			fmt.Sprintf("Scoped package %s has no explicit registry source (no .npmrc found)", depName),
		).
			At(filePath, 0, 0).
			WithMetadata("package", depName).
			WithMetadata("scope", scope).
			WithMetadata("ecosystem", "npm").
			Done()
		return
	}

	// Read .npmrc and check for scope registry.
	data, err := os.ReadFile(npmrcPath)
	if err != nil {
		return
	}
	scopeRegistry := fmt.Sprintf("%s:registry=", scope)
	if !strings.Contains(string(data), scopeRegistry) {
		resp.Finding(
			"DEPCONF-003",
			sdk.SeverityMedium,
			sdk.ConfidenceMedium,
			fmt.Sprintf("Scoped package %s has no explicit registry mapping in .npmrc", depName),
		).
			At(filePath, 0, 0).
			WithMetadata("package", depName).
			WithMetadata("scope", scope).
			WithMetadata("ecosystem", "npm").
			Done()
	}
}

// scanPipManifest checks requirements.txt for dependency confusion risks.
func scanPipManifest(resp *sdk.ResponseBuilder, filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	hasExtraIndex := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for extra-index-url.
		if rePipExtraIndex.MatchString(line) {
			hasExtraIndex = true
			continue
		}

		matches := rePipRequirement.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}

		pkgName := matches[1]

		for _, prefix := range internalPrefixes {
			if prefix.Pattern.MatchString(pkgName) {
				resp.Finding(
					"DEPCONF-001",
					sdk.SeverityHigh,
					sdk.ConfidenceHigh,
					fmt.Sprintf("Namespace collision risk: %s - %s", pkgName, prefix.Reason),
				).
					At(filePath, lineNum, lineNum).
					WithMetadata("package", pkgName).
					WithMetadata("ecosystem", "pip").
					Done()
			}
		}
	}

	// If internal-looking packages are present but no extra-index-url, flag it.
	if !hasExtraIndex {
		// Re-scan for internal packages to issue DEPCONF-003.
		f2, err := os.Open(filePath)
		if err != nil {
			return
		}
		defer f2.Close()

		scanner2 := bufio.NewScanner(f2)
		lineNum2 := 0
		for scanner2.Scan() {
			lineNum2++
			line := strings.TrimSpace(scanner2.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			matches := rePipRequirement.FindStringSubmatch(line)
			if len(matches) < 2 {
				continue
			}
			pkgName := matches[1]
			for _, prefix := range internalPrefixes {
				if prefix.Pattern.MatchString(pkgName) {
					resp.Finding(
						"DEPCONF-003",
						sdk.SeverityMedium,
						sdk.ConfidenceMedium,
						fmt.Sprintf("Package %s has no explicit registry source (no --extra-index-url)", pkgName),
					).
						At(filePath, lineNum2, lineNum2).
						WithMetadata("package", pkgName).
						WithMetadata("ecosystem", "pip").
						Done()
				}
			}
		}
	}
}

// scanGoMod checks go.mod for dependency confusion risks.
func scanGoMod(resp *sdk.ResponseBuilder, filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	inRequire := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" && inRequire {
			inRequire = false
			continue
		}

		if !inRequire {
			continue
		}

		matches := reGoModule.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}

		modulePath := matches[1]

		// Go modules with no dots in the first path segment are suspicious
		// because they are not hosted on a known domain.
		parts := strings.SplitN(modulePath, "/", 2)
		if len(parts) > 0 && !strings.Contains(parts[0], ".") {
			resp.Finding(
				"DEPCONF-001",
				sdk.SeverityHigh,
				sdk.ConfidenceHigh,
				fmt.Sprintf("Namespace collision risk: Go module %s has no domain prefix", modulePath),
			).
				At(filePath, lineNum, lineNum).
				WithMetadata("module", modulePath).
				WithMetadata("ecosystem", "go").
				Done()
		}
	}
}

// scanComposerManifest checks composer.json for dependency confusion risks.
func scanComposerManifest(resp *sdk.ResponseBuilder, filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	var pkg composerJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return
	}

	for depName, depVersion := range pkg.Require {
		for _, prefix := range internalPrefixes {
			if prefix.Pattern.MatchString(depName) {
				resp.Finding(
					"DEPCONF-001",
					sdk.SeverityHigh,
					sdk.ConfidenceHigh,
					fmt.Sprintf("Namespace collision risk: %s@%s - %s", depName, depVersion, prefix.Reason),
				).
					At(filePath, 0, 0).
					WithMetadata("package", depName).
					WithMetadata("version", depVersion).
					WithMetadata("ecosystem", "composer").
					Done()
			}
		}
	}
}

// checkMissingRegistryConfig reports when an ecosystem's manifest exists but
// no private registry configuration is found.
func checkMissingRegistryConfig(resp *sdk.ResponseBuilder, workspaceRoot, ecosystem string) {
	configs := privateRegistryConfigs[ecosystem]
	configNames := strings.Join(configs, ", ")

	resp.Finding(
		"DEPCONF-002",
		sdk.SeverityMedium,
		sdk.ConfidenceMedium,
		fmt.Sprintf("No private registry configuration found for %s ecosystem (expected one of: %s)", ecosystem, configNames),
	).
		At(workspaceRoot, 0, 0).
		WithMetadata("ecosystem", ecosystem).
		WithMetadata("expected_configs", configNames).
		Done()
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-depconfusion: %v\n", err)
		os.Exit(1)
	}
}
