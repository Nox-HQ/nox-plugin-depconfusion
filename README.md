# nox-plugin-depconfusion

**Dependency confusion guard for supply chain security.**

## Overview

`nox-plugin-depconfusion` detects dependency confusion attack vectors in package manifests across multiple ecosystems. Dependency confusion (also called namespace confusion) occurs when an attacker publishes a malicious package to a public registry using the same name as an internal/private package, tricking build systems into downloading the attacker-controlled version instead of the legitimate internal one.

This plugin scans package manifests (`package.json`, `requirements.txt`, `go.mod`, `composer.json`, and others) for packages with names that follow internal naming conventions -- prefixes like `@internal/`, `@corp/`, `company-`, `private-` -- and verifies that appropriate private registry configurations exist to anchor these packages to their intended source. It also checks for missing registry configuration files (`.npmrc`, `pip.conf`, `.gemrc`) that are essential for preventing confusion attacks.

The plugin belongs to the **Supply Chain** track and operates with a passive risk class. It performs read-only analysis of package manifests and registry configuration files without executing any package manager commands or making network requests.

## Use Cases

### Protecting Internal NPM Packages from Public Squatting

A large engineering organization uses scoped NPM packages under `@acme/` for internal shared libraries. Without an `.npmrc` file mapping the `@acme` scope to the private registry, `npm install` could resolve `@acme/auth-utils` from the public npmjs.com registry if an attacker publishes a package with that name. The depconfusion plugin flags every scoped package without an explicit registry mapping.

### Auditing Python Projects Before Enabling Extra Index URLs

A data science team uses internal Python packages named `company-ml-pipeline` and `internal-data-loader` alongside public PyPI packages. The plugin detects these internal-looking package names in `requirements.txt` and checks whether `--extra-index-url` or `--index-url` directives are present to ensure packages are fetched from the correct source.

### Validating Go Module Paths for Domain Ownership

Go modules without a domain prefix in their module path (e.g., `require internal-utils v1.0.0` instead of `require github.com/acme/internal-utils v1.0.0`) are flagged because they cannot be verified against a known domain, making them susceptible to confusion attacks. The plugin catches these non-domain-prefixed modules in `go.mod`.

### Ensuring Registry Configuration Exists Across Ecosystems

When a repository contains `package.json`, `requirements.txt`, and `Gemfile`, the plugin verifies that corresponding registry configuration files (`.npmrc`, `pip.conf`, `.gemrc`) exist. Missing configurations for any ecosystem with active manifests are flagged, alerting teams to potential confusion vectors they may not have considered.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/nox-hq/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install nox-hq/nox-plugin-depconfusion
   ```

2. **Create a test project with risky dependency patterns**

   ```bash
   mkdir -p demo-depconfusion && cd demo-depconfusion
   ```

   Create `package.json`:

   ```json
   {
     "name": "my-app",
     "dependencies": {
       "@internal/auth-utils": "^2.1.0",
       "@corp/billing-service": "^1.0.0",
       "express": "^4.18.0",
       "lodash": "^4.17.21"
     },
     "devDependencies": {
       "internal-test-helpers": "^1.0.0"
     }
   }
   ```

   Create `requirements.txt`:

   ```
   flask==3.0.0
   company-ml-pipeline==2.1.0
   private-data-loader==1.0.0
   requests==2.31.0
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/depconfusion .
   ```

4. **Review findings**

   ```
   DEPCONF-001  HIGH/HIGH    package.json:0     Namespace collision risk: @internal/auth-utils@^2.1.0 - Package uses @internal/ scope which may collide with public registry
   DEPCONF-001  HIGH/HIGH    package.json:0     Namespace collision risk: @corp/billing-service@^1.0.0 - Package uses @corp/ scope which may collide with public registry
   DEPCONF-001  HIGH/HIGH    package.json:0     Namespace collision risk: internal-test-helpers@^1.0.0 - Package name starts with 'internal-' prefix indicating private package
   DEPCONF-001  HIGH/HIGH    requirements.txt:2 Namespace collision risk: company-ml-pipeline - Package name starts with 'company-' prefix indicating private package
   DEPCONF-001  HIGH/HIGH    requirements.txt:3 Namespace collision risk: private-data-loader - Package name starts with 'private-' prefix indicating private package
   DEPCONF-002  MED/MED      .:0                No private registry configuration found for npm ecosystem (expected one of: .npmrc, .yarnrc, .yarnrc.yml)
   DEPCONF-002  MED/MED      .:0                No private registry configuration found for pip ecosystem (expected one of: pip.conf, .pip/pip.conf, pyproject.toml)
   DEPCONF-003  MED/MED      package.json:0     Scoped package @internal/auth-utils has no explicit registry source (no .npmrc found)
   DEPCONF-003  MED/MED      package.json:0     Scoped package @corp/billing-service has no explicit registry source (no .npmrc found)
   DEPCONF-003  MED/MED      requirements.txt:2 Package company-ml-pipeline has no explicit registry source (no --extra-index-url)
   DEPCONF-003  MED/MED      requirements.txt:3 Package private-data-loader has no explicit registry source (no --extra-index-url)

   11 findings (3 high, 8 medium)
   ```

## Rules

| Rule ID     | Description                                  | Severity | Confidence | CWE |
|-------------|----------------------------------------------|----------|------------|-----|
| DEPCONF-001 | Namespace collision risk: internal/org-prefixed package name matches patterns susceptible to dependency confusion | HIGH     | HIGH       | --  |
| DEPCONF-002 | Missing private registry configuration for ecosystem (no `.npmrc`, `pip.conf`, etc.) | MEDIUM   | MEDIUM     | --  |
| DEPCONF-003 | Ambiguous package source: scoped or internal package has no explicit registry mapping | MEDIUM   | MEDIUM     | --  |

### Internal Name Patterns Detected

| Pattern               | Example                   | Ecosystems |
|-----------------------|---------------------------|------------|
| `@internal/*`         | `@internal/auth-utils`    | npm        |
| `@private/*`          | `@private/config`         | npm        |
| `@corp/*`             | `@corp/billing-service`   | npm        |
| `@company/*`          | `@company/shared-models`  | npm        |
| `internal-*`          | `internal-test-helpers`   | npm, pip, composer |
| `company-*`           | `company-ml-pipeline`     | npm, pip, composer |
| `corp-*`              | `corp-data-utils`         | npm, pip, composer |
| `private-*`           | `private-data-loader`     | npm, pip, composer |

## Supported Languages / File Types

| Manifest File       | Ecosystem  | Analysis Depth                                |
|---------------------|------------|-----------------------------------------------|
| `package.json`      | npm        | Dependencies, devDependencies, scope registry |
| `requirements.txt`  | pip        | Package names, `--extra-index-url` directives |
| `setup.py`          | pip        | Manifest presence detection                   |
| `setup.cfg`         | pip        | Manifest presence detection                   |
| `pyproject.toml`    | pip        | Manifest presence detection                   |
| `Pipfile`           | pip        | Manifest presence detection                   |
| `go.mod`            | go         | Module paths, domain prefix validation        |
| `Gemfile`           | gem        | Manifest presence detection                   |
| `pom.xml`           | maven      | Manifest presence detection                   |
| `build.gradle`      | gradle     | Manifest presence detection                   |
| `build.gradle.kts`  | gradle     | Manifest presence detection                   |
| `composer.json`     | composer   | Require dependencies, name patterns           |
| `Cargo.toml`        | cargo      | Manifest presence detection                   |

## Configuration

The plugin uses Nox's standard configuration. No additional configuration is required.

```yaml
# .nox.yaml (optional)
plugins:
  nox/depconfusion:
    enabled: true
```

Directories automatically skipped during scanning: `.git`, `vendor`, `node_modules`, `__pycache__`, `.venv`.

## Installation

### Via Nox (recommended)

```bash
nox plugin install nox-hq/nox-plugin-depconfusion
```

### Standalone

```bash
go install github.com/nox-hq/nox-plugin-depconfusion@latest
```

### From source

```bash
git clone https://github.com/nox-hq/nox-plugin-depconfusion.git
cd nox-plugin-depconfusion
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run all tests
make test

# Run linter
make lint

# Build Docker image
docker build -t nox-plugin-depconfusion .

# Clean build artifacts
make clean
```

## Architecture

The plugin operates as a Nox plugin server communicating over stdio using the Nox Plugin SDK. The scan executes in two passes:

1. **Discovery Pass** -- Recursively walks the workspace to locate all package manifest files and registry configuration files. Each manifest is tagged with its ecosystem (npm, pip, go, etc.) and each registry config is tracked to determine coverage.
2. **Analysis Pass** -- Each discovered manifest is parsed with an ecosystem-specific scanner:
   - **NPM**: Parses `package.json`, checks all dependency names against internal prefix patterns, and verifies scoped packages have explicit registry mappings in `.npmrc`.
   - **pip**: Scans `requirements.txt` line-by-line for internal-looking package names and checks for `--extra-index-url` directives.
   - **Go**: Parses `go.mod` require blocks and flags modules whose first path segment lacks a domain (no dots).
   - **Composer**: Parses `composer.json` require sections for internal package name patterns.
3. **Registry Config Check** -- For each ecosystem with discovered manifests, the plugin verifies that at least one expected private registry configuration file exists in the workspace.

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/nox-hq/nox-plugin-depconfusion).

When extending ecosystem support:
1. Add the manifest filename to `manifestFiles` and the registry configs to `privateRegistryConfigs`.
2. Implement a `scan*Manifest` function with ecosystem-specific parsing logic.
3. Add test cases covering both positive detections and expected suppressions.

## License

Apache-2.0
