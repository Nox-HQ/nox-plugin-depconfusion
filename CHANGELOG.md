# Changelog

All notable changes to this project will be documented in this file.

- chore(deps): Go 1.26.5 and nox SDK v1.17.0 (#26)
- chore(deps): bump actions/setup-go from 6.5.0 to 7.0.0 (#19)


## [0.2.3] - 2026-07-25

### Fixed

- **DEPCONF-003 no longer fires on well-known public npm scopes.** The rule
  reported any scoped package lacking an `.npmrc`, which flagged the most
  ordinary dependencies in the ecosystem — `@types/node` and `@types/vscode`
  among them. Dependency confusion is the risk that a *private* name, one an
  attacker can claim on the public registry to shadow an internal package,
  resolves to the attacker's copy; `@types`, `@babel`, `@eslint` and friends
  have no private original to shadow. Scopes that look private (`@internal/*`,
  `@private/*`) still fire, and an unknown scope is still reported — for a rule
  about names an attacker could claim, failing toward reporting is the safe
  default.

- chore: add CI/CD, lint config, pre-commit hooks, and fix lint issues
- chore: add LICENSE, .gitignore, and tidy go.mod

