# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.1] - 2026-02-02

### Bugfix
- Fix timestamp, correctly show UTC time
- Fix issue with composer auditor - `CVE` and `Affected Versions` is always `unknown` / `N/A`

### Changed
- Removed CHANGELOG.md builder from GitHub action
- Parse CHANGELOG.md for release body

**Full Changelog**: https://github.com/shadowbane/audit-checks/compare/v1.0.0...v1.0.1

## [v1.0.0] - 2026-02-01

### Added
- Add Laravel app scanning feature with `app scan`
  - Scans immediate subdirectories for Laravel apps (detects `artisan` file)
  - Reads APP_NAME from `.env` file, falls back to directory name
  - Skips apps already in database (by path)
  - Prompts for custom name on conflicts
  - Supports `--all` flag for non-interactive bulk adding

### Changed
- Allow renaming apps with `app edit --name <newname>`
- Improved `app list` formatting
  - Dynamic column width based on longest app name
  - Shows full paths without truncation

**Full Changelog**: https://github.com/shadowbane/audit-checks/compare/v0.3.1...v1.0.0

## [v0.3.1] - 2026-01-31



**Full Changelog**: https://github.com/shadowbane/audit-checks/compare/v0.3...v0.3.1

## [v0.3] - 2026-01-31

**Full Changelog**: https://github.com/shadowbane/audit-checks/compare/3eef08b5c2a1addcb75de2ed90e47dafed77e059...v0.3

