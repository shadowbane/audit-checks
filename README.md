<div align="center">

# Audit-Checks

**Automated Security Auditing for Your Projects**

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/License-PolyForm%20Noncommercial-blue.svg?style=for-the-badge)](https://polyformproject.org/licenses/noncommercial/1.0.0/)
[![Inspired by Dependabot](https://img.shields.io/badge/Inspired%20by-Dependabot-0366d6?style=for-the-badge&logo=dependabot&logoColor=white)](https://github.com/dependabot)

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue?style=flat-square)]()
[![Gemini AI](https://img.shields.io/badge/AI%20Powered-Google%20Gemini-4285F4?style=flat-square&logo=google&logoColor=white)](https://ai.google.dev/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white)](https://sqlite.org/)

*A Go-based security auditing tool that automates vulnerability scanning across multiple deployments.*
*Particularly useful for teams managing numerous Laravel/PHP applications alongside Node.js projects.*

---

</div>

## Table of Contents

- [Overview](#overview)
- [Why This Tool?](#why-this-tool)
- [Features](#features)
- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Environment Variables](#environment-variables)
- [Deployment](#deployment)
- [License](#license)

## Overview

A Go-based security auditing tool inspired by GitHub's Dependabot. Built to automate security monitoring across multiple deployments - particularly useful for teams managing numerous Laravel/PHP applications alongside Node.js projects.

Instead of manually checking each project for vulnerabilities, Audit-Checks automatically runs security audits, tracks vulnerabilities over time, generates comprehensive reports, and sends notifications to stakeholders. With optional Google Gemini AI integration, you get intelligent summaries that make monitoring dozens of applications much easier.

## Why This Tool?

Managing security across multiple deployments can be overwhelming. If you're running dozens of Laravel applications (or
any mix of PHP/Node.js projects), manually running `composer audit` or `npm audit` on each one is tedious and easy to
forget.

Audit-Checks solves this by:

- **Centralizing audits** - Configure all your apps once, run a single command
- **Automating notifications** - Get Telegram or email alerts only when vulnerabilities are found
- **Providing AI summaries** - Gemini integration distills complex vulnerability reports into actionable insights
- **Tracking history** - SQLite database keeps audit history for trend analysis
- **Integrating with CI/CD** - Exit codes make it easy to fail pipelines on security issues

## Features

- **Multi-Package Manager Support** - Supports `composer audit` for PHP/Laravel projects and `npm audit` for Node.js
- **Concurrent Auditing** - Audit multiple projects simultaneously with configurable concurrency
- **Severity Filtering** - Only report vulnerabilities above your configured severity threshold
- **AI-Powered Analysis** - Optional Google Gemini integration for business risk assessment and remediation suggestions
- **Multiple Report Formats** - Generate JSON and Markdown reports automatically
- **Notification Channels** - Email (via Resend) and Telegram (with forum topic support)
- **Database Persistence** - Track vulnerability history in SQLite for trend analysis
- **Ignore Lists** - Per-app configuration to ignore specific CVEs or packages
- **CI/CD Ready** - Exit codes indicate vulnerability status for pipeline integration

## How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CLI Entry Point                               │
│                    (run, setup, app commands)                           │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Load Configuration                                 │
│              (Environment variables via Viper)                          │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Initialize Application                               │
│  ┌──────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────────┐    │
│  │   SQLite DB  │ │  Auditors  │ │ Reporters  │ │    Notifiers     │    │
│  │              │ │ (npm,      │ │ (JSON,     │ │ (Email,          │    │
│  │              │ │  composer) │ │  Markdown) │ │  Telegram)       │    │
│  └──────────────┘ └────────────┘ └────────────┘ └──────────────────┘    │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Run Audits (Concurrent)                            │
│                                                                         │
│  For each enabled app:                                                  │
│    1. Detect/Select appropriate auditor (npm or composer)               │
│    2. Execute audit command (npm audit --json / composer audit)         │
│    3. Parse results and extract vulnerabilities                         │
│    4. Filter by severity threshold                                      │
│    5. Run Gemini AI analysis (optional)                                 │
│    6. Store results in database                                         │
│    7. Generate reports (JSON, Markdown)                                 │
│    8. Send notifications (Email, Telegram)                              │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Generate Summary Report                              │
│                                                                         │
│  Exit Codes:                                                            │
│    0 = No vulnerabilities found                                         │
│    1 = Vulnerabilities found above threshold                            │
│    2 = Application error                                                │
└─────────────────────────────────────────────────────────────────────────┘
```

### Auditors

The application uses a registry pattern for pluggable auditors:

- **Composer Auditor**: Detects `composer.json` or `composer.lock`, runs `composer audit --format=json` (ideal for
  Laravel/PHP projects)
- **NPM Auditor**: Detects `package.json` or `package-lock.json`, runs `npm audit --json`

### Reporters

Reports are generated in the configured output directory:

- **JSON Reporter**: Machine-readable format with full vulnerability details
- **Markdown Reporter**: Human-readable tables with recommendations

Report filenames follow the pattern: `{appName}-{auditorType}-{YYYY-MM-DD-HHMMSS}.{json|md}`

### Notifiers

- **Email (Resend)**: Sends HTML-formatted vulnerability alerts
- **Telegram**: Creates dedicated forum topics per app for organized notifications (bot requires "Manage Topics" admin
  permission)

## Prerequisites

- Go 1.24 or later
- Node.js and npm (for auditing Node.js projects)
- PHP and Composer (for auditing PHP projects)
- SQLite

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/audit-checks.git
cd audit-checks

# Build the binary
go build -o audit-checks

# Or install directly
go install
```

### Configuration

1. Copy the example environment file:

```bash
cp .env.example .env
```

2. Edit `.env` with your configuration (see [Environment Variables](#environment-variables) below)

3. Initialize the database:

```bash
./audit-checks setup
```

4. Add applications to audit:

```bash
./audit-checks app add --name myapp --path /path/to/project --type npm
```

## Usage

### Commands

```bash
# Run audits for all enabled apps
./audit-checks run

# Run audit for a specific app
./audit-checks run --app myapp

# Dry run (no notifications sent)
./audit-checks run --dry-run

# Verbose logging
./audit-checks run --verbose

# Report only (skip notifications)
./audit-checks run --report-only

# Output as JSON
./audit-checks run --json-output

# Initialize/setup database
./audit-checks setup

# Show version
./audit-checks version
```

### App Management

```bash
# Add a new application
./audit-checks app add --name myapp --path /path/to/project --type npm

# List all applications
./audit-checks app list

# Show app details
./audit-checks app show myapp

# Enable/disable an application
./audit-checks app enable myapp
./audit-checks app disable myapp

# Edit an application
./audit-checks app edit myapp --path /new/path

# Remove an application
./audit-checks app remove myapp
```

## Environment Variables

### Application Environment

| Variable           | Description                                             | Default          |
|--------------------|---------------------------------------------------------|------------------|
| `APP_ENV`          | Environment mode (`production`, `development`, `local`) | `production`     |
| `LOG_LEVEL`        | Log level (`debug`, `info`, `warn`, `error`)            | `info`           |
| `LOG_DIRECTORY`    | Directory for log files                                 | `./storage/logs` |
| `LOG_FILE_ENABLED` | Enable file logging                                     | `true`           |
| `LOG_MAX_SIZE`     | Max log file size in MB                                 | `5`              |
| `LOG_MAX_BACKUPS`  | Number of log backups to keep                           | `10`             |
| `LOG_MAX_AGE`      | Max age of log files in days                            | `30`             |

### Database

| Variable         | Description                                           | Default              |
|------------------|-------------------------------------------------------|----------------------|
| `DB_SQLITE_PATH` | Path to SQLite database file                          | `./storage/audit.db` |
| `DB_LOG_LEVEL`   | Database log level (`debug`, `info`, `warn`, `error`) | `warn`               |

### Email Notifications (Resend)

| Variable            | Description                               | Default |
|---------------------|-------------------------------------------|---------|
| `RESEND_API_KEY`    | API key from [Resend](https://resend.com) | -       |
| `RESEND_FROM_EMAIL` | Sender email address                      | -       |

### Telegram Notifications

| Variable             | Description                                         | Default |
|----------------------|-----------------------------------------------------|---------|
| `TELEGRAM_BOT_TOKEN` | Bot token from [@BotFather](https://t.me/BotFather) | -       |
| `TELEGRAM_GROUP_ID`  | Group ID (negative number, must be forum-enabled)   | -       |
| `TELEGRAM_ENABLED`   | Enable Telegram notifications                       | `false` |

### AI Enhancement (Google Gemini)

| Variable         | Description                                                    | Default            |
|------------------|----------------------------------------------------------------|--------------------|
| `GEMINI_API_KEY` | API key from [Google AI Studio](https://makersuite.google.com) | -                  |
| `GEMINI_ENABLED` | Enable Gemini AI analysis                                      | `false`            |
| `GEMINI_MODEL`   | Gemini model to use                                            | `gemini-2.5-flash` |

### Audit Settings

| Variable             | Description                                                        | Default             |
|----------------------|--------------------------------------------------------------------|---------------------|
| `SEVERITY_THRESHOLD` | Minimum severity to report (`critical`, `high`, `moderate`, `low`) | `moderate`          |
| `REPORT_FORMATS`     | Comma-separated report formats (`json`, `markdown`)                | `json,markdown`     |
| `REPORT_OUTPUT_DIR`  | Directory for generated reports                                    | `./storage/reports` |
| `MAX_CONCURRENT`     | Maximum concurrent audits                                          | `3`                 |
| `RETRY_ATTEMPTS`     | Number of retry attempts on failure                                | `3`                 |

## Deployment

### Standalone Binary

```bash
# Build for production
CGO_ENABLED=1 go build -ldflags="-s -w" -o audit-checks

# Run with environment file
./audit-checks run
```

### Docker

```dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN apk add --no-cache gcc musl-dev
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o audit-checks

FROM alpine:latest
RUN apk add --no-cache nodejs npm php composer
WORKDIR /app
COPY --from=builder /app/audit-checks .
COPY .env.example .env
CMD ["./audit-checks", "run"]
```

### Scheduled Execution (Cron)

```bash
# Run daily at 6 AM
0 6 * * * cd /path/to/audit-checks && ./audit-checks run >> /var/log/audit-checks.log 2>&1
```

### CI/CD Integration

The application returns exit codes suitable for CI/CD pipelines:

- **Exit 0**: No vulnerabilities found - pipeline continues
- **Exit 1**: Vulnerabilities found above threshold - can fail the pipeline
- **Exit 2**: Application error - should investigate

Example GitHub Actions workflow:

```yaml
name: Security Audit
on:
  schedule:
    - cron: '0 6 * * *'
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Build
        run: go build -o audit-checks

      - name: Run Audit
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
          TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}
        run: ./audit-checks run
```

## Database Schema

The SQLite database contains the following tables:

- **apps**: Configured applications with settings, notification preferences, and Telegram topic IDs
- **settings**: Key-value configuration store
- **audit_results**: Audit run history with severity counts
- **vulnerabilities**: Individual vulnerability records linked to audit results

## Report Output

Reports are saved in the configured output directory with the following naming convention:

```
{appName}-{auditorType}-{YYYY-MM-DD-HHMMSS}.json
{appName}-{auditorType}-{YYYY-MM-DD-HHMMSS}.md
summary-{YYYY-MM-DD-HHMMSS}.json
summary-{YYYY-MM-DD-HHMMSS}.md
```

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/).

### You are free to:

- **Use** - For personal, educational, research, and nonprofit purposes
- **Modify** - Make changes and create derivative works
- **Share** - Distribute copies of the software

### Restrictions:

- **NonCommercial** - You may not use this software for commercial purposes

For the full license text, see [LICENSE.md](LICENSE.md).

---

<div align="center">

**Made with :heart: for the Laravel & PHP community**

</div>