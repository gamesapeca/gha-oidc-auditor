# gha-oidc-auditor

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/gamesapeca/gha-oidc-auditor.svg)](https://pkg.go.dev/github.com/gamesapeca/gha-oidc-auditor)
[![Go Report Card](https://goreportcard.com/badge/github.com/gamesapeca/gha-oidc-auditor)](https://goreportcard.com/report/github.com/gamesapeca/gha-oidc-auditor)
[![CI](https://github.com/gamesapeca/gha-oidc-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/gamesapeca/gha-oidc-auditor/actions/workflows/ci.yml)

Static security analyzer and least-privilege cloud trust policy engine for GitHub Actions OIDC workflows.

## Why This Project Exists

Modern cloud security standards (OpenSSF, CIS Benchmarks, AWS/GCP best practices) strongly advise replacing long-lived static credentials (`AWS_ACCESS_KEY_ID`, service account JSON keys) with **OpenID Connect (OIDC)** ephemeral authentication.

However, adopting OIDC shifts the security perimeter from credential storage to **workflow configuration integrity**:

* **OIDC Tokens Are Minted on Demand**: When a job requests `id-token: write`, GitHub's OIDC provider (`token.actions.githubusercontent.com`) issues a signed JWT containing runner claims (`sub`, `aud`, `repository`, `ref`, `environment`).
* **Supply Chain & Injection Attacks Steal Cloud Sessions**: If an OIDC-privileged job runs an unpinned action (`actions/checkout@v4`) or interpolates untrusted user data (`${{ github.event.issue.title }}`), attackers can achieve Remote Code Execution (RCE) inside the runner and exfiltrate short-lived cloud credentials directly from memory.
* **Overprivileged Trust Policies Grant Organization-Wide Access**: Cloud administrators frequently configure wildcard trust policies (`repo:my-org/*`), allowing any developer or compromised repository in the organization to assume production deployment roles.

`gha-oidc-auditor` was created to solve these challenges by providing:
1. **Deterministic Static Analysis**: Deep AST parsing of GitHub Actions workflows to identify OIDC privilege leaks, injection sinks, and insecure trigger combinations before they reach production.
2. **Automated Least-Privilege Policy Synthesis**: Mathematical generation of strict Cloud Trust Policies for AWS IAM, GCP Workload Identity Federation, and Azure Entra ID scoped strictly to verified branches and environment approval gates.

## Threat Model

When GitHub Actions workflows use OIDC to authenticate against cloud providers (AWS, GCP, Azure, HashiCorp Vault), ephemeral JSON Web Tokens (JWTs) are issued by GitHub's OIDC provider (`token.actions.githubusercontent.com`).

Vulnerabilities in workflow configuration or dependency management allow adversaries to compromise or mint tokens:

1. **Unauthorized Token Minting (`pull_request_target`)**: Workflows triggered by `pull_request_target` with `id-token: write` allow pull requests from forks to mint tokens with base-repository claims unless gated by environment approvals.
2. **Action Poisoning in Privileged Jobs**: Unpinned actions (using tags like `@v4` or `@main`) in jobs with `id-token: write` can be backdoored upstream to read `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` from runner memory.
3. **Context Injection to Token Exfiltration**: Untrusted context expressions (`${{ github.event.issue.title }}`) interpolated into `run:` scripts allow arbitrary command execution before or during cloud authentication.
4. **Overprivileged Cloud Trust Policies**: Wildcard claims (`repo:org/*`) in cloud trust policies allow any repository in an organization to assume production roles.

## Rules Catalog

| Rule ID | Severity | Name | Description |
| :--- | :--- | :--- | :--- |
| `OIDC-001` | HIGH | Global `id-token: write` | Workflow grants `id-token: write` at root level instead of job scope. |
| `OIDC-002` | CRITICAL | Ungated `pull_request_target` | `pull_request_target` trigger with OIDC write without environment protection rules. |
| `OIDC-003` | HIGH | Unpinned Action in OIDC Job | Privileged OIDC job uses mutable action refs instead of 40-char commit SHAs. |
| `OIDC-004` | CRITICAL | Context Injection in OIDC Step | Untrusted `${{ github.event.* }}` expressions evaluated in shell steps in OIDC jobs. |
| `OIDC-005` | MEDIUM | Multi-Cloud Ambiguity | Multiple cloud provider authentications combined in a single unsegmented job. |
| `OIDC-006` | CRITICAL | Unfiltered `workflow_run` | `workflow_run` trigger without branch filters minting OIDC tokens. |

## Installation

### Binary Installation

```bash
go install github.com/gamesapeca/gha-oidc-auditor/cmd/gha-oidc@latest
```

### Build from Source

```bash
git clone https://github.com/gamesapeca/gha-oidc-auditor.git
cd gha-oidc-auditor
make build
```

## Usage

### Local Workflow Audit

Scan all workflows in `.github/workflows`:

```bash
gha-oidc --path .github/workflows
```

Scan a single workflow file:

```bash
gha-oidc --path .github/workflows/deploy.yml
```

### Remote Repository Audit

Audit a remote repository using the GitHub API:

```bash
gha-oidc --repo owner/repo --token $GITHUB_TOKEN
```

### Organization-Wide Scan

Scan all active repositories in an organization:

```bash
gha-oidc --org my-org --token $GITHUB_TOKEN --format markdown --output audit-report.md
```

### Least-Privilege Trust Policy Generation

Generate scoped trust policies for AWS, GCP, or Azure based on detected workflow triggers and environments:

```bash
gha-oidc --path .github/workflows --generate-policies
```

Example generated AWS IAM Trust Policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:gamesapeca/gha-oidc-auditor:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

### CI/CD Integration

Add `gha-oidc-auditor` as a pipeline gate:

```yaml
name: Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1

      - name: Set up Go
        uses: actions/setup-go@0c52d547c9bc32b1aa3301fd7a9cb496313a4491 # v5.0.0
        with:
          go-version: '1.22'

      - name: Run OIDC Security Audit
        run: |
          go run ./cmd/gha-oidc --path .github/workflows --fail-on critical
```

## Flags Reference

| Flag | Shorthand | Default | Description |
| :--- | :--- | :--- | :--- |
| `--path` | `-p` | `.github/workflows` | Local path to workflow file or directory |
| `--repo` | `-r` | `""` | Remote GitHub repository (`owner/repo`) |
| `--org` | `-o` | `""` | GitHub organization name |
| `--token` | `-t` | `$GITHUB_TOKEN` | GitHub API Personal Access Token |
| `--format` | `-f` | `console` | Output format (`console`, `json`, `markdown`) |
| `--fail-on` | | `critical` | Exit threshold (`critical`, `high`, `medium`, `all`, `none`) |
| `--generate-policies` | | `false` | Synthesize least-privilege cloud trust policies |
| `--output` | | `""` | Output file path for audit results |

## Exit Codes

- `0`: Scan passed; no findings at or above failure threshold.
- `1`: Non-critical findings detected at or above failure threshold.
- `2`: Critical vulnerabilities detected (`OIDC-002`, `OIDC-004`, `OIDC-006`).
- `3`: Workflow parsing error.
- `4`: GitHub API communication failure.
- `5`: Invalid CLI arguments.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
