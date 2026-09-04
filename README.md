# gha-oidc-auditor

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/gamesapeca/gha-oidc-auditor.svg)](https://pkg.go.dev/github.com/gamesapeca/gha-oidc-auditor)
[![Go Report Card](https://goreportcard.com/badge/github.com/gamesapeca/gha-oidc-auditor)](https://goreportcard.com/report/github.com/gamesapeca/gha-oidc-auditor)
[![CI](https://github.com/gamesapeca/gha-oidc-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/gamesapeca/gha-oidc-auditor/actions/workflows/ci.yml)

Static security analyzer, least-privilege cloud trust policy engine, and zero-prerequisite offensive exploit chain synthesizer for GitHub Actions OIDC workflows.

## Why This Project Exists

Modern cloud security standards (OpenSSF, CIS Benchmarks, AWS/GCP best practices) strongly advise replacing long-lived static credentials (`AWS_ACCESS_KEY_ID`, service account JSON keys) with **OpenID Connect (OIDC)** ephemeral authentication.

However, adopting OIDC shifts the security perimeter from credential storage to **workflow configuration integrity**:

* **OIDC Tokens Are Minted on Demand**: When a job requests `id-token: write`, GitHub's OIDC provider (`token.actions.githubusercontent.com`) issues a signed JWT containing runner claims (`sub`, `aud`, `repository`, `ref`, `environment`).
* **Supply Chain & Injection Attacks Steal Cloud Sessions**: If an OIDC-privileged job runs an unpinned action (`actions/checkout@v4`), inherits secrets into third-party reusable workflows (`secrets: inherit`), or interpolates untrusted user data (`${{ github.event.issue.title }}`), attackers can achieve Remote Code Execution (RCE) inside the runner and exfiltrate short-lived cloud credentials directly from memory.
* **Overprivileged Trust Policies Grant Organization-Wide Access**: Cloud administrators frequently configure wildcard trust policies (`repo:my-org/*`), allowing any developer or compromised repository in the organization to assume production deployment roles.

`gha-oidc-auditor` was created to solve these challenges by providing:
1. **Deterministic Static Analysis**: Deep AST parsing of GitHub Actions workflows to identify OIDC privilege leaks, injection sinks, unpinned dependencies, and insecure trigger combinations before they reach production.
2. **Context-Aware Evaluation Matrix**: Precise noise reduction that evaluates `if:` actor/repository conditions, distinguishes external attacker payloads from internal inputs, deduplicates repeated step occurrences, and recognizes cryptographic architectural exceptions (such as SLSA Framework generators).
3. **Offensive Exploit Chains & Bug Bounty Mode**: Automated correlation of multi-condition zero-prerequisite attack paths with instant synthesis of submission-ready HackerOne/Bugcrowd Proof-of-Concept markdown reports.
4. **Automated Least-Privilege Policy Synthesis**: Mathematical generation of strict Cloud Trust Policies for AWS IAM, GCP Workload Identity Federation, Azure Entra ID, HashiCorp Vault JWT, and Kubernetes ServiceAccounts scoped strictly to verified branches and environment approval gates.

## Threat Model & Attack Primitives

When GitHub Actions workflows authenticate against cloud providers (AWS, GCP, Azure, HashiCorp Vault), ephemeral JSON Web Tokens (JWTs) are issued by GitHub's OIDC provider (`token.actions.githubusercontent.com`).

Adversaries exploit configuration flaws across 4 primary attack vectors:

1. **Unauthorized Token Minting (`pull_request_target`)**: Workflows triggered by `pull_request_target` with `id-token: write` allow pull requests from forks to mint tokens with base-repository claims unless gated by environment approvals.
2. **Action Poisoning in Privileged Jobs**: Unpinned actions (using mutable tags like `@v4` or `@main`) in jobs with `id-token: write` can be backdoored upstream to exfiltrate `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` from runner memory.
3. **Context Injection to Token Exfiltration**: Untrusted context expressions (`${{ github.event.issue.title }}`, `${{ github.event.comment.body }}`) interpolated into `run:` scripts allow arbitrary command execution before or during cloud authentication.
4. **Secrets Delegation via `secrets: inherit`**: Delegating all secrets to external third-party reusable workflows exposes cloud credentials and tokens to unvetted caller contexts.
5. **Overprivileged Cloud Trust Policies**: Wildcard claims (`repo:org/*`) in cloud trust policies allow any repository in an organization to assume production roles.

## Rules Catalog

| Rule ID | Severity | Name | Description |
| :--- | :--- | :--- | :--- |
| `OIDC-001` | HIGH / MEDIUM | Global `id-token: write` | Workflow grants `id-token: write` at root level instead of job scope. Severity scales with workflow triggers (HIGH for untrusted triggers, MEDIUM for internal/push triggers). |
| `OIDC-002` | CRITICAL / HIGH / MEDIUM | Context-Aware `pull_request_target` | `pull_request_target` trigger with OIDC write. Evaluated contextually: CRITICAL for untrusted fork checkout, HIGH for ungated execution, MEDIUM for guarded actor checks. |
| `OIDC-003` | HIGH | Mutable Action Pinning | Privileged OIDC job uses mutable action refs instead of 40-char commit SHAs. Automatically deduplicates multiple step occurrences and grants exceptions to SLSA generators. |
| `OIDC-004` | CRITICAL / MEDIUM | Context & Input Injection | Untrusted expressions interpolated in shell steps in OIDC jobs. Differentiates external attacker payloads (CRITICAL) from internal parameters (MEDIUM). |
| `OIDC-005` | MEDIUM | Multi-Cloud Ambiguity | Multiple cloud provider authentications combined in a single unsegmented job. |
| `OIDC-006` | CRITICAL | Unfiltered `workflow_run` | `workflow_run` trigger without branch filters minting OIDC tokens. |
| `OIDC-007` | HIGH | Self-Hosted Runner in OIDC Job | Non-ephemeral self-hosted runner executing privileged OIDC workflow on public triggers without approval gates. |
| `OIDC-008` | HIGH | External `secrets: inherit` | OIDC-privileged job delegating all caller secrets to external/third-party reusable workflows. |
| `OIDC-009` | HIGH | High-Value Action Mutable Tag | Detects high-value supply chain actions (e.g. `tj-actions`, `docker`, `aws-actions`) pinned by mutable tags anywhere in the workflow (CVE-2025-30066 class). |
| `OIDC-010` | INFO | 2026 Immutable Sub-Claim Format | Advisory finding detecting missing numeric organization and repository IDs (`repo:org@ID/repo@ID:*`) in subject claims following GitHub's July 2026 update. |
| `OIDC-011` | CRITICAL / HIGH | Secret / OIDC Token Log Exfiltration | Detects shell execution patterns leaking secrets (`echo $ACTIONS_ID_TOKEN...`, `printenv`, `env -0`) or deprecated `::set-output::` syntax. |
| `OIDC-012` | HIGH | Wildcard Cloud Trust Policy | Identifies cloud authentication configurations using wildcard sub-claims (`repo:org/*`), exposing organization-wide blast radius. |

### Detailed Rule Explanations

#### OIDC-001: Global id-token: write Permission
Workflows defining `permissions: id-token: write` at the top level expose token minting rights to all jobs, violating job-level isolation.
* Remediation: Define `permissions:` exclusively inside specific deployment jobs that interact with cloud providers.

#### OIDC-002: Context-Aware pull_request_target
The `pull_request_target` event runs in the context of the base repository. When combined with checkout of the fork reference (`ref: ${{ github.event.pull_request.head.sha }}`) and `id-token: write`, an external contributor can execute malicious code with base repository OIDC rights.
* Remediation: Gate the job behind a GitHub Environment approval or use `on: pull_request` for untrusted contributions.

#### OIDC-003: Action Pinning in Privileged Jobs
Actions referenced by mutable git tags (`@v4`, `@main`) can be hijacked upstream if maintainer credentials are compromised. In an OIDC-privileged job, a compromised action can exfiltrate `$ACTIONS_ID_TOKEN_REQUEST_TOKEN` directly from runner memory.
* Remediation: Pin actions to their immutable 40-character commit SHA (e.g., `actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11`).

#### OIDC-004: Context and Input Injection
Direct inline interpolation of untrusted expressions (e.g., `${{ github.event.issue.title }}`) into `run:` script bodies allows shell metacharacter injection before or during cloud authentication.
* Remediation: Pass dynamic context variables through environment variables under `env:` rather than inline template syntax `${{ }}`.

#### OIDC-005: Multi-Cloud Ambiguity
Authenticating against multiple cloud providers (e.g., AWS and GCP) in the same unsegmented job increases blast radius if one step or dependency is compromised.
* Remediation: Separate cloud deployments into dedicated, isolated jobs.

#### OIDC-006: Unfiltered workflow_run
Workflows triggering on `workflow_run` without explicit branch filters (`branches: [main]`) can be triggered by workflow runs from arbitrary branches, minting OIDC tokens on untrusted code executions.
* Remediation: Restrict `workflow_run` to protected branches and verify `github.event.workflow_run.head_branch`.

#### OIDC-007: Self-Hosted Runner on Public Triggers
Executing OIDC-privileged jobs on self-hosted runners without ephemeral container isolation or environment gates allows persistent compromise of internal network infrastructure.
* Remediation: Use GitHub-hosted runners or ephemeral runner groups with mandatory review gates.

#### OIDC-008: External secrets: inherit Delegation
Using `secrets: inherit` when calling external reusable workflows from third-party repositories passes all caller repository secrets to external infrastructure.
* Remediation: Explicitly define only the required secret arguments rather than inheriting all secrets.

#### OIDC-009: High-Value Action Mutable Tags (Supply Chain Hardening)
High-value actions frequently targeted in supply chain attacks (such as `tj-actions/changed-files`, `docker/login-action`, `aws-actions/configure-aws-credentials`) should always be SHA-pinned regardless of whether the specific job has OIDC tokens enabled.
* Remediation: Pin all high-value supply chain dependencies to 40-character commit SHAs.

#### OIDC-010: July 2026 Immutable Sub-Claim Verification
As of July 15, 2026, GitHub updated the default OIDC subject claim to include immutable numeric IDs (`repo:org@ID/repo@ID:*`). IAM policies relying solely on mutable repository names are vulnerable to name-squatting if an organization or repository is deleted and reregistered.
* Remediation: Update AWS IAM and cloud trust policies to accept both legacy and immutable numeric ID formats.

#### OIDC-011: Secret / OIDC Token Log Exfiltration
Shell commands executing `printenv`, `env -0`, or dumping token variables (`$ACTIONS_ID_TOKEN_REQUEST_TOKEN`) write sensitive ephemeral tokens into workflow logs, exposing them to log scraping.
* Remediation: Remove debug print statements and migrate away from deprecated `::set-output::` commands.

#### OIDC-012: Wildcard Cloud Trust Policy Detection
Cloud IAM trust policies configured with `repo:org/*` allow any repository in an organization to assume production roles, breaking tenant isolation.
* Remediation: Scope trust conditions strictly to specific repositories, branches (`ref:refs/heads/main`), and environments (`environment:production`).



## Zero-Prerequisite Exploit Chains (Bug Bounty Mode)

In addition to SAST posture auditing, `gha-oidc-auditor` operates in **Bug Bounty Mode** (`--bounty-mode`). In this mode, the engine correlates multi-condition security flaws across all primary CI/CD vulnerability classes:

* **`CHAIN-001` (Pwn-Request RCE via `pull_request_target`)** `[CWE-94 - CVSS 9.8]`: `pull_request_target` + no environment approval gate + no actor guard + checkout of untrusted fork ref (`head.sha`) + subsequent build/test execution + `id-token: write`.
* **`CHAIN-002` (Public Trigger Shell Command Injection)** `[CWE-78 - CVSS 9.8]`: Public event trigger (`issues`, `issue_comment`, `pull_request`) + no actor guard + shell step interpolating external data (`${{ github.event.comment.body }}`) + `id-token: write`.
* **`CHAIN-003` (JavaScript Code Injection in `actions/github-script`)** `[CWE-94 - CVSS 9.8]`: Public trigger + inline `${{ }}` template interpolation in JavaScript step + `id-token: write`.
* **`CHAIN-004` (Privilege Escalation via `workflow_run` Artifact Poisoning)** `[CWE-494 - CVSS 9.3]`: `workflow_run` without branch filters + artifact download + execution + `id-token: write`.
* **`CHAIN-005` (Token Write Privilege Escalation via `pull_request_target`)** `[CWE-269 - CVSS 9.1]`: `pull_request_target` + untrusted fork checkout + `contents: write` / `write-all` permissions without environment approval gate.
* **`CHAIN-006` (Repository Secrets Exfiltration via `secrets: inherit`)** `[CWE-522 - CVSS 8.6]`: Public trigger + external reusable workflow call with `secrets: inherit` without actor filters.
* **`CHAIN-007` (Runner Environment Hijacking via `$GITHUB_ENV`)** `[CWE-78 - CVSS 9.8]`: Public trigger + writing untrusted context directly to `$GITHUB_ENV` or `$GITHUB_PATH`.
* **`CHAIN-008` (Self-Hosted Runner Infrastructure Takeover)** `[CWE-284 - CVSS 9.8]`: Public trigger + execution on self-hosted runners without environment approval gate.

When executed with `--generate-poc`, the engine outputs a submission-ready Markdown report complete with HackerOne/Intigriti CWE classifications, reproduction steps, and deterministic cloud credential exfiltration payloads for AWS STS, GCP WIF, Azure AD, and HashiCorp Vault.


## Installation

### Binary Installation

```bash
go install github.com/gamesapeca/gha-oidc-auditor/cmd/gha-oidc@latest
```

### Docker / GitHub Container Registry

Run directly via OCI container image without needing Go installed locally:

```bash
docker run --rm -v $(pwd):/workspace ghcr.io/gamesapeca/gha-oidc-auditor:latest --path /workspace/.github/workflows
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

### Bug Bounty Mode & PoC Generation

Filter scan results exclusively for exploitable zero-prerequisite attack chains:

```bash
gha-oidc --repo target-org/target-repo --token $GITHUB_TOKEN --bounty-mode
```

Generate a submission-ready Bug Bounty Proof of Concept report:

```bash
gha-oidc --repo target-org/target-repo --token $GITHUB_TOKEN --generate-poc --poc-output report.md
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

### Remediation-as-Code (Terraform / OpenTofu HCL Generation)

Synthesize production-ready Terraform / OpenTofu `.tf` files directly for AWS IAM OIDC, GCP WIF, and Azure Entra ID:

```bash
# Output Terraform HCL to stdout
gha-oidc --path .github/workflows --generate-hcl --format hcl

# Write modular .tf files to infrastructure directory
gha-oidc --path .github/workflows --generate-hcl --hcl-output ./terraform/modules/gha_oidc
```

Example generated AWS IAM Terraform HCL module (with July 2026 immutable numeric IDs):

```hcl
# Generated by gha-oidc-auditor (Least-Privilege Remediation for my-org/my-service)
data "aws_iam_policy_document" "my_service_gha_oidc_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:my-org/my-service:ref:refs/heads/main",
        "repo:my-org@*/my-service@*:ref:refs/heads/main" # July 2026 Immutable Format
      ]
    }
  }
}

resource "aws_iam_role" "my_service_gha_deploy_role" {
  name               = "my-service-gha-deploy"
  assume_role_policy = data.aws_iam_policy_document.my_service_gha_oidc_assume_role.json
  tags = {
    ManagedBy = "gha-oidc-auditor"
    Security  = "Least-Privilege-OIDC"
  }
}
```

### Offline Cloud Trust Policy Verification (CIEM Mode)

Cross-audit an existing live AWS IAM Trust Policy or GCP WIF configuration against least-privilege standards:

```bash
# Audit an AWS IAM Trust Relationship JSON document
gha-oidc --verify-policy aws_trust_relationship.json --cloud-provider aws --repo my-org/my-service

# Audit a GCP Workload Identity Pool Provider configuration
gha-oidc --verify-policy gcp_wif_config.json --cloud-provider gcp --repo my-org/my-service
```

### CI/CD Integration

#### Official GitHub Action
Add `gha-oidc-auditor` as a native step in your GitHub Actions pipeline:

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

      - name: Run GHA OIDC Security Audit
        uses: gamesapeca/gha-oidc-auditor@v0.1.0
        with:
          path: .github/workflows
          fail-on: critical
```

#### GitHub Code Scanning (SARIF) Integration
Export results directly into GitHub's Security tab using official SARIF v2.1.0 output:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1

      - name: Run GHA OIDC Security Audit (SARIF)
        run: |
          go run ./cmd/gha-oidc --path .github/workflows --format sarif --output results.sarif --fail-on none

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Flags Reference

| Flag | Shorthand | Default | Description |
| :--- | :--- | :--- | :--- |
| `--path` | `-p` | `.github/workflows` | Local path to workflow file or directory |
| `--repo` | `-r` | `""` | Remote GitHub repository (`owner/repo`) |
| `--org` | `-o` | `""` | GitHub organization name |
| `--token` | `-t` | `$GITHUB_TOKEN` | GitHub API Personal Access Token |
| `--format` | `-f` | `console` | Output format (`console`, `json`, `sarif`, `markdown`, `hcl`) |
| `--concurrency` | `-c` | `runtime.NumCPU()` | Parallel workers for multi-workflow / multi-repo analysis |
| `--fail-on` | | `critical` | Exit threshold (`critical`, `high`, `medium`, `all`, `none`) |
| `--generate-policies` | | `false` | Synthesize least-privilege cloud trust policies (JSON) |
| `--generate-hcl` | | `false` | Synthesize Remediation-as-Code Terraform / OpenTofu HCL modules |
| `--hcl-output` | | `""` | Directory path to save synthesized `.tf` files |
| `--verify-policy` | | `""` | Cross-audit an existing local cloud trust policy JSON file |
| `--cloud-provider` | | `aws` | Cloud provider for policy verification (`aws`, `gcp`, `azure`) |
| `--output` | | `""` | Output file path for audit results |
| `--bounty-mode` | | `false` | Filter report to display only exploitable zero-prerequisite attack chains |
| `--generate-poc` | | `false` | Generate a submission-ready Bug Bounty PoC Markdown report |
| `--poc-output` | | `""` | Output file path to save the generated Bug Bounty PoC report |

## Exit Codes

- `0`: Scan passed; no findings at or above failure threshold.
- `1`: Non-critical findings detected at or above failure threshold.
- `2`: Critical vulnerabilities detected (`OIDC-002`, `OIDC-004`, `OIDC-006` or Exploit Chains).
- `3`: Workflow parsing error.
- `4`: GitHub API communication failure.
- `5`: Invalid CLI arguments.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
