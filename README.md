# gha-oidc-auditor

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.22-00ADD8?logo=go)](https://golang.org/)
[![CI](https://img.shields.io/badge/Security-AST%20Auditor-red.svg)]()

> **Security static analyzer & least-privilege cloud trust policy generator for GitHub Actions OIDC workflows.**

`gha-oidc-auditor` is an automated security analyzer designed to detect and remediate **Supply-Chain-to-Cloud Takeover** vulnerabilities in GitHub Actions workflows. It inspects ephemeral token issuance (`id-token: write`), execution triggers (`pull_request_target`, `workflow_run`), dependency immutability (SHA pinning), and context expression injections (`${{ ... }}`), synthesizing minimal-privilege Cloud Trust Policies for AWS IAM, GCP Workload Identity Federation, and Azure Entra ID.

---

## 🎯 The Threat Landscape

The migration from long-lived static secrets (`AWS_SECRET_ACCESS_KEY`) to federated OIDC authentication significantly improved credential safety in repose. However, it created a critical attack surface centered around the **ephemeral token lifecycle**:

```
+-----------------------------------------------------------------------------------------+
|                               ATTACK & EXPLOITATION SURFACE                             |
+-----------------------------------------------------------------------------------------+
| 1. Unauthorized Token Minting via External PR                                           |
|    'pull_request_target' + 'permissions: id-token: write'                               |
|    ──► External fork PRs can mint base repository OIDC tokens.                          |
|                                                                                         |
| 2. Dependency Hijacking in Privileged Jobs (Tag Poisoning)                             |
|    Mutable action references (e.g. '@v4', '@main') in OIDC jobs                        |
|    ──► Compromised upstream action captures ACTIONS_ID_TOKEN_REQUEST_URL from runner.    |
|                                                                                         |
| 3. Expression Context Injection (RCE)                                                   |
|    Interpolation of '${{ github.event.issue.title }}' in 'run:' steps                   |
|    ──► Injected command exfiltrates OIDC JWT prior to cloud authentication.             |
|                                                                                         |
| 4. Overprivileged Cloud Trust Policies (Wildcard IAM)                                   |
|    Overly broad 'sub' claims (e.g. 'repo:org/*') in Cloud Provider                      |
|    ──► Any repository in the organization can assume production cloud roles.            |
+-----------------------------------------------------------------------------------------+
```

---

## ⚡ Key Features

- **End-to-End OIDC Chain Analysis:** Evaluates `Trigger -> AST -> id-token Permission -> Cloud Action -> Blast Radius`.
- **Precedence-Aware Permission Resolution:** Accurately models GitHub Actions permission inheritance (`Job > Workflow > Org Default`).
- **Cloud Action Matcher:** Identifies and extracts Role ARNs, GCP Workload Pools, and Azure Client IDs from steps.
- **Automated Trust Policy Synthesizer:** Automatically generates minimal least-privilege IAM Trust Policies with strict `StringEquals` constraints for `aud` and `sub`.
- **CI/CD Integration Ready:** Configurable `--fail-on` thresholds and standard exit codes (`0`, `1`, `2`) for pipeline gates.
- **Resilient Remote Scans:** GitHub REST API fetcher with automatic `X-RateLimit-Reset` backoff and pagination.

---

## 📊 Comparison Matrix

| Feature | `actionlint` | `zizmor` | `checkov` | `gha-oidc-auditor` |
| :--- | :---: | :---: | :---: | :---: |
| **Primary Domain** | Syntax & Types | General GHA Linter | IaC & Compliance | **OIDC & Cloud Trust Security** |
| **OIDC + Cloud Provider Correlation** | ❌ | Partial | ❌ | **✅ Full (Roles, ARNs, Pools)** |
| **Cloud Trust Policy Generator** | ❌ | ❌ | ❌ | **✅ Automated (AWS / GCP / Azure)** |
| **Untrusted Context Injection in OIDC** | ❌ | ✅ | ❌ | **✅ Multiline AST Extraction** |
| **Precedence Permission Matrix** | ❌ | Partial | ❌ | **✅ Full Matrix Resolution** |
| **Remote Organization Auditing** | ❌ | Partial | ❌ | **✅ Rate-Limited Async Fetcher** |

---

## 🛡️ Rules Catalog

| Rule ID | Severity | Name | Description |
| :--- | :---: | :--- | :--- |
| **`OIDC-001`** | `HIGH` | Global `id-token: write` Exposure | Workflow defines `id-token: write` or `write-all` at the root level instead of restricting to specific jobs. |
| **`OIDC-002`** | `CRITICAL` | Ungated `pull_request_target` OIDC | Trigger `pull_request_target` combined with `id-token: write` without environment manual approval gate. |
| **`OIDC-003`** | `HIGH` | Mutable Action in OIDC Job | Privileged OIDC job uses mutable action references (`@v4`, `@main`) instead of immutable 40-character SHAs. |
| **`OIDC-004`** | `CRITICAL` | Context Injection in OIDC Step | Untrusted context (`${{ github.event.* }}`) interpolated into `run:` steps in an OIDC-privileged job. |
| **`OIDC-005`** | `MEDIUM` | Multi-Cloud Scope Ambiguity | Multiple cloud providers (e.g. AWS & GCP) authenticated within the same unsegmented job. |
| **`OIDC-006`** | `CRITICAL` | Unfiltered `workflow_run` OIDC | Workflow triggered via `workflow_run` without branch filtering while minting OIDC tokens. |

---

## 🚀 Installation

### Via Go Install:
```bash
go install github.com/gamesapeca/gha-oidc-auditor/cmd/gha-oidc@latest
```

### Build from Source:
```bash
git clone https://github.com/gamesapeca/gha-oidc-auditor.git
cd gha-oidc-auditor
go build -o gha-oidc ./cmd/gha-oidc
```

---

## 📖 Usage

### 1. Audit Local Repository Workflows
```bash
gha-oidc --path ./.github/workflows
```

### 2. Audit Remote GitHub Repository
```bash
gha-oidc --repo owner/repository --token $GITHUB_TOKEN
```

### 3. Audit Entire GitHub Organization
```bash
gha-oidc --org your-organization --token $GITHUB_TOKEN --format markdown --output audit_report.md
```

### 4. Synthesize Least-Privilege Cloud Trust Policies
```bash
gha-oidc --path ./.github/workflows --generate-policies
```

### 5. CI/CD Security Gate (GitHub Actions)
```yaml
- name: Audit OIDC Workflows
  run: |
    go install github.com/gamesapeca/gha-oidc-auditor/cmd/gha-oidc@latest
    gha-oidc --path ./.github/workflows --fail-on critical
```

---

## 📋 Generated Policy Sample (AWS IAM)

When run with `--generate-policies`, `gha-oidc-auditor` extracts workflow context to generate strict IAM Trust Policies:

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

---

## 🧪 Testing

Execute the comprehensive test suite (AST, Rules Engine, Remediation, Fetcher, and Reports):

```bash
go test -v ./...
```

---

## 📄 License

Distributed under the **Apache License 2.0**. See [`LICENSE`](LICENSE) for more information.
