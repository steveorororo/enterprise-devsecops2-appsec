# Enterprise DevSecOps AppSec Platform

Centrally maintained security execution engine for application pipelines, together with the
validation, regression testing and third-party tool lifecycle that keep it trustworthy.

This repository is not copied into application repositories. Application repositories call
its reusable workflows at an approved immutable commit.

```text
Application repository
        |
        | thin caller pinned to an immutable commit
        v
Reusable security workflow in this repository
        |
        v
Security result and gate
```

Audience is AppSec and platform maintainers. Application developers work from the developer
starter template instead.

## What this repository executes

| Workflow | Consumer job id | Control |
|---|---|---|
| `secret-scanning.yml` | `secrets-scan` | Committed credentials, full history |
| `dependency-security.yml` | `sca-trivy-fs` | Dependency vulnerabilities |
| `dependency-review.yml` | `dependency-review` | Dependencies added by a pull request |
| `iac-security.yml` | `iac-checkov` | Rendered manifests and container build |
| `manifest-security.yml` | `manifest-lint` | Kubernetes manifest security |
| `code-scanning.yml` | `codeql` | Static analysis |
| `security-gate.yml` | `gate` | Aggregate required check |
| `contract-check.yml` | not gated | Consumer wiring check |

Consumer job ids are part of the contract. They are what a consuming repository's gate
configuration and branch protection evaluate, so a control whose id changes stops being
evaluated while still reporting success.

Image build, SBOM, signing and GitOps promotion remain in the consuming repository. Moving
them requires a registry and credentials to demonstrate equivalence, which the current
validation environment does not provide, and an unproven extraction is not worth the blast
radius of centralizing it.

## Layout

| Path | Purpose |
|---|---|
| `platform/versions.yaml` | Platform version to approved immutable commit mapping |
| `platform/contract.yaml` | Reusable workflow interface, machine readable |
| `platform/toolchain.yaml` | Centrally owned third-party dependencies and their verification |
| `.github/workflows/` | Reusable security workflows consumers call |
| `security/` | Central scanner policy and the mandatory control set |
| `scripts/` | Release and contract gates, consumer updater, baseline harness |
| `tests/consumers/` | Representative application repository caller |
| `tests/fixtures/` | Clean, vulnerable and failure-mode fixtures |
| `tests/baseline/` | Expected control behaviour, machine readable |
| `tests/regression/` | Tests that the gates reject bad input |
| `docs/` | Architecture and compatibility rules |

## Validation

```text
python3 scripts/validate-platform-versions.py
python3 scripts/validate-consumer-contract.py
python3 scripts/validate-consumer-pin.py --target <consumer>
python3 tests/regression/test-fail-closed.py
python3 tests/regression/test-central-policy.py
python3 tests/regression/test-gate-contract.py --target <consumer>
python3 tests/regression/test-render-invariant.py --target <consumer> --tools <dir>
python3 scripts/run-baseline.py --target <consumer> --tools <dir> --codeql <cli>
```

Requires PyYAML. Scanner binaries are fetched at run time and are not committed.

## Releasing

1. Change the implementation and run the suite above.
2. Add the commit to `platform/versions.yaml` as a released version. The mapping is a gate:
   an unknown, malformed or unresolvable entry blocks rather than warns.
3. Move consumers with `scripts/update-consumer.py --target <consumer> --version <x.y.z>`,
   which rewrites the recorded release and every pinned reference together and refuses any
   version that is not released.

Release is not adoption. A consumer keeps executing its pinned commit until it merges the
update, so reporting should track which repositories have adopted a release rather than
assuming a fix propagated when it was published.
