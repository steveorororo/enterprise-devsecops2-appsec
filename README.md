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

## Current state

No platform version is released. The reusable security workflows are not implemented here
yet, and security implementation has not been extracted from the developer template. What
exists is the foundation the extraction will be measured against:

- the platform version to commit mapping and its release gate
- the reusable workflow compatibility contract and a consumer fixture
- the third-party toolchain inventory
- the validation harness and the recorded current-state security baseline

## Layout

| Path | Purpose |
|---|---|
| `platform/versions.yaml` | Platform version to approved immutable commit mapping |
| `platform/contract.yaml` | Reusable workflow interface, machine readable |
| `platform/toolchain.yaml` | Centrally owned third-party dependencies and their verification |
| `scripts/` | Release and contract gates, baseline harness |
| `tests/consumers/` | Representative application repository caller |
| `tests/fixtures/` | Clean, vulnerable and failure-mode fixtures |
| `tests/baseline/` | Expected control behaviour, machine readable |
| `tests/regression/` | Tests that the gates reject bad input |
| `docs/` | Architecture and compatibility rules |

## Validation

```text
python3 scripts/validate-platform-versions.py
python3 scripts/validate-consumer-contract.py
python3 tests/regression/test-fail-closed.py
python3 scripts/run-baseline.py --target <path to the developer template>
```

Requires PyYAML. Scanner binaries are fetched at run time and are not committed.
