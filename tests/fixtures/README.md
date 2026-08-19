# Fixtures

Inputs for the baseline and regression harness. Each fixture tests one property and has an
entry in `tests/baseline/expectations.yaml` stating the control, the tool and the expected
result.

Fixtures under `vulnerable-dependency`, `hardcoded-secret`, `insecure-manifest`,
`insecure-dockerfile` and `codeql-injection` are defective on purpose. They are inputs to
scanners and are never built, deployed or executed. The credential material is synthetic and
grants no access.

A scanner run over this repository will report findings here. That is the intended result.
Exclusions belong on the exact fixture path and only for the tools that would otherwise
process these files as production code.
