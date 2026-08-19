# Compatibility contract

The reusable workflow interface is an enterprise API. `platform/contract.yaml` is the machine
readable statement of it and is checked against the consumer fixture in
`tests/consumers/`. This file states the rules for changing it.

## Covered by the contract

Workflow paths, required and optional inputs, outputs, required secret names, expected
permissions, the required status check name, gate semantics, supported configuration
structure and supported caller behaviour.

## Breaking changes

The following require compatibility analysis and regression evidence before release:

- removing or renaming any contract element
- changing the meaning of an existing element
- increasing required privileges
- increasing secret exposure
- changing gate semantics
- renaming the required status check

Renaming the status check deserves particular care. Application repository rulesets require
it by name, so a rename removes branch protection for every consumer until each one updates.

## Compatible changes

Adding an optional input with a safe default, adding an output, and internal implementation
changes that leave observable behaviour unchanged. Prefer additive evolution.

## Version isolation is not multi-version serving

Consumers are isolated by their pinned commit, so this repository does not serve several
runtime versions at once and does not branch per release. The contract exists to protect
consumers at the moment they upgrade, not to keep old interfaces alive indefinitely.

## Secret contract

Each reusable workflow declares only the secrets it requires, and each caller passes only
those. `secrets: inherit` is rejected: a compromised application repository must not reach
unrelated credentials merely because they exist in the caller environment. Prefer OIDC or
short lived workload identity where the approved target platform supports it.
