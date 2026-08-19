# Security

## Reporting

Report a suspected vulnerability in this platform to the AppSec platform maintainers through
the approved enterprise channel. Do not open a public issue for an unpatched weakness.

## Why this repository is sensitive

Application repositories execute the workflows published here. A defect, a weakened control
or an unverified third-party dependency propagates to every repository that adopts the
affected release. Changes are reviewed on that basis rather than on the size of the diff.

## Controls that must not be weakened

- Mandatory controls fail closed. A scanner technical failure is not evidence that an
  application is secure, and is never reported as a pass.
- `continue-on-error` is not used for a mandatory control, and mandatory controls are not
  made skippable to obtain a green result.
- Workflows declare `permissions: {}` and grant the minimum at job level. A reusable workflow
  does not silently broaden caller privileges.
- Secret contracts are explicit. `secrets: inherit` is not a supported calling convention,
  because it grants a callee every credential the caller holds.
- Consumers pin immutable commits. Mutable references are not acceptable for production.
- Third-party artifacts are verified, and the trust material used to verify them is itself
  pinned and reviewed.

## Release integrity

A platform version resolves to exactly one approved immutable commit. The mapping is enforced
by `scripts/validate-platform-versions.py`, which fails closed on a missing, unknown,
malformed, mismatched or unresolvable entry. Release pressure is not a reason to bypass it.

Release is not adoption. A repository pinned to an older commit continues to execute that
commit until it adopts an update.
