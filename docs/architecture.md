# Architecture

## Two repositories

The developer starter template is thin and application facing. It holds application
configuration, build and deployment material, and thin callers. It does not own centrally
reusable security implementation.

This repository owns the security implementation, its validation, and the lifecycle of the
third-party tools it depends on. It is called, not copied.

The implementation that is tested here is the implementation that is released. Security
logic is not validated here and then copied back into the template, because that recreates
the distributed pipeline problem the split exists to remove.

## Versioning

Two values are tracked separately and must not be conflated.

`template_version` records which generation of the starter template created an application
repository. `platform_version` records which approved central release that repository
currently consumes.

A consumer pins an immutable commit. That pin provides version isolation on its own: two
applications on different releases execute different commits without this repository
maintaining parallel runtime branches. Release branches per version are therefore not
created. What is required is release mapping and traceability, held in
`platform/versions.yaml`.

Automated updates may raise the pinned commit, and must move `platform_version` in the same
change so the two never drift.

## Release is not adoption

A central fix is implemented once, tested once and released once. Repositories pinned to an
earlier commit keep executing that commit until they adopt an update. Reporting should
distinguish the current release, the version each repository has adopted, repositories
offered an update, and repositories overdue for a critical one. Update pull requests are not
propagation unless organization governance enforces their adoption.

## Two anti-bypass controls

Central policy prevents weakening controls inside the pipeline. A caller asking for a
mandatory control to be disabled does not get it disabled.

Repository rulesets prevent bypassing the pipeline entirely. A caller deleted from an
application repository removes the required check, and the ruleset blocks the merge.

These address different bypass paths and both are required. Neither substitutes for the
other.

## Authoritative security profile

A developer declared classification is configuration, not authority. The interface is
designed so the authoritative profile can later come from an approved enterprise source. The
system of record has not been selected, and is not assumed here. Where a declared
classification conflicts with an authoritative one, the control fails clearly rather than
accepting the weaker value.

## Artifact integrity

The immutable digest returned by the registry is the artifact identity. Mutable tags are not
the promotion identity. The artifact is built once, scanned by digest, has an SBOM bound to
that digest, and is promoted by that digest.

Verification at build time alone is not sufficient. Identity and signature or attestation are
verified again before workload execution, and a verification failure blocks deployment. Where
that enforcement lives, in admission control or elsewhere, is an enterprise platform decision
and is not assumed here.

## Extraction rule

Before a capability moves from the template into this repository, its current behaviour is
measured. For each capability a clean case and a relevant vulnerable case run through both
implementations, and finding, scanner result, job conclusion and gate conclusion are
compared. A new implementation may be stricter only under an approved decision. Unexplained
divergence stops that extraction and the existing implementation stays in place.

A capability with an unresolved detection gap is not centralized. Centralization multiplies
blast radius, and an unknown weakness distributed to every consumer is worse than the same
weakness in one repository.
