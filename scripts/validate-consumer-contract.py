#!/usr/bin/env python3
"""Check a consuming repository's caller against platform/contract.yaml.

The reusable workflow interface is an enterprise API. This detects drift that would break
consumers: a renamed or removed input, an undeclared input, a secret contract change, a
widened permission, a mutable workflow reference, or secrets: inherit.

Two further properties are enforced because they are security relevant rather than cosmetic.

  Job identity. The job id a consumer uses is the security gate contract. A control whose id
  changes stops being evaluated by the gate while everything still reports success.

  Pointer atomicity. The commit in the uses reference and the platform_ref input must be the
  same commit, and a declared platform_version must resolve to it. Otherwise a repository can
  execute one release while claiming another.

Permission comparison is one directional. A caller granting less than the contract declares is
acceptable. A caller granting more, or something the contract does not declare, is a privilege
increase and fails.
"""
import argparse
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRACT = REPO_ROOT / "platform" / "contract.yaml"
CONSUMER = REPO_ROOT / "tests" / "consumers" / "current" / "pr-security-caller.yml"
MAPPING = REPO_ROOT / "platform" / "versions.yaml"

SHA = re.compile(r"^[0-9a-f]{40}$")
UNRELEASED_REF = "PLATFORM_WORKFLOW_SHA"
RANK = {"read": 1, "write": 2}
PLATFORM_MARKER = "enterprise-devsecops2-appsec"


def load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def released_versions(mapping):
    """platform_version to commit, for released entries only."""
    released = {}
    if isinstance(mapping, dict):
        for entry in mapping.get("versions") or []:
            if isinstance(entry, dict) and entry.get("status") == "released":
                released[entry.get("platform_version")] = entry.get("workflow_sha")
    return released


def contract_for(contract, uses):
    for workflow in contract.get("workflows") or []:
        path = workflow.get("path", "")
        if path and path in uses:
            return workflow
    return None


def check_job(job_id, job, declared, released, problems):
    uses = job.get("uses", "")
    ref = uses.rsplit("@", 1)[-1] if "@" in uses else ""

    expected_id = declared.get("consumer_job_id")
    if expected_id and job_id != expected_id:
        problems.append("job %s calls %s, which the contract binds to job id %s. The job id is "
                        "the security gate contract." % (job_id, declared["path"], expected_id))

    if ref == UNRELEASED_REF:
        if released:
            problems.append("%s: a release exists, so the caller must pin a commit" % job_id)
        return
    if not SHA.fullmatch(ref):
        problems.append("%s: workflow reference %r is not a full 40 character commit"
                        % (job_id, ref))
        return

    supplied = job.get("with") or {}

    # Pointer atomicity.
    platform_ref = supplied.get("platform_ref")
    if platform_ref is not None and platform_ref != ref:
        problems.append("%s: platform_ref %s does not match the pinned commit %s"
                        % (job_id, str(platform_ref)[:12], ref[:12]))

    version = supplied.get("platform_version")
    if version is not None:
        resolved = released.get(str(version))
        if resolved is None:
            problems.append("%s: platform_version %s is not a released version"
                            % (job_id, version))
        elif resolved != ref:
            problems.append("%s: platform_version %s maps to %s but the caller executes %s"
                            % (job_id, version, resolved[:12], ref[:12]))

    # Inputs.
    inputs = declared.get("inputs") or {}
    required = {i["name"] for i in inputs.get("required") or []}
    optional = {i["name"] for i in inputs.get("optional") or []}
    for name in sorted(required - set(supplied)):
        problems.append("%s: omits required input %s" % (job_id, name))
    for name in sorted(set(supplied) - required - optional):
        problems.append("%s: passes undeclared input %s" % (job_id, name))

    # Secrets.
    secrets = job.get("secrets")
    if secrets == "inherit":
        problems.append("%s: uses secrets: inherit, which grants every caller credential"
                        % job_id)
    else:
        declared_secrets = declared.get("secrets") or {}
        allowed = {s["name"] for s in (declared_secrets.get("required") or [])}
        allowed |= {s["name"] for s in (declared_secrets.get("optional") or [])}
        supplied_secrets = set((secrets or {}).keys())
        for name in sorted(supplied_secrets - allowed):
            problems.append("%s: passes undeclared secret %s" % (job_id, name))
        for entry in declared_secrets.get("required") or []:
            if entry["name"] not in supplied_secrets:
                problems.append("%s: omits required secret %s" % (job_id, entry["name"]))

    # Permissions.
    contract_permissions = (declared.get("permissions") or {}).get("job") or {}
    for scope, level in (job.get("permissions") or {}).items():
        if scope not in contract_permissions:
            problems.append("%s: grants %s, which the contract does not declare"
                            % (job_id, scope))
        elif RANK.get(level, 99) > RANK.get(contract_permissions[scope], 0):
            problems.append("%s: grants %s: %s, exceeding the contract" % (job_id, scope, level))


def validate(contract, consumer, mapping):
    problems = []
    released = released_versions(mapping)

    if consumer.get("permissions") != {}:
        problems.append("caller workflow-level permissions must be {}")

    forbidden = (contract.get("caller") or {}).get("forbidden_references") or []
    calls = 0

    for job_id, job in (consumer.get("jobs") or {}).items():
        uses = (job or {}).get("uses", "")
        if PLATFORM_MARKER not in uses:
            continue
        calls += 1

        for reference in forbidden:
            if uses.endswith(reference):
                problems.append("%s: uses mutable reference %s" % (job_id, reference))

        declared = contract_for(contract, uses)
        if declared is None:
            problems.append("%s: calls %s, which the contract does not declare"
                            % (job_id, uses.split("@")[0]))
            continue
        check_job(job_id, job, declared, released, problems)

    if calls == 0:
        problems.append("caller does not invoke the platform at all")

    return problems


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--consumer", type=Path, default=CONSUMER)
    parser.add_argument("--mapping", type=Path, default=MAPPING)
    args = parser.parse_args()

    try:
        contract = load(args.contract)
        consumer = load(args.consumer)
        mapping = load(args.mapping)
    except (OSError, yaml.YAMLError) as exc:
        print("consumer contract check: cannot read inputs: %s" % exc, file=sys.stderr)
        return 1

    problems = validate(contract, consumer, mapping)
    if problems:
        print("consumer contract violated:", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1

    print("consumer contract satisfied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
