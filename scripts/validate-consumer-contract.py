#!/usr/bin/env python3
"""Check the consumer fixture against platform/contract.yaml.

The reusable workflow interface is an enterprise API. This detects drift that would break
application repositories: a renamed or removed input, an undeclared input, a secret contract
change, a widened permission, a mutable workflow reference, or secrets: inherit.

Permission comparison is one directional. A caller granting less than the contract declares
is acceptable. A caller granting more, or granting something the contract does not declare,
is a privilege increase and fails.
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


def load(path: Path) -> object:
    return yaml.safe_load(path.read_text())


def any_release_exists(mapping: object) -> bool:
    if not isinstance(mapping, dict):
        return False
    return any(
        isinstance(entry, dict) and entry.get("status") == "released"
        for entry in mapping.get("versions") or []
    )


def validate(contract: dict, consumer: dict, released: bool) -> list[str]:
    problems: list[str] = []

    declared = next(
        (w for w in contract.get("workflows") or [] if w.get("path", "").endswith("pr-security.yml")),
        None,
    )
    if declared is None:
        return ["contract declares no pr-security.yml workflow"]

    jobs = consumer.get("jobs") or {}
    if len(jobs) != 1:
        return ["consumer fixture must declare exactly one job"]
    job = next(iter(jobs.values()))

    # Workflow reference.
    uses = job.get("uses", "")
    if declared["path"] not in uses:
        problems.append(f"caller does not reference {declared['path']}")
    ref = uses.rsplit("@", 1)[-1] if "@" in uses else ""
    for forbidden in contract.get("caller", {}).get("forbidden_references") or []:
        if uses.endswith(forbidden):
            problems.append(f"caller uses mutable reference {forbidden}")
    if released:
        if not SHA.fullmatch(ref):
            problems.append("a platform version is released, so the caller must pin a 40 character SHA")
    elif ref != UNRELEASED_REF and not SHA.fullmatch(ref):
        problems.append(f"caller reference must be a 40 character SHA or {UNRELEASED_REF}")

    # Inputs.
    inputs = declared.get("inputs") or {}
    required = {i["name"] for i in inputs.get("required") or []}
    optional = {i["name"] for i in inputs.get("optional") or []}
    supplied = set((job.get("with") or {}).keys())
    for name in sorted(required - supplied):
        problems.append(f"caller omits required input {name}")
    for name in sorted(supplied - required - optional):
        problems.append(f"caller passes undeclared input {name}")

    # Secrets.
    secrets = job.get("secrets")
    if secrets == "inherit":
        problems.append("caller uses secrets: inherit, which grants every caller credential")
    else:
        declared_secrets = declared.get("secrets") or {}
        allowed = {s["name"] for s in (declared_secrets.get("required") or [])}
        allowed |= {s["name"] for s in (declared_secrets.get("optional") or [])}
        supplied_secrets = set((secrets or {}).keys())
        for name in sorted(supplied_secrets - allowed):
            problems.append(f"caller passes undeclared secret {name}")
        for entry in declared_secrets.get("required") or []:
            if entry["name"] not in supplied_secrets:
                problems.append(f"caller omits required secret {entry['name']}")

    # Permissions.
    if consumer.get("permissions") != {}:
        problems.append("caller workflow-level permissions must be {}")
    contract_job_permissions = (declared.get("permissions") or {}).get("job") or {}
    for scope, level in (job.get("permissions") or {}).items():
        if scope not in contract_job_permissions:
            problems.append(f"caller grants {scope}, which the contract does not declare")
        elif RANK.get(level, 99) > RANK.get(contract_job_permissions[scope], 0):
            problems.append(f"caller grants {scope}: {level}, exceeding the contract")

    return problems


def main() -> int:
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
        print(f"consumer contract check: cannot read inputs: {exc}", file=sys.stderr)
        return 1

    problems = validate(contract, consumer, any_release_exists(mapping))
    if problems:
        print("consumer contract violated:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print("consumer contract satisfied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
