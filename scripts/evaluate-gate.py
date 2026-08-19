#!/usr/bin/env python3
"""Aggregate upstream job results into a single required status check.

Each scanner fails its own job when it exceeds its configured threshold. This turns those
job results into one check that branch protection can require, so adding a scanner does not
mean editing branch protection.

Only success passes. A skipped job passes only if the consuming repository lists it as
skippable and the platform permits that exemption. A job listed as required but absent from
the payload fails the gate, so deleting a job from the workflow breaks the build rather than
quietly removing a control.

The consuming repository declares its own required jobs. It may add controls, and it may not
remove the ones the platform makes mandatory or mark them skippable. Without that check a
caller could delete an entry from its own configuration and the gate would keep reporting
success while no longer evaluating a mandatory control.
"""
import argparse
import json
import sys
from pathlib import Path

import yaml

def load_gate_config(path: Path) -> tuple[set[str], set[str]]:
    cfg = yaml.safe_load(path.read_text()) or {}
    required = set(cfg.get("required_jobs") or [])
    skippable = set(cfg.get("skippable_jobs") or [])
    return required, skippable


def load_platform_policy(path: Path) -> tuple[set[str], set[str]]:
    cfg = yaml.safe_load(path.read_text()) or {}
    mandatory = set(cfg.get("mandatory_jobs") or [])
    permitted = set(cfg.get("permitted_skippable") or [])
    return mandatory, permitted


def check_policy(required: set[str], skippable: set[str],
                 mandatory: set[str], permitted: set[str]) -> list[str]:
    problems = []
    for name in sorted(mandatory - required):
        problems.append(f"{name}: required by platform policy but absent from the "
                        f"repository gate configuration")
    for name in sorted(mandatory & skippable):
        problems.append(f"{name}: mandatory under platform policy and cannot be skippable")
    for name in sorted(skippable - permitted):
        problems.append(f"{name}: listed as skippable, which platform policy does not permit")
    return problems


def evaluate(needs: dict, required: set[str], skippable: set[str]) -> list[str]:
    problems = []

    for name in sorted(required - set(needs)):
        problems.append(f"{name}: required by the gate but absent from the workflow")

    for name, job in sorted(needs.items()):
        result = (job or {}).get("result")
        if result == "success":
            continue
        if result == "skipped" and name in skippable:
            continue
        if result == "skipped":
            problems.append(f"{name}: skipped, and not listed under skippable_jobs")
        else:
            problems.append(f"{name}: {result}")

    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--needs", required=True, help="JSON of the workflow's needs context")
    parser.add_argument("--config", type=Path, required=True,
                        help="Consuming repository's security gate configuration")
    parser.add_argument("--policy", type=Path, default=None,
                        help="Platform mandatory control policy")
    args = parser.parse_args()

    required, skippable = load_gate_config(args.config)

    problems = []
    if args.policy is not None:
        mandatory, permitted = load_platform_policy(args.policy)
        problems.extend(check_policy(required, skippable, mandatory, permitted))

    problems.extend(evaluate(json.loads(args.needs), required, skippable))

    if problems:
        print("security gate failed:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print("security gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
