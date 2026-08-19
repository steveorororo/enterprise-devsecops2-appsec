#!/usr/bin/env python3
"""Validate platform/versions.yaml as a release gate.

The mapping from platform_version to an approved immutable commit decides which
implementation a consuming repository executes. It is enforced rather than reported: every
condition below fails the run, and none of them degrade to a warning.

  missing or unreadable mapping
  malformed structure
  duplicate or malformed version identifier
  released entry without a full 40 character commit SHA
  released entry whose SHA does not exist in this repository
  unreleased entry that carries a SHA
  current_released naming a version that is absent or not released
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
MAPPING = REPO_ROOT / "platform" / "versions.yaml"

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
SHA = re.compile(r"^[0-9a-f]{40}$")
STATUSES = {"released", "unreleased"}


def commit_exists(sha: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "cat-file", "-e", f"{sha}^{{commit}}"],
        capture_output=True,
    )
    return result.returncode == 0


def validate(document: object) -> list[str]:
    problems: list[str] = []

    if not isinstance(document, dict):
        return ["top-level document must be a mapping"]

    entries = document.get("versions")
    if not isinstance(entries, list) or not entries:
        return ["versions must be a non-empty list"]

    seen: set[str] = set()
    released: set[str] = set()

    for index, entry in enumerate(entries):
        label = f"versions[{index}]"
        if not isinstance(entry, dict):
            problems.append(f"{label}: entry must be a mapping")
            continue

        version = entry.get("platform_version")
        if not isinstance(version, str) or not SEMVER.fullmatch(version):
            problems.append(f"{label}: platform_version must be MAJOR.MINOR.PATCH")
            continue
        label = f"version {version}"
        if version in seen:
            problems.append(f"{label}: duplicate platform_version")
            continue
        seen.add(version)

        status = entry.get("status")
        if status not in STATUSES:
            problems.append(f"{label}: status must be one of {sorted(STATUSES)}")
            continue

        sha = entry.get("workflow_sha")

        if status == "unreleased":
            if sha is not None:
                problems.append(f"{label}: unreleased entry must not carry a workflow_sha")
            continue

        released.add(version)
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            problems.append(f"{label}: released entry needs a full 40 character workflow_sha")
            continue
        if not commit_exists(sha):
            problems.append(f"{label}: workflow_sha {sha[:12]} does not exist in this repository")

    current = document.get("current_released")
    if current is not None:
        if not isinstance(current, str):
            problems.append("current_released must be a version string or null")
        elif current not in seen:
            problems.append(f"current_released {current!r} is not present in versions")
        elif current not in released:
            problems.append(f"current_released {current!r} is not a released version")

    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mapping", type=Path, default=MAPPING)
    args = parser.parse_args()

    try:
        document = yaml.safe_load(args.mapping.read_text())
    except (OSError, yaml.YAMLError) as exc:
        print(f"platform/versions.yaml: cannot read mapping: {exc}", file=sys.stderr)
        return 1

    problems = validate(document)
    if problems:
        print("platform version mapping rejected:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print("platform version mapping accepted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
