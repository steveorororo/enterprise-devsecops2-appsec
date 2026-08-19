#!/usr/bin/env python3
"""Verify a consuming repository's platform pin is internally consistent.

A consumer records the release it executes in config/platform.yaml and pins that commit in
every workflow that calls the platform. Those must agree. If they drift, the repository
executes one implementation while reporting another, and an operator reading the recorded
version draws the wrong conclusion about which fixes are present.

Every condition below blocks. None of them degrade to a warning, because the recorded version
is used to decide whether a repository has adopted a security fix.
"""
import argparse
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
MAPPING = REPO_ROOT / "platform" / "versions.yaml"

SHA = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"uses:\s*(?P<repo>[\w.-]+/[\w.-]+)/(?P<path>\.github/workflows/[\w.-]+)@(?P<ref>\S+)")


def released_versions(mapping):
    released = {}
    for entry in (mapping or {}).get("versions") or []:
        if isinstance(entry, dict) and entry.get("status") == "released":
            released[entry.get("platform_version")] = entry.get("workflow_sha")
    return released


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True,
                        help="Consuming repository to check")
    parser.add_argument("--mapping", type=Path, default=MAPPING)
    args = parser.parse_args()

    target = args.target.resolve()
    pointer_file = target / "config" / "platform.yaml"
    workflows = target / ".github" / "workflows"

    if not pointer_file.is_file():
        print("no platform pointer at %s" % pointer_file, file=sys.stderr)
        return 1

    pointer = yaml.safe_load(pointer_file.read_text(encoding="utf-8")) or {}
    mapping = yaml.safe_load(args.mapping.read_text(encoding="utf-8")) or {}
    released = released_versions(mapping)

    version = str(pointer.get("platform_version") or "")
    ref = str(pointer.get("platform_ref") or "")
    repository = str(pointer.get("platform_repository") or "")

    problems = []

    if not SHA.fullmatch(ref):
        problems.append("platform_ref %r is not a full 40 character commit" % ref)
    if version not in released:
        problems.append("platform_version %s is not a released version" % version)
    elif released[version] != ref:
        problems.append("platform_version %s maps to %s but this repository pins %s"
                        % (version, released[version][:12], ref[:12]))

    calls = 0
    for path in sorted(workflows.glob("*.yml")) + sorted(workflows.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        for match in USES.finditer(text):
            if repository and match.group("repo") != repository:
                continue
            calls += 1
            found = match.group("ref")
            if found != ref:
                problems.append("%s pins %s for %s, but the recorded release is %s"
                                % (path.name, found[:12], match.group("path"), ref[:12]))

    if calls == 0:
        problems.append("no workflow calls %s" % (repository or "the platform"))

    print("consumer:        %s" % target.name)
    print("platform version: %s" % version)
    print("platform commit:  %s" % ref[:12])
    print("pinned calls:     %d" % calls)

    if problems:
        print("\nconsumer pin rejected:", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1

    print("\nconsumer pin consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
