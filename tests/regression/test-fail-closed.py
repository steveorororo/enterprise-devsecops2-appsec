#!/usr/bin/env python3
"""Regression tests for the release and contract gates.

Version integrity and the compatibility contract are only controls if they reject bad input.
Each case below mutates a valid document in a temporary directory and asserts the validator
exits non-zero. A validator that starts accepting one of these is a silent loss of control,
which is exactly the failure this file exists to catch.
"""
import copy
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
VERSIONS = REPO_ROOT / "scripts" / "validate-platform-versions.py"
CONSUMER = REPO_ROOT / "scripts" / "validate-consumer-contract.py"
MAPPING = REPO_ROOT / "platform" / "versions.yaml"
CONTRACT = REPO_ROOT / "platform" / "contract.yaml"
FIXTURE = REPO_ROOT / "tests" / "consumers" / "current" / "pr-security-caller.yml"

REAL_COMMIT = "0" * 40


def run(script: Path, *args: str) -> int:
    return subprocess.run(
        [sys.executable, str(script), *args], capture_output=True, text=True
    ).returncode


def write(directory: Path, name: str, document: object) -> Path:
    path = directory / name
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    return path


def version_cases(base: dict) -> list[tuple[str, object]]:
    def mutate(fn) -> dict:
        document = copy.deepcopy(base)
        fn(document)
        return document

    return [
        ("malformed document", ["not", "a", "mapping"]),
        ("no versions", mutate(lambda d: d.update(versions=[]))),
        (
            "released without sha",
            mutate(lambda d: d["versions"].append(
                {"platform_version": "9.9.9", "status": "released", "workflow_sha": None}
            )),
        ),
        (
            "released with unknown sha",
            mutate(lambda d: d["versions"].append(
                {"platform_version": "9.9.9", "status": "released", "workflow_sha": REAL_COMMIT}
            )),
        ),
        (
            "released with short sha",
            mutate(lambda d: d["versions"].append(
                {"platform_version": "9.9.9", "status": "released", "workflow_sha": "abc123"}
            )),
        ),
        (
            "unreleased carrying a sha",
            mutate(lambda d: d["versions"][0].update(workflow_sha=REAL_COMMIT)),
        ),
        (
            "duplicate version",
            mutate(lambda d: d["versions"].append(copy.deepcopy(d["versions"][0]))),
        ),
        (
            "malformed version identifier",
            mutate(lambda d: d["versions"][0].update(platform_version="one")),
        ),
        ("unknown status", mutate(lambda d: d["versions"][0].update(status="draft"))),
        (
            "current_released names an unknown version",
            mutate(lambda d: d.update(current_released="4.0.0")),
        ),
        (
            "current_released names an unreleased version",
            mutate(lambda d: d.update(current_released=next(
                e["platform_version"] for e in d["versions"] if e["status"] == "unreleased"))),
        ),
    ]


def consumer_cases(base: dict) -> list[tuple[str, object]]:
    def mutate(fn) -> dict:
        document = copy.deepcopy(base)
        fn(document)
        return document

    def job(document: dict, name: str = "manifest-lint") -> dict:
        return document["jobs"][name]

    def rename(document: dict, old: str, new_name: str) -> None:
        document["jobs"][new_name] = document["jobs"].pop(old)

    other = "0" * 40

    return [
        ("mutable main reference", mutate(lambda d: job(d).update(
            uses="steveorororo/enterprise-devsecops2-appsec/.github/workflows/"
                 "manifest-security.yml@main"))),
        ("secrets inherit", mutate(lambda d: job(d).update(secrets="inherit"))),
        ("undeclared secret", mutate(lambda d: job(d).update(secrets={"REGISTRY_TOKEN": "x"}))),
        ("required input removed", mutate(lambda d: job(d)["with"].pop("platform_ref"))),
        ("undeclared input", mutate(lambda d: job(d)["with"].update(sast=False))),
        ("privilege increase", mutate(lambda d: job(d)["permissions"].update(contents="write"))),
        ("undeclared permission", mutate(lambda d: job(d)["permissions"].update(actions="write"))),
        ("workflow permissions widened",
         mutate(lambda d: d.update(permissions={"contents": "read"}))),
        # The pinned commit and the platform_ref input must be the same release, or a
        # repository executes one implementation while loading another's configuration.
        ("pointer split across releases",
         mutate(lambda d: job(d)["with"].update(platform_ref=other))),
        ("platform_version not released",
         mutate(lambda d: job(d)["with"].update(platform_version="9.9.9"))),
        # Job ids are the security gate contract. A renamed control stops being evaluated.
        ("gate job id renamed", mutate(lambda d: rename(d, "manifest-lint", "manifests"))),
        ("gate job id renamed to a plausible alias",
         mutate(lambda d: rename(d, "iac-checkov", "checkov"))),
    ]


def main() -> int:
    base_mapping = yaml.safe_load(MAPPING.read_text())
    base_consumer = yaml.safe_load(FIXTURE.read_text())

    failures: list[str] = []
    checked = 0

    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)

        for name, document in version_cases(base_mapping):
            checked += 1
            path = write(directory, "versions.yaml", document)
            if run(VERSIONS, "--mapping", str(path)) == 0:
                failures.append(f"version mapping accepted: {name}")

        for name, document in consumer_cases(base_consumer):
            checked += 1
            path = write(directory, "caller.yml", document)
            code = run(
                CONSUMER, "--consumer", str(path),
                "--contract", str(CONTRACT), "--mapping", str(MAPPING),
            )
            if code == 0:
                failures.append(f"consumer contract accepted: {name}")

    checked += 2
    if run(VERSIONS) != 0:
        failures.append("valid version mapping rejected")
    if run(CONSUMER) != 0:
        failures.append("valid consumer fixture rejected")

    if failures:
        print(f"fail-closed regression failed ({len(failures)} of {checked}):", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"fail-closed regression passed ({checked} cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
