#!/usr/bin/env python3
"""Prove an unapproved registry destination is refused.

Registry flexibility must not become a way to publish an application image somewhere the
platform never approved. The resolver decides the destination from central policy, and it
runs in a job that holds no registry permission, so a refusal happens before any credential
could be offered to the requested host.

Each case below must be refused with a non-zero exit and no resolved destination. A case that
starts passing means a consuming repository could redirect its artifacts.
"""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RESOLVER = REPO_ROOT / "scripts" / "resolve-registry.py"
POLICY = REPO_ROOT / "security" / "registries.yaml"

APPROVED_PATH = "steveorororo/enterprise-devsecops2-appsec"
UNAPPROVED_HOST = "registry.example-unapproved.invalid"


def resolve(**kwargs):
    command = [sys.executable, str(RESOLVER), "--policy", str(POLICY)]
    for key, value in kwargs.items():
        command += ["--" + key.replace("_", "-"), value]
    return subprocess.run(command, capture_output=True, text=True)


def main():
    failures = []

    approved = resolve(provider="ghcr", path=APPROVED_PATH, image_name="sample-app",
                       requested_host="ghcr.io")
    if approved.returncode != 0:
        failures.append("approved GHCR destination was refused: %s" % approved.stderr.strip())
    elif "registry_host=ghcr.io" not in approved.stdout:
        failures.append("approved destination did not resolve to the policy host")

    refused = [
        ("unapproved provider",
         dict(provider="attacker-registry", path=APPROVED_PATH, image_name="app")),
        ("unapproved host claimed against an approved provider",
         dict(provider="ghcr", path=APPROVED_PATH, image_name="app",
              requested_host=UNAPPROVED_HOST)),
        ("provider that is named but not configured",
         dict(provider="artifactory", path="repo/path", image_name="app")),
        ("provider that is named but not reachable",
         dict(provider="openshift-internal", path="namespace", image_name="app")),
        ("path traversal in the repository path",
         dict(provider="ghcr", path="owner/../elsewhere", image_name="app")),
        ("placeholder repository path",
         dict(provider="ghcr", path="<your-org>/app", image_name="app")),
        ("placeholder image name",
         dict(provider="ghcr", path=APPROVED_PATH, image_name="<image>")),
        ("image name carrying a registry host",
         dict(provider="ghcr", path=APPROVED_PATH,
              image_name=UNAPPROVED_HOST + "/app")),
    ]

    for name, arguments in refused:
        result = resolve(**arguments)
        if result.returncode == 0:
            failures.append("%s was accepted: %s" % (name, result.stdout.strip()))
        elif "registry_host=" in result.stdout:
            failures.append("%s emitted a destination while refusing" % name)

    total = len(refused) + 1
    if failures:
        print("registry policy failed (%d of %d):" % (len(failures), total), file=sys.stderr)
        for failure in failures:
            print("  " + failure, file=sys.stderr)
        return 1

    print("registry policy holds (%d cases): approved destination resolves, "
          "every unapproved destination is refused" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
