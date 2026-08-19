#!/usr/bin/env python3
"""Guard the centrally owned scanner policy against ungoverned change.

Central configuration applies to every consuming repository, so a skip added here silently
removes a control everywhere. Each accepted exception below is fixed and justified, and a
change to the set fails until the list here is updated deliberately.

This replaces the equivalent assertion that lived in a consuming repository before the
configuration was centralized. A consumer cannot meaningfully police policy it no longer owns.
"""
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKOV = REPO_ROOT / "security" / "checkov.yaml"
KUBE_LINTER = REPO_ROOT / "security" / "kube-linter.yaml"
MANDATORY = REPO_ROOT / "security" / "mandatory-jobs.yaml"

# Accepted Checkov exceptions, each tied to a platform constraint rather than convenience.
#   CKV_K8S_11    CPU limits deliberately unset so containers burst into spare capacity.
#   CKV_K8S_23    OpenShift restricted SCC assigns the UID at admission.
#   CKV_K8S_40    Same, for the UID range assertion.
#   CKV_DOCKER_2  The kubelet runs the manifest probes; a Dockerfile HEALTHCHECK is ignored.
APPROVED_CHECKOV_SKIPS = {"CKV_K8S_11", "CKV_K8S_23", "CKV_K8S_40", "CKV_DOCKER_2"}

# Controls that must remain mandatory for every consumer.
REQUIRED_MANDATORY_JOBS = {
    "secrets-scan", "dependency-review", "iac-checkov", "manifest-lint", "codeql",
}


def check_checkov():
    config = yaml.safe_load(CHECKOV.read_text(encoding="utf-8")) or {}
    problems = []

    actual = set(config.get("skip-check") or [])
    for check in sorted(actual - APPROVED_CHECKOV_SKIPS):
        problems.append("checkov skip %s is not an approved exception" % check)
    for check in sorted(APPROVED_CHECKOV_SKIPS - actual):
        problems.append("approved checkov exception %s is no longer present" % check)

    if config.get("soft-fail") is not False:
        problems.append("checkov soft-fail must remain false, findings have to block")

    frameworks = set(config.get("framework") or [])
    for framework in ("kubernetes", "dockerfile"):
        if framework not in frameworks:
            problems.append("checkov no longer scans the %s framework" % framework)

    return problems


def check_kube_linter():
    config = yaml.safe_load(KUBE_LINTER.read_text(encoding="utf-8")) or {}
    checks = (config.get("checks") or {})
    included = set(checks.get("include") or [])
    problems = []

    # Container hardening and host isolation are the reason this linter runs at all.
    for check in ("privileged-container", "run-as-non-root", "host-network", "host-pid",
                  "privilege-escalation-container", "docker-sock"):
        if check not in included:
            problems.append("kube-linter no longer includes %s" % check)

    return problems


def check_mandatory_jobs():
    config = yaml.safe_load(MANDATORY.read_text(encoding="utf-8")) or {}
    mandatory = set(config.get("mandatory_jobs") or [])
    permitted = set(config.get("permitted_skippable") or [])
    problems = []

    for job in sorted(REQUIRED_MANDATORY_JOBS - mandatory):
        problems.append("%s is no longer mandatory for consumers" % job)
    for job in sorted(mandatory & permitted):
        problems.append("%s is both mandatory and permitted to skip" % job)

    return problems


def main():
    problems = check_checkov() + check_kube_linter() + check_mandatory_jobs()

    if problems:
        print("central policy changed without approval:", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1

    print("central scanner policy intact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
