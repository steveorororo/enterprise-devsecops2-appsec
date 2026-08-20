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
REGISTRIES = REPO_ROOT / "security" / "registries.yaml"
SIGNING = REPO_ROOT / "security" / "signing-policy.yaml"

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


def check_registries():
    config = yaml.safe_load(REGISTRIES.read_text(encoding="utf-8")) or {}
    providers = config.get("providers") or {}
    problems = []

    ghcr = providers.get("ghcr") or {}
    if ghcr.get("status") != "approved" or ghcr.get("registry_host") != "ghcr.io":
        problems.append("the approved pilot registry is no longer ghcr.io")

    # A provider that has not been configured and tested must not be usable, otherwise an
    # unverified destination becomes reachable by a consumer.
    for name in ("artifactory", "openshift-internal"):
        entry = providers.get(name) or {}
        if entry.get("status") == "approved" and not entry.get("registry_host"):
            problems.append("%s is approved with no registry host" % name)

    for name, entry in providers.items():
        if not (entry or {}).get("path_pattern"):
            problems.append("provider %s has no path pattern, so any path would be accepted"
                            % name)

    return problems


def check_signing():
    config = (yaml.safe_load(SIGNING.read_text(encoding="utf-8")) or {}).get("signing") or {}
    problems = []

    issuer = config.get("certificate_oidc_issuer")
    identity = config.get("certificate_identity_regexp")

    if issuer != "https://token.actions.githubusercontent.com":
        problems.append("unexpected signing issuer %r" % issuer)

    # An identity expectation that is not anchored, or that does not name the signing
    # workflow, would accept signatures from other repositories or other workflows.
    if not identity or not identity.startswith(r"^https://github\.com/"):
        problems.append("signer identity expectation is not anchored to a GitHub identity")
    elif "artifact-security" not in identity:
        problems.append("signer identity expectation does not name the signing workflow")

    return problems


def main():
    problems = (check_checkov() + check_kube_linter() + check_mandatory_jobs()
                + check_registries() + check_signing())

    if problems:
        print("central policy changed without approval:", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1

    print("central scanner policy intact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
