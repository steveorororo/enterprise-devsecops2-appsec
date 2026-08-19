#!/usr/bin/env python3
"""Exercise the fixtures against a reference implementation and compare with expectations.

Establishes what the controls in a target repository actually detect, rather than assuming
the implementation is correct because its pipeline was green. Scanner configuration and the
gate implementation are read from the target, so the measured behaviour is the target's own.

A tool that cannot run is reported as unavailable and never as a pass. A tool that fails
technically is reported as tool_error and never as clean, because a scanner that did not
complete is not evidence that an application is secure.
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTATIONS = REPO_ROOT / "tests" / "baseline" / "expectations.yaml"
GATE_CASES = REPO_ROOT / "tests" / "baseline" / "gate-cases.yaml"

CLEAN = "clean"
FINDING = "finding"
TOOL_ERROR = "tool_error"
UNAVAILABLE = "unavailable"

EXECUTABLES = {
    "gitleaks": "gitleaks",
    "trivy": "trivy",
    "kube-linter": "kube-linter",
    "kustomize": "kustomize",
}


class Tools:
    """Resolves scanner executables from an explicit directory or from PATH."""

    def __init__(self, directory, python, codeql=None):
        self.directory = directory
        self.python = python
        self.codeql = codeql

    def find(self, tool):
        name = EXECUTABLES[tool]
        if self.directory:
            for candidate in (self.directory / name, self.directory / (name + ".exe")):
                if candidate.is_file():
                    return str(candidate)
        return shutil.which(name)

    def has_checkov(self):
        return run([self.python, "-m", "checkov.main", "--version"]).returncode == 0


def policy_file(platform_relative, target, target_relative):
    """Central policy where it exists, otherwise the target's own copy.

    Configuration migrates to this repository as capabilities are centralized. The fallback
    keeps the harness able to measure a pre-extraction reference implementation.
    """
    central = REPO_ROOT / platform_relative
    if central.is_file():
        return central
    return target / target_relative


def run(command, cwd=None):
    return subprocess.run(command, capture_output=True, text=True, cwd=cwd,
                          encoding="utf-8", errors="replace")


def run_with_input(command, stdin_text):
    return subprocess.run(command, capture_output=True, text=True, input=stdin_text,
                          encoding="utf-8", errors="replace")


def classify_gitleaks(result):
    if result.returncode == 0:
        return CLEAN
    if result.returncode == 1 and "leaks found" in (result.stderr + result.stdout):
        return FINDING
    return TOOL_ERROR


def classify_trivy(result):
    if result.returncode == 1:
        return FINDING
    if result.returncode != 0:
        return TOOL_ERROR
    return CLEAN


def classify_kube_linter(result):
    combined = (result.stdout + result.stderr).lower()
    if "no lint errors found" in combined:
        return CLEAN
    if "no valid objects found" in combined:
        # The linter accepts input it could not parse and exits zero. Reported as a technical
        # failure rather than a clean result.
        return TOOL_ERROR
    if "lint error" in combined:
        return FINDING
    if result.returncode == 0:
        return CLEAN
    return TOOL_ERROR


def classify_checkov(result):
    try:
        report = json.loads(result.stdout or "null")
    except json.JSONDecodeError:
        return TOOL_ERROR
    if report is None:
        return TOOL_ERROR

    entries = report if isinstance(report, list) else [report]
    resources = 0
    failed = 0
    for entry in entries:
        summary = (entry or {}).get("summary") or {}
        resources += int(summary.get("passed") or 0) + int(summary.get("failed") or 0)
        failed += int(summary.get("failed") or 0)

    if resources == 0:
        # Checkov exits zero on input it cannot parse, which would otherwise be
        # indistinguishable from a clean scan.
        return TOOL_ERROR
    return FINDING if failed else CLEAN


def codeql_matrix(case, target):
    """Exercise the target's own language selection against the no-source fixture."""
    script = target / "scripts" / "utility" / "read-pipeline-config.py"
    if not script.is_file():
        return UNAVAILABLE, "target has no read-pipeline-config.py"

    fixture = REPO_ROOT / case["fixture"]
    with tempfile.TemporaryDirectory() as raw:
        workspace = Path(raw)
        (workspace / "config").mkdir(parents=True)
        (workspace / "scripts" / "utility").mkdir(parents=True)
        (workspace / ".github" / "workflows").mkdir(parents=True)
        shutil.copy(script, workspace / "scripts" / "utility" / script.name)
        shutil.copy(fixture / "pipeline.yaml", workspace / "config" / "pipeline.yaml")
        (workspace / ".github" / "workflows" / "pr-validate.yml").write_text("name: placeholder\n")

        result = run([sys.executable, str(workspace / "scripts" / "utility" / script.name)],
                     cwd=str(workspace))
        if result.returncode != 0:
            detail = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "failed"
            return TOOL_ERROR, detail

        matrix = None
        for line in result.stdout.splitlines():
            if line.startswith("codeql_matrix="):
                matrix = json.loads(line.split("=", 1)[1])
        if matrix is None:
            return TOOL_ERROR, "no codeql_matrix emitted"

        present = {e["language"]: e.get("source_present") for e in matrix["include"]}
        if present.get("actions") is not True:
            return FINDING, "workflow language not analysed"
        if present.get("javascript-typescript") is not False:
            return FINDING, "absent application language marked present"
        return CLEAN, "actions present, javascript-typescript absent"


def codeql_analyze(case, target, tools):
    """Build a database from the fixture and analyse it with the target's own configuration.

    Language and build mode come from the target's language table rather than being restated
    here, so the analysis matches what the target would run.
    """
    if not tools.codeql:
        return UNAVAILABLE, "codeql cli not provided"

    config = policy_file("security/codeql-config.yml", target,
                         "security/sast/codeql-config.yml")
    if not config.is_file():
        return UNAVAILABLE, "no codeql configuration available"

    fixture = REPO_ROOT / case["fixture"]
    language = case.get("language", "javascript-typescript")
    build_mode = case.get("build_mode", "none")

    with tempfile.TemporaryDirectory() as raw:
        database = Path(raw) / "db"
        sarif = Path(raw) / "results.sarif"

        created = run([tools.codeql, "database", "create", str(database),
                       "--language=" + language,
                       "--build-mode=" + build_mode,
                       "--source-root=" + str(fixture),
                       "--codescanning-config=" + str(config)])
        if created.returncode != 0:
            return TOOL_ERROR, "database create failed"

        analysed = run([tools.codeql, "database", "analyze", str(database),
                        "--format=sarif-latest", "--output=" + str(sarif),
                        "--threads=4"])
        if analysed.returncode != 0:
            return TOOL_ERROR, "analysis failed"

        try:
            report = json.loads(sarif.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return TOOL_ERROR, "unreadable sarif"

        runs = report.get("runs") or []
        results = runs[0].get("results") if runs else []
        if not results:
            return CLEAN, "no alerts"

        # The branch ruleset blocks on high or higher, so only alerts at that level are
        # treated as blocking here.
        severities = {}
        for run_entry in runs:
            tool_block = run_entry.get("tool") or {}
            rule_sets = [(tool_block.get("driver") or {}).get("rules") or []]
            for extension in tool_block.get("extensions") or []:
                rule_sets.append(extension.get("rules") or [])
            for rules in rule_sets:
                for rule in rules:
                    value = (rule.get("properties") or {}).get("security-severity")
                    if value is not None:
                        severities[rule.get("id")] = float(value)

        blocking = []
        for result in results:
            if severities.get(result.get("ruleId"), 0.0) >= 7.0:
                blocking.append(result.get("ruleId"))

        if not blocking:
            return CLEAN, "alerts below the blocking threshold"
        return FINDING, ", ".join(sorted(set(blocking)))


def scan(case, target, tools):
    tool = case["tool"]
    fixture = REPO_ROOT / case["fixture"]

    if tool == "gitleaks":
        binary = tools.find("gitleaks")
        if not binary:
            return UNAVAILABLE, "gitleaks not installed"
        result = run([binary, "detect", "--source", str(fixture), "--no-git",
                      "--redact", "--exit-code", "1", "--no-banner"])
        return classify_gitleaks(result), "exit %d" % result.returncode

    if tool == "trivy-fs":
        binary = tools.find("trivy")
        if not binary:
            return UNAVAILABLE, "trivy not installed"
        result = run([binary, "fs", "--scanners", "vuln", "--severity", "CRITICAL,HIGH",
                      "--ignore-unfixed", "--exit-code", "1", "--quiet", str(fixture)])
        return classify_trivy(result), "exit %d" % result.returncode

    if tool == "kube-linter":
        binary = tools.find("kube-linter")
        if not binary:
            return UNAVAILABLE, "kube-linter not installed"
        config = policy_file("security/kube-linter.yaml", target,
                             "security/iac/.kube-linter.yaml")

        # The template renders overlays and lints the result, so the render is part of the
        # control. Linting source files directly would skip it and would not measure the
        # control as it is actually wired.
        if (fixture / "kustomization.yaml").is_file():
            kustomize = tools.find("kustomize")
            if not kustomize:
                return UNAVAILABLE, "kustomize not installed"
            rendered = run([kustomize, "build", str(fixture)])
            if rendered.returncode != 0:
                return TOOL_ERROR, "render failed"
            result = run_with_input([binary, "lint", "--config", str(config), "-"],
                                    rendered.stdout)
        else:
            result = run([binary, "lint", "--config", str(config), str(fixture)])
        return classify_kube_linter(result), "exit %d" % result.returncode

    if tool == "checkov":
        if not tools.has_checkov():
            return UNAVAILABLE, "checkov not installed"
        config = policy_file("security/checkov.yaml", target,
                             "security/iac/.checkov.yaml")
        result = run([tools.python, "-m", "checkov.main", "-d", str(fixture),
                      "--config-file", str(config), "--quiet", "--compact", "-o", "json"])
        return classify_checkov(result), "exit %d" % result.returncode

    if tool == "codeql-matrix":
        return codeql_matrix(case, target)

    if tool == "codeql":
        return codeql_analyze(case, target, tools)

    return UNAVAILABLE, "unknown tool " + tool


def evaluate_gate(case, target, python):
    """Evaluate with the platform gate implementation against the target's configuration."""
    script = REPO_ROOT / "scripts" / "evaluate-gate.py"
    config = target / "config" / "security-gate.yaml"
    policy = REPO_ROOT / "security" / "mandatory-jobs.yaml"
    if not config.is_file():
        return UNAVAILABLE, "target has no gate configuration"
    needs = {}
    for name, result in (case.get("needs") or {}).items():
        needs[name] = {"result": result}
    outcome = run([python, str(script), "--needs", json.dumps(needs),
                   "--config", str(config), "--policy", str(policy)])
    return ("pass" if outcome.returncode == 0 else "fail"), "exit %d" % outcome.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True,
                        help="Reference implementation to measure")
    parser.add_argument("--tools", type=Path, default=None,
                        help="Directory holding scanner executables")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--codeql", default=None,
                        help="Path to the CodeQL CLI executable")
    parser.add_argument("--expect-commit", default=None,
                        help="Commit the target must be at. Use 'any' to measure a "
                             "post-extraction implementation instead of the frozen baseline.")
    args = parser.parse_args()

    target = args.target.resolve()
    if not (target / "security").is_dir():
        print("target %s does not look like the developer template" % target, file=sys.stderr)
        return 1

    tools = Tools(args.tools.resolve() if args.tools else None, args.python, args.codeql)
    expectations = yaml.safe_load(EXPECTATIONS.read_text())
    gate = yaml.safe_load(GATE_CASES.read_text())

    baseline = expectations.get("baseline") or {}
    head = run(["git", "-C", str(target), "rev-parse", "HEAD"]).stdout.strip()
    print("target      %s" % target)
    expected = args.expect_commit or baseline.get("commit")
    print("expected    %s" % (expected or "unset"))
    print("actual      %s" % (head or "unknown"))
    if expected == "any":
        print("measuring the checked out implementation, not the frozen baseline")
    elif expected and head and expected != head:
        print("\nbaseline commit mismatch. The frozen reference is not checked out.",
              file=sys.stderr)
        return 1
    print("")

    rows = []
    mismatches = []
    unavailable = []

    for case in expectations["cases"]:
        expected = case["expect"]
        actual, detail = scan(case, target, tools)
        if actual == UNAVAILABLE:
            verdict = "SKIP"
            unavailable.append("%s: %s" % (case["id"], detail))
        elif actual == expected:
            verdict = "PASS"
        else:
            verdict = "FAIL"
            kind = "detection gap" if (expected == FINDING and actual == CLEAN) else "mismatch"
            mismatches.append("%s: expected %s, got %s (%s)"
                              % (case["id"], expected, actual, kind))
        rows.append((case["id"], case["control"], case["tool"], expected, actual, verdict))

    for case in gate["cases"]:
        expected = case["expect"]
        actual, detail = evaluate_gate(case, target, args.python)
        if actual == UNAVAILABLE:
            verdict = "SKIP"
            unavailable.append("%s: %s" % (case["id"], detail))
        elif actual == expected:
            verdict = "PASS"
        else:
            verdict = "FAIL"
            mismatches.append("%s: expected gate %s, got %s" % (case["id"], expected, actual))
        rows.append((case["id"], "security-gate", "evaluate-gate", expected, actual, verdict))

    width = max(len(row[0]) for row in rows)
    header = "%s  %s  %s  %s  %s  result" % (
        "case".ljust(width), "control".ljust(32), "tool".ljust(13),
        "expected".ljust(10), "actual".ljust(11))
    print(header)
    for identifier, control, tool, expected, actual, verdict in rows:
        print("%s  %s  %s  %s  %s  %s" % (
            identifier.ljust(width), control.ljust(32), tool.ljust(13),
            expected.ljust(10), actual.ljust(11), verdict))

    passed = 0
    for row in rows:
        if row[5] == "PASS":
            passed += 1
    print("\n%d passed, %d failed, %d not executed"
          % (passed, len(mismatches), len(unavailable)))

    if unavailable:
        print("\nnot executed:")
        for entry in unavailable:
            print("  " + entry)

    if mismatches:
        print("\nbaseline mismatches:", file=sys.stderr)
        for entry in mismatches:
            print("  " + entry, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
