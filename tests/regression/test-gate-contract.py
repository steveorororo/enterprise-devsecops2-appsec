#!/usr/bin/env python3
"""Assert the security gate contract against a consuming repository's workflows.

The names in config/security-gate.yaml are GitHub Actions job ids, not display names. A
required job that is renamed while its implementation moves stops being evaluated by the
gate, and the control disappears without any test failing. This compares the authoritative
list against the job keys that actually exist.

Run after every capability extraction. A required job whose id no longer exists is a
security contract break, not a cosmetic difference.
"""
import argparse
import sys
from pathlib import Path

import yaml


def workflow_job_ids(workflows_dir):
    """Job ids per workflow file, read as plain YAML mappings."""
    found = {}
    for path in sorted(workflows_dir.glob("*.yml")) + sorted(workflows_dir.glob("*.yaml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            print("cannot parse %s: %s" % (path.name, exc), file=sys.stderr)
            continue
        jobs = document.get("jobs")
        if isinstance(jobs, dict):
            found[path.name] = set(jobs.keys())
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True,
                        help="Consuming repository to audit")
    parser.add_argument("--workflow", default="pr-validate.yml",
                        help="Workflow that must carry the required jobs")
    args = parser.parse_args()

    target = args.target.resolve()
    gate_config = target / "config" / "security-gate.yaml"
    workflows = target / ".github" / "workflows"

    if not gate_config.is_file():
        print("no security gate configuration at %s" % gate_config, file=sys.stderr)
        return 1

    config = yaml.safe_load(gate_config.read_text(encoding="utf-8")) or {}
    required = list(config.get("required_jobs") or [])
    skippable = list(config.get("skippable_jobs") or [])

    if not required:
        print("security gate lists no required jobs", file=sys.stderr)
        return 1

    per_workflow = workflow_job_ids(workflows)
    present = per_workflow.get(args.workflow, set())
    everywhere = set()
    for ids in per_workflow.values():
        everywhere |= ids

    problems = []

    for job in sorted(required):
        if job in present:
            continue
        if job in everywhere:
            others = sorted(n for n, ids in per_workflow.items() if job in ids)
            problems.append("required job %s is not in %s, it is in %s"
                            % (job, args.workflow, ", ".join(others)))
        else:
            problems.append("required job %s does not exist as a job id in any workflow" % job)

    for job in sorted(skippable):
        if job not in required:
            problems.append("skippable job %s is not listed as required, so the gate never "
                            "evaluates it" % job)
        elif job not in everywhere:
            problems.append("skippable job %s does not exist as a job id" % job)

    print("workflow:      %s" % args.workflow)
    print("required jobs: %d" % len(required))
    for job in sorted(required):
        state = "present" if job in present else "MISSING"
        print("  %-20s %s" % (job, state))

    if problems:
        print("\nsecurity gate contract broken:", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1

    print("\nsecurity gate contract intact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
