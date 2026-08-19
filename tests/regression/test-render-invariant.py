#!/usr/bin/env python3
"""Prove the manifest security control fails closed on unparseable input.

kube-linter reports "no valid objects found" and exits zero when given input it cannot
parse. The control therefore does not rest on the linter alone: it rests on rendering the
manifests first, so a render failure propagates and fails the job.

Two compositions are exercised against the same unparseable fixture.

  render then lint    the supported composition. Rendering fails, so the control fails.
  lint only           the composition that drops the render. The linter exits zero and the
                      unparseable manifest passes.

The second composition is constructed here to demonstrate that the baseline fixture rejects
it. It is not an implementation of the control and is not used anywhere outside this test.
Without this check the fixture could pass for the wrong reason and the invariant would be
silently lost the next time the control is reimplemented.
"""
import argparse
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "failure-modes" / "malformed-manifest"
HARNESS = REPO_ROOT / "scripts" / "run-baseline.py"


def load_harness():
    """Reuse the harness classifier so this test cannot drift from the baseline run."""
    spec = importlib.util.spec_from_file_location("run_baseline", HARNESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def locate(name, directory):
    if directory:
        for candidate in (directory / name, directory / (name + ".exe")):
            if candidate.is_file():
                return str(candidate)
    return shutil.which(name)


def run(command, stdin_text=None):
    return subprocess.run(command, capture_output=True, text=True, input=stdin_text,
                          encoding="utf-8", errors="replace")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True,
                        help="Reference implementation supplying the linter configuration")
    parser.add_argument("--tools", type=Path, default=None,
                        help="Directory holding scanner executables")
    args = parser.parse_args()

    tools_dir = args.tools.resolve() if args.tools else None
    kube_linter = locate("kube-linter", tools_dir)
    kustomize = locate("kustomize", tools_dir)
    if not kube_linter or not kustomize:
        print("render invariant NOT EXECUTED: kube-linter or kustomize unavailable",
              file=sys.stderr)
        return 2

    harness = load_harness()
    # The check policy is centrally owned. The target fallback keeps this able to measure a
    # consumer that has not adopted the centralized control yet.
    config = harness.policy_file("security/kube-linter.yaml", args.target.resolve(),
                                 "security/iac/.kube-linter.yaml")
    if not config.is_file():
        print("render invariant NOT EXECUTED: no linter configuration available",
              file=sys.stderr)
        return 2

    failures = []

    # Supported composition. The render must fail and that failure is the control.
    rendered = run([kustomize, "build", str(FIXTURE)])
    if rendered.returncode == 0:
        failures.append("render succeeded on unparseable input, so the fixture no longer "
                        "exercises render error propagation")
    else:
        print("render then lint: render failed as required, control fails closed")

    # Composition that drops the render, constructed only to show the fixture rejects it.
    # The manifest file is linted directly, which is what an implementation that skipped the
    # render would do. Pointing the linter at the directory instead would exercise its
    # kustomize handling rather than the permissive path this invariant guards.
    manifest = FIXTURE / "deployment.yaml"
    lint_only = run([kube_linter, "lint", "--config", str(config), str(manifest)])
    verdict = harness.classify_kube_linter(lint_only)

    if lint_only.returncode != 0:
        # kube-linter began rejecting unparseable input. The invariant would then no longer
        # depend on the render, which is a change worth noticing rather than assuming.
        print("lint only: linter now exits %d on unparseable input" % lint_only.returncode)
        print("the linter's behaviour changed. Re-confirm whether the render step is still "
              "the control before relying on this result.")
    elif verdict == harness.CLEAN:
        failures.append("lint only returned clean and the harness accepted it, so dropping "
                        "the render would pass the baseline")
    else:
        print("lint only: linter exits 0 but the harness classifies %s, so the composition "
              "without a render is rejected" % verdict)

    if failures:
        print("\nrender invariant FAILED:", file=sys.stderr)
        for failure in failures:
            print("  " + failure, file=sys.stderr)
        return 1

    print("\nrender invariant proven: the control fails closed, and the composition that "
          "omits the render does not pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
