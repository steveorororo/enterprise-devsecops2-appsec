#!/usr/bin/env python3
"""Prove GitOps promotion carries the exact approved digest.

The digest the registry returned is the deployment identity. Promotion must write that
digest into the desired state, and must not substitute a tag: a tag can be repointed after
the artifact was scanned, signed and approved, which would deploy something that was never
examined.

Renders the consuming repository's deployment overlays with a known digest and checks the
result. Requires kustomize, and the target's rendering script.
"""
import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# A digest that is not the placeholder shipped in the template, so a render that silently
# ignored the input cannot pass.
SAMPLE_DIGEST = "sha256:e3d7a40d1e1ec0e28c10319ca4d89ad8ecfe35b126394ac1efff64e75486d969"
SAMPLE_IMAGE = "ghcr.io/steveorororo/enterprise-devsecops2-appsec/artifact-clean"
PLACEHOLDER_DIGEST = "sha256:" + "0" * 64
MUTABLE_TAG = re.compile(r"image:\s*\S+:(latest|main|dev|test|prod)\b")


def run(command, cwd=None):
    return subprocess.run(command, capture_output=True, text=True, cwd=cwd,
                          encoding="utf-8", errors="replace")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True,
                        help="Consuming repository whose overlays are rendered")
    parser.add_argument("--digest", default=SAMPLE_DIGEST)
    parser.add_argument("--image", default=SAMPLE_IMAGE)
    args = parser.parse_args()

    if not shutil.which("kustomize"):
        print("gitops digest fidelity NOT EXECUTED: kustomize unavailable", file=sys.stderr)
        return 2

    renderer = args.target.resolve() / "scripts" / "utility" / "render-deployment.py"
    if not renderer.is_file():
        print("gitops digest fidelity NOT EXECUTED: target has no rendering script",
              file=sys.stderr)
        return 2

    failures = []

    with tempfile.TemporaryDirectory() as raw:
        workspace = Path(raw) / "repo"
        shutil.copytree(args.target.resolve(), workspace,
                        ignore=shutil.ignore_patterns(".git"))

        # The template ships a placeholder registry name. Set a real one so the render
        # reflects a configured application.
        overlay = workspace / "deploy" / "overlays" / "dev" / "kustomization.yaml"
        overlay.write_text(
            overlay.read_text(encoding="utf-8").replace("<set-by-registry-config>", args.image),
            encoding="utf-8")

        output = Path(raw) / "rendered.yaml"
        result = run([sys.executable, str(workspace / "scripts" / "utility" / "render-deployment.py"),
                      "--environment", "dev", "--digest", args.digest,
                      "--output", str(output)], cwd=str(workspace))

        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            print("gitops digest fidelity NOT EXECUTED: render failed: %s"
                  % (detail[-1] if detail else "unknown"), file=sys.stderr)
            return 2

        rendered = output.read_text(encoding="utf-8")

        if args.digest not in rendered:
            failures.append("rendered desired state does not contain the promoted digest")
        if PLACEHOLDER_DIGEST in rendered:
            failures.append("rendered desired state still carries the placeholder digest")
        mutable = MUTABLE_TAG.search(rendered)
        if mutable:
            failures.append("rendered desired state references a mutable tag: %s"
                            % mutable.group(0).strip())
        if "@" + args.digest not in rendered:
            failures.append("image is not pinned by digest")

        # A render that ignored the requested digest must be refused rather than promoted.
        wrong = run([sys.executable, str(workspace / "scripts" / "utility" / "render-deployment.py"),
                     "--environment", "dev", "--digest", "sha256:" + "1" * 64,
                     "--output", str(Path(raw) / "other.yaml")], cwd=str(workspace))
        if wrong.returncode == 0:
            other = (Path(raw) / "other.yaml").read_text(encoding="utf-8")
            if args.digest in other:
                failures.append("a second render reused the previous digest")

    if failures:
        print("gitops digest fidelity FAILED:", file=sys.stderr)
        for failure in failures:
            print("  " + failure, file=sys.stderr)
        return 1

    print("gitops digest fidelity proven: desired state pins %s and uses no mutable tag"
          % args.digest[:19])
    return 0


if __name__ == "__main__":
    sys.exit(main())
