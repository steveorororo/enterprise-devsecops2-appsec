#!/usr/bin/env python3
"""Move a consuming repository to an approved platform release.

Rewrites the recorded release and every pinned workflow reference in one pass, so a
repository never sits in a state where it executes one release and reports another. Intended
to run in automation that opens a pull request for review: this changes files, it does not
adopt anything. A repository adopts a release when that pull request is merged.

Only released versions are accepted. An unknown, unreleased or malformed version is refused
rather than written.
"""
import argparse
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
MAPPING = REPO_ROOT / "platform" / "versions.yaml"

SHA = re.compile(r"^[0-9a-f]{40}$")


def resolve(mapping, version):
    for entry in (mapping or {}).get("versions") or []:
        if isinstance(entry, dict) and entry.get("platform_version") == version:
            if entry.get("status") != "released":
                return None, "version %s is not released" % version
            sha = entry.get("workflow_sha")
            if not isinstance(sha, str) or not SHA.fullmatch(sha):
                return None, "version %s has no usable commit" % version
            return sha, None
    return None, "version %s is not in the platform mapping" % version


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True,
                        help="Consuming repository to update")
    parser.add_argument("--version", required=True, help="Platform release to move to")
    parser.add_argument("--mapping", type=Path, default=MAPPING)
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would change without writing")
    args = parser.parse_args()

    target = args.target.resolve()
    pointer_file = target / "config" / "platform.yaml"
    if not pointer_file.is_file():
        print("no platform pointer at %s" % pointer_file, file=sys.stderr)
        return 1

    mapping = yaml.safe_load(args.mapping.read_text(encoding="utf-8")) or {}
    new_sha, problem = resolve(mapping, args.version)
    if problem:
        print("update refused: %s" % problem, file=sys.stderr)
        return 1

    pointer_text = pointer_file.read_text(encoding="utf-8")
    pointer = yaml.safe_load(pointer_text) or {}
    old_sha = str(pointer.get("platform_ref") or "")
    repository = str(pointer.get("platform_repository") or "")

    if old_sha == new_sha:
        print("already on %s at %s" % (args.version, new_sha[:12]))
        return 0

    changed = []

    updated_pointer = re.sub(r'platform_version:\s*"[^"]*"',
                             'platform_version: "%s"' % args.version, pointer_text)
    updated_pointer = re.sub(r"platform_ref:\s*\S+",
                             "platform_ref: %s" % new_sha, updated_pointer)
    if updated_pointer != pointer_text:
        changed.append(pointer_file.relative_to(target).as_posix())
        if not args.dry_run:
            pointer_file.write_text(updated_pointer, encoding="utf-8", newline="\n")

    workflows = target / ".github" / "workflows"
    for path in sorted(workflows.glob("*.yml")) + sorted(workflows.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        if repository and repository not in text:
            continue
        # Both the reference the workflow executes and the input that loads central
        # configuration move together. Updating one without the other is the split this
        # tool exists to prevent.
        updated = text.replace("%s@%s" % (repository, old_sha), "%s@%s" % (repository, new_sha))
        updated = updated.replace("platform_ref: %s" % old_sha, "platform_ref: %s" % new_sha)
        if updated != text:
            changed.append(path.relative_to(target).as_posix())
            if not args.dry_run:
                path.write_text(updated, encoding="utf-8", newline="\n")

    verb = "would update" if args.dry_run else "updated"
    print("%s %s from %s to %s (%s)"
          % (verb, target.name, old_sha[:12], new_sha[:12], args.version))
    for entry in changed:
        print("  " + entry)

    if not changed:
        print("no pinned reference matched the recorded commit", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
