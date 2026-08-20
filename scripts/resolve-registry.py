#!/usr/bin/env python3
"""Resolve and authorize a container registry destination.

A consuming repository chooses a provider and a repository path. It does not choose whether a
destination is permitted. This resolves the request against the approved destinations in
security/registries.yaml and refuses anything else.

The refusal happens before the caller reaches any authentication step, so credentials are
never offered to a host the platform has not approved. That ordering is the control: a check
performed after login would already have leaked the credential to the destination.

Emits GitHub Actions output when a destination is approved:

  registry_host        approved host, taken from policy rather than from the request
  image_ref            host/path/name
  authentication_mode  how the publishing job should authenticate
"""
import argparse
import os
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY = REPO_ROOT / "security" / "registries.yaml"

PLACEHOLDER = re.compile(r"<[^>]*>")
UNSAFE = re.compile(r"[\x00-\x1f\x7f\s]")
NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def reject(message):
    print("registry destination rejected: %s" % message, file=sys.stderr)
    return 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", required=True, help="Registry provider key")
    parser.add_argument("--path", required=True,
                        help="Repository path within the registry, such as owner/name")
    parser.add_argument("--image-name", required=True, help="Image name to publish")
    parser.add_argument("--requested-host", default=None,
                        help="Host the caller believes it is publishing to. Compared against "
                             "policy; a mismatch is rejected rather than corrected.")
    parser.add_argument("--policy", type=Path, default=POLICY)
    args = parser.parse_args()

    try:
        policy = yaml.safe_load(args.policy.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return reject("cannot read registry policy: %s" % exc)

    providers = policy.get("providers") or {}
    provider = providers.get(args.provider)

    if provider is None:
        return reject("provider %r is not an approved provider. Approved: %s"
                      % (args.provider, ", ".join(sorted(
                          name for name, entry in providers.items()
                          if (entry or {}).get("status") == "approved")) or "none"))

    status = provider.get("status")
    if status != "approved":
        return reject("provider %r has status %r and is not usable. A destination that is not "
                      "configured and tested cannot be verified." % (args.provider, status))

    host = provider.get("registry_host")
    if not host or PLACEHOLDER.search(str(host)):
        return reject("provider %r has no approved registry host" % args.provider)

    # The caller may state where it believes it is publishing. Policy decides, and a
    # disagreement is a rejection rather than a silent correction, because a caller that
    # expected another destination has not been satisfied.
    if args.requested_host and args.requested_host != host:
        return reject("requested host %r is not the approved host %r for provider %r"
                      % (args.requested_host, host, args.provider))

    path = args.path
    if not path or PLACEHOLDER.search(path) or UNSAFE.search(path):
        return reject("repository path %r is unset, a placeholder, or contains unsafe "
                      "characters" % path)

    pattern = provider.get("path_pattern")
    if pattern and not re.match(pattern, path):
        return reject("repository path %r does not match the approved pattern for %r"
                      % (path, args.provider))

    if ".." in path.split("/"):
        return reject("repository path must not contain path traversal segments")

    image_name = args.image_name
    if not image_name or PLACEHOLDER.search(image_name) or not NAME.match(image_name):
        return reject("image name %r is unset, a placeholder, or not a valid image name"
                      % image_name)

    image_ref = "%s/%s/%s" % (host, path, image_name)

    lines = [
        "registry_host=%s" % host,
        "image_ref=%s" % image_ref,
        "authentication_mode=%s" % provider.get("authentication_mode", ""),
    ]

    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line + "\n")
    for line in lines:
        print(line)

    return 0


if __name__ == "__main__":
    sys.exit(main())
