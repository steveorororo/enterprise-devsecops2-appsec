# Synthetic credential. Randomly generated, never issued, and grants no access. Exists so the
# secret control can be proven to fail a build on a committed credential.
#
# Deliberately not the vendor documentation example value. Secret scanners allowlist the
# published example credentials as known non-secrets, so a fixture built from one proves
# nothing about detection.
AWS_ACCESS_KEY_ID = "AKIA4T7HZ2QK9RBNVX3M"
AWS_SECRET_ACCESS_KEY = "Xy7pQ2mLd8Rt4vNc0BzWfKa1JhSu6EgYoPrTiZbQ"
