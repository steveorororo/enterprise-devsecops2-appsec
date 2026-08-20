# Minimal image with no operating system packages, used to prove the artifact chain end to
# end without vulnerability findings interfering with the result.
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
COPY app.txt /app.txt
USER 1001
ENTRYPOINT ["/bin/sh", "-c", "cat /app.txt"]
