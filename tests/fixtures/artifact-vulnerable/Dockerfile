# Defective on purpose. An end of life base image with known fixed vulnerabilities, used to
# prove image scanning blocks on the exact artifact that was pushed. Never deployed.
FROM alpine:3.9@sha256:414e0518bb9228d35e4cd5165567fb91d26c6a214e9c95899e1e056fcd349011
COPY app.txt /app.txt
ENTRYPOINT ["/bin/sh", "-c", "cat /app.txt"]
