FROM python:3.12-slim@sha256:9c85d1d49df54abca1c5db3b4016400e198e9e9bb699f32f1ef8e5c0c2149ccf
WORKDIR /app
COPY app/requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt || true
USER 1001
CMD ["python", "-c", "print('ok')"]
