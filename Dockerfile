FROM python:3.12.15-alpine3.24@sha256:7a63cb93468d7ce5f24b1332a8f7a27f444b3221b0a3d6b5573036b78d937c78

ARG HOTPOT_VERSION=dev
ARG HOTPOT_GIT_SHA=unknown
ARG HOTPOT_BUILD_DATE=unknown

LABEL org.opencontainers.image.source="https://github.com/dwightmulcahy/hotpot" \
      org.opencontainers.image.title="Hotpot" \
      org.opencontainers.image.version="${HOTPOT_VERSION}" \
      org.opencontainers.image.revision="${HOTPOT_GIT_SHA}" \
      org.opencontainers.image.created="${HOTPOT_BUILD_DATE}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOTPOT_VERSION=${HOTPOT_VERSION} \
    HOTPOT_GIT_SHA=${HOTPOT_GIT_SHA} \
    HOTPOT_BUILD_DATE=${HOTPOT_BUILD_DATE}

RUN addgroup -S hotpot && adduser -S -G hotpot -u 10001 hotpot
WORKDIR /app
COPY requirements-core.txt .
RUN pip install --no-cache-dir -r requirements-core.txt
COPY sitecustomize.py ./sitecustomize.py
COPY hotpot ./hotpot
COPY profiles ./profiles
RUN mkdir -p /data && chown -R hotpot:hotpot /data /app
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.getenv('HOTPOT_PORT','8080')+'/_hotpot/live', timeout=3).read()"]
CMD ["python", "-m", "hotpot.server"]
