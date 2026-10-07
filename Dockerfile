FROM python:3.12-alpine

ARG HOTPOT_VERSION=dev
ARG HOTPOT_GIT_SHA=unknown
ARG HOTPOT_BUILD_DATE=unknown

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
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
CMD ["python", "-m", "hotpot.durable_gateway"]
