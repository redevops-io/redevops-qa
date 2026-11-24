# redevops-qa standalone image. Build context: the repository root, INCLUDING .git (the bundle builder names the commit it builds from and refuses a dirty tree).
#
#   docker buildx build -f deploy/standalone/Dockerfile --platform linux/amd64,linux/arm64 .
#
# Both platforms are built the same way, each from ITS OWN bundle: the pinned bundle of the platform (tools/build_bundle.py --platform: hash-locked wheelhouse, the pinned upstream
# trees) installed with the bundle's own install.sh, and the Chromium of the platform's browser lock installed with the bundle's own install-browser.sh (sha256 of the archives and of
# the unpacked tree checked against the pin). Lanes on both: Playwright Chromium and Robot Framework.
# linux/amd64 : bundle/third-party.lock.json, bundle/browser.lock.json
# linux/arm64 : bundle/third-party.lock.linux-arm64.json, bundle/browser.lock.linux-arm64.json (until 0.6.5 this image carried the evidence commands only)
# ---------------------------------------------------------------------------------------------------------------- stage 1: the pinned bundle (runs on the build host)
FROM --platform=$BUILDPLATFORM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS bundle
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY . /src
WORKDIR /src
# fetch_pins.py: the two pinned upstreams at their exact commits over plain HTTPS (no token), verified (HEAD, clean tree, digests).
# build_bundle.py: refuses a dirty tree; the third-party wheels come from the package index, hash-checked against the third-party lock of the TARGET platform (the build host
# only downloads them: nothing of the target platform is executed in this stage, so it runs on the build host whatever the target is).
RUN case "$TARGETARCH" in amd64) platform=linux-x86_64;; arm64) platform=linux-arm64;; *) echo "no bundle exists for $TARGETARCH" >&2; exit 1;; esac \
 && python tools/fetch_pins.py > /tmp/fetch_pins.log \
 && python tools/build_bundle.py build --platform "$platform" --out /out \
 && cd /out && sha256sum -c ./*.tar.sha256

# ---------------------------------------------------------------------------------------------------------------- stage 2: the runtime image
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS runtime
ARG TARGETARCH
ARG VERSION=0.0.0-unset
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="redevops-qa" \
      org.opencontainers.image.description="redevops-qa: runs frozen test specifications against its bundled fixture app and verifies the evidence it kept (CLI and a small authenticated HTTP service)" \
      org.opencontainers.image.source="https://github.com/redevops-io/redevops-qa" \
      org.opencontainers.image.licenses="LicenseRef-AGPL-3.0-or-later-with-Commons-Clause" \
      org.opencontainers.image.vendor="RedevOps" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LC_ALL=C.UTF-8 LANG=C.UTF-8
RUN groupadd --gid 10001 qa \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /home/qa --shell /usr/sbin/nologin qa \
 && install -d -o 10001 -g 10001 -m 0750 /data

COPY --from=bundle /out /tmp/bundle
RUN set -eux; \
    # Security updates the pinned base image does not have yet (the base is pinned by digest; this is the one place the image takes newer Debian packages, and the build date decides which).
    apt-get update; apt-get -y --no-install-recommends upgrade; \
    cd /tmp/bundle && sha256sum -c ./*.tar.sha256 && tar xf ./*.tar && cd redevops-qa-bundle-*; \
    ./install.sh --prefix /opt/redevops-qa; \
    ./install-browser.sh --prefix /opt/redevops-qa --with-deps; \
    # `playwright install-deps` also installs a virtual X server for headed runs; the lanes here are headless, so it is removed again (the libraries Chromium loads stay).
    apt-get -y purge xvfb xserver-common; apt-get -y autoremove --purge; \
    apt-get clean; rm -rf /var/lib/apt/lists/*; \
    # The browser pin records four metadata files (deb.deps, rpm.deps) at mode 0600, and the pin check hashes every file as the user that runs the lane: give those four files (only) to the
    # runtime user, mode unchanged, so the tree check passes without making the rest of the browser tree writable by it.
    find /opt/redevops-qa/browsers -type f \( -name deb.deps -o -name rpm.deps \) -exec chown 10001:10001 {} +; \
    rm -rf /tmp/bundle /root/.cache

# The HTTP service (standard library only, packages/qa-service) runs on the interpreter of the installation, so it sees exactly the lanes that installation has; the plans are the
# shipped examples of the runner; the licence texts travel with the image.
COPY packages/qa-service/src/qa_service /opt/redevops-qa/venv/lib/python3.12/site-packages/qa_service
COPY packages/qa-runner/examples /opt/redevops-qa/share/plans
COPY LICENSE LICENSE-COMMONS-CLAUSE LICENSE.md /opt/redevops-qa/share/licence/
RUN printf '%s\n' '#!/bin/sh' "exec /opt/redevops-qa/venv/bin/python -I -m qa_service \"\$@\"" > /usr/local/bin/redevops-qa-service \
 && chmod 755 /usr/local/bin/redevops-qa-service \
 && /opt/redevops-qa/venv/bin/python -I -c "import qa_service"

# Bind on all interfaces INSIDE the container (the published port is what Compose and the manifests restrict); the service still refuses to start without a token.
ENV PATH=/opt/redevops-qa/bin:/usr/local/bin:/usr/bin:/bin HOME=/tmp TMPDIR=/tmp PLAYWRIGHT_BROWSERS_PATH=/opt/redevops-qa/browsers \
    QA_SERVICE_BIND=0.0.0.0 QA_SERVICE_PORT=8080 QA_SERVICE_DATA_DIR=/data QA_SERVICE_PLANS_DIR=/opt/redevops-qa/share/plans
USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=6s --start-period=15s --retries=3 CMD ["redevops-qa-service", "healthcheck"]
CMD ["redevops-qa-service"]
