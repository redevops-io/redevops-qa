# redevops-qa standalone image. Build context: the repository root, INCLUDING .git (the bundle builder names the commit it builds from and refuses a dirty tree).
#
#   docker buildx build -f deploy/standalone/Dockerfile --platform linux/amd64,linux/arm64 .
#
# linux/amd64 : the pinned bundle (tools/build_bundle.py: hash-locked wheelhouse, the pinned upstream trees) installed with the bundle's own install.sh, and the Chromium of
#               bundle/browser.lock.json installed with the bundle's own install-browser.sh (sha256 of the archives and of the unpacked tree checked against the pin).
#               Lanes: Playwright Chromium and Robot Framework. This is the one platform the product's evidence is for.
# linux/arm64 : the bundle's platform pin (CPython 3.12, Linux x86_64) refuses another platform and the browser pin names x86_64 archives only, so the repository's own
#               first-party wheels (pure Python, hash-checked from the same bundle) are installed WITHOUT the browser and Robot wheels: `verify`, `report`, `inspect`,
#               `freeze`, `doctor` and the HTTP service work; `run` and `demo` cannot start a lane and say so.
# ---------------------------------------------------------------------------------------------------------------- stage 1: the pinned bundle (runs on the build host)
FROM --platform=$BUILDPLATFORM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS bundle
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY . /src
WORKDIR /src
# fetch_pins.py: the two pinned upstreams at their exact commits over plain HTTPS (no token), verified (HEAD, clean tree, digests).
# build_bundle.py: refuses a dirty tree; the third-party wheels come from the package index, hash-checked against bundle/third-party.lock.json.
RUN python tools/fetch_pins.py > /tmp/fetch_pins.log \
 && python tools/build_bundle.py build --out /out \
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
    if [ "$TARGETARCH" = "amd64" ]; then \
        ./install.sh --prefix /opt/redevops-qa; \
        ./install-browser.sh --prefix /opt/redevops-qa --with-deps; \
        # `playwright install-deps` also installs a virtual X server for headed runs; the lanes here are headless, so it is removed again (the libraries Chromium loads stay).
        apt-get -y purge xvfb xserver-common; apt-get -y autoremove --purge; \
        apt-get clean; rm -rf /var/lib/apt/lists/*; \
        # The browser pin records four metadata files (deb.deps, rpm.deps) at mode 0600, and the pin check hashes every file as the user that runs the lane: give those four files (only) to the
        # runtime user, mode unchanged, so the tree check passes without making the rest of the browser tree writable by it.
        find /opt/redevops-qa/browsers -type f \( -name deb.deps -o -name rpm.deps \) -exec chown 10001:10001 {} +; \
    else \
        apt-get clean; rm -rf /var/lib/apt/lists/*; \
        mkdir -p /opt/redevops-qa/bin; \
        python3.12 -m venv /opt/redevops-qa/venv; \
        awk 'BEGIN{keep=0} /^[A-Za-z0-9_.-]+==/{keep=($0 ~ /^redevops-qa-(adapter-kit|bridge|egress|evidence|fixture-app|pinned-upstreams|playwright|robot|runner|third-party-notices)==/)} keep{print}' requirements.lock > /tmp/first-party.lock; \
        env -i PATH="$PATH" HOME=/tmp PIP_NO_CACHE_DIR=1 /opt/redevops-qa/venv/bin/python -m pip install --no-index --no-deps --only-binary=:all: --find-links wheelhouse --require-hashes -r /tmp/first-party.lock; \
        printf '%s\n' '#!/bin/sh' 'unset PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE PYTHONINSPECT PYTHONBREAKPOINT' \
            "exec '/opt/redevops-qa/venv/bin/python' -E -s '/opt/redevops-qa/venv/bin/redevops-qa' \"\$@\"" > /opt/redevops-qa/bin/redevops-qa; \
        chmod 755 /opt/redevops-qa/bin/redevops-qa; \
    fi; \
    rm -rf /tmp/bundle /tmp/first-party.lock /root/.cache

# The HTTP service (standard library only, packages/qa-service) runs on the interpreter of the installation, so it sees exactly the lanes that installation has; the plans are the
# shipped examples of the runner; the licence texts travel with the image.
COPY packages/qa-service/src/qa_service /opt/redevops-qa/venv/lib/python3.12/site-packages/qa_service
COPY packages/qa-runner/examples /opt/redevops-qa/share/plans
COPY LICENSE LICENSE-COMMONS-CLAUSE LICENSE.md /opt/redevops-qa/share/licence/
RUN printf '%s\n' '#!/bin/sh' "exec /opt/redevops-qa/venv/bin/python -I -m qa_service \"\$@\"" > /usr/local/bin/redevops-qa-service \
 && chmod 755 /usr/local/bin/redevops-qa-service \
 && /opt/redevops-qa/venv/bin/python -I -c "import qa_service"

# Bind on all interfaces INSIDE the container (the published port is what Compose and the manifests restrict); the service still refuses to start without a token.
ENV PATH=/opt/redevops-qa/bin:/usr/local/bin:/usr/bin:/bin HOME=/tmp TMPDIR=/tmp \
    QA_SERVICE_BIND=0.0.0.0 QA_SERVICE_PORT=8080 QA_SERVICE_DATA_DIR=/data QA_SERVICE_PLANS_DIR=/opt/redevops-qa/share/plans
USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=6s --start-period=15s --retries=3 CMD ["redevops-qa-service", "healthcheck"]
CMD ["redevops-qa-service"]
