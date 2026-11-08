# syntax=docker/dockerfile:1
# Fork-only overlay (W17-ii, E16): the fork agent image + the standalone Docker Compose CLI, pinned by SHA-256 (fail closed: a wrong hash fails the build).
# `fork-base` is a NAMED BUILD CONTEXT (the locally built base image as an OCI layout, see scripts/fork/build-image.sh): it never touches a registry.
# SHA-256 values: docker/compose release v5.4.0 — the downloaded binary, its `.sha256` file and `checksums.txt` of the release agree (2026-11-08).
FROM fork-base
ARG TARGETARCH
ARG COMPOSE_VERSION=v5.4.0
ARG COMPOSE_SHA256_AMD64=837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be
ARG COMPOSE_SHA256_ARM64=fc5d1371f1ec7987e703da94ede49af3fbfb240b83f22991a98511de7bc4b93b
RUN set -eu; \
    case "$TARGETARCH" in amd64) a=x86_64; s="$COMPOSE_SHA256_AMD64";; arm64) a=aarch64; s="$COMPOSE_SHA256_ARM64";; *) echo "unsupported arch $TARGETARCH" >&2; exit 1;; esac; \
    printf '%s' "$s" | grep -Eq '^[0-9a-f]{64}$'; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/docker-compose "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-${a}"; \
    echo "${s}  /tmp/docker-compose" | sha256sum -c -; \
    install -m 0755 /tmp/docker-compose /usr/local/bin/docker-compose; rm -f /tmp/docker-compose; \
    test "$(docker-compose version --short)" = "${COMPOSE_VERSION#v}"
