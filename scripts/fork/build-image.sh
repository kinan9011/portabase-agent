#!/usr/bin/env bash
# Build the FORK agent image locally, by digest (W15b, ADR-007 R11). Fork-only path.
#   - Builds docker/Dockerfile target `prod` with cargo feature `fork-stacks` for ONE platform (default linux/amd64).
#   - Loads it into the local docker engine under a local tag AND writes an OCI archive; records the OCI manifest digest
#     (the digest a registry would serve after a digest-preserving copy) in $OUT/image.json.
#   - W17-ii: the base image is then wrapped by docker/fork/Dockerfile (+ the Compose CLI pinned by SHA-256) as a second, local step: `fork-base` is an OCI-LAYOUT
#     build context, so nothing is pulled from or pushed to a registry. The recorded digest is the digest of the FINAL (overlay) image.
#   - This script only builds on this machine. Getting the archive to a registry is a manual owner step: docs/fork/README.md.
# Env: PLATFORM (linux/amd64) · FORK_IMAGE_TAG (portabase-agent-fork:<cargo version>-fork-<git rev>) · OUT (target/fork-image) · ALLOW_DIRTY=1 (record dirty:true)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
PLATFORM="${PLATFORM:-linux/amd64}"
VERSION="$(cargo pkgid | awk -F'[#@]' '{print $NF}')"
REV="$(git rev-parse --short=12 HEAD)"
FORK_IMAGE_TAG="${FORK_IMAGE_TAG:-portabase-agent-fork:${VERSION}-fork-${REV}}"
OUT="${OUT:-target/fork-image}"

DIRTY=false
if [ -n "$(git status --porcelain)" ]; then
  [ "${ALLOW_DIRTY:-}" = "1" ] || { echo "build-image: working tree is dirty (commit first, or ALLOW_DIRTY=1 to record dirty:true)" >&2; exit 2; }
  DIRTY=true
fi

mkdir -p "$OUT"
BASE_TAG="portabase-agent-fork-base:${VERSION}-fork-${REV}"
COMMON=(-f docker/Dockerfile --target prod --build-arg CARGO_FEATURES=fork-stacks --platform "$PLATFORM" --provenance=false --sbom=false)
docker buildx build "${COMMON[@]}" --load -t "$BASE_TAG" .
docker buildx build "${COMMON[@]}" --output "type=oci,dest=$OUT/base.oci.tar" .
rm -rf "$OUT/base-oci" && mkdir -p "$OUT/base-oci" && tar -xf "$OUT/base.oci.tar" -C "$OUT/base-oci"
BASE_DIGEST="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["manifests"][0]["digest"])' "$OUT/base-oci/index.json")"
case "$BASE_DIGEST" in sha256:????????????????????????????????????????????????????????????????) ;; *) echo "build-image: unexpected base digest '$BASE_DIGEST'" >&2; exit 3 ;; esac
OVERLAY=(-f docker/fork/Dockerfile --build-context "fork-base=oci-layout://$PWD/$OUT/base-oci@$BASE_DIGEST" --platform "$PLATFORM" --provenance=false --sbom=false ${COMPOSE_BUILD_ARGS:-})
docker buildx build "${OVERLAY[@]}" --load -t "$FORK_IMAGE_TAG" .
docker buildx build "${OVERLAY[@]}" --output "type=oci,dest=$OUT/image.oci.tar" .

DIGEST="$(tar -xOf "$OUT/image.oci.tar" index.json | python3 -c 'import json,sys;print(json.load(sys.stdin)["manifests"][0]["digest"])')"
case "$DIGEST" in sha256:????????????????????????????????????????????????????????????????) ;; *) echo "build-image: unexpected digest '$DIGEST'" >&2; exit 3 ;; esac
IMAGE_ID="$(docker image inspect -f '{{.Id}}' "$FORK_IMAGE_TAG")"

python3 - "$OUT/image.json" <<PY
import json, sys
rec = {
    "image_tag": "$FORK_IMAGE_TAG",
    "oci_manifest_digest": "$DIGEST",
    "local_image_id": "$IMAGE_ID",
    "git_rev": "$(git rev-parse HEAD)",
    "dirty": $( [ "$DIRTY" = true ] && echo True || echo False ),
    "dockerfile_sha256": "$(sha256sum docker/Dockerfile | cut -d' ' -f1)",
    "overlay_dockerfile_sha256": "$(sha256sum docker/fork/Dockerfile | cut -d' ' -f1)",
    "base_image_tag": "$BASE_TAG",
    "base_oci_manifest_digest": "$BASE_DIGEST",
    "compose_version": "v$(docker run --rm --entrypoint docker-compose "$FORK_IMAGE_TAG" version --short)",
    "compose_sha256": "$(docker run --rm --entrypoint sha256sum "$FORK_IMAGE_TAG" /usr/local/bin/docker-compose | cut -d' ' -f1)",
    "cargo_features": "fork-stacks",
    "platform": "$PLATFORM",
    "buildx_version": "$(docker buildx version | awk '{print $2}')",
    "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "published": False,
}
json.dump(rec, open(sys.argv[1], "w"), indent=2)
open(sys.argv[1], "a").write("\n")
print(json.dumps(rec, indent=2))
PY
