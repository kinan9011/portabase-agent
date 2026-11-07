# Fork agent task channel (feature `fork-stacks`)

Fork-only code lives in `src/fork/`; the stock build (`cargo build`) contains none of it. Design + risk list: vault ADR-007 (restore architecture + agent channel, W15).

* Build the fork agent: `cargo build --release --features fork-stacks` (Docker: `--build-arg CARGO_FEATURES=fork-stacks`).
* Enable: `FORK_CHANNEL_ENABLED=true` and `FORK_CHANNEL_BUNDLE_FILE=/path/to/bundle` (the enrolment bundle shown ONCE by the dashboard; file mode **0600**, never argv). Optional: `FORK_CHANNEL_STATE_FILE` (default `$DATA_PATH/fork-channel-state.json`), `FORK_CHANNEL_POLL_SECONDS` (2–300, default 5).
* The channel is **https only**. The single exemption (fork lab) needs `FORK_ALLOW_INSECURE_LOOPBACK=true` **and** a loopback host (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`); it logs a warning on every start. A plain-HTTP LAN dashboard (e.g. `http://192.168.8.32:8887`) is refused: put the dashboard behind TLS first.
* Tasks are RSA-signed by the dashboard and verified against the public key **pinned in the bundle**; unsigned, forged, expired, replayed, rolled-back, foreign or unknown-type tasks are refused. After a dashboard database rollback or a suspected compromise: **re-enrol** the agent (new bundle).
* Upstream hooks (registry `scripts/fork/patch-registry.txt`): A01 `src/main.rs`, A02 `Cargo.toml`, A03 `src/services/backup/uploader.rs`, A04 `docker/Dockerfile`. Check: `bash scripts/fork/check-patches.sh`.
* Tests: `cargo test --features fork-stacks fork::`.

## Channel maintenance tasks (W15b, ADR-007 A11/A12)

Capability `channel-maint.v1`. Three signed task types, the **only** types that may change the agent's credential or trusted keys (each is verified like every other task first: pinned key, agent/enrolment, seq, expiry, payload hash):

* `pin_add` — trust one more dashboard public key (RSA SPKI PEM; the `kid` must equal the first 12 hex of SHA-256(SPKI DER); at most 8 pins).
* `pin_revoke` — stop trusting a key. Refused for the key that signed the task and for the last remaining pin.
* `rotate_credential` — switch to a new credential (`fork.<agent_id>.<43 base64url>`). The dashboard keeps the old one valid until the agent proves the new one.

Effects are written **first** to the replay state file (`FORK_CHANNEL_STATE_FILE`, mode 0600, atomic rename, fail closed) and only then used; a failed write changes nothing and reports `failed:state_unavailable`. The state file therefore now holds the rotated credential and runtime-added pins: keep its directory **outside any backed-up volume**. The bundle file itself is never rewritten (mount it `:ro`). Effective pins = bundle pins − revoked + added; 0 or more than 8 effective pins, or a stored pin that no longer parses, makes the channel refuse to start. Re-enrolling (new `enroll_id`) resets all of it and is the universal cure.

K2 (dashboard signing key) rotation: generate the new pair offline → `pin_add(new public key)` to every agent → swap `server_private.pem` on the dashboard and restart → `pin_revoke(old kid)` (now signed by the new key). Re-enrol stays the fallback.

## Fork agent image (W15b)

* Build locally, by digest: `bash scripts/fork/build-image.sh` (Docker buildx, `docker/Dockerfile` target `prod`, `--build-arg CARGO_FEATURES=fork-stacks`, one platform, default `linux/amd64`). It loads the image into the local engine, writes `target/fork-image/image.oci.tar` and records `target/fork-image/image.json` (OCI manifest digest, local image id, git rev, Dockerfile SHA-256, features, platform, buildx version). It never talks to a registry.
* `.github/workflows/fork-image.yml` (`workflow_dispatch` only, `contents: read`, no secrets, no registry access) runs the same script for `linux/amd64` and `linux/arm64` and uploads `image.json` + the OCI archive as artifacts.

### Local build record (not published)

| field | value |
|---|---|
| image tag (local) | `portabase-agent-fork:1.25.2-fork-a440e2ce66d0` (also tagged `portabase-agent-fork:w15b-lab`) |
| OCI manifest digest | `sha256:03dbb148ed2c275b9a181c060d16e53b100c6357bcd97d8b7ebd1365cbff5879` |
| git rev (agent) | `a440e2ce66d0e4ee14621e795e33d22bb5bf8d5a`, clean tree |
| cargo features / platform | `fork-stacks` / `linux/amd64` |
| built | 2026-11-07, buildx v0.36.1 |
| published | **no** (owner decision, below) |

### Publishing (owner decision)

Nothing is pushed by the fork tooling. To publish, pick a registry and name (recommendation: GHCR under your own account, e.g. `ghcr.io/<you>/portabase-agent:<version>-fork`), then copy the archive **preserving the digest**: `skopeo copy --preserve-digests oci-archive:target/fork-image/image.oci.tar docker://<registry>/<name>:<tag>` (or `crane push target/fork-image/image.oci.tar <ref>`). Check: `docker buildx imagetools inspect <ref>` must show the digest recorded in `image.json`. Deploy by `@sha256:<digest>`. For multi-arch, dispatch `fork-image.yml`, then combine the per-arch images with `docker buildx imagetools create` at publish time. Record the published digest in the fork's compatibility matrix.
