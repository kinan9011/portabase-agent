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

## Restore target configuration (W17-i, ADR-007 A13)
An agent becomes a **restore target** only when its host is configured for it. Until then it is a plain backup agent: it does **not** report `restore.target.v1`, the dashboard's restore planner blocks with `target_capability_missing`, and any restore task is refused by the agent (`capability_missing`).

| Env var | Meaning |
|---|---|
| `FORK_ALLOWED_PATH_ROOTS` | Colon list of absolute directories restores may write under (default empty = not a restore target). Each must exist, be a real directory (no symlink in the path), and must not be, contain or lie under `/`, `/etc`, `/proc`, `/sys`, `/dev`, `/run`, `/var/run`, `/boot`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/root`, `/var/lib/docker`, the docker socket or the agent state directory. One invalid root disables the whole feature (one log line). |
| `FORK_HOST_ROLE` | `test` (default) or `production`. A task whose plan says `production` is refused on a `test` host (`host_role_mismatch`); a `production` task also needs the dashboard's `production_target` approval (`approval_missing`). A production restore therefore needs the dashboard approval **and** this explicit host-side opt-in. |
| `FORK_ARTIFACT_HTTP_HOSTS` | Comma list of exact artifact hosts that may be fetched over plain `http` (default empty = https only; e.g. a LAN MinIO). Redirects are never followed. |

Requirements: the Docker socket is mounted (restores create labelled volumes and run hardened helper containers from the agent's own image), and **every root is bind-mounted into the agent container at the same host path** (`-v /srv/restore:/srv/restore`): the agent proves it at start of every stage with a probe file read back through a helper container (`root_not_shared` otherwise), because compose bind sources are *host* paths.

What the four tasks do (all signed, target-addressed, idempotent per `restore_id`, bounded by a deadline, heartbeating while they run):
`restore_probe` (roots, free space, workspace state) · `restore_stage` (verify the signed manifest with a pinned key, download each artifact with a size cap and no redirects, decrypt, compare SHA-256/size with the manifest, audit the tar, extract into the planned destinations) · `restore_apply` (labelled Docker volumes/networks, sqlite file placement, non-PostgreSQL dump unpack) · `restore_cleanup` (removes only resources carrying this run's `restore_id` + `agent_id` labels, and the workspace only if `.portabase/owner.json` carries this run). PostgreSQL restore, compose render and `compose_up` arrive with W17-ii. The agent's journal and replay state live next to the channel state file (`${DATA_PATH:-/config}`); keep that directory out of any backed-up volume.

## Compose (W17-ii)

`compose.render.v1` is reported only on a restore target (`FORK_ALLOWED_PATH_ROOTS`, Docker socket) whose image is the **fork overlay** (`docker/fork/Dockerfile`: Docker Compose v5.4.0 pinned by SHA-256 per architecture, the build fails closed on a mismatch) and whose own container id / image id the agent can resolve.

- `FORK_PROTECTED_CONTAINERS` — comma list of container names or 64-hex ids that `compose up` must never touch (in addition to the agent itself, Portabase / Arcane images and every container that mounts the Docker socket). An invalid entry disables the capability.
- The agent refuses (`container_conflict`) to start a project whose name or `container_name`s collide with a container it does not own; it never stops, renames or recreates a foreign container.
- Images are built **locally only** (`bash scripts/fork/build-image.sh`, `published: false`). Never `docker push` from this script; publishing is a manual owner step.
- Private-registry images cannot be pulled (the agent has no registry credentials): `compose_failed`.

## Stop-during-backup (quiesce) — W17b, ADR-007 A15

The agent can stop selected containers of ONE compose project while the dashboard copies files / volumes, then start them again. **Off by default, three switches:**
the dashboard flag `FORK_QUIESCE_ENABLED`, a per-stack enable by a system administrator on the dashboard, and **this host**: set on the agent container

| Variable | Meaning |
|---|---|
| `FORK_QUIESCE_ENABLED=true` | Host owner opt-in. Without it the agent never reports `quiesce.v1` and refuses every quiesce task (`capability_missing`). |
| `FORK_QUIESCE_MAX_STOP_SECONDS` | Hard cap of the stop window on this host, 60–3600, default 1800. The agent restarts the containers when it elapses, whatever the dashboard says. |
| `FORK_PROTECTED_CONTAINERS` | Extra protected containers (names or 64-hex ids). The agent's own container, Portabase / agent / Arcane images and any container that mounts the Docker socket are always protected. |

Needs the Docker socket (`-v /var/run/docker.sock:/var/run/docker.sock`) and **a restart policy on the agent container (`unless-stopped`/`always`)**: if the host reboots or the agent is killed during a window, only the agent's boot replay starts the containers again (Docker does not restart containers that were stopped through the API).

**What it guarantees.** A journal (`<state dir>/fork-quiesce/<task>.json`, 0600, never inside a volume) is written before the first stop. At every agent start — even when the task channel is disabled or its bundle is broken — journaled containers that were running before and are not running now are started again, in reverse stop order, verified one by one (running, healthy when a healthcheck exists, still running after a 3 s settle). The agent-local deadline uses the monotonic clock and does not depend on the dashboard. Only containers named in the agent's own journal are ever started.

**What it refuses (whole task, nothing stopped):** a container outside the stack's compose project; the agent / Portabase / Arcane / a Docker-socket mounter anywhere in that project; an ambiguous or changed container id; a running second copy of a chosen service; paused / restarting containers; containers owned by a restore.

**Manual recovery.** If the dashboard is gone and the agent cannot start a container: `docker ps -a --filter label=com.docker.compose.project=<project>`; the containers it stopped are listed (names, ids) in the journal file in the agent's state volume; `docker start <id>`. Removing the journal file afterwards clears the `quiesce_pending` block.
