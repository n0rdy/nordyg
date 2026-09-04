# Nordyg

macOS DNS client: Go core (`core/`) compiled to a universal C archive, SwiftUI shell (`app/`).
See `CONTEXT.md` (local only, not committed) for decisions and the bridge rules, and
`docs/contract.md` for the JSON contract every op must follow.

## Commands

- `make test` — Go unit tests, offline.
- `make archive` — universal `core/build/libnordyg.a` + header, copies header to `app/NordygCore/`.
- `make smoke` — Swift bridge harness; `NORDYG_SMOKE_NET=1 make smoke` adds a live query.
- `make lint` — golangci-lint.

## Core layout (`core/internal/`)

- `bridge` envelope, dispatch, panic recovery, cancel registry (no cgo).
- `contract` shared JSON types, endpoint/question/options validation.
- `transport` udp/tcp/dot/doh/doq exchanges, bootstrap, error classification.
- `msg` miekg message → contract message (typed fields, EDNS, dig text).
- `query`, `compare`, `trace`, `presets`, `export` the ops; `ops` wires them.
- `dnssec` trust anchors (`trustanchors.txt`), chain walk, NSEC/NSEC3 proofs, fetchers.
- `txtdecode` SPF/DMARC/DKIM decoding, attached to TXT records by the query decorator.
- `testdns` in-process UDP/TCP/DoT/DoH/DoQ servers and certs for tests only.

## Rules

- The C surface is exactly `NordygQuery`, `NordygCancel`, `NordygFree`. New functionality is a
  new `op` in the JSON contract, never a new exported function.
- Every op lives in its own package under `core/internal/` and is registered in
  `core/internal/ops`. Ops return `*bridge.Error` with a stable code for expected failures.
- Handlers must respect `ctx` so `NordygCancel` works.
- The core never uses the system resolver; endpoints are always explicit in params.
- Tests never touch the public internet. Use an in-process `dns.Server` fixture.
- Do not run git write operations (commit, push, init, etc.); the author does those.
