# Nordyg

A native macOS app for DNS queries. Type a name, pick a record type and a resolver, and see
everything the wire returned: DNSSEC chain, DoH/DoT/DoQ, multi-resolver compare, delegation
trace, history. No CLI, on purpose.

Nordyg is open source under Apache 2.0. You can build it yourself with Xcode, or buy the
signed and notarized build on the Mac App Store to support the project.

## Layout

- `core/` Go module with all DNS logic, compiled to a universal static C archive. The C surface
  is three functions (`NordygQuery`, `NordygCancel`, `NordygFree`); everything else is a JSON
  contract.
- `app/` SwiftUI shell. `app/NordygCore` is the Clang module that imports the archive;
  `app/smoke` is a Swift harness that exercises the bridge in CI.

## Building

Requires Xcode and Go. The Go version is pinned in the Makefile; any Go on PATH that can
download toolchains will do.

```sh
make test      # Go tests, no network needed
make archive   # core/build/libnordyg.a (x86_64 + arm64) and header
make smoke     # build and run the Swift bridge harness
make run       # build the app and open it
```

Or open `app/Nordyg.xcodeproj` in Xcode after `make archive`.

## Licence

Apache 2.0, see `LICENSE`.
