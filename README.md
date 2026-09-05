# Nordyg

A native macOS app for DNS queries. Type a name, pick a record type and a resolver, and see
everything the wire returned: DNSSEC chain, DoH/DoT/DoQ, multi-resolver compare, delegation
trace, history. No CLI, on purpose.

Nordyg is open source under the AGPL-3.0. You can build it yourself with Xcode, or buy the
signed and notarized build on the Mac App Store to support the project.

## Open source, closed to contributions

Nordyg is open source, but I do not accept external contributions. This is a personal
project and I want to keep full control over the codebase and where it goes. I also don't
have the free time to review and manage contributions.

So please do not open pull requests. If you find a bug, have a question or a suggestion,
use the Discussions section. See [CONTRIBUTING.md](CONTRIBUTING.md).

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

GNU Affero General Public License v3.0, see `LICENSE`.
