# `lib` — the project's shared library package

Shared code for your proof suites: helpers, fixtures, and topologies that more than one suite needs.
`require("lib")` reaches it from any proof (the directory name here is the `require()` name).

- `init.lua` — the module. The retrofit ships the structure-discovery surface the quality legs
  stand on, plus black-box starters:
  - `lib.metadata` — `cargo metadata`, decoded, as a shared fixture (the project's own account of
    its structure — the reason the gates carry no preconceived layout).
  - `lib.src_roots(meta)` — the workspace members' `src/` roots, derived rather than assumed.
  - `lib.build` — one `cargo build --workspace` per proof file that asks.
  - `lib.bin(name)` — path to a built binary, for proofs that drive it.
- `prova.toml` — the package's `[package]` section (name, and private `[dependencies]`). It's the
  same manifest a project uses: a package is a package, so `lib/` can grow its own `proofs/` to
  prove itself.

A multi-file library can `require("lib.<sub>")` its own siblings placed next to `init.lua`.
