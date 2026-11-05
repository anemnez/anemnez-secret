# Project packages

Each top-level directory here is a project-local package. They're discovered because the manifest
declares this directory as the packages directory (`packages = ".prova/packages"` in
`.prova/prova.toml`) — a proof then reaches one with `require("<dir-name>")`, no per-package entry
needed.

The retrofit ships one: [`lib/`](lib/), your project's shared library — it owns the
structure-discovery surface the quality gates stand on (`lib.metadata`, `lib.src_roots`) and the
black-box starters (`lib.build`, `lib.bin`). Add more as your suites grow. To pull in a
*published* package instead, declare it under `[dependencies]` in the manifest (a local path or a
pinned git source).
