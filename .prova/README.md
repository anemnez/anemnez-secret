# The quality surface

This project's quality gating is driven through [prova](https://github.com/prova-rs/prova):
black-box proofs of behavior plus ratcheted quality gates, one runner, one exit code — the same
command locally and in CI. This directory is the nook: prova's own files, out of the project's way.

## The bar

```bash
prova                    # build smoke + the project's black-box proofs — the inner loop
prova --last-failed      # re-run only what's red
prova run quality        # clippy -D warnings, unwrap/expect census, duplication, file sizes
prova run ut             # unit tests, conducted once via cargo nextest, adopted into the account
prova run coverage       # line coverage, ratcheted against the committed baseline
prova run all            # the pre-push sweep: proofs + ut + quality, one exit code
```

Proofs live in `proofs/` at the project root (`*.prova.lua` — Lua, black-box, through the built
artifacts via `lib.build` / `lib.bin("<name>")`). The manifest and its profile surface live in
`prova.toml` here; shared proof code lives in `packages/lib/`.

## First-run ritual (once)

The ratchets — unwrap/expect counts, oversized files, duplication, coverage — refuse to pass
without a committed floor. Establish the floors, then commit `baselines/quality.json` with the
code:

```bash
prova run quality --update-baseline
prova run coverage --update-baseline
```

The establishing pass reports red while it writes the floors (a metric with no floor passes
nothing — the refusal to green-wash); the run after it is the green ratchet. On a legacy codebase
the floors land wherever the project stands: existing debt becomes ratcheted standing debt, not a
wall of red — and every paydown is banked by re-running with `--update-baseline` (which refuses
to loosen).

## How the gates stay honest

- **Ratchets, not thresholds** — every metric is held to the committed baseline, so quality only
  moves one way. Tightening is a normal commit; loosening is a hand edit you have to own in review.
- **Layout-agnostic** — the gates read the project's structure from `cargo metadata` at runtime
  (`packages/lib/init.lua`), never from an assumed directory shape.
- **Switches, not env vars** — the heavy legs (`quality`, `ut`, `coverage`) recompile the
  workspace, so they never run because someone typed `prova`. Profiles throw the switches;
  `prova -s <class>` is the ad-hoc door.
- **`requires` vs `must_run`** — a missing tool skips a test on your laptop (visibly), but FAILS
  the profile that promised it in CI. A box that lost its toolchain can never green-wash a run.
- **Conduct once, read many** — `prova run ut` compiles and runs the unit tests exactly once
  (the junit-emitting profile ships in `nextest.toml` here, handed to nextest as tool config so
  it never collides with the project's own `.config/nextest.toml`), then any number of proofs
  bind prose claims to named cases from the account.

CI (`.github/workflows/`) runs the same profiles via
[`prova-rs/run-action`](https://github.com/prova-rs/run-action) — there is no separate CI command
to keep in step with the local one.
