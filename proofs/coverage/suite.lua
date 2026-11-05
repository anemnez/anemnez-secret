-- The coverage leg is one opt-in class: conducting `cargo llvm-cov nextest` rebuilds the workspace
-- instrumented and runs every unit test under it, so it must never fire because a person typed
-- `prova`. The `coverage` profile throws it; `-s coverage` is the ad-hoc door.
suite.config { switch = "coverage" }
