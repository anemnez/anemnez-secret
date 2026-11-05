-- anemnez-secret is a library: it has no binary to drive, so its claims (docs/specs/SECRET.md) are
-- spoken for by named unit tests (proofs/ut/nextest.prova.lua) and the owed ones are promises
-- (proofs/claims.prova.lua). This suite keeps the one true black-box fact: the workspace builds.
--
-- The retrofit knows nothing about what this project DOES, so it does not pretend to prove any
-- behavior. What it can prove today is that the artifacts exist to be driven; what the project
-- owes is stated as a PROMISE — an executable spec that reports as its own outcome (PROMISED,
-- green in CI, visible in `prova owed`) until a real body proves it, at which point it demands
-- graduation. Replace the promise with proofs that drive what this project actually does:
-- black-box, through the built artifacts (`lib.build` + `lib.bin("<name>")`), never through
-- the internals.

local lib = require("lib") -- the project's shared library package (.prova/packages/lib)

prova.test("the workspace builds — the artifacts black-box proofs drive exist", {
	requires = { "cargo" },
	locks = { prova.writes("cargo") },
}, function(t)
	t:use(lib.build)
end)
