-- Quality gate: production code does not sprout new .unwrap()/.expect() calls — both are latent
-- panics. Test code uses them freely (idiomatic), so we count only lib+bin targets via clippy's
-- restriction lints, which exclude tests, and ratchet the counts against the committed baseline in
-- .prova/baselines/quality.json (lower is better). No new ones allowed; removing them is welcome —
-- run `prova run quality --update-baseline` to tighten the floor once you have. The ritual
-- establishes the floors wherever the project stands: zero on a fresh tree, the honest count on a
-- legacy one — existing debt becomes ratcheted standing debt, not a wall of red.
--
-- To SCHEDULE a paydown, add a `goal` beside the metric's value in the baseline file
-- (`"goal": 15.0`): the ratchet then FAILS the run when the goal is reached, demanding you bank
-- the gain and retire or lower the goal — reaching a target is a decision point, never a silent
-- pass. It is how a standing count becomes a burndown with a deadline someone actually hits.
--
-- A panic that IS the design exits the census through a targeted #[allow(clippy::unwrap_used)] /
-- #[allow(clippy::expect_used)] on the item, carrying its argument in a comment — never a blanket
-- allow. Two shapes have earned it: a build-script panic is a build failure (exactly the right
-- outcome for a missing cargo-provided variable), and an invariant where panicking beats a silent
-- wrong result — the vacuous green this whole surface exists to prevent. The allow suppresses the
-- lint, so a documented exception never inflates the count you are ratcheting down: the floor
-- keeps measuring the debt, not the design.
--
-- HEAVY (recompiles with the restriction lints enabled): behind the `quality` switch, same as the
-- clippy wall. One clippy invocation feeds all three counts via a file-scoped fixture.

local restrict = prova.fixture("clippy_restrict", Scope.File, function()
	local r = shell.run(
		{ "cargo", "clippy", "--workspace", "--lib", "--bins", "--all-features", "--",
			"-W", "clippy::unwrap_used", "-W", "clippy::expect_used",
			"-W", "clippy::too_many_lines" },
		{ cwd = prova.root, merge_stderr = true }
	)
	return r.stdout or ""
end)

-- The count is clippy's own diagnostic tally for the lint (a stable, monotonic proxy for the site
-- count — more calls, higher number), which is exactly what a no-regression ratchet needs.
local function count(out, needle)
	local _, n = out:gsub(needle, "")
	return n
end

prova.test("production .unwrap() count does not regress past the baseline", { switch = "quality", locks = { prova.writes("cargo") } }, function(t)
	measure.ratchet(t, "rust.unwrap.production", count(t:use(restrict), "used `unwrap%(%)`"), { set = "quality" })
end)

prova.test("production .expect() count does not regress past the baseline", { switch = "quality", locks = { prova.writes("cargo") } }, function(t)
	measure.ratchet(t, "rust.expect.production", count(t:use(restrict), "used `expect%(%)`"), { set = "quality" })
end)

prova.test("oversized functions (clippy::too_many_lines) do not multiply past the baseline", { switch = "quality", locks = { prova.writes("cargo") } }, function(t)
	-- The file-size gate's sibling at function granularity (threshold in clippy.toml): the count of
	-- functions past the line limit is standing debt — ratcheted, paid down, never quietly grown.
	measure.ratchet(t, "rust.functions.too_long", count(t:use(restrict), "this function has too many lines"), { set = "quality" })
end)
