--- Coverage, ratcheted: `cargo llvm-cov nextest` rebuilds the workspace instrumented, runs every
--- unit test under it, and the line-coverage total is held to the committed baseline in
--- .prova/baselines/quality.json — a regression is red, and a new floor is raised deliberately via
--- `prova run coverage --update-baseline`.
---
--- This is the UNIT layer only. When your black-box proofs drive the binary hard enough to earn
--- it, graduate to the layered conduct prova itself runs — the suite through an instrumented
--- binary, unit + black-box reported alone AND merged, with the delta naming files that are
--- proven-black-box but unit-naked (the granular-unit-test worklist, computed rather than
--- guessed). See prova's proofs/coverage/coverage_test.lua for the exemplar.

prova.test("line coverage does not regress past the baseline", {
	locks = { prova.writes("cargo") },
	requires = { "cargo-llvm-cov", "cargo-nextest" },
}, function(t)
	-- One conduct: instrumented build + run, report as json on stdout (test progress on stderr).
	local r = shell.run(
		{ "cargo", "llvm-cov", "nextest", "--workspace", "--json", "--summary-only" },
		{ cwd = prova.root, timeout = "1800s" }
	)
	t:expect(r.code, "cargo llvm-cov failed:\n" .. (r.stderr or "")):equals(0)
	local report = json.decode(r.stdout or "{}")
	measure.ratchet(t, "rust.coverage.lines", report.data[1].totals.lines.percent, {
		set = "quality", direction = "higher_is_better",
	})
end)
