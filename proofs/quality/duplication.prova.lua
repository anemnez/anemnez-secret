-- Quality gate: token-level code duplication does not multiply. `jscpd` (min-tokens 100, so only
-- the egregious copy-paste registers — idiomatic Rust repetition stays under the bar) scans the
-- production source and the clone COUNT is ratcheted, exactly like the unwrap census. Semantic
-- DRY ("two paths that do the same thing") has no detector; token clones are the honest ceiling.
--
-- `jscpd` is a world fact (requires — a box without it skips visibly; CI installs it); asking for
-- the quality class is intent (the switch). The dirs scanned come from `cargo metadata`
-- (lib.src_roots) — production source only, never target/ or vendored deps.

local lib = require("lib")

prova.test("token-level clone count does not regress past the baseline", {
	-- `cargo metadata` READS workspace state a build may rewrite: coexists with other
	-- readers, waits out any build in any instance (prova learn locks).
	locks = { prova.reads("cargo") },
	switch = "quality",
	requires = { "jscpd", "cargo" },
}, function(t)
	local roots = lib.src_roots(t:use(lib.metadata))
	t:expect(#roots, "no source roots to scan — cargo metadata found no members"):gt(0)

	local out = prova.root .. "/target/jscpd"
	fs.remove_all(out)
	local cmd = { "jscpd", "--min-tokens", "100", "--reporters", "json", "--output", out }
	for _, root in ipairs(roots) do
		cmd[#cmd + 1] = root
	end
	shell.run(cmd, { cwd = prova.root, merge_stderr = true, timeout = "300s" })
	local report = json.decode(fs.read(out .. "/jscpd-report.json"))
	local clones = report.statistics.total.clones
	t:expect(clones, "the report carries a clone total"):gte(0)
	measure.ratchet(t, "rust.duplication.clones", clones, { set = "quality" })
end)
