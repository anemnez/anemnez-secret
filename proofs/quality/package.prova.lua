-- Quality gate: the crate is always publishable.
--
-- anemnez-secret is published to Artichoke's Cargo registry (`publish = ["artichoke"]`), and its
-- consumers build from that published `.crate`, not from this checkout. So the gate builds the
-- crate exactly as a consumer receives it: `cargo package` packs the files Cargo would upload, then
-- compiles them on their own. A file the build needs but the package leaves out, a path dependency
-- without a version, or a manifest field the registry refuses is red here, never at publish time.
--
-- Nothing is uploaded. Publishing is the release's job, after a green gate.

local packaged = prova.fixture("cargo_package", Scope.File, function()
	return shell.run(
		{ "cargo", "package", "-p", "anemnez-secret", "--allow-dirty" },
		{ cwd = prova.root, merge_stderr = true, timeout = "900s" }
	)
end)

prova.test("the crate packages and builds from its package alone", {
	requires = { "cargo" },
	switch = "quality",
	locks = { prova.writes("cargo") },
}, function(t)
	local r = t:use(packaged)
	local out = r.stdout or ""
	t:expect(r.code, "cargo package failed:\n" .. out):equals(0)
	t:expect(out:find("Packaged", 1, true), "cargo package reported no package:\n" .. out):never():is_nil()
	t:expect(out:find("Verifying", 1, true), "the package was not built on its own:\n" .. out):never():is_nil()
end)
