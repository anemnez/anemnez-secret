--- The deputed unit-test leg: `prova run ut` conducts cargo nextest ONCE for the whole workspace —
--- compilation and execution both live in a file-scoped fixture that emits one junit artifact —
--- then one proof adopts every case into the account, and sibling readers can bind claims to
--- named cases at zero additional compilations (conduct once, read many).
---
--- The `ut` switch (suite.lua) is intent; `cargo-nextest` stays a `requires` world fact: two facts
--- with two remedies. The profile `must_run`s the deputy, so `prova run ut` fails rather than
--- skips when nextest is missing — a profile is a contract, not a courtesy.
---
--- A workspace with ZERO unit tests reads RED here, deliberately: `prova run ut` asked for the
--- unit-test account and there is none to adopt. On a legacy project that has never written unit
--- tests, that red is the leg telling you where to start — not a gate to weaken.

-- Conduct the deputy once. The stale artifact is removed FIRST, so a deputy that dies before
-- emitting (a compile error) leaves nothing behind and the adoption fails loudly on "matched
-- nothing" — never a previous run's verdicts wearing this run's face. The deputy's exit code is
-- deliberately not asserted here: the adopting proof reports red with the deputed cases' own
-- names, which a fixture death would hide.
-- The `prova` profile (junit emission, fail-fast off) ships in .prova/nextest.toml and reaches
-- nextest as TOOL config — composing under, never colliding with, the project's own
-- .config/nextest.toml. A repo-defined [profile.prova] would win, deliberately.
local deputy = prova.fixture("nextest-junit", Scope.File, function()
	local artifact = prova.root .. "/target/nextest/prova/junit.xml"
	fs.remove_all(artifact)
	shell.run(
		{ "cargo", "nextest", "run", "--workspace", "--profile", "prova",
			"--tool-config-file", "prova:" .. prova.root .. "/.prova/nextest.toml" },
		{ cwd = prova.root, merge_stderr = true, timeout = "1800s" }
	)
	return artifact
end)

prova.test("the workspace's unit-test account holds — every nextest case adopted", {
	requires = { "cargo-nextest" },
	-- The house rule, framework-enforced (prova learn locks): cargo takes process-wide locks
	-- of its own, so every conduct that compiles declares the writer hold — bound across every
	-- prova instance at this home, so two agents and a human never race a build.
	locks = { prova.writes("cargo") },
}, function(t)
	junit.verify(t, { results = t:use(deputy) })
end)

-- Readers: one claim, one named unit test — a prose claim discharged by a specific case in the
-- deputy's own account, without a second run. As claims accrete, bind them like this:
--
--   prova.test("the parser rejects unterminated input, spoken for by its unit test", {
--   	requires = { "cargo-nextest" },
--   }, function(t)
--   	local report = junit.load(t:use(deputy))
--   	for _, c in ipairs(report.cases) do
--   		if c.name == "parser::tests::rejects_unterminated_input" then
--   			t:expect(c.outcome, c.name):equals("passed")
--   			return
--   		end
--   	end
--   	t:expect(false, "parser::tests::rejects_unterminated_input is missing from the account"):is_true()
--   end)

-- docs/specs/SECRET.md: each claim the unit tests discharge, by the named cases that speak for it. A
-- case missing from the account is red, never a skip, so a renamed test cannot orphan its claim.
local function spoken_for(claim, cases)
	prova.test("claim " .. claim .. " — spoken for by its unit tests", {
		requires = { "cargo-nextest" },
		covers = "docs/specs/SECRET.md#" .. claim,
	}, function(t)
		local report = junit.load(t:use(deputy))
		local seen = {}
		for _, c in ipairs(report.cases) do
			for _, wanted in ipairs(cases) do
				if c.name == wanted or c.name:sub(-#wanted - 2) == "::" .. wanted then
					seen[wanted] = true
					t:expect(c.outcome, c.name):equals("passed")
				end
			end
		end
		for _, wanted in ipairs(cases) do
			t:expect(seen[wanted] == true, wanted .. " is missing from the account"):is_true()
		end
	end)
end

spoken_for("a-secret-never-prints", { "secret::tests::a_secret_printed_any_way_says_nothing" })
spoken_for("a-caller-is-known-by-its-code-signature", {
	"identity::tests::only_a_hardened_untamperable_signature_is_an_identity",
	"identity::tests::the_trust_table_admits_an_owner_and_a_scoped_entry_and_nothing_else",
	"identity::tests::a_running_codes_signature_is_read_only_after_it_is_validated",
	"identity::tests::a_peers_audit_token_finds_its_code_and_an_ad_hoc_peer_is_no_identity",
	"identity::tests::a_process_knows_its_own_identity_by_the_same_check",
})
spoken_for("a-held-key-is-read-only-by-its-owning-build", {
	"custody::tests::an_item_holds_what_was_put_under_it",
	"custody::tests::errors_never_say_the_value_and_locked_is_not_not_held",
})
spoken_for("a-hand-off-never-leaves-a-key-unheld", {
	"handoff::tests::a_hand_off_moves_the_value_and_finishes_after_a_cut",
	"handoff::tests::a_successor_that_cannot_prove_the_value_leaves_the_original",
	"handoff::tests::finish_settles_every_state_it_finds",
})
spoken_for("a-key-goes-only-to-a-checked-successor", {
	"retrust::tests::a_successor_is_allowed_by_identifier_then_team_then_the_owner",
	"retrust::tests::a_key_moves_to_a_checked_child_and_never_to_another",
	"retrust::tests::only_the_spawned_childs_connection_is_taken",
})
