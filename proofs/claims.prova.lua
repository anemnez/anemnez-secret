-- docs/specs/SECRET.md: the claims no code speaks for yet, held as PROMISES so `prova owed` lists them
-- and a green run cannot pretend they are proven.

local SPEC = "docs/specs/SECRET.md#"

for _, owed in ipairs({
	{ "a-caller-is-known-by-its-code-signature", "identity moves here from fabric's step 0 writers.rs (J)" },
	{ "the-owner-is-proven-never-assumed", "the real check is one #[ignore] by-hand test; its users' tests (Ladon's policy) bind it" },
}) do
	prova.test("claim " .. owed[1] .. " — owed", {
		promises = owed[2],
		covers = SPEC .. owed[1],
	}, function(t)
		t:expect(false, owed[2]):is_true()
	end)
end
