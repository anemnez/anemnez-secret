-- Quality gate: oversized source files do not multiply. A big file is where bugs hide and where
-- an agent loses the thread — but a retrofit cannot know which giants are legacy, so nothing here
-- hard-fails on day one. The COUNT of files past the limit is ratcheted: the ritual establishes
-- it wherever the project stands (existing giants become standing debt, not a wall of red),
-- growth past the floor is red, and every paydown is banked with --update-baseline.
--
-- The honest tradeoff vs a hard limit with a grandfather list: while the count is above zero, a
-- NEW giant appearing in the same run an old one is paid down can hide inside a flat count —
-- which is why every offender is named in the output below. Once the count reaches zero, this
-- ratchet IS the hard limit.
--
-- Layout-agnostic: the roots scanned come from `cargo metadata` (lib.src_roots), never from an
-- assumed directory shape — a single crate and a many-member workspace both answer correctly.

local lib = require("lib")

local LIMIT = 1500

-- wc -l semantics: count newlines, so the numbers match a plain `wc -l` and each other.
local function line_count(path)
	local _, n = fs.read(path):gsub("\n", "")
	return n
end

-- fs.glob's base is a concrete dir; "*.rs" catches files directly under it and "**/*.rs" the
-- nested ones. Globbing both and de-duping is robust regardless of whether "**" matches depth zero.
local function source_files(roots)
	local seen, out = {}, {}
	for _, root in ipairs(roots) do
		for _, pat in ipairs({ "*.rs", "**/*.rs" }) do
			for _, path in ipairs(fs.glob(root, pat)) do
				if not seen[path] then
					seen[path] = true
					out[#out + 1] = path
				end
			end
		end
	end
	return out
end

prova.test("oversized source files (> " .. LIMIT .. " lines) do not multiply past the baseline", {
	locks = { prova.reads("cargo") },
	switch = "quality",
	requires = { "cargo" },
}, function(t)
	local files = source_files(lib.src_roots(t:use(lib.metadata)))
	-- Vacuity guard: zero scanned files means the discovery broke, not that the project is clean.
	t:expect(#files, "no source files scanned — cargo metadata found no member src/ roots"):gt(0)

	local prefix = prova.root .. "/"
	local over = 0
	for _, path in ipairs(files) do
		local n = line_count(path)
		if n > LIMIT then
			over = over + 1
			local rel = path:sub(1, #prefix) == prefix and path:sub(#prefix + 1) or path
			print(string.format("  oversized  %-60s %6d lines", rel, n))
		end
	end
	measure.ratchet(t, "rust.files.oversized", over, { set = "quality" })
end)
