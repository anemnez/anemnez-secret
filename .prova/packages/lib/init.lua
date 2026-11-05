-- The project's shared library package. Anything reused across proof suites — helpers, shared
-- fixtures, topologies — lives here, and `require("lib")` reaches it from any proof.
--
-- The retrofit ships it with the structure-discovery surface the quality legs stand on: this
-- overlay carries NO preconceived notion of the project's layout, so everything that needs to
-- know the shape asks `cargo metadata` — the project's own account of itself — at runtime. A
-- single crate and a many-member workspace answer the same questions.

local lib = {}

--- `cargo metadata` for this workspace, decoded. Workspace members only (`--no-deps`), so the
--- packages listed are exactly the code this project owns.
lib.metadata = prova.fixture("cargo.metadata", Scope.File, function()
	local r = shell.run(
		{ "cargo", "metadata", "--no-deps", "--format-version", "1" },
		{ cwd = prova.root, timeout = "120s" }
	)
	if r.code ~= 0 then
		error("cargo metadata failed — is this a Rust project?\n" .. (r.stderr or ""))
	end
	return json.decode(r.stdout)
end)

--- The workspace members' source roots (absolute `…/src` dirs), derived from metadata rather
--- than assumed. This is what the file-size and duplication gates scan: production source,
--- never target/ or vendored deps.
---@param meta table a decoded `lib.metadata` value
---@return string[]
function lib.src_roots(meta)
	local roots, seen = {}, {}
	for _, pkg in ipairs(meta.packages or {}) do
		local dir = pkg.manifest_path:match("^(.*)/Cargo%.toml$")
		if dir then
			local root = dir .. "/src"
			if not seen[root] and fs.exists(root) then
				seen[root] = true
				roots[#roots + 1] = root
			end
		end
	end
	return roots
end

--- Build the workspace once per proof file that asks, so black-box proofs drive the SAME
--- artifacts a user would run. Grow this into your project's real boot surface (build + start
--- the service, hand back its address, defer the shutdown).
lib.build = prova.fixture("cargo.build", Scope.File, function()
	local r = shell.run(
		{ "cargo", "build", "--workspace" },
		{ cwd = prova.root, merge_stderr = true, timeout = "1800s" }
	)
	if r.code ~= 0 then
		error("cargo build failed:\n" .. (r.stdout or ""))
	end
end)

--- Path to a named binary in the debug target dir — pair with `t:use(lib.build)`, e.g.
--- `shell.run({ lib.bin("my-server"), "--port", "0" })`. Honors a relocated target dir via
--- metadata when you have it; the plain form covers the common case.
---@param name string the binary's name (a [[bin]] target)
---@return string
function lib.bin(name)
	return prova.root .. "/target/debug/" .. name
end

return lib
