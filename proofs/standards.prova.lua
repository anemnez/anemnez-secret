-- The org's project standards, enforced here rather than remembered. See `prova-project-standards`.
--
-- Profiles are detected from what is on disk. A deliberate exception is a waiver with a reason, an
-- owner and an end, reported as a skip rather than vanishing; past its end it is red.

local standards = require("project-standards")

standards.check {
	except = {
		-- anemnez-secret is public by design (CLAUDE.md: MIT OR Apache-2.0, a public repo): products
		-- outside the Anemnez stack hold their key material with it, so it never takes the private
		-- licence. Waived, never fixed, as anemnez-extension is (E m/7103).
		["repo/license-file"] = {
			why = "public by design: MIT OR Apache-2.0 (LICENSE-MIT, LICENSE-APACHE), never the Anemnez licence",
			owner = "G",
			ends = "2027-11-10",
		},
		["cargo/license"] = {
			why = "public by design: the workspace licence is MIT OR Apache-2.0, never LicenseRef-Anemnez-Proprietary",
			owner = "G",
			ends = "2027-11-10",
		},
		-- The clock bans point at anemnez-clock's injected Clock, which is a private crate, and this one
		-- may depend on no private crate (CLAUDE.md). Two direct reads remain: retrust.rs's bounded poll
		-- and identity.rs's elapsed check. They move onto a clock this crate can take (anemnez-clock's
		-- pure face made public, or a caller-passed deadline) rather than onto a private copy.
		["cargo/clock-bans"] = {
			why = "anemnez-clock is private and this public crate takes no private dependency; retrust.rs and "
				.. "identity.rs still read Instant directly until a public clock face or a caller-passed deadline",
			owner = "I",
			ends = "2026-12-10",
		},
	},
}
