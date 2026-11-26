# anemnez-secret

How a product on the Anemnez Stack holds its OWN key material: the keys that never travel (a role's
signing key, a host's sealing key, a product's own OAuth grant). Shared credentials, the ones a
person enters once for several hosts or products, are Ladon's, used by reference (ladon
`docs/specs/LADON.md`).

Part of the Anemnez SDK (fabric CONVERGENCE.md §0: "anemnez-* libraries form our SDK, and our
various products are implementations or users of them"). Owner G; D reviews as swarm architect.
MIT OR Apache-2.0. Released to Artichoke's cargo registry by Herald. No decision here names a
publisher (fabric ACCESS.md#no-decision-names-a-publisher): a team or identifier is data in a trust
table, never a constant in a decision.

## 1. A secret never prints

<!-- claim: a-secret-never-prints -->
**A secret's value never prints.** `Secret` is the only type that holds one. It is not `Clone` and
not `Serialize`, its `Debug` and `Display` print a fixed placeholder, and its bytes are overwritten
when it is dropped. The one way to read it is `expose`, lent to a closure at the edge that uses it.
A value that reaches a log line, an error, a status answer or a test failure says nothing.

## 2. Custody: a held key is read only by its owning build

<!-- claim: a-held-key-is-read-only-by-its-owning-build -->
**A product's key is kept in the login keychain, written by the product's own binary, so its access
list admits that binary's code signature and no other process reads it without a person.** An item
is named by a service and an account the product chooses (a per-instance account such as
`signer@<node id>`). A value never passes a command line: the Security framework is called directly.
- **Locked is not logged out.** A keychain that is locked or refuses without a dialog answers
  `Unavailable`, never `NotHeld`, so no caller makes a new key over an old one.
- **Never a dialog.** A `Keychain` is non-interactive by default: making one turns keychain dialogs off
  for the process, never to be turned on again, so an item whose access list doesn't admit the caller
  (another build's, the normal case after a signing change) answers `Unavailable` at once, never a
  prompt on the person's screen with a daemon blocked on it. `login_interactive` is the explicit
  opt-in, for a command a person runs at the Mac, never a daemon (F and D, 2026-11-06).
- **`held` never reads the value**, only the item's attributes.
- **Tests never see a person's keychain**: they use a keychain file of their own.
- **The maker is on the item.** `add` never overwrites, and writes `made by: <designated requirement>`
  in the item's comment, which `maker` reads back without the value, so a refusal after a signing
  change says whose item it is.
- **A signing change is carried across by the access list, never by an edit of it** (F m/37706, D m/37713).
  Editing an existing item's access list asks for the keychain's password, so an item gains a reader only
  by being written again, the hand-off way. `add_trusting(item, value, made_by, trusted, table)` writes it
  trusting exactly `trusted`, and nothing else, this binary included. Each requirement in `trusted` must be
  one `table` pins to a team it trusts: an Anemnez identifier, anchored at Apple, with the leaf's OU the
  team, compared as the framework prints it. A leaf CN (a member, not the team), another team, a cdhash, a
  path or a widened requirement is refused by name, with nothing written. A team build meets its team's
  requirement, so the build placed now, its successor and a rollback all read the item. `rename` gives the
  moved item the list of the one it moves, so a `.next` moved into place keeps every reader. `trusts` reads
  the list back without the value. The comment still names its maker alone, as today's readers expect.
  Two of the calls it needs, `SecTrustedApplicationCreateFromRequirement` and
  `SecTrustedApplicationCopyRequirement`, are exported by Security.framework but declared only in its private
  header. They are never linked: they are resolved at first use by `dlsym`, and a macOS that stops exporting
  either answers `Trusting::Unsupported`, named, from `add_trusting` and `trusts` alone. No product fails to
  load, and an ordinary adopt goes on by its note alone, today's rule (E m/37742, D m/37740). That is the
  weaker check: on such a macOS the planted-entry check below is off (E m/37772, F m/37773). It is said once
  at WARN when taken, so a host on that fallback is seen (D m/37770).

<!-- claim: a-hand-off-never-leaves-a-key-unheld -->
**A key carried across a signing change is held at every step** (from Artichoke's keyring, F). A
build under a new identity cannot read the old one's item, so the old build hands the value over:
the successor keeps it under `<item>.next` and proves it holds the same value, only then is the
original removed, and only then does `.next` take the item's name. A run cut short anywhere finishes
when run again. The proof is an HMAC-SHA-256 of the value under a fresh nonce the old build chose,
so it gives a guesser nothing to test a value against, even a short secret.

<!-- claim: a-key-goes-only-to-a-checked-successor -->
**A key goes only to a successor its holder has checked** (retrust; F's retrust, D's conditions). The
holder starts the successor binary as a child and listens on a socket in a fresh directory only it
can enter, named to the child in `ANEMNEZ_RETRUST_SOCKET`; the child connects. That connection's
audit token is the child's own, read at connect, so `identity` judges the code that answered. A
socketpair would not do: both its ends carry the token of the process that made it, the holder.
**Only the child it spawned is taken**: the connection's audit-token pid must be that child's (unreaped,
so the pid cannot be reused). A connection from any other process, however it is signed, is refused and
dropped while the holder keeps waiting, so an impostor can neither receive nor deny the hand-off; once
the child is connected, the socket is unlinked (D and F, 2026-11-06). The
successor must answer as the identifier the holder expects; one of the holder's OWN team is allowed as
configured, and one of any other team only through the owner check, which names the change. Only then
does the hand-off run over the connection. A product's binary that finds `ANEMNEZ_RETRUST_SOCKET` set
runs `retrust::serve` and nothing else.

<!-- claim: a-signing-key-is-made-on-its-host-and-held-by-its-build -->
**A product's own signing key is made on the host that uses it and held by the build that made it**
(`signer`; moved from Artichoke's role keyring by rule 2, N m/15079, G m/15083). A key is identity, so it
never travels (LADON §3). `signer::adopt(keychain, item, made_by)` answers the build's Ed25519 key:
- **Made once, never remade.** If nothing is held, it is made from the OS's entropy and added. A held
  item is read back, and a race to make one reads the winner's.
- **Unavailable never makes one.** A keychain that can't be read now is an error naming the item's maker
  and this build. That holds for a hand-off's `.next` item too: one that can't be read is never taken as
  no hand-off pending, so nothing is made beside a key that was handed off (F m/37654). Custody's `add`
  never overwrites, so nothing can be made over it either way.
- **Another build's item is refused by name.** An item is this build's when every entry on its access list
  is the house's, and its `made by:` names this build or its list trusts this build's requirement. The
  house's entries are exactly two kinds, compared as the framework prints a requirement: a requirement the
  trust table pins to its team, and this build's own designated requirement, which is the creator entry a
  plain `add` writes (D m/37751). One foreign entry is enough to refuse, whatever the note says: an item's
  creator is on its list by default and any process may add an item, so a list naming this build beside
  its planter is a key someone else holds (D m/37713, F m/37745). A list that trusts any application is
  foreign too, as is an entry whose requirement can't be read.
  The owner entry (who may change the list) must be empty, which means the person alone with the keychain
  password, as every item custody writes leaves it, or the house's. Every partition the item carries must
  be the house's: `teamid:<a team the trust table trusts>`, or `cdhash:<this binary's own>` only when this
  binary has no team. securityd stamps the real creator's partition on every item in the login keychain,
  and a planter can add a partition beside it but never remove it. So a planted item is refused even when
  it lists only us under our note with a value its planter chose (F m/37773, D m/37792). So is one made
  by `security add-generic-password` (`apple-tool:`); a person re-makes a key through the product's own
  verb. securityd stamps every item under the user's `Library/Keychains` (the login keychain's
  included) and nothing elsewhere, so whether a stamp is required follows where the keychain file lives,
  never how it was opened (D m/37833). Under `Library/Keychains` an item with no stamp is refused.
  Elsewhere none is required, but any stamp an item carries is judged. A keychain outside
  `Library/Keychains` has no creator stamp, so for custody it is test-only: today no product opens one,
  and every `create_at` and `open_at` caller is a row on a temporary directory (read by value,
  2026-11-26). A keychain path must be absolute, since a relative one is created in the person's own
  `Library/Keychains` (E m/37831). All of it is read
  on every read, so a list changed after adoption is refused at the next one. Any other item is refused,
  naming its maker. A successor takes a key only by a hand-off, and a hand-off cut short (its `.next` held,
  the item not) is finished by `handoff::finish`.
- **It never prints and never leaves.** The key signs and hands out its public half. Its `Debug` shows
  only the public half, and nothing exports its bytes.
- **A read never makes one.** `signer::held(keychain, item, made_by)` is `adopt` without its one write of a
  new key, for a product that reads its key each time it signs: nothing held and no hand-off pending answers
  `None`, and the caller reads what it held before custody or adopts. Every other case is `adopt`'s, by the same
  decision, a hand-off cut short finished included.
- The service, the account and the requirement are the caller's. `<signer>@<node id>` is the default
  account shape, so two hosts hold two keys.

<!-- claim: a-key-held-before-custody-is-adopted-never-reminted -->
**A key a product held before custody is adopted, never reminted** (D m/30267: on a live host, a role key that
silently changes breaks everything signed under it). `signer::adopt_existing(keychain, item, made_by, key)` takes
the key's 32 bytes (or 64 hex digits) through the same decision as `adopt`, and only its Make case differs: nothing
held, it writes that key, reads it back and compares, and never mints. This build's item already held must hold
that same key, and two different keys for one role are refused `role-key-forked`, naming neither. `signer::adopt_file`
orders the hand-off by what its readers trust (house node `durable.order`): the item is written and read back
first, and only then is the file renamed `<name>.adopted`, never deleted. So a crash leaves the file still
authoritative or the item verified equal to it, and the next run finishes. A file is adopted only when it is this
user's and owner-only, or it is refused `key-file-not-private` and left alone, so a key another process may have
read or written never becomes a build's identity. The kept copy has an end (E m/30362): `signer::retire_adopted`
removes it, called by the product once a later run reads the item as held and its adopting build is last-good. The
unlink is what ends the copy. It overwrites with zeros first only as best effort, since on APFS (copy-on-write) or an
SSD the zeros land on new blocks and the old ones stay until reused, so it's never a secure erase. The key's real
retirement is the custody item that replaced it, and the person's disk encryption (D m/30433). A key file is checked
and read on one handle opened without following a link, and a kept copy is written only when it's a regular file, so
a link in either place is refused, never followed (E m/30435). Which source a product reads first
(the item, a legacy item, the file) is its own migration reader's, and it mints with `adopt` only when every one is
absent, saying so by name.
- **The requirement has one read:** `identity::own_requirement()`, this build's designated requirement as
  `codesign -d -r-` prints it, read through the Security framework from the running code (strictly valid first),
  so no product runs `codesign` for its `made_by` or keeps its own copy of that read (rule 2; D m/24044).
- **The house's team has one runtime home:** `identity::ANEMNEZ_TEAM` (`TrustTable::house()` over it), so a build
  judging itself compares against our team, never the team its own signature names (circular; D m/24146). A by-hand
  row ties it to the team that signs a placed build.

## 3. Identity: one place a code signature is judged

<!-- claim: a-caller-is-known-by-its-code-signature -->
**A caller is known by its code signature, judged in one place.** From an audit token
(`LOCAL_PEERTOKEN`), never a pid: `SecCodeCheckValidity` with `kSecCSStrictValidate`, then the
hardened runtime and none of `get-task-allow`, `disable-library-validation` or
`allow-dyld-environment-variables`, and only then the signing identifier and team, checked against a
trust table. The built-in entry ("team P9DJA3JCKP, `ai.anemnez.<p>d` owns `<p>`") is the table's
default data, overridable only by a person. Nothing else in any product writes these checks (J,
moved from fabric's step 0 `writers.rs`).
- `identity::of_peer(socket)` gives a peer's [`Identity`] `{team, identifier}`, or why it has none. The
  requirement is `anchor apple generic` (any team; which teams count is the table's), validated before
  anything is read from the signature. A platform binary names no team, so it is no identity.
- `TrustTable` holds the rows: `Anemnez {team}`, under which `ai.anemnez.<p>` writes what product `<p>`
  owns (who owns what is the caller's to say), and `Scoped {team, identifier, segment}`, which a person
  adds for one other team's process and exactly one segment. `TrustTable::anemnez(team)` is the default
  data, and an empty table admits nobody. `admits(identity, segment, owner)` is the one decision.
- `identity::own()` is this process's identity by the same check (`SecCodeCopySelf`). A product builds its
  default table from it (`TrustTable::anemnez(&own()?.team)`, "my own team"), never from a config file
  another process could edit. Config may narrow a table, never widen it; widening is a person's act,
  through the owner check.
- A verdict vouches for the process that connected, at connect, not for whoever later holds the socket,
  so a product never passes its connection on.

<!-- claim: a-processs-code-identity-is-read-from-its-audit-token -->
**Any process's code identity is read from its audit token, by value** (K, G m/15989; for miniond's consent floor,
I m/15971). `identity::code_of_pid(pid)` takes the pid's audit token (`task_name_for_pid`, then
`TASK_AUDIT_TOKEN`), holds the token's own pid to the one asked, finds the running code by that token
(`kSecGuestAttributeAudit`, never the pid alone), and validates it with `kSecCSStrictValidate`, no flag loosened.
Only then does it read the signing identifier and decide the [`Signer`] by requirement, in one pure function
(`signer`): `Apple` for `anchor apple`, `Team(id)` for `anchor apple generic` with the team its signature names, and
`AdHoc` for anything else that is valid. Unlike `of_peer`, it judges no hardened runtime and trusts no team: it says
who signed a process, and the caller decides (a consent surface is refused, never admitted, by what it finds). A
process that is gone, isn't this user's to name, or isn't valid is Err, and a caller that guards with it refuses.
It blocks, as `of_peer` does. The identity carries the process it was read from (its `Token`: pid and pidversion,
from the same audit token), so a caller holds that same process from the read to its act (G m/16009).

## 4. The owner is proven, never assumed

<!-- claim: the-owner-is-proven-never-assumed -->
**A person's decision passes the macOS owner check.** An agent can run any CLI, so "the owner" is
never a flag, a TTY or the user id. A grant (Ladon), a new host for a sealed secret (SEALING's
`extend`), a key handed to another team's build: each passes `LAContext`
`deviceOwnerAuthentication` (Touch ID or the login password), shown the change it approves. It sits
behind `OwnerCheck`, so tests stand in for it, and `Refuse` is the default wherever the real check is
not wired, so an unproven owner is refused, never trusted.
