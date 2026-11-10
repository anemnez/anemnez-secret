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
- `identity::process(pid)` reads one process (pid, unique id, the parent's unique id as the kernel
  recorded it at fork, pidversion), and `tree_of(pid)` / `tree_of_peer(socket)` its ancestors by unique
  id, each link believed only when it is the recorded parent, so from the second link up a reused pid
  never joins. The first link of `tree_of_peer` is whoever holds the socket's peer pid now, a stated
  limit. The one home for a process tree (D's census; moved from Agora's place.rs).

## 4. The owner is proven, never assumed

<!-- claim: the-owner-is-proven-never-assumed -->
**A person's decision passes the macOS owner check.** An agent can run any CLI, so "the owner" is
never a flag, a TTY or the user id. A grant (Ladon), a new host for a sealed secret (SEALING's
`extend`), a key handed to another team's build: each passes `LAContext`
`deviceOwnerAuthentication` (Touch ID or the login password), shown the change it approves. It sits
behind `OwnerCheck`, so tests stand in for it, and `Refuse` is the default wherever the real check is
not wired, so an unproven owner is refused, never trusted.
