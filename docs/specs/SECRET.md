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
- **`held` never reads the value**, only the item's attributes.
- **Tests never see a person's keychain**: they use a keychain file of their own.
- Next (from Artichoke's keyring, F): a hand-off that writes `<item>.next` before the original goes,
  every step idempotent; `made by: <designated requirement>` in the item's comment; and retrust to a
  successor build, the same team from configuration, any other team only through the owner check.

## 3. Identity: one place a code signature is judged

<!-- claim: a-caller-is-known-by-its-code-signature -->
**A caller is known by its code signature, judged in one place.** From an audit token
(`LOCAL_PEERTOKEN`), never a pid: `SecCodeCheckValidity` with `kSecCSStrictValidate`, then the
hardened runtime and none of `get-task-allow`, `disable-library-validation` or
`allow-dyld-environment-variables`, and only then the signing identifier and team, checked against a
trust table. The built-in entry ("team P9DJA3JCKP, `ai.anemnez.<p>d` owns `<p>`") is the table's
default data, overridable only by a person. Nothing else in any product writes these checks (J,
moving fabric's step 0 `writers.rs` here).

## 4. The owner is proven, never assumed

<!-- claim: the-owner-is-proven-never-assumed -->
**A person's decision passes the macOS owner check.** An agent can run any CLI, so "the owner" is
never a flag, a TTY or the user id. A grant (Ladon), a new host for a sealed secret (SEALING's
`extend`), a key handed to another team's build: each passes `LAContext`
`deviceOwnerAuthentication` (Touch ID or the login password), shown the change it approves. It sits
behind `OwnerCheck`, so tests stand in for it, and `Refuse` is the default wherever the real check is
not wired, so an unproven owner is refused, never trusted.
