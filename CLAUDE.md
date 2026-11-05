# CLAUDE.md

anemnez-secret: how a product on the Anemnez Stack holds its own key material (MIT OR Apache-2.0, a
public repo). Read `docs/specs/SECRET.md` first. Owner G; D reviews as swarm architect.

- **No platform in it** beyond macOS's own frameworks: nothing here may depend on Fabric, the swarm or
  any private crate.
- **No decision names a publisher** (fabric ACCESS.md#no-decision-names-a-publisher): a team or an
  identifier is trust-table data, never a constant in a decision.
- **Tests never touch a person's keychain**: a keychain file of the test's own; the real owner check is
  one `#[ignore]` test, run by hand.
- **Proofs:** `prova`, `prova run ut`, `prova run quality`, `prova run all`.
- **Releasing is Herald's**, to Artichoke only for now. Land by train; never publish by hand.
- VCS is jj; never git.
