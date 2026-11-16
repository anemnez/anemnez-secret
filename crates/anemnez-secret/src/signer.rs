//! A product's own signing key on this host (`docs/specs/SECRET.md#a-signing-key-is-made-on-its-host-and-held-by-its-build`):
//! an Ed25519 key made on the host that uses it, kept in custody by the build that made it, and never
//! travelling (LADON §3: a key is identity). Moved here from Artichoke's role keyring (rule 2), so every
//! product that signs as itself holds its key one way (N m/15079, G m/15083).
//!
//! The service, the account and the requirement a build notes are the caller's data; only
//! `<signer>@<node id>` ([`account`]) is offered as the default shape. Built on [`custody`]: `made_by`, "an
//! Unavailable keychain never means make a new key" and the successor's hand-off are custody's and
//! [`handoff`]'s, one implementation each.

use std::fmt;

use ed25519_dalek::Signer as _;

use crate::Secret;
use crate::custody::{CustodyError, Item, Keychain};
use crate::handoff;

/// The default account shape: a signer's name and the node it is held for, so two hosts, or two
/// instances on one host, hold two keys.
pub fn account(signer: &str, node_id: &str) -> String {
    format!("{signer}@{node_id}")
}

/// A signing key held in custody. It never prints and nothing exports its bytes: it signs, and it hands
/// out its public half.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }

    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        self.0.sign(message)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey(public {})", hex(self.verifying_key().as_bytes()))
    }
}

/// How [`adopt`] came by the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adopted {
    /// Nothing was held, so it was made here, now.
    Made,
    /// This build's item was already there.
    Held,
    /// A hand-off to this build was cut short: its `.next` item was moved into place.
    Finished,
}

/// Why no key was adopted. It never names the key's value.
#[derive(Debug, PartialEq, Eq)]
pub enum SignerError {
    /// The keychain can't be read now (locked, or it refused without a dialog). Nothing is made in the
    /// key's place: try again later.
    Unavailable { item: Item, maker: Option<String>, this_build: String },
    /// The item is noted as another build's. A successor takes it by a hand-off (`retrust`), never by
    /// reading or replacing it.
    AnotherBuilds { item: Item, maker: Option<String>, this_build: String },
    /// The item holds something that isn't a 32-byte key.
    NotAKey(Item),
    /// The keychain failed in its own words.
    Store(String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let noted = |m: &Option<String>| m.clone().unwrap_or_else(|| "not noted".to_owned());
        match self {
            Self::Unavailable { item, maker, this_build } => write!(
                f,
                "{item} can't be read now, and no key is made in its place. It was made by: {}; this build is: {this_build}",
                noted(maker)
            ),
            Self::AnotherBuilds { item, maker, this_build } => write!(
                f,
                "{item} is another build's ({}); this build ({this_build}) takes it only by a hand-off",
                noted(maker)
            ),
            Self::NotAKey(item) => write!(f, "{item} doesn't hold a 32-byte key"),
            Self::Store(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for SignerError {}

/// What custody answered about the item, as [`step`] reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// The item is held. `ours`: its made-by note is this build's.
    Held { ours: bool },
    /// Nothing is held. `next`: a hand-off's `.next` item is.
    NotHeld { next: bool },
    /// The keychain can't be read now.
    Unavailable,
}

/// What [`adopt`] does next: the whole decision, pure (rule 1), so a key is made in exactly one case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Use,
    RefuseAnothers,
    FinishHandOff,
    Make,
    RefuseUnavailable,
}

/// The decision: use this build's held key, finish a hand-off, make one only when nothing is held and no
/// hand-off is pending, and otherwise refuse by name.
pub fn step(read: Read) -> Step {
    match read {
        Read::Held { ours: true } => Step::Use,
        Read::Held { ours: false } => Step::RefuseAnothers,
        Read::NotHeld { next: true } => Step::FinishHandOff,
        Read::NotHeld { next: false } => Step::Make,
        Read::Unavailable => Step::RefuseUnavailable,
    }
}

/// The key held under `item` by this build (`made_by`, its designated requirement), made here if none is
/// held. Never remade: a held key is read back, an Unavailable keychain is an error, and another build's
/// item is refused by name. The host of [`step`]: it reads custody, and does what `step` says.
pub fn adopt(keychain: &Keychain, item: &Item, made_by: &str) -> Result<(SigningKey, Adopted), SignerError> {
    let got = keychain.get(item);
    let read = match &got {
        Ok(_) => Read::Held { ours: keychain.maker(item).as_deref() == Some(made_by) },
        Err(CustodyError::NotHeld(_)) => Read::NotHeld { next: matches!(keychain.held(&item.next()), Ok(true)) },
        Err(CustodyError::Unavailable { .. }) => Read::Unavailable,
        Err(e) => return Err(SignerError::Store(e.to_string())),
    };
    match step(read) {
        Step::Use => match got {
            Ok(secret) => Ok((held_by(keychain, item, made_by, &secret)?, Adopted::Held)),
            Err(e) => Err(SignerError::Store(e.to_string())),
        },
        Step::RefuseAnothers => Err(SignerError::AnotherBuilds {
            item: item.clone(),
            maker: keychain.maker(item),
            this_build: made_by.to_owned(),
        }),
        Step::FinishHandOff => {
            handoff::finish(keychain, item, made_by).map_err(SignerError::Store)?;
            let secret = keychain.get(item).map_err(|e| unavailable(keychain, item, made_by, e))?;
            Ok((held_by(keychain, item, made_by, &secret)?, Adopted::Finished))
        }
        Step::Make => make(keychain, item, made_by),
        Step::RefuseUnavailable => Err(SignerError::Unavailable {
            item: item.clone(),
            maker: keychain.maker(item),
            this_build: made_by.to_owned(),
        }),
    }
}

fn make(keychain: &Keychain, item: &Item, made_by: &str) -> Result<(SigningKey, Adopted), SignerError> {
    let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let made = key.verifying_key();
    match keychain.add(item, &Secret::new(hex(&key.to_bytes()).into_bytes()), made_by) {
        Ok(()) => {}
        // Another process made it first: read its, never write over it.
        Err(CustodyError::Exists(_)) => {
            let secret = keychain.get(item).map_err(|e| unavailable(keychain, item, made_by, e))?;
            return Ok((held_by(keychain, item, made_by, &secret)?, Adopted::Held));
        }
        Err(e) => return Err(SignerError::Store(e.to_string())),
    }
    let back = keychain.get(item).map_err(|e| unavailable(keychain, item, made_by, e))?;
    let kept = parse(item, &back)?;
    if kept.verifying_key() != made {
        return Err(SignerError::Store(format!("{item} was written but reads back another key")));
    }
    Ok((kept, Adopted::Made))
}

/// This build's key from a held item: noted as made by this build, and a key.
fn held_by(keychain: &Keychain, item: &Item, made_by: &str, secret: &Secret) -> Result<SigningKey, SignerError> {
    let maker = keychain.maker(item);
    if maker.as_deref() != Some(made_by) {
        return Err(SignerError::AnotherBuilds { item: item.clone(), maker, this_build: made_by.to_owned() });
    }
    parse(item, secret)
}

fn unavailable(keychain: &Keychain, item: &Item, made_by: &str, e: CustodyError) -> SignerError {
    match e {
        CustodyError::Unavailable { .. } => {
            SignerError::Unavailable { item: item.clone(), maker: keychain.maker(item), this_build: made_by.to_owned() }
        }
        other => SignerError::Store(other.to_string()),
    }
}

/// The item's value: 64 hex digits, a trailing newline allowed (Artichoke's role items are written so).
fn parse(item: &Item, secret: &Secret) -> Result<SigningKey, SignerError> {
    secret.expose(|value| {
        let text = std::str::from_utf8(value).map_err(|_| SignerError::NotAKey(item.clone()))?.trim();
        let mut bytes = [0u8; 32];
        if text.len() != 64 {
            return Err(SignerError::NotAKey(item.clone()));
        }
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| SignerError::NotAKey(item.clone()))?;
        }
        Ok(SigningKey(ed25519_dalek::SigningKey::from_bytes(&bytes)))
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{Adopted, Read, SignerError, Step, account, adopt, step};
    use crate::Secret;
    use crate::custody::{Item, Keychain};
    use ed25519_dalek::Verifier as _;

    const ME: &str = "identifier \"ai.anemnez.exampled\" and anchor apple generic";
    const OTHER: &str = "identifier \"ai.anemnez.otherd\" and anchor apple generic";

    fn keychain() -> (tempfile::TempDir, Keychain, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("scratch");
        let path = dir.path().join("proof.keychain-db");
        let k = Keychain::create_at(&path, "proof-only").expect("a keychain of its own");
        (dir, k, path)
    }

    fn item(node: &str) -> Item {
        Item::new("ai.anemnez.example.signer", account("signer", node))
    }

    /// The whole decision, every case: a key is made in exactly one.
    #[test]
    fn a_key_is_made_only_when_nothing_is_held_and_no_hand_off_is_pending() {
        let table = [
            (Read::Held { ours: true }, Step::Use),
            (Read::Held { ours: false }, Step::RefuseAnothers),
            (Read::NotHeld { next: true }, Step::FinishHandOff),
            (Read::NotHeld { next: false }, Step::Make),
            (Read::Unavailable, Step::RefuseUnavailable),
        ];
        for (read, want) in table {
            assert_eq!(step(read), want, "{read:?}");
        }
    }

    #[test]
    fn a_key_is_made_once_then_adopted_never_remade() {
        let (_dir, k, _) = keychain();
        let (made, how) = adopt(&k, &item("node-a"), ME).expect("made");
        assert_eq!(how, Adopted::Made);
        let (again, how) = adopt(&k, &item("node-a"), ME).expect("held");
        assert_eq!(how, Adopted::Held);
        assert_eq!(again.verifying_key(), made.verifying_key(), "the same key, not a new one");
        let message = b"signed by the held key";
        assert!(made.verifying_key().verify(message, &again.sign(message)).is_ok());
    }

    #[test]
    fn an_unavailable_keychain_never_makes_a_key() {
        let (_dir, k, path) = keychain();
        let theirs = item("node-a");
        // Made by another code identity (/usr/bin/security), so this build reads it as Unavailable.
        let made = std::process::Command::new("/usr/bin/security")
            .args(["add-generic-password", "-s", &theirs.service, "-a", &theirs.account, "-w", "not-ours"])
            .arg(&path)
            .status()
            .expect("security");
        assert!(made.success());
        let got = adopt(&k, &theirs, ME);
        assert!(matches!(got, Err(SignerError::Unavailable { .. })), "{got:?}");
        assert!(k.held(&theirs).unwrap_or(false), "the item is still there");
        assert!(!k.held(&theirs.next()).unwrap_or(true), "and nothing was made beside it");
    }

    #[test]
    fn another_builds_item_is_refused_naming_it() {
        let (_dir, k, _) = keychain();
        let it = item("node-a");
        k.add(&it, &Secret::new(b"11".repeat(32)), OTHER).expect("another build's item");
        let got = adopt(&k, &it, ME);
        assert!(matches!(&got, Err(SignerError::AnotherBuilds { maker: Some(m), .. }) if m == OTHER), "{got:?}");
        let said = got.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(said.contains("ai.anemnez.otherd") && !said.contains("1111"), "{said}");
    }

    #[test]
    fn a_successor_finishes_a_hand_off_cut_short() {
        let (_dir, k, _) = keychain();
        let it = item("node-a");
        // What a hand-off leaves when it stops before its rename: the successor's own .next item.
        k.add(&it.next(), &Secret::new(b"22".repeat(32)), ME).expect("the handed-off item");
        let (key, how) = adopt(&k, &it, ME).expect("finished");
        assert_eq!(how, Adopted::Finished);
        assert!(k.held(&it).unwrap_or(false) && !k.held(&it.next()).unwrap_or(true), ".next moved into place");
        let (again, how) = adopt(&k, &it, ME).expect("held");
        assert_eq!((how, again.verifying_key()), (Adopted::Held, key.verifying_key()));
    }

    #[test]
    fn two_node_ids_hold_two_keys() {
        let (_dir, k, _) = keychain();
        let (a, _) = adopt(&k, &item("node-a"), ME).expect("a");
        let (b, _) = adopt(&k, &item("node-b"), ME).expect("b");
        assert_ne!(a.verifying_key(), b.verifying_key());
    }

    #[test]
    fn a_key_never_prints_its_value() {
        let (_dir, k, _) = keychain();
        let it = item("node-a");
        k.add(&it, &Secret::new(b"33".repeat(32)), ME).expect("held");
        let (key, _) = adopt(&k, &it, ME).expect("held");
        let said = format!("{key:?}");
        assert!(!said.contains("3333") && said.contains("public"), "{said}");
    }

    #[test]
    fn an_item_that_isnt_a_key_is_refused_by_name() {
        let (_dir, k, _) = keychain();
        let it = item("node-a");
        k.add(&it, &Secret::new(b"not hex".to_vec()), ME).expect("held");
        assert!(matches!(adopt(&k, &it, ME), Err(SignerError::NotAKey(_))));
    }
}
