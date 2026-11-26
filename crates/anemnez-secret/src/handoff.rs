//! Carrying a held key across a signing change (`docs/specs/SECRET.md#a-hand-off-never-leaves-a-key-unheld`),
//! from Artichoke's keyring (F, 2026-11-05). A keychain item admits the build that made it; a build under
//! a new identity cannot read it. So the old build hands the value to the new one, and some item always
//! holds it:
//!
//! 1. the successor keeps the value under `<item>.next` and proves it read back the same value;
//! 2. only then does the old build remove its original;
//! 3. the successor moves `.next` to the item.
//!
//! Every step is idempotent: a hand-off cut short at any point finishes when it is run again. The
//! successor proves what it kept with an HMAC-SHA-256 of the value under a fresh nonce the old build
//! chose, so the proof says nothing a guesser could test a value against, even for a short secret.

use sha2::{Digest, Sha256};

use crate::Secret;
use crate::custody::{Confirm, Confirmed, CustodyError, Item, Keychain, Moved};

/// A successor's proof that it holds a value: HMAC-SHA-256(nonce, value).
pub type Witness = [u8; 32];

/// HMAC-SHA-256 (RFC 2104), written on SHA-256 directly: no fallible key setup.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| k.map(|b| b ^ byte);
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(message).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

/// Whether `got` is the expected proof, compared in constant time; a proof of another length is refused.
pub fn verify(expected: &Witness, got: &[u8]) -> bool {
    if got.len() != expected.len() {
        return false;
    }
    expected.iter().zip(got).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// The proof of `value` under `nonce`.
pub fn witness(value: &Secret, nonce: &[u8; 32]) -> Witness {
    value.expose(|v| hmac_sha256(nonce, v))
}

/// A fresh nonce, from the OS.
fn nonce() -> Result<[u8; 32], String> {
    use std::io::Read;
    let mut n = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut n))
        .map_err(|e| format!("no randomness for the hand-off: {e}"))?;
    Ok(n)
}

/// Why a hand-off didn't end with `.next` gone: kept by design, or failed. A caller matches the value, never a phrase
/// (F m/38787, rule 15).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandOffError {
    /// `hand-off-kept`: the item is written and `.next` kept beside it, since no reader other than the writer read
    /// it (D m/38588). Nothing is lost: the placed build's `signer::held_confirmed` finishes it. `why` says so whole.
    Kept { item: Item, why: String },
    /// It failed, in words: nothing that was held is lost.
    Failed(String),
}

impl std::fmt::Display for HandOffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kept { why, .. } | Self::Failed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for HandOffError {}

impl From<String> for HandOffError {
    fn from(why: String) -> Self {
        Self::Failed(why)
    }
}

impl From<HandOffError> for String {
    fn from(e: HandOffError) -> Self {
        e.to_string()
    }
}

/// The build a value is handed to: in use, the new binary as a checked child process (its identity
/// judged by its connection's audit token, `identity`), and a stand-in in tests.
pub trait Successor {
    /// Keep `value` under `<item>.next` and prove it read it back. The proof arrives as bytes (over
    /// the successor's connection, in use), checked by [`verify`].
    fn receive(&mut self, value: &Secret, nonce: &[u8; 32]) -> Result<Vec<u8>, String>;
    /// Move `.next` to the item, once the original is gone.
    ///
    /// # Errors
    /// [`HandOffError::Kept`] when it is written and `.next` kept; [`HandOffError::Failed`] otherwise.
    fn finish(&mut self) -> Result<(), HandOffError>;
}

/// The old build's side: hand `item`'s value to `successor`, removing the original only after the
/// successor has proved it holds the same value. Run again after a cut, it finishes.
///
/// # Errors
/// [`HandOffError::Kept`] when the successor wrote the item and kept `.next`; [`HandOffError::Failed`] otherwise.
pub fn hand_off(keychain: &Keychain, item: &Item, successor: &mut dyn Successor) -> Result<(), HandOffError> {
    match keychain.get(item) {
        Ok(value) => {
            let nonce = nonce()?;
            let theirs = successor.receive(&value, &nonce)?;
            if !verify(&witness(&value, &nonce), &theirs) {
                return Err(HandOffError::Failed(format!(
                    "the successor kept another value under {}; the original is left as it is",
                    item.next()
                )));
            }
            keychain.remove(item).map_err(|e| e.to_string())?;
        }
        // Removed on an earlier run that was cut short: the successor's .next holds it.
        Err(CustodyError::NotHeld(_)) => {}
        Err(e) => return Err(HandOffError::Failed(e.to_string())),
    }
    successor.finish()
}

/// The successor's side, receiving: keep `value` under `<item>.next` (or find it already there), read
/// it back, and prove what it holds.
pub fn receive(
    keychain: &Keychain,
    item: &Item,
    value: &Secret,
    nonce: &[u8; 32],
    made_by: &str,
) -> Result<Witness, String> {
    let next = item.next();
    match keychain.add(&next, value, made_by) {
        Ok(()) | Err(CustodyError::Exists(_)) => {}
        Err(e) => return Err(e.to_string()),
    }
    let kept = keychain.get(&next).map_err(|e| e.to_string())?;
    Ok(witness(&kept, nonce))
}

/// The successor's side, finishing with no other reader: once the original is gone, write the item from `.next` and
/// keep `.next` beside it, an error saying `hand-off-kept` (D m/38588). This process wrote `.next`, so its own read-back
/// proves nothing about the build that reads the item next (MB16's path); only [`finish_confirmed`], on another
/// reader's word, removes `.next`. `retrust::serve` finishes so: the item it read from is never removed.
///
/// # Errors
/// [`HandOffError::Kept`] for a move kept beside its `.next`; [`finish_confirmed`]'s failures as
/// [`HandOffError::Failed`].
pub fn finish(keychain: &Keychain, item: &Item, made_by: &str) -> Result<(), HandOffError> {
    match finish_confirmed(keychain, item, made_by, &NoOtherReader)? {
        Finished::Done => Ok(()),
        Finished::Kept(why) => Err(HandOffError::Kept { item: item.clone(), why }),
    }
}

/// No reader but this writer: never confirms, so `.next` is kept.
struct NoOtherReader;

impl Confirm for NoOtherReader {
    fn confirms(&self, _: &Item, _: &Secret) -> Confirmed {
        Confirmed::Unclear(
            "no reader but its writer; finish it by signer::held_confirmed, the placed build run fresh".into(),
        )
    }
}

/// What [`finish_confirmed`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finished {
    /// The item holds the value, read by `confirm`'s reader, and `.next` is gone (or there was nothing to move).
    Done,
    /// The item holds the value, but `confirm`'s reader didn't read it, so `.next` is kept beside it: why, by name.
    Kept(String),
}

/// [`finish`], with `.next` removed only once `confirm`, a reader other than this writer (the placed build, run
/// fresh), reads the item (D m/38565). Short of that, both are kept, [`Finished::Kept`].
///
/// # Errors
/// Both held with different values, neither held, an original this build can't read, or the store's.
pub fn finish_confirmed(
    keychain: &Keychain,
    item: &Item,
    made_by: &str,
    confirm: &dyn Confirm,
) -> Result<Finished, String> {
    let next = item.next();
    let kept = |why: String| format!("hand-off-kept: {item} is written, and {next} is kept beside it: {why}");
    match (keychain.get(item), keychain.get(&next)) {
        (Err(CustodyError::NotHeld(_)), Ok(_)) => match keychain.rename_confirmed(&next, item, made_by, confirm) {
            Ok(Moved::Moved) => Ok(Finished::Done),
            Ok(Moved::Kept(why)) => Ok(Finished::Kept(kept(why))),
            Err(e) => Err(e.to_string()),
        },
        (Ok(_), Err(CustodyError::NotHeld(_))) => Ok(Finished::Done),
        // A rename cut short after its write: both hold the same value, so .next goes once the other reader reads
        // the item.
        (Ok(a), Ok(b)) if a.expose(|x| b.expose(|y| x == y)) => match confirm.confirms(item, &a) {
            Confirmed::Reads => keychain.remove(&next).map(|()| Finished::Done).map_err(|e| e.to_string()),
            Confirmed::Cannot(why) | Confirmed::Unclear(why) => Ok(Finished::Kept(kept(why))),
        },
        (Ok(_), Ok(_)) => Err(format!("{item} and {} hold different values; nothing is changed", next)),
        (Err(CustodyError::NotHeld(_)), Err(CustodyError::NotHeld(_))) => {
            Err(format!("neither {item} nor {next} is held"))
        }
        (Err(e), _) => Err(format!(
            "the original {item} is not this build's to read ({e}); hand it off from the build that made it"
        )),
        (_, Err(e)) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{Successor, finish, hand_off, receive, witness};
    use crate::Secret;
    use crate::custody::{Item, Keychain};

    const VALUE: &str = "role-key-seed-ZZZtopSECRET";
    const NEW: &str = "identifier \"ai.anemnez.exampled\"";

    fn keychain() -> (tempfile::TempDir, Keychain) {
        let dir = tempfile::tempdir().expect("scratch");
        let k =
            Keychain::create_at(&dir.path().join("proof.keychain-db"), "proof-only").expect("a keychain of its own");
        (dir, k)
    }

    /// A successor in this process, on the same keychain; `cut` stops it after receiving, as a crash would.
    struct Local<'a> {
        keychain: &'a Keychain,
        item: Item,
        cut: bool,
        lie: bool,
        short: bool,
    }

    impl Successor for Local<'_> {
        fn receive(&mut self, value: &Secret, nonce: &[u8; 32]) -> Result<Vec<u8>, String> {
            let w = receive(self.keychain, &self.item, value, nonce, NEW)?;
            if self.short {
                return Ok(w[..16].to_vec());
            }
            Ok(if self.lie { witness(&Secret::new(b"another".to_vec()), nonce) } else { w }.to_vec())
        }
        fn finish(&mut self) -> Result<(), super::HandOffError> {
            if self.cut {
                return Err(super::HandOffError::Failed("cut short".into()));
            }
            // The placed build, run fresh, read it: the carry's finish.
            match super::finish_confirmed(self.keychain, &self.item, NEW, &Says(crate::custody::Confirmed::Reads))? {
                super::Finished::Done => Ok(()),
                super::Finished::Kept(why) => Err(super::HandOffError::Kept { item: self.item.clone(), why }),
            }
        }
    }

    fn held(k: &Keychain, item: &Item) -> Option<Vec<u8>> {
        k.get(item).ok().map(|s| s.expose(|v| v.to_vec()))
    }

    /// `SECRET.md#a-hand-off-never-leaves-a-key-unheld`: the value ends under the item, made by the new
    /// build; a run cut short after the original went finishes when run again; and at every step some
    /// item held the value.
    #[test]
    fn a_hand_off_moves_the_value_and_finishes_after_a_cut() {
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example.role", "promoter@node");
        k.add(&item, &Secret::new(VALUE.into()), "identifier \"ai.anemnez.example\"").unwrap();
        assert_eq!(k.maker(&item).as_deref(), Some("identifier \"ai.anemnez.example\""), "made by, without the value");

        let mut cut = Local { keychain: &k, item: item.clone(), cut: true, lie: false, short: false };
        assert!(hand_off(&k, &item, &mut cut).is_err(), "cut short after the original went");
        assert!(
            held(&k, &item).is_none() && held(&k, &item.next()).as_deref() == Some(VALUE.as_bytes()),
            ".next holds it"
        );

        let mut again = Local { keychain: &k, item: item.clone(), cut: false, lie: false, short: false };
        hand_off(&k, &item, &mut again).expect("run again, it finishes");
        assert_eq!(held(&k, &item).as_deref(), Some(VALUE.as_bytes()));
        assert!(held(&k, &item.next()).is_none(), "no .next left");
        assert_eq!(k.maker(&item).as_deref(), Some(NEW), "the item is the new build's now");
        hand_off(&k, &item, &mut again).expect("and again: idempotent");
        assert_eq!(held(&k, &item).as_deref(), Some(VALUE.as_bytes()));
    }

    /// A proof of the wrong length is refused, and the original stays (D, 2026-11-06).
    #[test]
    fn a_proof_of_the_wrong_length_is_refused() {
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example.role", "short@node");
        k.add(&item, &Secret::new(VALUE.into()), "old").unwrap();
        let mut short = Local { keychain: &k, item: item.clone(), cut: false, lie: false, short: true };
        assert!(hand_off(&k, &item, &mut short).unwrap_err().to_string().contains("left as it is"));
        assert_eq!(held(&k, &item).as_deref(), Some(VALUE.as_bytes()), "the original stays");
        let w = witness(&Secret::new(VALUE.into()), &[7u8; 32]);
        assert!(super::verify(&w, &w) && !super::verify(&w, &w[..31]) && !super::verify(&w, &[0u8; 33]));
    }

    /// A successor that cannot prove it holds the same value never gets the original removed.
    #[test]
    fn a_successor_that_cannot_prove_the_value_leaves_the_original() {
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example.role", "feed@node");
        k.add(&item, &Secret::new(VALUE.into()), "old").unwrap();
        let mut liar = Local { keychain: &k, item: item.clone(), cut: false, lie: true, short: false };
        let refused = hand_off(&k, &item, &mut liar).unwrap_err().to_string();
        assert!(refused.contains("left as it is"), "{refused}");
        assert!(!refused.contains("ZZZtop"), "{refused}");
        assert_eq!(held(&k, &item).as_deref(), Some(VALUE.as_bytes()), "the original stays");
    }

    /// finish() is safe at every state it can find: both held and equal (a rename cut after its write)
    /// keeps `.next` until another reader reads the item, then cleans up; both held and different changes nothing; neither held says so; add never overwrites.
    #[test]
    fn finish_settles_every_state_it_finds() {
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example.role", "x");
        k.add(&item, &Secret::new(VALUE.into()), "old").unwrap();
        k.add(&item.next(), &Secret::new(VALUE.into()), NEW).unwrap();
        let kept = finish(&k, &item, NEW).unwrap_err();
        assert!(matches!(&kept, super::HandOffError::Kept { item: i, .. } if *i == item), "kept, by value: {kept:?}");
        assert!(kept.to_string().starts_with("hand-off-kept"), "and said by name");
        assert!(held(&k, &item.next()).is_some());
        let read = Says(crate::custody::Confirmed::Reads);
        assert_eq!(super::finish_confirmed(&k, &item, NEW, &read), Ok(super::Finished::Done), "read fresh: .next goes");
        assert!(held(&k, &item.next()).is_none());
        k.add(&item.next(), &Secret::new(b"different".to_vec()), NEW).unwrap();
        let differ = finish(&k, &item, NEW).unwrap_err();
        assert!(matches!(&differ, super::HandOffError::Failed(why) if why.contains("different values")), "{differ:?}");
        assert_eq!(held(&k, &item).as_deref(), Some(VALUE.as_bytes()), "nothing changed");
        assert!(matches!(
            k.add(&item, &Secret::new(b"over".to_vec()), NEW),
            Err(crate::custody::CustodyError::Exists(_))
        ));
        let none = Item::new("ai.anemnez.example.role", "absent");
        assert!(finish(&k, &none, NEW).unwrap_err().to_string().contains("neither"));
    }

    /// A stand-in for the placed build run fresh: it answers what it's told.
    struct Says(crate::custody::Confirmed);
    impl crate::custody::Confirm for Says {
        fn confirms(&self, _: &Item, _: &Secret) -> crate::custody::Confirmed {
            self.0.clone()
        }
    }

    /// The carry's finish keeps `.next` until the placed build, run fresh, reads the item (D m/38565): moving and
    /// cut short after the move alike, a refusal or no answer keeps both, by name, and its word moves it.
    #[test]
    fn a_finish_keeps_next_until_another_reader_reads_the_item() {
        use super::{Finished, finish_confirmed};
        use crate::custody::Confirmed;
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example.role", "carried@node");
        k.add(&item.next(), &Secret::new(VALUE.into()), NEW).unwrap();
        let cannot = Says(Confirmed::Cannot("the placed build can't read it".into()));
        let first = finish_confirmed(&k, &item, NEW, &cannot).expect("written");
        assert!(matches!(&first, Finished::Kept(why) if why.starts_with("hand-off-kept")), "{first:?}");
        assert!(held(&k, &item).is_some() && held(&k, &item.next()).is_some(), "both kept");
        let unclear = Says(Confirmed::Unclear("no answer".into()));
        let again = finish_confirmed(&k, &item, NEW, &unclear).expect("both held, the same");
        assert!(matches!(again, Finished::Kept(_)), "cut short after the move: still kept");
        assert!(held(&k, &item.next()).is_some());
        assert_eq!(finish_confirmed(&k, &item, NEW, &Says(Confirmed::Reads)), Ok(Finished::Done));
        assert!(held(&k, &item.next()).is_none(), "read fresh: .next goes");
        assert_eq!(held(&k, &item).as_deref(), Some(VALUE.as_bytes()));
    }

    /// RFC 4231 test case 2: HMAC-SHA-256 is the standard one.
    #[test]
    fn hmac_sha256_meets_rfc_4231() {
        let mac = super::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn a_witness_depends_on_the_nonce_and_the_value() {
        let v = Secret::new(VALUE.into());
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_eq!(witness(&v, &a), witness(&Secret::new(VALUE.into()), &a));
        assert_ne!(witness(&v, &a), witness(&v, &b), "a fresh nonce, a fresh proof");
        assert_ne!(witness(&v, &a), witness(&Secret::new(b"other".to_vec()), &a));
    }
}
