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
use crate::custody::{CustodyError, Item, Keychain};

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
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
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

/// The build a value is handed to: in use, the new binary as a checked child process (its identity
/// judged by its connection's audit token, `identity`), and a stand-in in tests.
pub trait Successor {
    /// Keep `value` under `<item>.next` and prove it read it back.
    fn receive(&mut self, value: &Secret, nonce: &[u8; 32]) -> Result<Witness, String>;
    /// Move `.next` to the item, once the original is gone.
    fn finish(&mut self) -> Result<(), String>;
}

/// The old build's side: hand `item`'s value to `successor`, removing the original only after the
/// successor has proved it holds the same value. Run again after a cut, it finishes.
pub fn hand_off(
    keychain: &Keychain,
    item: &Item,
    successor: &mut dyn Successor,
) -> Result<(), String> {
    match keychain.get(item) {
        Ok(value) => {
            let nonce = nonce()?;
            let theirs = successor.receive(&value, &nonce)?;
            if theirs != witness(&value, &nonce) {
                return Err(format!(
                    "the successor kept another value under {}; the original is left as it is",
                    item.next()
                ));
            }
            keychain.remove(item).map_err(|e| e.to_string())?;
        }
        // Removed on an earlier run that was cut short: the successor's .next holds it.
        Err(CustodyError::NotHeld(_)) => {}
        Err(e) => return Err(e.to_string()),
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

/// The successor's side, finishing: once the original is gone, move `.next` to the item.
pub fn finish(keychain: &Keychain, item: &Item, made_by: &str) -> Result<(), String> {
    let next = item.next();
    match (keychain.get(item), keychain.get(&next)) {
        (Err(CustodyError::NotHeld(_)), Ok(_)) => keychain
            .rename(&next, item, made_by)
            .map_err(|e| e.to_string()),
        (Ok(_), Err(CustodyError::NotHeld(_))) => Ok(()),
        // A rename cut short after its write: both hold the same value, so .next goes.
        (Ok(a), Ok(b)) if a.expose(|x| b.expose(|y| x == y)) => {
            keychain.remove(&next).map_err(|e| e.to_string())
        }
        (Ok(_), Ok(_)) => Err(format!(
            "{item} and {} hold different values; nothing is changed",
            next
        )),
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
    use super::{Successor, Witness, finish, hand_off, receive, witness};
    use crate::Secret;
    use crate::custody::{Item, Keychain};

    const VALUE: &str = "role-key-seed-ZZZtopSECRET";
    const NEW: &str = "identifier \"ai.anemnez.exampled\"";

    fn keychain() -> (tempfile::TempDir, Keychain) {
        let dir = tempfile::tempdir().expect("scratch");
        let k = Keychain::create_at(&dir.path().join("proof.keychain-db"), "proof-only")
            .expect("a keychain of its own");
        (dir, k)
    }

    /// A successor in this process, on the same keychain; `cut` stops it after receiving, as a crash would.
    struct Local<'a> {
        keychain: &'a Keychain,
        item: Item,
        cut: bool,
        lie: bool,
    }

    impl Successor for Local<'_> {
        fn receive(&mut self, value: &Secret, nonce: &[u8; 32]) -> Result<Witness, String> {
            let w = receive(self.keychain, &self.item, value, nonce, NEW)?;
            Ok(if self.lie {
                witness(&Secret::new(b"another".to_vec()), nonce)
            } else {
                w
            })
        }
        fn finish(&mut self) -> Result<(), String> {
            if self.cut {
                return Err("cut short".into());
            }
            finish(self.keychain, &self.item, NEW)
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
        k.add(
            &item,
            &Secret::new(VALUE.into()),
            "identifier \"ai.anemnez.example\"",
        )
        .unwrap();
        assert_eq!(
            k.maker(&item).as_deref(),
            Some("identifier \"ai.anemnez.example\""),
            "made by, without the value"
        );

        let mut cut = Local {
            keychain: &k,
            item: item.clone(),
            cut: true,
            lie: false,
        };
        assert!(
            hand_off(&k, &item, &mut cut).is_err(),
            "cut short after the original went"
        );
        assert!(
            held(&k, &item).is_none()
                && held(&k, &item.next()).as_deref() == Some(VALUE.as_bytes()),
            ".next holds it"
        );

        let mut again = Local {
            keychain: &k,
            item: item.clone(),
            cut: false,
            lie: false,
        };
        hand_off(&k, &item, &mut again).expect("run again, it finishes");
        assert_eq!(held(&k, &item).as_deref(), Some(VALUE.as_bytes()));
        assert!(held(&k, &item.next()).is_none(), "no .next left");
        assert_eq!(
            k.maker(&item).as_deref(),
            Some(NEW),
            "the item is the new build's now"
        );
        hand_off(&k, &item, &mut again).expect("and again: idempotent");
        assert_eq!(held(&k, &item).as_deref(), Some(VALUE.as_bytes()));
    }

    /// A successor that cannot prove it holds the same value never gets the original removed.
    #[test]
    fn a_successor_that_cannot_prove_the_value_leaves_the_original() {
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example.role", "feed@node");
        k.add(&item, &Secret::new(VALUE.into()), "old").unwrap();
        let mut liar = Local {
            keychain: &k,
            item: item.clone(),
            cut: false,
            lie: true,
        };
        let refused = hand_off(&k, &item, &mut liar).unwrap_err();
        assert!(refused.contains("left as it is"), "{refused}");
        assert!(!refused.contains("ZZZtop"), "{refused}");
        assert_eq!(
            held(&k, &item).as_deref(),
            Some(VALUE.as_bytes()),
            "the original stays"
        );
    }

    /// finish() is safe at every state it can find: both held and equal (a rename cut after its write)
    /// cleans up; both held and different changes nothing; neither held says so; add never overwrites.
    #[test]
    fn finish_settles_every_state_it_finds() {
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example.role", "x");
        k.add(&item, &Secret::new(VALUE.into()), "old").unwrap();
        k.add(&item.next(), &Secret::new(VALUE.into()), NEW)
            .unwrap();
        finish(&k, &item, NEW).expect("equal: .next goes");
        assert!(held(&k, &item.next()).is_none());
        k.add(&item.next(), &Secret::new(b"different".to_vec()), NEW)
            .unwrap();
        assert!(
            finish(&k, &item, NEW)
                .unwrap_err()
                .contains("different values")
        );
        assert_eq!(
            held(&k, &item).as_deref(),
            Some(VALUE.as_bytes()),
            "nothing changed"
        );
        assert!(matches!(
            k.add(&item, &Secret::new(b"over".to_vec()), NEW),
            Err(crate::custody::CustodyError::Exists(_))
        ));
        let none = Item::new("ai.anemnez.example.role", "absent");
        assert!(finish(&k, &none, NEW).unwrap_err().contains("neither"));
    }

    /// RFC 4231 test case 2: HMAC-SHA-256 is the standard one.
    #[test]
    fn hmac_sha256_meets_rfc_4231() {
        let mac = super::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn a_witness_depends_on_the_nonce_and_the_value() {
        let v = Secret::new(VALUE.into());
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_eq!(witness(&v, &a), witness(&Secret::new(VALUE.into()), &a));
        assert_ne!(
            witness(&v, &a),
            witness(&v, &b),
            "a fresh nonce, a fresh proof"
        );
        assert_ne!(
            witness(&v, &a),
            witness(&Secret::new(b"other".to_vec()), &a)
        );
    }
}
