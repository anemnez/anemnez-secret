//! Keychain custody (`docs/specs/SECRET.md#a-held-key-is-read-only-by-its-owning-build`): a product's
//! own key material, kept in a macOS keychain as a generic password and written by the product's
//! own binary, so the item's access list admits that binary's code signature. Nothing here takes a
//! value on a command line: the Security framework is called directly.
//!
//! An item is named by its `service` and `account`, both chosen by the product (a per-instance
//! account such as `signer@<node id>` is the caller's naming). A locked keychain is
//! [`CustodyError::Unavailable`], never [`CustodyError::NotHeld`], so a caller never reads "locked"
//! as "logged out" and makes a new key over the old one.

use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};
use security_framework::os::macos::passwords::find_generic_password;

use crate::Secret;

/// errSecItemNotFound.
const NOT_FOUND: i32 = -25300;
/// errSecInteractionNotAllowed: the keychain is locked and may not prompt.
const INTERACTION_NOT_ALLOWED: i32 = -25308;
/// errSecAuthFailed: the keychain refused (locked, or this binary is not on the item's list).
const AUTH_FAILED: i32 = -25293;
/// errSecDuplicateItem.
const DUPLICATE: i32 = -25299;

/// Where an item lives: its service and its account.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Item {
    pub service: String,
    pub account: String,
}

impl Item {
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    /// The item a hand-off writes before the original goes: `<account>.next`, same service.
    pub fn next(&self) -> Self {
        Self {
            service: self.service.clone(),
            account: format!("{}.next", self.account),
        }
    }
}

/// How an item's comment names the build that made it, readable without the value.
pub const MADE_BY: &str = "made by: ";

impl std::fmt::Display for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} / {}", self.service, self.account)
    }
}

/// Why custody did not do what it was asked. Never a value.
#[derive(Debug, PartialEq, Eq)]
pub enum CustodyError {
    /// Nothing is held under that item.
    NotHeld(Item),
    /// The keychain cannot be read now (locked, or it refused without a dialog). Try again later;
    /// it is not a reason to make a new key.
    Unavailable { item: Item, status: i32 },
    /// `add` found an item already there: it never overwrites.
    Exists(Item),
    /// The keychain failed in its own words (an OS status, never the value).
    Store { item: Item, status: i32 },
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotHeld(item) => write!(f, "{item} is not held"),
            Self::Unavailable { item, status } => {
                write!(
                    f,
                    "{item} cannot be read now (OSStatus {status}: locked, or refused without a dialog)"
                )
            }
            Self::Exists(item) => write!(f, "{item} is already held, and add never overwrites"),
            Self::Store { item, status } => {
                write!(f, "{item}: the keychain failed (OSStatus {status})")
            }
        }
    }
}

impl std::error::Error for CustodyError {}

/// A keychain, for custody.
pub struct Keychain {
    /// None: the user's default keychain (the login keychain).
    keychain: Option<SecKeychain>,
}

impl Keychain {
    /// The user's default keychain. Never in a test: tests use [`Keychain::create_at`].
    pub fn login() -> Self {
        Self { keychain: None }
    }

    /// A keychain file of its own at `path`, made with `password` (proofs: never the login keychain).
    pub fn create_at(path: &std::path::Path, password: &str) -> Result<Self, String> {
        let mut keychain = CreateOptions::new()
            .password(password)
            .create(path)
            .map_err(|e| e.to_string())?;
        keychain.unlock(Some(password)).map_err(|e| e.to_string())?;
        Ok(Self {
            keychain: Some(keychain),
        })
    }

    fn keychains(&self) -> Option<Vec<SecKeychain>> {
        self.keychain.clone().map(|k| vec![k])
    }

    fn error(item: &Item, e: &security_framework::base::Error) -> CustodyError {
        match e.code() {
            NOT_FOUND => CustodyError::NotHeld(item.clone()),
            INTERACTION_NOT_ALLOWED | AUTH_FAILED => CustodyError::Unavailable {
                item: item.clone(),
                status: e.code(),
            },
            DUPLICATE => CustodyError::Exists(item.clone()),
            status => CustodyError::Store {
                item: item.clone(),
                status,
            },
        }
    }

    /// Keep `value` under `item`, replacing what was there. The calling binary writes it, so the
    /// item's access list names this binary's code signature.
    pub fn put(&self, item: &Item, value: Secret) -> Result<(), CustodyError> {
        let written = match &self.keychain {
            Some(keychain) => {
                value.expose(|v| keychain.set_generic_password(&item.service, &item.account, v))
            }
            None => value.expose(|v| {
                security_framework::passwords::set_generic_password(&item.service, &item.account, v)
            }),
        };
        written.map_err(|e| Self::error(item, &e))
    }

    /// The value under `item`.
    pub fn get(&self, item: &Item) -> Result<Secret, CustodyError> {
        let keychains = self.keychains();
        match find_generic_password(keychains.as_deref(), &item.service, &item.account) {
            Ok((password, _)) => Ok(Secret::new(password.to_vec())),
            Err(e) => Err(Self::error(item, &e)),
        }
    }

    /// Forget `item`.
    pub fn remove(&self, item: &Item) -> Result<(), CustodyError> {
        let keychains = self.keychains();
        match find_generic_password(keychains.as_deref(), &item.service, &item.account) {
            Ok((_, found)) => {
                found.delete();
                Ok(())
            }
            Err(e) => Err(Self::error(item, &e)),
        }
    }

    /// Keep `value` under `item` only if nothing is there: it never overwrites ([`CustodyError::Exists`]).
    /// The item's comment names `made_by` (the writing build's designated requirement), so a refusal
    /// after a signing change can say whose item it is without reading the value.
    pub fn add(&self, item: &Item, value: &Secret, made_by: &str) -> Result<(), CustodyError> {
        use security_framework::item::{ItemAddOptions, ItemAddValue, ItemClass, Location};
        let data = value.expose(core_foundation::data::CFData::from_buffer);
        let mut add = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data,
        });
        add.set_service(&item.service)
            .set_account_name(&item.account)
            .set_label(format!("{} / {}", item.service, item.account))
            .set_comment(format!("{MADE_BY}{made_by}"));
        if let Some(keychain) = &self.keychain {
            add.set_location(Location::FileKeychain(keychain.clone()));
        }
        add.add().map_err(|e| Self::error(item, &e))
    }

    /// The build that made `item`, as its comment names it: read from the item's attributes, never its
    /// value. None when the item is absent or carries no such note.
    pub fn maker(&self, item: &Item) -> Option<String> {
        use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::generic_password())
            .service(&item.service)
            .account(&item.account)
            .load_attributes(true)
            .load_data(false);
        search.limit(Limit::Max(1));
        if let Some(keychain) = &self.keychain {
            search.keychains(std::slice::from_ref(keychain));
        }
        let found = search.search().ok()?;
        let attributes = found.first()?.simplify_dict()?;
        attributes
            .get("icmt")?
            .strip_prefix(MADE_BY)
            .map(str::to_owned)
    }

    /// Move this build's own `from` to `to`: written under `to` (never over an item there), read back,
    /// and only then is `from` removed, so one of the two always holds the value.
    pub fn rename(&self, from: &Item, to: &Item, made_by: &str) -> Result<(), CustodyError> {
        let value = self.get(from)?;
        self.add(to, &value, made_by)?;
        let back = self.get(to)?;
        if back.expose(|b| value.expose(|v| b != v)) {
            return Err(CustodyError::Store {
                item: to.clone(),
                status: 0,
            });
        }
        self.remove(from)
    }

    /// Whether `item` exists, found by its attributes alone: the value is never read into memory to
    /// answer.
    pub fn held(&self, item: &Item) -> Result<bool, CustodyError> {
        use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::generic_password())
            .service(&item.service)
            .account(&item.account)
            .load_refs(true)
            .load_data(false);
        search.limit(Limit::Max(1));
        if let Some(keychain) = &self.keychain {
            search.keychains(std::slice::from_ref(keychain));
        }
        match search.search() {
            Ok(found) => Ok(!found.is_empty()),
            Err(e) if e.code() == NOT_FOUND => Ok(false),
            Err(e) => Err(Self::error(item, &e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CustodyError, Item, Keychain};
    use crate::Secret;

    const VALUE: &str = "ed25519-seed-0123456789ZZZtopSECRETvalue";

    fn keychain() -> (tempfile::TempDir, Keychain) {
        let dir = tempfile::tempdir().expect("scratch");
        let k = Keychain::create_at(&dir.path().join("proof.keychain-db"), "proof-only")
            .expect("a keychain of its own");
        (dir, k)
    }

    /// `SECRET.md#a-held-key-is-read-only-by-its-owning-build`: what was put under an item is what
    /// it reads back, a put replaces it, a removed item is not held, and `held` never reads the
    /// value. Never the login keychain.
    #[test]
    fn an_item_holds_what_was_put_under_it() {
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example.role", "promoter@01a195f1");
        assert!(!k.held(&item).unwrap());
        assert_eq!(
            k.get(&item).unwrap_err(),
            CustodyError::NotHeld(item.clone())
        );
        k.put(&item, Secret::new(VALUE.into())).unwrap();
        assert!(k.held(&item).unwrap());
        assert_eq!(
            k.get(&item).unwrap().expose(|v| v.to_vec()),
            VALUE.as_bytes()
        );
        k.put(&item, Secret::new(b"rotated".to_vec())).unwrap();
        assert_eq!(k.get(&item).unwrap().expose(|v| v.to_vec()), b"rotated");
        let other = Item::new("ai.anemnez.example.role", "promoter@another-node");
        assert!(!k.held(&other).unwrap(), "an account is its own item");
        k.remove(&item).unwrap();
        assert!(!k.held(&item).unwrap());
        assert!(matches!(k.remove(&item), Err(CustodyError::NotHeld(_))));
    }

    /// `SECRET.md#a-held-key-is-read-only-by-its-owning-build`: every error says what and why,
    /// never the value; and "locked" reads as Unavailable, never NotHeld.
    #[test]
    fn errors_never_say_the_value_and_locked_is_not_not_held() {
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example", "key");
        k.put(&item, Secret::new(VALUE.into())).unwrap();
        let errors = [
            CustodyError::NotHeld(item.clone()),
            Keychain::error(&item, &security_framework::base::Error::from_code(-25308)),
            Keychain::error(&item, &security_framework::base::Error::from_code(-25293)),
            Keychain::error(&item, &security_framework::base::Error::from_code(-1)),
        ];
        assert!(
            matches!(errors[1], CustodyError::Unavailable { .. }),
            "locked is unavailable"
        );
        assert!(
            matches!(errors[2], CustodyError::Unavailable { .. }),
            "refused is unavailable"
        );
        assert!(matches!(errors[3], CustodyError::Store { .. }));
        for e in &errors {
            let said = format!("{e} {e:?}");
            assert!(
                !said.contains("SECRET") && !said.contains("ZZZtop"),
                "{said}"
            );
            assert!(
                said.contains("ai.anemnez.example"),
                "it names the item: {said}"
            );
        }
    }
}
