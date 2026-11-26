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
pub use crate::access::Listing;
use std::os::unix::ffi::OsStrExt as _;

/// Keychain dialogs. A non-interactive [`Keychain`] (every constructor but [`Keychain::login_interactive`])
/// turns them off for the process when it is made, and nothing here turns them on again: an item whose
/// access list doesn't admit the caller (another build's, the normal case after a signing change) then
/// answers Unavailable at once, and a daemon never puts 'wants to use your confidential information' on
/// the person's screen. Off once and never re-enabled is thread-safe and covers the legacy keychain
/// APIs custody uses (F and D, 2026-11-06).
mod quiet {
    use security_framework_sys::keychain::SecKeychainSetUserInteractionAllowed;

    /// Set once a non-interactive Keychain is made: from then on this process never turns dialogs on.
    static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// Turn keychain dialogs off for this process, for good.
    pub(super) fn off() {
        QUIET.store(true, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: a plain call; it sets whether this process may show keychain dialogs.
        unsafe { SecKeychainSetUserInteractionAllowed(0) };
    }

    /// Turn keychain dialogs on, unless this process has already made a non-interactive Keychain: a
    /// process is one or the other, never both (D, 2026-11-06).
    pub(super) fn on() -> Result<(), String> {
        if QUIET.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("this process already holds a non-interactive keychain, so it never shows a keychain dialog; run the interactive command in a process of its own".into());
        }
        // SAFETY: as above.
        unsafe { SecKeychainSetUserInteractionAllowed(1) };
        Ok(())
    }

    /// Whether dialogs are allowed right now (tests).
    #[cfg(test)]
    pub(super) fn allowed() -> bool {
        use security_framework_sys::keychain::SecKeychainGetUserInteractionAllowed;
        let mut now = 1u8;
        // SAFETY: a plain out-parameter read of the process's setting.
        unsafe { SecKeychainGetUserInteractionAllowed(&mut now) };
        now != 0
    }
}

/// Whether a keychain is unlocked. A search by attributes on a locked keychain finds nothing rather than
/// failing, so "not held" there would be a guess: custody asks first, and says Unavailable (N m/15128).
mod lock {
    use core_foundation::base::TCFType as _;
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework_sys::base::SecKeychainRef;

    /// kSecUnlockStateStatus.
    const UNLOCKED: u32 = 1;

    unsafe extern "C" {
        fn SecKeychainGetStatus(keychain: SecKeychainRef, status: *mut u32) -> i32;
    }

    /// `keychain`'s lock state (None: the user's default keychain), or the status the read failed with.
    pub(super) fn unlocked(keychain: Option<&SecKeychain>) -> Result<bool, i32> {
        let raw = keychain.map_or(std::ptr::null_mut(), |k| k.as_concrete_TypeRef());
        let mut status = 0u32;
        // SAFETY: a plain out-parameter read; a null keychain is the default one, as the API documents.
        let code = unsafe { SecKeychainGetStatus(raw, &mut status) };
        if code == 0 { Ok(status & UNLOCKED != 0) } else { Err(code) }
    }
}

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
        Self { service: service.into(), account: account.into() }
    }

    /// The item a hand-off writes before the original goes: `<account>.next`, same service.
    pub fn next(&self) -> Self {
        Self { service: self.service.clone(), account: format!("{}.next", self.account) }
    }
}

/// How an item's comment names the build that made it, readable without the value.
pub const MADE_BY: &str = "made by: ";

impl std::fmt::Display for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} / {}", self.service, self.account)
    }
}

/// Whether a reader other than the writer read an item (D m/38565): a fresh process of the build that must read it,
/// asked by its caller, since only the caller can spawn that build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmed {
    /// It read the item, and the value it read is the one written.
    Reads,
    /// It answered, and could not read the item, or read another value: why, never the value.
    Cannot(String),
    /// It didn't answer within its bound: unclear, kept as a refusal (rule 5).
    Unclear(String),
}

/// A reader other than the writer, asked whether it reads `item` holding `value` ([`Keychain::rename`]).
pub trait Confirm {
    /// Ask the other reader; compare what it read with `value` (never print either).
    fn confirms(&self, item: &Item, value: &Secret) -> Confirmed;
}

/// The writer's own read-back, named for what it is: what [`Keychain::rename`] trusts, for a move whose next reader is
/// this same build (fabricd's seal retiring its own key). It proves only that this process reads `item`, so no hand-off
/// finishes on it (D m/38588): a carry passes a fresh process of its placed build instead.
pub struct WritersOwnRead<'a>(pub &'a Keychain);

impl Confirm for WritersOwnRead<'_> {
    fn confirms(&self, item: &Item, value: &Secret) -> Confirmed {
        match self.0.get(item) {
            Ok(read) if read.expose(|r| value.expose(|v| r == v)) => Confirmed::Reads,
            Ok(_) => Confirmed::Cannot(format!("{item} reads another value")),
            Err(e) => Confirmed::Cannot(e.to_string()),
        }
    }
}

/// What a [`Keychain::rename`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Moved {
    /// `to` holds the value and its other reader read it; `from` is gone.
    Moved,
    /// `to` holds the value, but its other reader didn't read it, so `from` is kept beside it: why.
    Kept(String),
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
                write!(f, "{item} cannot be read now (OSStatus {status}: locked, or refused without a dialog)")
            }
            Self::Exists(item) => write!(f, "{item} is already held, and add never overwrites"),
            Self::Store { item, status } => {
                write!(f, "{item}: the keychain failed (OSStatus {status})")
            }
        }
    }
}

impl std::error::Error for CustodyError {}

/// What a row plants: who the list trusts (and this binary), its owners, and its partitions.
#[cfg(test)]
pub(crate) struct Planted<'a> {
    pub trusted: &'a [&'a str],
    pub with_self: bool,
    pub owners: &'a [&'a str],
    pub partitions: &'a [&'a str],
}

/// `text` as the framework prints a code requirement: the spelling [`Keychain::trusts`] and [`Listing`] use, so a
/// caller compares a requirement it holds with an item's list without a printer of its own (F m/37818).
///
/// # Errors
/// [`Trusting::NotTheTeams`] naming `text` when it is no code requirement.
pub fn printed_requirement(text: &str) -> Result<String, Trusting> {
    crate::access::requirement(text).map_err(|status| Trusting::NotTheTeams {
        item: Item::new("", ""),
        why: format!("'{text}' is no code requirement (OSStatus {status})"),
    })
}

/// Why [`Keychain::add_trusting`] wrote nothing.
#[derive(Debug)]
#[non_exhaustive]
pub enum Trusting {
    /// A requirement the trust table doesn't pin to a team it trusts (D m/37713), named with why: nothing written.
    NotTheTeams { item: Item, why: String },
    /// This macOS doesn't export a private call the carry-across needs (resolved at first use, never linked; E m/37742),
    /// named: only making or reading a trusting list fails, nothing else.
    Unsupported { item: Item, why: String },
    /// Custody's own refusal.
    Custody(CustodyError),
}

impl Trusting {
    fn of(item: &Item, refused: crate::access::Refused) -> Self {
        match refused {
            crate::access::Refused::Unsupported(why) => Self::Unsupported { item: item.clone(), why },
            crate::access::Refused::Status(status) => Self::Custody(CustodyError::Store { item: item.clone(), status }),
        }
    }
}

impl std::fmt::Display for Trusting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotTheTeams { item, why } => {
                write!(f, "{item} trusts only its team's builds: {why}; nothing written")
            }
            Self::Unsupported { item, why } => write!(f, "{item}: {why}"),
            Self::Custody(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Trusting {}

/// What [`Keychain::accounts`] found under a service.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Accounts {
    /// Each account held, sorted.
    pub names: Vec<String>,
    /// Items found under the service whose attributes didn't read or named no account: held, but not
    /// nameable, so a caller must say so rather than read them as absent.
    pub unreadable: usize,
    /// Each account's note, as [`Keychain::put_noted`] wrote it (its description attribute), read with
    /// the names and never with a value. An account with no note is absent here.
    pub notes: std::collections::BTreeMap<String, String>,
}

/// A keychain, for custody.
pub struct Keychain {
    /// None: the user's default keychain (the login keychain).
    keychain: Option<SecKeychain>,
    /// Whether securityd stamps this keychain's items with their creator's partition: by where its file lives.
    stamped: bool,
}

impl Keychain {
    /// The user's default keychain, non-interactive: keychain dialogs are off for the process from here
    /// on. Never in a test: tests use [`Keychain::create_at`].
    pub fn login() -> Self {
        quiet::off();
        Self { keychain: None, stamped: true }
    }

    /// The user's default keychain WITH dialogs, for a command a person runs at the Mac (an explicit
    /// adoption). Never in a daemon: it turns dialogs on for the whole process, so it is refused in a
    /// process that has already made a non-interactive Keychain.
    pub fn login_interactive() -> Result<Self, String> {
        quiet::on()?;
        Ok(Self { keychain: None, stamped: true })
    }

    /// A keychain file of its own at `path`, made with `password` (proofs: never the login keychain).
    /// Non-interactive, as [`Keychain::login`].
    pub fn create_at(path: &std::path::Path, password: &str) -> Result<Self, String> {
        absolute(path)?;
        let mut keychain = CreateOptions::new().password(password).create(path).map_err(|e| e.to_string())?;
        keychain.unlock(Some(password)).map_err(|e| e.to_string())?;
        quiet::off();
        Ok(Self { keychain: Some(keychain), stamped: stamped_at(path, home().as_deref()) })
    }

    /// An existing keychain file at `path`, unlocked with `password` (a proof's successor opens the
    /// file its holder made). Non-interactive, as [`Keychain::login`].
    pub fn open_at(path: &std::path::Path, password: &str) -> Result<Self, String> {
        absolute(path)?;
        let mut keychain = SecKeychain::open(path).map_err(|e| e.to_string())?;
        keychain.unlock(Some(password)).map_err(|e| e.to_string())?;
        quiet::off();
        Ok(Self { keychain: Some(keychain), stamped: stamped_at(path, home().as_deref()) })
    }

    /// Unavailable for `item` when the keychain is locked (or its state can't be read): an attribute search
    /// then answers nothing, which must never read as "not held".
    fn readable(&self, item: &Item) -> Result<(), CustodyError> {
        match lock::unlocked(self.keychain.as_ref()) {
            Ok(true) => Ok(()),
            Ok(false) => Err(CustodyError::Unavailable { item: item.clone(), status: INTERACTION_NOT_ALLOWED }),
            Err(status) => Err(CustodyError::Unavailable { item: item.clone(), status }),
        }
    }

    fn keychains(&self) -> Option<Vec<SecKeychain>> {
        self.keychain.clone().map(|k| vec![k])
    }

    fn error(item: &Item, e: &security_framework::base::Error) -> CustodyError {
        match e.code() {
            NOT_FOUND => CustodyError::NotHeld(item.clone()),
            INTERACTION_NOT_ALLOWED | AUTH_FAILED => CustodyError::Unavailable { item: item.clone(), status: e.code() },
            DUPLICATE => CustodyError::Exists(item.clone()),
            status => CustodyError::Store { item: item.clone(), status },
        }
    }

    /// Keep `value` under `item`, replacing what was there. The calling binary writes it, so the
    /// item's access list names this binary's code signature.
    pub fn put(&self, item: &Item, value: Secret) -> Result<(), CustodyError> {
        let written = match &self.keychain {
            Some(keychain) => value.expose(|v| keychain.set_generic_password(&item.service, &item.account, v)),
            None => {
                value.expose(|v| security_framework::passwords::set_generic_password(&item.service, &item.account, v))
            }
        };
        written.map_err(|e| Self::error(item, &e))
    }

    /// Keep `value` under `item`, replacing what was there, with `note` in the item's description
    /// attribute: a small fact about the value (when it was made, say) that [`Self::accounts`] returns
    /// without the value ever being read. An existing item is updated in place, keeping its access
    /// list; a new one is written by the calling binary, as [`Self::put`] writes it.
    pub fn put_noted(&self, item: &Item, value: &Secret, note: &str) -> Result<(), CustodyError> {
        use security_framework::item::{
            ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, ItemUpdateOptions, ItemUpdateValue, Location,
            update_item,
        };
        let data = || value.expose(core_foundation::data::CFData::from_buffer);
        let mut search = ItemSearchOptions::new();
        search.class(ItemClass::generic_password()).service(&item.service).account(&item.account);
        if let Some(keychain) = &self.keychain {
            search.keychains(std::slice::from_ref(keychain));
        }
        let mut update = ItemUpdateOptions::new();
        update.set_value(ItemUpdateValue::Data(data())).set_description(note);
        match update_item(&search, &update) {
            Ok(()) => return Ok(()),
            Err(e) if e.code() == NOT_FOUND => {}
            Err(e) => return Err(Self::error(item, &e)),
        }
        let mut add = ItemAddOptions::new(ItemAddValue::Data { class: ItemClass::generic_password(), data: data() });
        add.set_service(&item.service)
            .set_account_name(&item.account)
            .set_label(format!("{} / {}", item.service, item.account))
            .set_description(note);
        if let Some(keychain) = &self.keychain {
            add.set_location(Location::FileKeychain(keychain.clone()));
        }
        match add.add() {
            Ok(()) => Ok(()),
            // Another writer added it between the two calls: update the one now there.
            Err(e) if e.code() == DUPLICATE => update_item(&search, &update).map_err(|e| Self::error(item, &e)),
            Err(e) => Err(Self::error(item, &e)),
        }
    }

    /// Whether this keychain's items are judged as stamped with their creator's partition, by where its file lives (D
    /// m/37833): securityd stamps every item under the user's `Library/Keychains`, the login keychain's included, and
    /// nothing elsewhere (read by value, 2026-11-26). So a keychain opened by its path there gets the full check, and one
    /// outside it, a test's, needs no stamp. Where items are stamped, an item with none is refused.
    pub(crate) fn stamps(&self) -> bool {
        self.stamped
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
        self.add_with(item, value, made_by, None)
    }

    /// [`Self::add`], with an access list that trusts exactly `trusted`, each a code requirement that `table` pins to a
    /// team it trusts under the Anemnez rule (an identifier, anchored at Apple, the leaf's OU the team; D m/37713): a
    /// signing change carried across, so the build placed now and its successor of another designated requirement, both
    /// signed by the team, read the one item with no prompt, and a rollback still does (F m/37706). Nothing else is on
    /// the list, this binary included: a team build meets its team's requirement, and a list custody writes never trusts
    /// a code outside the team. The comment still names `made_by` alone, as every reader of it today expects; the list
    /// is read back by [`Self::trusts`]. Editing an existing item's access list asks for the keychain's password, so an
    /// item gains a reader only by being written again, the hand-off way.
    ///
    /// # Errors
    /// [`Trusting::NotTheTeams`] for a requirement `table` doesn't pin, nothing written; [`Self::add`]'s otherwise.
    pub fn add_trusting(
        &self,
        item: &Item,
        value: &Secret,
        made_by: &str,
        trusted: &[&str],
        table: &crate::identity::TrustTable,
    ) -> Result<(), Trusting> {
        self.add_pinned(item, value, made_by, trusted, table, false)
    }

    /// [`Self::add_trusting`], with this build's own application entry kept beside the team's requirements (F m/38513,
    /// D m/38511): the carry's first step, so the build placed now still reads the item when it can't meet a
    /// requirement judged in full (an unsealed bundle's main executable fails one), and its successor reads it by the
    /// team's. The requirements are pinned by `table` as [`Self::add_trusting`]'s are; the own entry is this binary
    /// as the keychain records it, never a name.
    ///
    /// # Errors
    /// As [`Self::add_trusting`].
    pub fn add_trusting_with_own(
        &self,
        item: &Item,
        value: &Secret,
        made_by: &str,
        trusted: &[&str],
        table: &crate::identity::TrustTable,
    ) -> Result<(), Trusting> {
        self.add_pinned(item, value, made_by, trusted, table, true)
    }

    fn add_pinned(
        &self,
        item: &Item,
        value: &Secret,
        made_by: &str,
        trusted: &[&str],
        table: &crate::identity::TrustTable,
        with_own: bool,
    ) -> Result<(), Trusting> {
        if trusted.is_empty() {
            return Err(Trusting::NotTheTeams { item: item.clone(), why: "no requirement to trust".into() });
        }
        for text in trusted {
            crate::access::team_pinned(text, table).map_err(|why| Trusting::NotTheTeams { item: item.clone(), why })?;
        }
        self.add_listing(item, value, made_by, trusted, with_own)
    }

    /// An item trusting `trusted` and, for a row that must read what it wrote, this binary too: never pinned, so
    /// never outside a test.
    #[cfg(test)]
    pub(crate) fn add_trusting_unpinned(
        &self,
        item: &Item,
        value: &Secret,
        made_by: &str,
        trusted: &[&str],
        with_self: bool,
    ) -> Result<(), Trusting> {
        self.add_listing(item, value, made_by, trusted, with_self)
    }

    /// For rows only: an item as a planter would make it, its list trusting `planted.trusted` (and this binary,
    /// `planted.with_self`), with an owner entry and a partition entry added before the add.
    #[cfg(test)]
    pub(crate) fn add_planted(
        &self,
        item: &Item,
        value: &Secret,
        made_by: &str,
        planted: &Planted<'_>,
    ) -> Result<(), Trusting> {
        let access = crate::access::trusting(
            &format!("{} / {}", item.service, item.account),
            planted.trusted,
            planted.with_self,
        )
        .map_err(|refused| Trusting::of(item, refused))?;
        crate::access::plant(&access, planted.owners, planted.partitions)
            .map_err(|refused| Trusting::of(item, refused))?;
        self.add_with(item, value, made_by, Some(&access)).map_err(Trusting::Custody)
    }

    fn add_listing(
        &self,
        item: &Item,
        value: &Secret,
        made_by: &str,
        trusted: &[&str],
        with_self: bool,
    ) -> Result<(), Trusting> {
        let access = crate::access::trusting(&format!("{} / {}", item.service, item.account), trusted, with_self)
            .map_err(|refused| Trusting::of(item, refused))?;
        self.add_with(item, value, made_by, Some(&access)).map_err(Trusting::Custody)
    }

    /// The add every writer here goes through: with `access`, the item's access list is that one, else the default
    /// (this binary alone).
    fn add_with(
        &self,
        item: &Item,
        value: &Secret,
        made_by: &str,
        access: Option<&core_foundation::base::CFType>,
    ) -> Result<(), CustodyError> {
        use security_framework::item::{ItemAddOptions, ItemAddValue, ItemClass, Location};
        let data = value.expose(core_foundation::data::CFData::from_buffer);
        let mut add = ItemAddOptions::new(ItemAddValue::Data { class: ItemClass::generic_password(), data });
        add.set_service(&item.service)
            .set_account_name(&item.account)
            .set_label(format!("{} / {}", item.service, item.account))
            .set_comment(format!("{MADE_BY}{made_by}"));
        if let Some(keychain) = &self.keychain {
            add.set_location(Location::FileKeychain(keychain.clone()));
        }
        let Some(access) = access else { return add.add().map_err(|e| Self::error(item, &e)) };
        added_with_access(&add, access).map_err(|e| Self::error(item, &e))
    }

    /// The code requirements `item`'s access list trusts to read its value, as the framework spells each one (this
    /// binary's among them), read off the item's reference: its value is never read. What [`Self::add_trusting`] wrote
    /// is read back by this.
    ///
    /// # Errors
    /// [`Trusting::Unsupported`] on a macOS that doesn't export the call that reads a list's requirements;
    /// [`CustodyError::NotHeld`], Unavailable for a locked keychain, and the store's own, as [`Trusting::Custody`].
    pub fn trusts(&self, item: &Item) -> Result<Vec<String>, Trusting> {
        self.listing(item).map(|listing| listing.readers)
    }

    /// `item`'s whole access list as a [`Listing`]: who reads its value, who may change the list, and the partitions
    /// that say which code made it, read off the item's reference, never its value (D m/37792).
    ///
    /// # Errors
    /// As [`Self::trusts`].
    pub fn listing(&self, item: &Item) -> Result<Listing, Trusting> {
        let found = self.reference(item).map_err(Trusting::Custody)?;
        let access = crate::access::of(core_foundation::base::TCFType::as_concrete_TypeRef(&found))
            .map_err(|status| Trusting::Custody(CustodyError::Store { item: item.clone(), status }))?;
        crate::access::listing(&access).map_err(|refused| Trusting::of(item, refused))
    }

    /// `item`'s keychain reference, found by its attributes: the value is never read.
    fn reference(
        &self,
        item: &Item,
    ) -> Result<security_framework::os::macos::keychain_item::SecKeychainItem, CustodyError> {
        use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
        self.readable(item)?;
        let mut search = ItemSearchOptions::new();
        search.class(ItemClass::generic_password()).service(&item.service).account(&item.account).load_refs(true);
        search.limit(Limit::Max(1));
        if let Some(keychain) = &self.keychain {
            search.keychains(std::slice::from_ref(keychain));
        }
        let found = search.search().map_err(|e| Self::error(item, &e))?;
        match found.into_iter().next() {
            Some(SearchResult::Ref(Reference::KeychainItem(found))) => Ok(found),
            _ => Err(CustodyError::NotHeld(item.clone())),
        }
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
        attributes.get("icmt")?.strip_prefix(MADE_BY).map(str::to_owned)
    }

    /// Move this build's own `from` to `to`, `from` removed once this writer's own read-back reads `to`
    /// ([`WritersOwnRead`]): [`Self::rename_confirmed`] with no other reader, for a move whose next reader is this same
    /// build (fabricd's seal retiring its own key). A carry, whose next reader is another build, takes
    /// [`Self::rename_confirmed`].
    ///
    /// # Errors
    /// As [`Self::rename_confirmed`]; a move its own read-back didn't confirm is the store's, both kept.
    pub fn rename(&self, from: &Item, to: &Item, made_by: &str) -> Result<(), CustodyError> {
        match self.rename_confirmed(from, to, made_by, &WritersOwnRead(self))? {
            Moved::Moved => Ok(()),
            Moved::Kept(_) => Err(CustodyError::Store { item: to.clone(), status: 0 }),
        }
    }

    /// Move this build's own `from` to `to`: written under `to` (never over an item there), read back, and then
    /// `from` is removed only once `confirm` says a reader other than this writer read `to` (D m/38565): the writing
    /// process can read what it just wrote, so its own read-back proves nothing about the build that must read it
    /// next. Anything short of [`Confirmed::Reads`] keeps both, [`Moved::Kept`] naming why, so one of the two always
    /// holds the value where its reader can reach it. `to` gets `from`'s access list without its stamps
    /// ([`crate::access`]), so every reader `from` was written for survives the move.
    ///
    /// # Errors
    /// The store's, on reading `from` or writing `to`; a `to` that reads back another value is the store's too.
    pub fn rename_confirmed(
        &self,
        from: &Item,
        to: &Item,
        made_by: &str,
        confirm: &dyn Confirm,
    ) -> Result<Moved, CustodyError> {
        let value = self.get(from)?;
        let access =
            crate::access::of_for_writing(core_foundation::base::TCFType::as_concrete_TypeRef(&self.reference(from)?))
                .map_err(|status| CustodyError::Store { item: from.clone(), status })?;
        self.add_with(to, &value, made_by, Some(&access))?;
        let back = self.get(to)?;
        if back.expose(|b| value.expose(|v| b != v)) {
            return Err(CustodyError::Store { item: to.clone(), status: 0 });
        }
        match confirm.confirms(to, &value) {
            Confirmed::Reads => self.remove(from).map(|()| Moved::Moved),
            Confirmed::Cannot(why) | Confirmed::Unclear(why) => Ok(Moved::Kept(why)),
        }
    }

    /// The accounts held under `service`, found by their attributes alone: no value is read into memory
    /// to answer. A caller that keeps derived copies sweeps them by this (Ladon's copy sweep), so an
    /// item nobody asks for again is still found. Sorted, so the answer is the same however the
    /// keychain orders it. An item the search found under `service` whose attributes don't read, or
    /// that names no account, is never dropped silently: it is counted in [`Accounts::unreadable`], so
    /// a sweep can say what it could not reach (D m/14807). The Security framework gives no way to
    /// plant such an item in a proof, so that count is stated here rather than shown by a row.
    pub fn accounts(&self, service: &str) -> Result<Accounts, CustodyError> {
        use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
        self.readable(&Item::new(service, "*"))?;
        let mut search = ItemSearchOptions::new();
        search.class(ItemClass::generic_password()).service(service).load_attributes(true).load_data(false);
        search.limit(Limit::All);
        if let Some(keychain) = &self.keychain {
            search.keychains(std::slice::from_ref(keychain));
        }
        let found = match search.search() {
            Ok(found) => found,
            Err(e) if e.code() == NOT_FOUND => {
                return self.readable(&Item::new(service, "*")).map(|()| Accounts::default());
            }
            Err(e) => return Err(Self::error(&Item::new(service, "*"), &e)),
        };
        let mut accounts = Accounts::default();
        for attributes in found.iter().map(|f| f.simplify_dict()) {
            match attributes {
                // Another service: the search's own filter should never return one, but it is not ours.
                Some(a) if a.get("svce").is_some_and(|s| s != service) => {}
                Some(a) => match a.get("acct") {
                    Some(account) => {
                        if let Some(note) = a.get("desc") {
                            accounts.notes.insert(account.clone(), note.clone());
                        }
                        accounts.names.push(account.clone());
                    }
                    None => accounts.unreadable += 1,
                },
                None => accounts.unreadable += 1,
            }
        }
        accounts.names.sort();
        accounts.names.dedup();
        if accounts.names.is_empty() && accounts.unreadable == 0 {
            // As for held: an empty list is confirmed against the lock state once more (D m/15135).
            self.readable(&Item::new(service, "*"))?;
        }
        Ok(accounts)
    }

    /// Whether `item` exists, found by its attributes alone: the value is never read into memory to
    /// answer.
    pub fn held(&self, item: &Item) -> Result<bool, CustodyError> {
        use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
        self.readable(item)?;
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
        // An empty answer is confirmed against the lock state once more: a keychain locked between the first
        // read and the search finds nothing, which isn't "not held" (D m/15135). A found item needs no second read.
        match search.search() {
            Ok(found) if !found.is_empty() => Ok(true),
            Ok(_) => self.readable(item).map(|()| false),
            Err(e) if e.code() == NOT_FOUND => self.readable(item).map(|()| false),
            Err(e) => Err(Self::error(item, &e)),
        }
    }
}

/// A keychain path must be absolute: a relative one is created, or looked for, in the user's `Library/Keychains`, so a
/// row or a tool that names one writes into the person's own (E m/37831; it happened, 2026-11-26).
fn absolute(path: &std::path::Path) -> Result<(), String> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(format!(
            "give an absolute keychain path: a relative one ({}) is created in ~/Library/Keychains",
            path.display()
        ))
    }
}

/// Whether securityd stamps a keychain at `path`: under `home`'s `Library/Keychains`, compared by components after
/// resolving what exists of it, never by text.
fn stamped_at(path: &std::path::Path, home: Option<&std::path::Path>) -> bool {
    let Some(home) = home else { return false };
    let under = home.join("Library").join("Keychains");
    let under = under.canonicalize().unwrap_or(under);
    let resolved = match path.parent().map(std::path::Path::canonicalize) {
        Some(Ok(dir)) => dir.join(path.file_name().unwrap_or_default()),
        // What can't be resolved is judged as spelled, and a `..` in it is never under anything.
        _ if path.components().any(|c| c == std::path::Component::ParentDir) => return false,
        _ => path.to_path_buf(),
    };
    resolved.starts_with(&under)
}

/// This user's home directory, as the user database has it (never `$HOME`, which a caller may set).
fn home() -> Option<std::path::PathBuf> {
    // SAFETY: getpwuid returns a pointer into static storage or null; it is read at once, on this thread.
    let entry = unsafe { libc::getpwuid(libc::getuid()) };
    if entry.is_null() {
        return None;
    }
    // SAFETY: a non-null entry's pw_dir is a NUL-terminated string while the entry lives.
    let dir = unsafe { std::ffi::CStr::from_ptr((*entry).pw_dir) };
    Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

/// `add` with `access` as the item's access list (kSecAttrAccess): `security-framework`'s add takes none, so its
/// dictionary is taken and the access put in beside the rest.
fn added_with_access(
    add: &security_framework::item::ItemAddOptions,
    access: &core_foundation::base::CFType,
) -> Result<(), security_framework::base::Error> {
    use core_foundation::base::TCFType as _;
    use core_foundation::dictionary::CFMutableDictionary;
    #[allow(deprecated)]
    let dictionary = add.to_dictionary();
    let mut dictionary: CFMutableDictionary<core_foundation::base::CFType, core_foundation::base::CFType> =
        // SAFETY: a fresh mutable copy of a dictionary this side owns, returned owned.
        unsafe {
            CFMutableDictionary::wrap_under_create_rule(crate::access::mutable_copy(dictionary.as_concrete_TypeRef()))
        };
    dictionary.set(crate::access::attr_access().as_CFType(), access.clone());
    // SAFETY: a plain add of a dictionary alive for the call; no result is asked for.
    let status = unsafe {
        security_framework_sys::keychain_item::SecItemAdd(dictionary.as_concrete_TypeRef(), std::ptr::null_mut())
    };
    if status == 0 { Ok(()) } else { Err(security_framework::base::Error::from_code(status)) }
}

#[cfg(test)]
#[path = "custody_bundle_tests.rs"]
mod bundle;

#[cfg(test)]
mod tests {
    use super::{Accounts, CustodyError, Item, Keychain};
    use crate::Secret;

    const VALUE: &str = "ed25519-seed-0123456789ZZZtopSECRETvalue";

    fn keychain() -> (tempfile::TempDir, Keychain) {
        let dir = tempfile::tempdir().expect("scratch");
        let k =
            Keychain::create_at(&dir.path().join("proof.keychain-db"), "proof-only").expect("a keychain of its own");
        (dir, k)
    }

    const MAKER: &str = "identifier \"ai.anemnez.exampled\" and anchor apple generic";

    /// The house team's requirement for `identifier`, in the one shape (team-shaped from the trust data, never a
    /// literal team).
    fn team(identifier: &str) -> String {
        format!(
            r#"identifier "{identifier}" and anchor apple generic and certificate leaf[subject.OU] = "{}""#,
            crate::identity::ANEMNEZ_TEAM
        )
    }

    /// An item carried across trusts exactly its team's requirements, read back off its access list with its value
    /// never read, and nothing else, this binary included (D m/37713); its comment still names its maker alone. Any
    /// requirement the trust table doesn't pin to its team is refused by name, nothing written: a leaf CN (a member,
    /// not the team), another team, a cdhash, no identifier, or an identifier outside the house.
    #[test]
    fn an_item_carried_across_trusts_its_teams_requirements_alone() {
        let (_dir, k) = keychain();
        let house = crate::identity::TrustTable::house();
        let item = Item::new("ai.anemnez.example.role", "promoter@node");
        let (now, next) = (team("ai.anemnez.exampled"), team("ai.anemnez.example-app"));
        k.add_trusting(&item, &Secret::new(VALUE.as_bytes().to_vec()), MAKER, &[&now, &next], &house).expect("made");
        let printed = |r: &str| crate::access::requirement(r).expect("parses");
        let mut want = vec![printed(&now), printed(&next)];
        want.sort();
        assert_eq!(k.trusts(&item).expect("its access list reads"), want, "the team's two, and nothing else");
        assert_eq!(k.maker(&item).as_deref(), Some(MAKER), "the note names the maker alone");
        let plain = Item::new("ai.anemnez.example.role", "plain@node");
        k.add(&plain, &Secret::new(VALUE.as_bytes().to_vec()), MAKER).expect("made");
        assert!(!k.trusts(&plain).expect("reads").contains(&printed(&now)), "a plain add trusts this binary alone");
        let refused = [
            "identifier \"ai.anemnez.exampled\" and anchor apple generic and certificate leaf[subject.CN] = \"Apple Development: A Member (ABCDE12345)\"".to_owned(),
            team("ai.anemnez.exampled").replace(crate::identity::ANEMNEZ_TEAM, "ZZZZZZZZZZ"),
            "cdhash H\"0123456789abcdef0123456789abcdef01234567\"".to_owned(),
            format!("anchor apple generic and certificate leaf[subject.OU] = \"{}\"", crate::identity::ANEMNEZ_TEAM),
            team("com.example.elsewhere"),
            format!("{} or anchor apple generic", team("ai.anemnez.exampled")),
            "not a requirement (".to_owned(),
        ];
        for (n, bad) in refused.iter().enumerate() {
            let it = Item::new("ai.anemnez.example.role", format!("bad-{n}@node"));
            let got = k.add_trusting(&it, &Secret::new(VALUE.as_bytes().to_vec()), MAKER, &[&now, bad], &house);
            assert!(matches!(got, Err(super::Trusting::NotTheTeams { .. })), "{bad}: {got:?}");
            assert!(!k.held(&it).expect("reads"), "{bad}: nothing written");
        }
        assert!(matches!(
            k.trusts(&Item::new("ai.anemnez.example.role", "none@node")),
            Err(super::Trusting::Custody(CustodyError::NotHeld(_)))
        ));
    }

    /// A keychain path is absolute or refused by name, nothing made (E m/37831): a relative one would be created in
    /// the person's own Library/Keychains. Whether its items are stamped follows where it lives (D m/37833): under the
    /// user's Library/Keychains yes, anywhere else no, and a path that only spells those words is not under it.
    #[test]
    fn a_keychain_path_is_absolute_and_its_stamping_follows_where_it_lives() {
        // The guard first, so a broken one fails here and never creates a keychain in the person's Library.
        assert!(super::absolute(std::path::Path::new("relative.keychain-db")).is_err(), "a relative path");
        assert!(super::absolute(std::path::Path::new("/tmp/x.keychain-db")).is_ok(), "an absolute one");
        for refused in [
            Keychain::create_at(std::path::Path::new("relative.keychain-db"), "proof-only").err(),
            Keychain::open_at(std::path::Path::new("relative.keychain-db"), "proof-only").err(),
        ] {
            let why = refused.expect("refused");
            assert!(why.contains("give an absolute keychain path"), "{why}");
        }
        let home = std::path::Path::new("/Users/someone");
        assert!(super::stamped_at(std::path::Path::new("/Users/someone/Library/Keychains/x.keychain-db"), Some(home)));
        assert!(!super::stamped_at(std::path::Path::new("/tmp/x/x.keychain-db"), Some(home)));
        assert!(!super::stamped_at(
            std::path::Path::new("/tmp/Users/someone/Library/Keychains/x.keychain-db"),
            Some(home)
        ));
        assert!(
            !super::stamped_at(
                std::path::Path::new("/Users/someone/Library/Keychains/../../x.keychain-db"),
                Some(home)
            ),
            "never by text"
        );
        assert!(!super::stamped_at(std::path::Path::new("/Users/someone/Library/Keychains/x.keychain-db"), None));
        let (_dir, k) = keychain();
        assert!(!k.stamps(), "a test's keychain, under a temporary directory");
        assert!(Keychain::login().stamps(), "the login keychain");
    }

    /// A requirement prints as the framework prints it, so a caller compares it with an item's list without a printer
    /// of its own (F m/37818): the house shape round-trips to what `trusts` reads back, and text that isn't one is refused.
    #[test]
    fn a_requirement_prints_as_an_items_list_reads_it() {
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example.role", "printed@node");
        let now = team("ai.anemnez.exampled");
        let house = crate::identity::TrustTable::house();
        k.add_trusting(&item, &Secret::new(VALUE.as_bytes().to_vec()), MAKER, &[&now], &house).expect("made");
        assert_eq!(k.trusts(&item).expect("reads"), vec![super::printed_requirement(&now).expect("prints")]);
        assert!(matches!(super::printed_requirement("not a requirement ("), Err(super::Trusting::NotTheTeams { .. })));
    }

    /// A rename keeps the access list: a hand-off's `.next` written trusting the team's requirement, moved into place,
    /// still trusts it (F m/37706: a move that took the default list would drop it). Red with rename's plain add. This
    /// binary is on the list only so the row can read what it moves.
    #[test]
    fn a_rename_keeps_every_requirement_the_item_trusted() {
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example.role", "promoter@node");
        let now = team("ai.anemnez.exampled");
        k.add_trusting_unpinned(&item.next(), &Secret::new(VALUE.as_bytes().to_vec()), MAKER, &[&now], true)
            .expect("made");
        let before = k.trusts(&item.next()).expect("reads");
        k.rename(&item.next(), &item, MAKER).expect("moved into place");
        assert_eq!(k.trusts(&item).expect("reads"), before, "every requirement survives the move");
        assert!(before.contains(&crate::access::requirement(&now).expect("parses")));
        assert!(!k.held(&item.next()).expect("reads"), ".next is gone");
        assert_eq!(k.get(&item).expect("reads").expose(|v| v.to_vec()), VALUE.as_bytes());
    }

    /// A stand-in for the fresh process a carry spawns: it answers what it's told.
    struct Says(super::Confirmed);
    impl super::Confirm for Says {
        fn confirms(&self, _: &Item, _: &Secret) -> super::Confirmed {
            self.0.clone()
        }
    }

    /// A `to` the writer reads and a fresh reader can't keeps `from` (D m/38565): the move removes `from` only on
    /// the other reader's word, never on the writer's own read-back; refused or unanswered, both are kept, by name.
    #[test]
    fn a_rename_keeps_the_original_until_another_reader_reads_the_moved_item() {
        let (_dir, k) = keychain();
        for (n, said) in [
            super::Confirmed::Cannot("the placed build can't read it".into()),
            super::Confirmed::Unclear("no answer within its bound".into()),
        ]
        .into_iter()
        .enumerate()
        {
            let item = Item::new("ai.anemnez.example.role", format!("kept-{n}@node"));
            k.add(&item.next(), &Secret::new(VALUE.as_bytes().to_vec()), MAKER).expect("made");
            let moved = k.rename_confirmed(&item.next(), &item, MAKER, &Says(said.clone())).expect("written");
            assert!(matches!(&moved, super::Moved::Kept(why) if !why.is_empty()), "{said:?}: {moved:?}");
            assert!(k.held(&item.next()).expect("reads"), "{said:?}: the original is kept");
            assert!(k.held(&item).expect("reads"), "{said:?}: beside the moved item");
        }
        let item = Item::new("ai.anemnez.example.role", "moved@node");
        k.add(&item.next(), &Secret::new(VALUE.as_bytes().to_vec()), MAKER).expect("made");
        let moved = k.rename_confirmed(&item.next(), &item, MAKER, &Says(super::Confirmed::Reads)).expect("written");
        assert_eq!(moved, super::Moved::Moved);
        assert!(!k.held(&item.next()).expect("reads"), "read by the other reader: the original goes");
    }

    /// A rename never copies the partitions stamped on the item it moves (F m/38557): securityd stamps the item's
    /// creator itself, and an add that sets a partition entry asks for the keychain's password where securityd stamps,
    /// so a copied stamp failed MB16's move with -25293 and dialogs off. The readers survive the move; the planted
    /// stamp doesn't.
    #[test]
    fn a_rename_moves_the_readers_and_never_the_partitions() {
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example.role", "promoter@node");
        let now = team("ai.anemnez.exampled");
        let planted =
            super::Planted { trusted: &[&now], with_self: true, owners: &[], partitions: &["teamid:ZZZZZZZZZZ"] };
        k.add_planted(&item.next(), &Secret::new(VALUE.as_bytes().to_vec()), MAKER, &planted).expect("made");
        assert!(k.listing(&item.next()).expect("reads").partitions.contains(&"teamid:ZZZZZZZZZZ".to_owned()), "posed");
        let readers = k.listing(&item.next()).expect("reads").readers;
        k.rename(&item.next(), &item, MAKER).expect("moved into place");
        let moved = k.listing(&item).expect("reads");
        assert_eq!(moved.readers, readers, "every reader survives the move");
        assert!(
            moved.partitions.is_empty(),
            "no stamp is copied, and a path keychain stamps none: {:?}",
            moved.partitions
        );
        assert_eq!(k.get(&item).expect("reads").expose(|v| v.to_vec()), VALUE.as_bytes());
    }

    /// By hand only (it makes, then deletes, a keychain file of its own under ~/Library/Keychains, where securityd
    /// stamps; never the login keychain): the move F's MB16 carry failed (F m/38557). `.next` trusts this binary by
    /// requirement alone, as a team-only list trusts the placed build, and is stamped with this binary's partition.
    /// The rename's add was refused -25293 while the stamp was copied; now the moved item reads, stamped afresh.
    /// It stays `#[ignore]`, by hand only, and never reaches a gate (rule 10, E m/38563): it makes a keychain in the
    /// person's ~/Library/Keychains, so never un-ignore it for coverage.
    #[test]
    #[ignore = "by hand: a scratch keychain under ~/Library/Keychains, where securityd stamps"]
    fn a_rename_in_a_stamped_keychain_is_stamped_afresh_never_refused() {
        let home = super::home().expect("a home");
        let path = home.join(format!("Library/Keychains/anemnez-proof-{}.keychain-db", std::process::id()));
        let k = Keychain::create_at(&path, "proof-only").expect("a keychain of its own");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(k.stamps(), "securityd stamps here");
            let me = crate::identity::own_requirement().expect("this binary's requirement");
            let item = Item::new("ai.anemnez.example.role", "promoter@node");
            k.add_trusting_unpinned(&item.next(), &Secret::new(VALUE.as_bytes().to_vec()), MAKER, &[&me], false)
                .expect("made");
            let stamped = k.listing(&item.next()).expect("reads").partitions;
            assert_eq!(stamped.len(), 1, "the creator's stamp: {stamped:?}");
            k.rename(&item.next(), &item, MAKER).expect("moved into place, never refused");
            assert_eq!(k.listing(&item).expect("reads").partitions, stamped, "stamped afresh, as the mover");
            assert_eq!(k.get(&item).expect("reads").expose(|v| v.to_vec()), VALUE.as_bytes());
        }));
        drop(k);
        let _ = std::process::Command::new("/usr/bin/security").arg("delete-keychain").arg(&path).status();
        assert!(!path.exists(), "the scratch keychain is gone");
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }

    /// `SECRET.md#a-held-key-is-read-only-by-its-owning-build`: what was put under an item is what
    /// it reads back, a put replaces it, a removed item is not held, and `held` never reads the
    /// value. Never the login keychain.
    #[test]
    fn an_item_holds_what_was_put_under_it() {
        let (_dir, k) = keychain();
        let item = Item::new("ai.anemnez.example.role", "promoter@01a195f1");
        assert!(!k.held(&item).unwrap());
        assert_eq!(k.get(&item).unwrap_err(), CustodyError::NotHeld(item.clone()));
        k.put(&item, Secret::new(VALUE.into())).unwrap();
        assert!(k.held(&item).unwrap());
        assert_eq!(k.get(&item).unwrap().expose(|v| v.to_vec()), VALUE.as_bytes());
        k.put(&item, Secret::new(b"rotated".to_vec())).unwrap();
        assert_eq!(k.get(&item).unwrap().expose(|v| v.to_vec()), b"rotated");
        let other = Item::new("ai.anemnez.example.role", "promoter@another-node");
        assert!(!k.held(&other).unwrap(), "an account is its own item");
        k.remove(&item).unwrap();
        assert!(!k.held(&item).unwrap());
        assert!(matches!(k.remove(&item), Err(CustodyError::NotHeld(_))));
    }

    /// `SECRET.md#a-held-key-is-read-only-by-its-owning-build`: `accounts` names every item under a
    /// service and nothing under another, never reading a value, and an empty service is no error.
    #[test]
    fn accounts_names_each_item_under_its_service_alone() {
        let (_dir, k) = keychain();
        assert_eq!(k.accounts("ai.anemnez.example.copies").unwrap(), Accounts::default());
        for account in ["b", "a", "c"] {
            k.put(&Item::new("ai.anemnez.example.copies", account), Secret::new(VALUE.into())).unwrap();
        }
        k.put(&Item::new("ai.anemnez.example.copies.other", "z"), Secret::new(VALUE.into())).unwrap();
        k.put(&Item::new("ai.anemnez.example", "y"), Secret::new(VALUE.into())).unwrap();
        let found = k.accounts("ai.anemnez.example.copies").unwrap();
        assert_eq!((found.names, found.unreadable), (vec!["a".to_owned(), "b".into(), "c".into()], 0));
        assert!(found.notes.is_empty(), "a plain put leaves no note");
        k.remove(&Item::new("ai.anemnez.example.copies", "b")).unwrap();
        assert_eq!(k.accounts("ai.anemnez.example.copies").unwrap().names, ["a", "c"]);
    }

    /// `SECRET.md#a-held-key-is-read-only-by-its-owning-build`, "locked is not logged out" (N m/15128): on a
    /// locked keychain, `held` and `accounts` answer Unavailable, never "not held" or an empty list, though an
    /// attribute search there finds nothing; unlocked again, the item is there.
    #[test]
    fn a_locked_keychain_is_unavailable_to_an_attribute_search_never_empty() {
        let dir = tempfile::tempdir().expect("scratch");
        let path = dir.path().join("proof.keychain-db");
        let k = Keychain::create_at(&path, "proof-only").expect("a keychain of its own");
        let item = Item::new("ai.anemnez.example.copies", "a");
        k.put(&item, Secret::new(VALUE.into())).unwrap();
        assert!(k.held(&item).unwrap());
        let locked = std::process::Command::new("/usr/bin/security").arg("lock-keychain").arg(&path).status();
        assert!(locked.is_ok_and(|s| s.success()), "locked");
        assert!(matches!(k.held(&item), Err(CustodyError::Unavailable { .. })), "{:?}", k.held(&item));
        assert!(matches!(k.accounts("ai.anemnez.example.copies"), Err(CustodyError::Unavailable { .. })));
        let k = Keychain::open_at(&path, "proof-only").expect("unlocked again");
        assert!(k.held(&item).unwrap(), "unlocked, it's there");
    }

    /// `SECRET.md#a-held-key-is-read-only-by-its-owning-build`: a noted put keeps its note beside the
    /// value, `accounts` returns the note with the name and never the value, a second noted put replaces
    /// both, and a noted put over a plain item adds the note to it.
    #[test]
    fn a_noted_put_keeps_its_note_where_accounts_reads_it() {
        let (_dir, k) = keychain();
        let service = "ai.anemnez.example.copies";
        let (a, b) = (Item::new(service, "a"), Item::new(service, "b"));
        k.put_noted(&a, &Secret::new(VALUE.into()), "1793900000").unwrap();
        assert_eq!(k.get(&a).unwrap().expose(|v| v.to_vec()), VALUE.as_bytes());
        let found = k.accounts(service).unwrap();
        assert_eq!((found.names, found.notes.get("a").map(String::as_str)), (vec!["a".to_owned()], Some("1793900000")));

        k.put_noted(&a, &Secret::new(b"rotated".to_vec()), "1793903600").unwrap();
        assert_eq!(k.get(&a).unwrap().expose(|v| v.to_vec()), b"rotated", "the value is replaced");
        assert_eq!(k.accounts(service).unwrap().notes["a"], "1793903600", "and the note with it");

        k.put(&b, Secret::new(VALUE.into())).unwrap();
        assert!(!k.accounts(service).unwrap().notes.contains_key("b"));
        k.put_noted(&b, &Secret::new(VALUE.into()), "1793907200").unwrap();
        assert_eq!(k.accounts(service).unwrap().notes["b"], "1793907200", "a plain item gains the note");
        assert_eq!(k.accounts(service).unwrap().names, ["a", "b"], "updated in place, never a second item");
    }

    /// `SECRET.md#a-held-key-is-read-only-by-its-owning-build` (F, 2026-11-06): an item another code
    /// identity made (here /usr/bin/security, so its access list admits only that tool) reads as
    /// Unavailable at once, with no dialog and no block, and the process's dialog setting is restored.
    #[test]
    fn another_builds_item_reads_unavailable_without_a_dialog() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proof.keychain-db");
        let k = Keychain::create_at(&path, "proof-only").unwrap();
        assert!(!super::quiet::allowed(), "a non-interactive Keychain turns dialogs off");
        let made = std::process::Command::new("/usr/bin/security")
            .args(["add-generic-password", "-s", "ai.anemnez.example", "-a", "theirs", "-w", "a-test-value"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success(), "security made the item");
        assert!(k.held(&Item::new("ai.anemnez.example", "theirs")).unwrap(), "it is there");
        // D, 2026-11-06: two threads reading at once, each through its own Keychain; none blocks.
        let (tx, rx) = std::sync::mpsc::channel();
        for _ in 0..2 {
            let (tx, path) = (tx.clone(), path.clone());
            std::thread::spawn(move || {
                let k = Keychain::open_at(&path, "proof-only").unwrap();
                for _ in 0..20 {
                    let _ = tx.send(k.get(&Item::new("ai.anemnez.example", "theirs")).map(|_| ()));
                }
            });
        }
        for _ in 0..40 {
            let read =
                rx.recv_timeout(std::time::Duration::from_secs(10)).expect("answered without blocking on a dialog");
            assert!(matches!(read, Err(CustodyError::Unavailable { .. })), "{read:?}");
        }
        assert!(!super::quiet::allowed(), "and dialogs stay off");
    }

    /// A process is one or the other (D, 2026-11-06): once a non-interactive Keychain exists, an
    /// interactive one is refused, naming why, and dialogs stay off.
    #[test]
    fn an_interactive_keychain_is_refused_once_a_quiet_one_exists() {
        let dir = tempfile::tempdir().unwrap();
        let _quiet = Keychain::create_at(&dir.path().join("proof.keychain-db"), "proof-only").unwrap();
        let refused = Keychain::login_interactive().map(|_| ()).unwrap_err();
        assert!(refused.contains("non-interactive"), "{refused}");
        assert!(!super::quiet::allowed(), "dialogs stay off");
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
        assert!(matches!(errors[1], CustodyError::Unavailable { .. }), "locked is unavailable");
        assert!(matches!(errors[2], CustodyError::Unavailable { .. }), "refused is unavailable");
        assert!(matches!(errors[3], CustodyError::Store { .. }));
        for e in &errors {
            let said = format!("{e} {e:?}");
            assert!(!said.contains("SECRET") && !said.contains("ZZZtop"), "{said}");
            assert!(said.contains("ai.anemnez.example"), "it names the item: {said}");
        }
    }
}
