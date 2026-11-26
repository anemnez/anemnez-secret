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

/// How [`adopt`] or [`adopt_existing`] came by the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Adopted {
    /// Nothing was held, so it was made here, now.
    Made,
    /// This build's item was already there.
    Held,
    /// A hand-off to this build was cut short: its `.next` item was moved into place.
    Finished,
    /// A key this product held before custody (a file) was written into its item and read back equal: never a new
    /// key (D m/30267).
    Imported,
}

/// Why no key was adopted. It never names the key's value.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The item holds another key than the one a product held before custody: two keys for one role, refused, never
    /// "the first one wins" (D m/30267). Neither key is named.
    Forked(Item),
    /// A key file another user could read, or that this user doesn't own: never adopted, so a key another process may
    /// have read or written never becomes this build's identity (E m/30362). The path and its mode or owner, never
    /// its bytes.
    NotPrivate { file: std::path::PathBuf, why: String },
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
            Self::Forked(item) => write!(f, "role-key-forked: {item} holds another key than the one this product held"),
            Self::NotPrivate { file, why } => {
                write!(f, "key-file-not-private: {} {why}; make it 0600 and this user's, then adopt it", file.display())
            }
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
///
/// It decides from the item's attributes (`held`, `maker`) before it opens the value (G m/15111): another
/// build's item fails the keychain's access list on `get`, so deciding from `get` would read it as
/// Unavailable, "try later", when what it needs is a hand-off. The value is read only to use it.
pub fn adopt(keychain: &Keychain, item: &Item, made_by: &str) -> Result<(SigningKey, Adopted), SignerError> {
    adopt_or(keychain, item, made_by, || {
        write_key(keychain, item, made_by, ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng), Adopted::Made)
    })
}

/// The key a product held before custody (`key`: its 32 bytes, or 64 hex digits, a newline allowed), brought into
/// `item` for this build (D m/30267). It never mints: nothing held, it writes `key`, reads it back and compares;
/// this build's item held already (a crash after the write, say), it must hold that same key. Two different keys for
/// one role are [`SignerError::Forked`]. Every other case is [`adopt`]'s, by the same [`step`].
///
/// # Errors
/// [`SignerError::NotAKey`] for bytes that aren't a key, [`SignerError::Forked`], and [`adopt`]'s refusals.
pub fn adopt_existing(
    keychain: &Keychain,
    item: &Item,
    made_by: &str,
    key: &[u8],
) -> Result<(SigningKey, Adopted), SignerError> {
    let given = seed_of(item, key)?;
    let public = given.verifying_key();
    let (kept, how) =
        adopt_or(keychain, item, made_by, || write_key(keychain, item, made_by, given, Adopted::Imported))?;
    if kept.verifying_key() != public {
        return Err(SignerError::Forked(item.clone()));
    }
    Ok((kept, how))
}

/// [`adopt_existing`] from the file a product held its key in, with the hand-off ordered by what its readers trust
/// (house node `durable.order`; D m/30267): the item is written, read back and compared first, and only then is the file
/// renamed `<name>.adopted`, never deleted. A crash anywhere leaves the file still authoritative or the item verified
/// equal to it, and a second run finds the item and renames the file.
///
/// # Errors
/// [`SignerError::Store`] for a file that can't be read or renamed, by its path, and [`adopt_existing`]'s refusals,
/// which leave the file as it was.
pub fn adopt_file(
    keychain: &Keychain,
    item: &Item,
    made_by: &str,
    file: &std::path::Path,
) -> Result<(SigningKey, Adopted), SignerError> {
    let bytes = read_private(file)?;
    let adopted = adopt_existing(keychain, item, made_by, &bytes)?;
    let mut name = file.file_name().map(std::ffi::OsStr::to_os_string).unwrap_or_default();
    name.push(".adopted");
    let retired = file.with_file_name(name);
    std::fs::rename(file, &retired)
        .map_err(|e| SignerError::Store(format!("{item} holds the key, but {} wasn't renamed: {e}", file.display())))?;
    Ok(adopted)
}

/// Remove the `<name>.adopted` copy [`adopt_file`] kept (E m/30362), so no host keeps a forgotten copy of its signing
/// key beside the custody item that replaced it. The caller calls it once a later run reads the item as
/// [`Adopted::Held`] and the build that adopted it is last-good, the end of its rollback window; its own rule says when,
/// and this says how, once. What ends the copy is the unlink. The file is overwritten with zeros first, but only as
/// best effort: on a copy-on-write filesystem (APFS) or an SSD the zeros land on new blocks and the old ones stay until
/// reused, so it is never a secure erase (D m/30433). The key's real retirement is the custody item replacing it, and
/// the person's disk encryption. Opened once without following a link, and only a regular file is touched, so a copy
/// swapped for a link never gets its target written (E m/30435). Nothing there is nothing to do.
///
/// # Errors
/// [`SignerError::Store`] naming the path, when it can't be opened, overwritten or removed, or isn't a regular file.
pub fn retire_adopted(file: &std::path::Path) -> Result<bool, SignerError> {
    use std::io::Write as _;
    let mut name = file.file_name().map(std::ffi::OsStr::to_os_string).unwrap_or_default();
    name.push(".adopted");
    let kept = file.with_file_name(name);
    let store = |e: std::io::Error| SignerError::Store(format!("{}: {e}", kept.display()));
    let mut out = match open_no_follow(&kept, true) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(store(e)),
    };
    let meta = out.metadata().map_err(store)?;
    if !meta.is_file() {
        return Err(SignerError::Store(format!("{} isn't a regular file, so it's left alone", kept.display())));
    }
    out.write_all(&vec![0u8; usize::try_from(meta.len()).unwrap_or(0)]).map_err(store)?;
    out.sync_all().map_err(store)?;
    drop(out);
    std::fs::remove_file(&kept).map_err(store)?;
    Ok(true)
}

/// `path` opened once, never through a link (`O_NOFOLLOW`): a link in its place is refused, not followed.
fn open_no_follow(path: &std::path::Path, write: bool) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new().read(!write).write(write).custom_flags(libc::O_NOFOLLOW).open(path)
}

/// A key file's bytes, read from the one handle its owner and mode were checked on (E m/30435): opened without
/// following a link, then that handle's owner and mode read, so nothing can swap the file between the check and the
/// read. Adopted only when it is a regular file, this user's, and owner-only (0600 or tighter).
fn read_private(file: &std::path::Path) -> Result<zeroize::Zeroizing<Vec<u8>>, SignerError> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;
    let store = |e: std::io::Error| SignerError::Store(format!("{}: {e}", file.display()));
    let not = |why: String| SignerError::NotPrivate { file: file.to_path_buf(), why };
    let mut handle = open_no_follow(file, false).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            not("is a link, which is never followed".to_owned())
        } else {
            store(e)
        }
    })?;
    let meta = handle.metadata().map_err(store)?;
    if !meta.is_file() {
        return Err(not("isn't a regular file".to_owned()));
    }
    let me = nix_uid();
    if meta.uid() != me {
        return Err(not(format!("is owned by uid {}, not this user's {me}", meta.uid())));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(not(format!("has mode {:o}, which others can read or write", meta.mode() & 0o777)));
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    handle.read_to_end(&mut bytes).map_err(store)?;
    Ok(bytes)
}

/// This process's effective uid.
fn nix_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// [`step`]'s host for [`adopt`] and [`adopt_existing`]: custody read, then what `step` says, with `make` the one
/// case that writes a key.
fn adopt_or(
    keychain: &Keychain,
    item: &Item,
    made_by: &str,
    make: impl FnOnce() -> Result<(SigningKey, Adopted), SignerError>,
) -> Result<(SigningKey, Adopted), SignerError> {
    match held(keychain, item, made_by)? {
        Some(kept) => Ok(kept),
        None => make(),
    }
}

/// The key this build holds under `item`, read and never made: [`adopt`] without its one write of a new key, for a
/// product that reads its key each time it signs and must never mint there (a key made in a read's place is a new
/// identity, D m/30267). A hand-off cut short is finished, as [`adopt`] finishes it. `None`: nothing is held and no
/// hand-off is pending, so the caller reads what it held before custody, or adopts.
///
/// It decides from the item's attributes before it opens the value, as [`adopt`] does (G m/15111).
///
/// # Errors
/// [`adopt`]'s refusals: Unavailable, another build's, not a key, the store's own.
pub fn held(keychain: &Keychain, item: &Item, made_by: &str) -> Result<Option<(SigningKey, Adopted)>, SignerError> {
    let read = match keychain.held(item) {
        Ok(true) => Read::Held { ours: ours(keychain, item, made_by) },
        Ok(false) => not_held(keychain.held(&item.next()))?,
        Err(CustodyError::Unavailable { .. }) => Read::Unavailable,
        Err(e) => return Err(SignerError::Store(e.to_string())),
    };
    match step(read) {
        Step::Use => {
            let secret = keychain.get(item).map_err(|e| unavailable(keychain, item, made_by, e))?;
            Ok(Some((held_by(keychain, item, made_by, &secret)?, Adopted::Held)))
        }
        Step::RefuseAnothers => Err(SignerError::AnotherBuilds {
            item: item.clone(),
            maker: keychain.maker(item),
            this_build: made_by.to_owned(),
        }),
        Step::FinishHandOff => {
            handoff::finish(keychain, item, made_by).map_err(SignerError::Store)?;
            let secret = keychain.get(item).map_err(|e| unavailable(keychain, item, made_by, e))?;
            Ok(Some((held_by(keychain, item, made_by, &secret)?, Adopted::Finished)))
        }
        Step::Make => Ok(None),
        Step::RefuseUnavailable => Err(SignerError::Unavailable {
            item: item.clone(),
            maker: keychain.maker(item),
            this_build: made_by.to_owned(),
        }),
    }
}

/// Write `key` into `item` for `made_by`, read it back and compare: how [`adopt`] makes one and [`adopt_existing`]
/// imports one, said as `how`.
fn write_key(
    keychain: &Keychain,
    item: &Item,
    made_by: &str,
    key: ed25519_dalek::SigningKey,
    how: Adopted,
) -> Result<(SigningKey, Adopted), SignerError> {
    let made = key.verifying_key();
    let value = zeroize::Zeroizing::new(hex(&key.to_bytes()));
    match keychain.add(item, &Secret::new(value.as_bytes().to_vec()), made_by) {
        Ok(()) => {}
        // Another process made it first: read its, never write over it.
        Err(CustodyError::Exists(_)) => {
            let secret = keychain.get(item).map_err(|e| unavailable(keychain, item, made_by, e))?;
            return Ok((held_by(keychain, item, made_by, &secret)?, Adopted::Held));
        }
        // A keychain that can't be written now (locked) made nothing: said as Unavailable, never as a
        // store failure, so the caller tries later rather than reads it as broken.
        Err(e) => return Err(unavailable(keychain, item, made_by, e)),
    }
    let back = keychain.get(item).map_err(|e| unavailable(keychain, item, made_by, e))?;
    let kept = parse(item, &back)?;
    if kept.verifying_key() != made {
        return Err(SignerError::Store(format!("{item} was written but reads back another key")));
    }
    Ok((kept, how))
}

/// Whether a held item is this build's (D m/37751, m/37792): every entry on its access list is the house's (who reads
/// it, who may change the list, and the partitions naming the code that made it), and its note names this build or its
/// list trusts this build's requirement (a signing change carried across, F m/37706). A requirement is the house's when
/// the trust table pins it to its team or it is this build's own designated requirement (the creator entry a plain
/// `add` writes). A partition is the house's when it is `teamid:<a team the table trusts>`, or `cdhash:<this binary's
/// own>` only when this binary has no team (an ad hoc test build): securityd stamps the real creator and it can't be
/// forged away, so a planted item, even one listing only us under our note with a value its planter chose, carries
/// its planter's stamp and is refused (F m/37773), as is one made by `security add-generic-password` (`apple-tool:`).
/// The owner entry may be empty, the person alone with the keychain password, as every item custody writes leaves it.
/// Read off the item's attributes, never its value, on every read, so a list changed after adoption is refused at the
/// next one. A list that can't be read is not this build's, except on a macOS that doesn't export the call reading a
/// list's requirements: then the note alone, as before carry-across, said once at WARN (D m/37740, m/37770).
fn ours(keychain: &Keychain, item: &Item, made_by: &str) -> bool {
    let noted = keychain.maker(item).as_deref() == Some(made_by);
    let listing = match keychain.listing(item) {
        Ok(listing) => listing,
        Err(crate::custody::Trusting::Unsupported { why, .. }) => {
            note_alone(&why);
            return noted;
        }
        Err(_) => return false,
    };
    let me = crate::access::requirement(made_by).ok();
    let running = crate::identity::own_requirement().ok().and_then(|r| crate::access::requirement(&r).ok());
    let own_cdhash = running
        .as_deref()
        .and_then(|r| r.strip_prefix("cdhash H\""))
        .and_then(|r| r.strip_suffix('"'))
        .map(|hash| format!("cdhash:{}", hash.to_ascii_lowercase()));
    let table = crate::identity::TrustTable::house();
    let teams: Vec<String> = table
        .entries()
        .iter()
        .filter_map(|t| match t {
            crate::identity::Trusted::Anemnez { team } => Some(format!("teamid:{team}")),
            _ => None,
        })
        .collect();
    let house = |r: &str| {
        Some(r) == me.as_deref() || Some(r) == running.as_deref() || crate::access::team_pinned(r, &table).is_ok()
    };
    let made_here = |p: &str| teams.iter().any(|t| t == p) || Some(p) == own_cdhash.as_deref();
    ours_by_access(noted, &listing, keychain.stamps(), me.as_deref(), house, made_here)
}

/// Said once per process at WARN, the first time [`ours`] reads by the note alone, so a host on that fallback is seen
/// (D m/37770): the rule before carry-across, losing nothing it had, but no longer refusing a planted list.
fn note_alone(why: &str) {
    static SAID: std::sync::Once = std::sync::Once::new();
    SAID.call_once(|| {
        tracing::warn!(why, "signer reads a held key's owner by its note alone: access lists can't be read")
    });
}

/// The access list's half of [`ours`], pure: someone reads it and every reader is `house`, every owner is `house` (none
/// is the person alone), it carries a partition where its keychain `stamped` its items, and every partition is
/// `made_here`, and the note names this build (`noted`)
/// or the list trusts its requirement (`me`, as the framework prints it). One entry outside the house refuses it,
/// whatever the note says.
fn ours_by_access(
    noted: bool,
    listing: &crate::custody::Listing,
    stamped: bool,
    me: Option<&str>,
    house: impl Fn(&str) -> bool,
    made_here: impl Fn(&str) -> bool,
) -> bool {
    !listing.readers.is_empty()
        && listing.readers.iter().all(|r| house(r))
        && listing.owners.iter().all(|r| house(r))
        && (!stamped || !listing.partitions.is_empty())
        && listing.partitions.iter().all(|p| made_here(p))
        && (noted || me.is_some_and(|me| listing.readers.iter().any(|r| r == me)))
}

/// Nothing is held under the item: whether a hand-off is pending, by its `.next` item's answer. An answer that isn't one
/// is never "none pending", which would let [`adopt`] make a key beside one that was handed off (F m/37654): a locked
/// keychain is Unavailable, as for the item itself, and any other error is the store's.
fn not_held(next: Result<bool, CustodyError>) -> Result<Read, SignerError> {
    match next {
        Ok(next) => Ok(Read::NotHeld { next }),
        Err(CustodyError::Unavailable { .. }) => Ok(Read::Unavailable),
        Err(e) => Err(SignerError::Store(e.to_string())),
    }
}

/// This build's key from a held item: this build's by [`ours`], read again after the value (a hand-off may have just
/// moved it), and a key.
fn held_by(keychain: &Keychain, item: &Item, made_by: &str, secret: &Secret) -> Result<SigningKey, SignerError> {
    if !ours(keychain, item, made_by) {
        let maker = keychain.maker(item);
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
        let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
        if text.len() != 64 {
            return Err(SignerError::NotAKey(item.clone()));
        }
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| SignerError::NotAKey(item.clone()))?;
        }
        Ok(SigningKey(ed25519_dalek::SigningKey::from_bytes(&bytes)))
    })
}

/// A key from what a product held: its 32 bytes, or 64 hex digits (a newline allowed), as an item holds it.
fn seed_of(item: &Item, key: &[u8]) -> Result<ed25519_dalek::SigningKey, SignerError> {
    if let Ok(seed) = <[u8; 32]>::try_from(key) {
        return Ok(ed25519_dalek::SigningKey::from_bytes(&zeroize::Zeroizing::new(seed)));
    }
    parse(item, &Secret::new(key.to_vec())).map(|k| k.0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        Adopted, Read, SignerError, Step, account, adopt, adopt_existing, adopt_file, held, not_held, note_alone, ours,
        ours_by_access, retire_adopted, step,
    };
    use crate::Secret;
    use crate::custody::CustodyError;
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

    /// A key file as a product keeps one: owner-only.
    fn key_file(path: &std::path::Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, bytes).expect("a key file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("owner-only");
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
        let it = item("node-a");
        // Locked, with dialogs off: custody answers Unavailable, never NotHeld.
        let locked = std::process::Command::new("/usr/bin/security").arg("lock-keychain").arg(&path).status();
        assert!(locked.is_ok_and(|s| s.success()), "locked");
        let got = adopt(&k, &it, ME);
        assert!(matches!(got, Err(SignerError::Unavailable { .. })), "{got:?}");
        let k = Keychain::open_at(&path, "proof-only").expect("unlocked again");
        assert!(!k.held(&it).unwrap_or(true), "nothing was made while it was locked");
    }

    /// An item another code identity made, with no made-by note: whose it is can't be told, so it is
    /// refused, and nothing is made beside it.
    #[test]
    fn an_unnoted_item_of_another_identity_is_never_replaced() {
        let (_dir, k, path) = keychain();
        let theirs = item("node-a");
        let made = std::process::Command::new("/usr/bin/security")
            .args(["add-generic-password", "-s", &theirs.service, "-a", &theirs.account, "-w", "not-ours"])
            .arg(&path)
            .status()
            .expect("security");
        assert!(made.success());
        let got = adopt(&k, &theirs, ME);
        assert!(matches!(got, Err(SignerError::AnotherBuilds { maker: None, .. })), "{got:?}");
        assert!(!k.held(&theirs.next()).unwrap_or(true), "nothing was made beside it");
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

    /// G m/15111: in production another build's item fails the access list, so only its attributes say
    /// whose it is. Written by /usr/bin/security (another code identity) and noted as another build's.
    #[test]
    fn another_builds_item_it_cannot_open_is_refused_as_theirs_not_unavailable() {
        let (_dir, k, path) = keychain();
        let theirs = item("node-a");
        let comment = format!("made by: {OTHER}");
        let made = std::process::Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-s",
                &theirs.service,
                "-a",
                &theirs.account,
                "-j",
                &comment,
                "-w",
                "not-ours",
            ])
            .arg(&path)
            .status()
            .expect("security");
        assert!(made.success());
        let got = adopt(&k, &theirs, ME);
        assert!(matches!(&got, Err(SignerError::AnotherBuilds { maker: Some(m), .. }) if m == OTHER), "{got:?}");
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

    /// A read never makes a key: nothing held is `None` and leaves nothing behind, a held key is read as held, a hand-off
    /// cut short is finished as `adopt` finishes it, and a locked keychain or another build's item is refused as
    /// `adopt` refuses it. Red when `held` mints where `adopt` would.
    #[test]
    fn a_read_never_makes_a_key_and_otherwise_answers_as_adopt_does() {
        let (_dir, k, path) = keychain();
        let it = item("node-a");
        assert!(matches!(held(&k, &it, ME), Ok(None)), "nothing held");
        assert!(!k.held(&it).unwrap_or(true) && !k.held(&it.next()).unwrap_or(true), "and nothing made");
        let (made, _) = adopt(&k, &it, ME).expect("made");
        let (read, how) = held(&k, &it, ME).expect("read").expect("held");
        assert_eq!((read.verifying_key(), how), (made.verifying_key(), Adopted::Held));
        let handed = item("node-b");
        k.add(&handed.next(), &Secret::new(b"44".repeat(32)), ME).expect("the handed-off item");
        let (_, how) = held(&k, &handed, ME).expect("finished").expect("held");
        assert_eq!(how, Adopted::Finished);
        assert!(k.held(&handed).unwrap_or(false) && !k.held(&handed.next()).unwrap_or(true), ".next moved into place");
        let theirs = item("node-c");
        k.add(&theirs, &Secret::new(b"55".repeat(32)), OTHER).expect("another build's item");
        assert!(matches!(held(&k, &theirs, ME), Err(SignerError::AnotherBuilds { .. })));
        let locked = std::process::Command::new("/usr/bin/security").arg("lock-keychain").arg(&path).status();
        assert!(locked.is_ok_and(|s| s.success()), "locked");
        assert!(
            matches!(held(&k, &item("node-d"), ME), Err(SignerError::Unavailable { .. })),
            "never None when locked"
        );
    }

    /// Nothing held under the item, and its `.next` unread: never "no hand-off pending", which would let `adopt` mint
    /// beside a key that was handed off (F m/37654). A locked keychain is Unavailable, any other error the store's.
    #[test]
    fn an_unread_next_is_never_read_as_no_hand_off() {
        let it = item("node-a");
        assert_eq!(not_held(Ok(true)).ok(), Some(Read::NotHeld { next: true }));
        assert_eq!(not_held(Ok(false)).ok(), Some(Read::NotHeld { next: false }));
        let locked = not_held(Err(CustodyError::Unavailable { item: it.next(), status: -25308 }));
        assert_eq!(locked.ok(), Some(Read::Unavailable), "a locked .next is Unavailable");
        let failed = not_held(Err(CustodyError::Store { item: it.next(), status: -25291 }));
        assert!(matches!(failed, Err(SignerError::Store(_))), "any other error is the store's: {failed:?}");
    }

    /// The access list's half of `ours`, every case (D m/37713, m/37751, m/37792): readers, owners and partitions all
    /// the house's, and this build named by its note or its list; one entry outside the house anywhere refuses it.
    #[test]
    fn a_house_only_access_list_is_this_builds_by_list_or_note_and_one_foreign_entry_refuses_it() {
        let house = |r: &str| r.starts_with("team:") || r == "own";
        let made_here = |p: &str| p == "teamid:house";
        let l = |readers: &[&str], owners: &[&str], partitions: &[&str]| crate::custody::Listing {
            readers: readers.iter().map(|r| (*r).to_owned()).collect(),
            owners: owners.iter().map(|r| (*r).to_owned()).collect(),
            partitions: partitions.iter().map(|r| (*r).to_owned()).collect(),
        };
        let ok =
            |noted, listing: &crate::custody::Listing, me| ours_by_access(noted, listing, true, me, house, made_here);
        let here = ["teamid:house"];
        assert!(ok(false, &l(&["team:me", "team:before"], &[], &here), Some("team:me")), "carried across");
        assert!(ok(true, &l(&["own"], &[], &here), Some("team:me")), "a plain add's creator entry, noted");
        assert!(ok(true, &l(&["own"], &["own"], &here), Some("team:me")), "an owner of the house");
        assert!(!ok(false, &l(&["team:me", "cdhash H\"00\""], &[], &here), Some("team:me")), "a planter reads");
        assert!(!ok(true, &l(&["own", "cdhash H\"00\""], &[], &here), Some("team:me")), "noted, planted");
        assert!(!ok(true, &l(&["own", "<any application>"], &[], &here), Some("team:me")), "any application reads");
        assert!(!ok(false, &l(&["team:me", "<unreadable>"], &[], &here), Some("team:me")), "a reader it can't read");
        assert!(!ok(true, &l(&["own"], &["cdhash H\"00\""], &here), Some("team:me")), "a foreign owner");
        assert!(!ok(true, &l(&["own"], &["<any application>"], &here), Some("team:me")), "anyone may re-list");
        assert!(!ok(true, &l(&["own"], &[], &["teamid:house", "cdhash:00"]), Some("team:me")), "a planter's stamp");
        assert!(!ok(true, &l(&["own"], &[], &["apple-tool:"]), Some("team:me")), "made by the security tool");
        assert!(!ok(true, &l(&["own"], &[], &["<unreadable>"]), Some("team:me")), "a stamp that can't be read");
        assert!(!ok(true, &l(&["own"], &[], &[]), Some("team:me")), "no stamp where its keychain stamps");
        let unstamped =
            |listing: &crate::custody::Listing| ours_by_access(true, listing, false, Some("team:me"), house, made_here);
        assert!(unstamped(&l(&["own"], &[], &[])), "a keychain file of its own stamps nothing");
        assert!(!unstamped(&l(&["own"], &[], &["cdhash:00"])), "but a stamp there is still judged");
        assert!(!ok(false, &l(&["team:before"], &[], &here), Some("team:me")), "trusted by neither");
        assert!(!ok(true, &l(&[], &[], &here), Some("team:me")), "an empty list trusts no one");
        assert!(!ok(false, &l(&["team:me"], &[], &here), None), "an own requirement that didn't parse");
    }

    /// On a real keychain (D m/37713, F m/37745): an item listing this build's team requirement beside a code outside
    /// the house is another build's, its value never read; so is one noted as this build's whose list also trusts a
    /// foreign requirement; one trusting the team's requirements alone, this build's among them, is this build's by the
    /// list while its note still names its maker; and a plain add's item is this build's by its note, its creator entry
    /// the running binary's own.
    #[test]
    fn a_planted_item_listing_this_build_beside_its_planter_is_another_builds() {
        let (_dir, k, _) = keychain();
        let team = |id: &str| {
            format!(
                r#"identifier "{id}" and anchor apple generic and certificate leaf[subject.OU] = "{}""#,
                crate::identity::ANEMNEZ_TEAM
            )
        };
        let (me, foreign) = (
            team("ai.anemnez.exampled"),
            team("ai.anemnez.exampled").replace(crate::identity::ANEMNEZ_TEAM, "ZZZZZZZZZZ"),
        );
        let key = Secret::new(b"66".repeat(32));
        let planted = item("node-a");
        k.add_trusting_unpinned(&planted, &key, OTHER, &[&me, &foreign], false).expect("planted beside this build");
        assert!(matches!(held(&k, &planted, &me), Err(SignerError::AnotherBuilds { .. })), "never ours");
        let noted = item("node-b");
        k.add_trusting_unpinned(&noted, &key, &me, &[&foreign], true).expect("noted as ours, a foreign reader too");
        assert!(matches!(held(&k, &noted, &me), Err(SignerError::AnotherBuilds { .. })), "a note excuses nothing");
        let carried = item("node-c");
        k.add_trusting(&carried, &key, OTHER, &[&me], &crate::identity::TrustTable::house()).expect("carried across");
        assert!(ours(&k, &carried, &me), "the team's list names this build");
        assert_eq!(k.maker(&carried).as_deref(), Some(OTHER), "the note still names its maker");
        assert!(!ours(&k, &carried, ME), "a build the list doesn't name");
        let plain = item("node-d");
        k.add(&plain, &key, ME).expect("a plain add");
        assert!(ours(&k, &plain, ME), "by its note, its creator entry the running binary's own");
        // A planter that copies everything ours carries, and adds a house team's partition, still carries its own
        // stamp beside it (D m/37792): here the planter is this binary, so stamp a foreign team for it to be judged.
        let forged = item("node-e");
        k.add_planted(
            &forged,
            &key,
            ME,
            &crate::custody::Planted { trusted: &[], with_self: true, owners: &[], partitions: &["teamid:ZZZZZZZZZZ"] },
        )
        .expect("a foreign team's stamp");
        assert!(matches!(held(&k, &forged, ME), Err(SignerError::AnotherBuilds { .. })), "a foreign partition");
        let tool = item("node-f");
        k.add_planted(
            &tool,
            &key,
            ME,
            &crate::custody::Planted { trusted: &[], with_self: true, owners: &[], partitions: &["apple-tool:"] },
        )
        .expect("as the security tool stamps");
        assert!(matches!(held(&k, &tool, ME), Err(SignerError::AnotherBuilds { .. })), "apple-tool: is no house");
        let owned = item("node-g");
        k.add_planted(
            &owned,
            &key,
            ME,
            &crate::custody::Planted { trusted: &[], with_self: true, owners: &[foreign.as_str()], partitions: &[] },
        )
        .expect("an owner outside the house");
        assert!(matches!(held(&k, &owned, ME), Err(SignerError::AnotherBuilds { .. })), "a foreign owner re-lists");
        let listing = k.listing(&plain).expect("reads");
        assert!(listing.owners.is_empty(), "a plain add's owner is the person alone: {listing:?}");
        assert!(listing.partitions.is_empty(), "securityd stamps nothing in a keychain file of its own: {listing:?}");
    }

    /// The note-alone fallback is said at WARN once per process, never again however often it is taken (D m/37770).
    #[test]
    fn the_note_alone_fallback_is_said_once_at_warn() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Count(Arc<AtomicUsize>);
        impl tracing::Subscriber for Count {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                if *event.metadata().level() == tracing::Level::WARN {
                    self.0.fetch_add(1, Ordering::SeqCst);
                }
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }
        let warned = Arc::new(AtomicUsize::new(0));
        tracing::subscriber::with_default(Count(warned.clone()), || {
            note_alone("this macOS doesn't export SecTrustedApplicationCopyRequirement");
            note_alone("this macOS doesn't export SecTrustedApplicationCopyRequirement");
        });
        assert_eq!(warned.load(Ordering::SeqCst), 1, "said once");
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

    /// D m/30267: a role held only in a file adopts its own key. The same public key before and after, the item written
    /// and read back first, and only then the file renamed `.adopted`, never deleted. Afterwards the item alone serves,
    /// and nothing is minted.
    #[test]
    fn a_file_only_role_adopts_its_own_key_and_the_file_is_renamed_after() {
        let (dir, k, _) = keychain();
        let it = item("01a09ccd-file");
        let seed = [7u8; 32];
        let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let file = dir.path().join("signer.key");
        key_file(&file, &seed);
        let (key, how) = adopt_file(&k, &it, ME, &file).expect("adopted");
        assert_eq!((key.verifying_key(), how), (public, Adopted::Imported));
        assert!(!file.exists(), "the file is no longer authoritative");
        assert_eq!(std::fs::read(dir.path().join("signer.key.adopted")).expect("kept"), seed, "renamed, never deleted");
        let (again, how) = adopt(&k, &it, ME).expect("held");
        assert_eq!((again.verifying_key(), how), (public, Adopted::Held), "the item serves, and nothing is minted");
    }

    /// A crash after the item was written and before the rename: the next run finds this build's item holding the same
    /// key, reads it as held, and renames the file then. A key given as 64 hex digits is the same key as its bytes.
    #[test]
    fn a_crash_after_the_write_is_finished_by_the_next_run_with_no_new_key() {
        let (dir, k, _) = keychain();
        let it = item("01a09ccd-crash");
        let seed = [9u8; 32];
        let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        let (first, how) = adopt_existing(&k, &it, ME, format!("{hex}\n").as_bytes()).expect("imported");
        assert_eq!(how, Adopted::Imported);
        let file = dir.path().join("signer.key");
        key_file(&file, &seed);
        let (second, how) = adopt_file(&k, &it, ME, &file).expect("finished");
        assert_eq!((second.verifying_key(), how), (first.verifying_key(), Adopted::Held));
        assert!(dir.path().join("signer.key.adopted").exists() && !file.exists());
    }

    /// Two different keys for one role are refused by name, never "the first one wins", and the file is left as it
    /// was; another build's item is refused as another build's, the file untouched too.
    #[test]
    fn a_file_and_an_item_that_differ_are_refused_as_forked_and_the_file_is_kept() {
        let (dir, k, _) = keychain();
        let it = item("01a09ccd-forked");
        adopt_existing(&k, &it, ME, &[1u8; 32]).expect("one key held");
        let file = dir.path().join("signer.key");
        key_file(&file, &[2u8; 32]);
        let forked = adopt_file(&k, &it, ME, &file).expect_err("refused");
        assert_eq!(forked, SignerError::Forked(it.clone()));
        assert!(forked.to_string().starts_with("role-key-forked: "), "{forked}");
        assert!(file.exists(), "the file is left as it was");
        let theirs = item("01a09ccd-theirs");
        adopt_existing(&k, &theirs, OTHER, &[3u8; 32]).expect("another build's");
        let refused = adopt_file(&k, &theirs, ME, &file).expect_err("refused");
        assert!(matches!(refused, SignerError::AnotherBuilds { .. }), "{refused:?}");
        assert!(file.exists());
        let garbage = dir.path().join("garbage.key");
        key_file(&garbage, b"not a key");
        assert_eq!(
            adopt_file(&k, &item("01a09ccd-garbage"), ME, &garbage).err(),
            Some(SignerError::NotAKey(item("01a09ccd-garbage")))
        );
        assert!(garbage.exists());
    }

    /// E m/30362: a key file another user could read, or this user doesn't own, is never adopted, and it's left as it
    /// was. Said by name with its mode, never its bytes.
    #[test]
    fn a_key_file_others_can_read_is_refused_by_name_and_left_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let (dir, k, _) = keychain();
        let file = dir.path().join("signer.key");
        key_file(&file, &[5u8; 32]);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("readable by others");
        let refused = adopt_file(&k, &item("01a09ccd-open"), ME, &file).expect_err("refused");
        assert!(matches!(&refused, SignerError::NotPrivate { .. }), "{refused:?}");
        assert!(
            refused.to_string().starts_with("key-file-not-private: ") && refused.to_string().contains("644"),
            "{refused}"
        );
        assert!(file.exists() && !dir.path().join("signer.key.adopted").exists(), "left as it was");
        assert!(
            adopt(&k, &item("01a09ccd-open"), ME).is_ok_and(|(_, how)| how == Adopted::Made),
            "nothing was written"
        );
    }

    /// E m/30362: the kept `.adopted` copy has an end. Retiring it overwrites and removes it; with nothing kept there's
    /// nothing to do. The item still serves.
    #[test]
    fn the_kept_copy_is_retired_overwritten_and_removed() {
        let (dir, k, _) = keychain();
        let it = item("01a09ccd-retire");
        let file = dir.path().join("signer.key");
        key_file(&file, &[6u8; 32]);
        let (adopted, _) = adopt_file(&k, &it, ME, &file).expect("adopted");
        assert_eq!(retire_adopted(&file), Ok(true), "removed");
        assert!(!dir.path().join("signer.key.adopted").exists() && !file.exists());
        assert_eq!(retire_adopted(&file), Ok(false), "nothing kept: nothing to do");
        let (held, how) = adopt(&k, &it, ME).expect("held");
        assert_eq!((held.verifying_key(), how), (adopted.verifying_key(), Adopted::Held));
    }

    /// E m/30435: a key file is checked and read on one handle opened without following a link, so a link in its place
    /// is refused by name, never followed to whatever it points at; and a kept copy swapped for a link is never written
    /// through, its target untouched.
    #[test]
    fn a_link_in_a_key_files_place_is_refused_and_never_written_through() {
        let (dir, k, _) = keychain();
        let target = dir.path().join("elsewhere.key");
        key_file(&target, &[8u8; 32]);
        let file = dir.path().join("signer.key");
        std::os::unix::fs::symlink(&target, &file).expect("a link");
        let refused = adopt_file(&k, &item("01a09ccd-link"), ME, &file).expect_err("refused");
        assert!(matches!(&refused, SignerError::NotPrivate { why, .. } if why.contains("link")), "{refused:?}");
        let other = dir.path().join("other.key");
        std::os::unix::fs::symlink(&target, dir.path().join("other.key.adopted"))
            .expect("a kept copy swapped for a link");
        assert!(retire_adopted(&other).is_err(), "a link is never written through");
        assert_eq!(std::fs::read(&target).expect("the target"), [8u8; 32], "its target is untouched");
    }
}
