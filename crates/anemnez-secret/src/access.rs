//! An item's access list: which code may read its value without a prompt. Custody writes an item trusting this
//! binary, and, for a signing change carried across (F m/37706), further code requirements beside it, so the build
//! placed now and its successor of another designated requirement both read the one item, and a rollback still reads
//! it. Nothing here reads a value: an access list is read off the item's reference alone.
//!
//! The Security framework's legacy keychain access calls, by FFI: `security-framework` wraps none of them.
//! `SecTrustedApplicationCreateFromRequirement` and `SecTrustedApplicationCopyRequirement` are exported by
//! Security.framework but declared only in its private header (SecTrustedApplicationPriv.h); the public alternative,
//! `SecTrustedApplicationCreateFromPath`, needs the other build's binary on disk. So they are never linked: they are
//! resolved at first use by `dlsym` ([`Private`]), and a macOS that stops exporting either answers a named refusal from
//! the carry-across alone, never a product that fails to load (E m/37742, D m/37751).

use std::ffi::{CString, c_char, c_void};

use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::base::{CFAllocatorRef, CFIndex, CFType, OSStatus, TCFType};
use core_foundation::dictionary::{CFDictionaryRef, CFMutableDictionaryRef};
use core_foundation::string::{CFString, CFStringRef};
use security_framework_sys::base::{SecAccessRef, SecKeychainItemRef};

type SecTrustedApplicationRef = *mut c_void;
type SecRequirementRef = *mut c_void;
type SecAclRef = *mut c_void;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecACLAuthorizationDecrypt: CFStringRef;
    static kSecAttrAccess: CFStringRef;
    fn SecTrustedApplicationCreateFromPath(path: *const c_char, app: *mut SecTrustedApplicationRef) -> OSStatus;
    fn SecRequirementCreateWithString(text: CFStringRef, flags: u32, requirement: *mut SecRequirementRef) -> OSStatus;
    fn SecRequirementCopyString(requirement: SecRequirementRef, flags: u32, text: *mut CFStringRef) -> OSStatus;
    fn SecAccessCreate(descriptor: CFStringRef, apps: CFArrayRef, access: *mut SecAccessRef) -> OSStatus;
    fn SecKeychainItemCopyAccess(item: SecKeychainItemRef, access: *mut SecAccessRef) -> OSStatus;
    fn SecAccessCopyACLList(access: SecAccessRef, acls: *mut CFArrayRef) -> OSStatus;
    fn SecACLCopyContents(
        acl: SecAclRef,
        apps: *mut CFArrayRef,
        description: *mut CFStringRef,
        prompt: *mut u16,
    ) -> OSStatus;
    fn SecACLCopyAuthorizations(acl: SecAclRef) -> CFArrayRef;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFDictionaryCreateMutableCopy(
        allocator: CFAllocatorRef,
        capacity: CFIndex,
        dictionary: CFDictionaryRef,
    ) -> CFMutableDictionaryRef;
}

/// A mutable copy of `dictionary`, returned owned (the create rule).
///
/// # Safety
/// `dictionary` must be a live CFDictionary.
pub(crate) unsafe fn mutable_copy(dictionary: CFDictionaryRef) -> CFMutableDictionaryRef {
    // SAFETY: the caller hands a live dictionary; the default allocator and no capacity bound.
    unsafe { CFDictionaryCreateMutableCopy(std::ptr::null(), 0, dictionary) }
}

/// The two private calls, resolved at first use (E m/37742, D m/37751): never linked, so dyld never needs them at launch.
struct Private {
    create_from_requirement:
        unsafe extern "C" fn(*const c_char, SecRequirementRef, *mut SecTrustedApplicationRef) -> OSStatus,
    copy_requirement: unsafe extern "C" fn(SecTrustedApplicationRef, *mut SecRequirementRef) -> OSStatus,
}

/// `name`'s address in the process, or why not, by name.
fn resolve(name: &std::ffi::CStr) -> Result<*mut c_void, String> {
    // SAFETY: a lookup in every image already loaded (RTLD_DEFAULT); `name` is a NUL-terminated string.
    let found = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    if found.is_null() {
        Err(format!(
            "this macOS doesn't export {}: an item can't be made trusting, or read for, a code requirement",
            name.to_string_lossy()
        ))
    } else {
        Ok(found)
    }
}

/// The private calls, resolved once (Security.framework is loaded with custody's public calls).
fn private() -> Result<&'static Private, String> {
    static PRIVATE: std::sync::OnceLock<Result<Private, String>> = std::sync::OnceLock::new();
    PRIVATE
        .get_or_init(|| {
            let create = resolve(c"SecTrustedApplicationCreateFromRequirement")?;
            let copy = resolve(c"SecTrustedApplicationCopyRequirement")?;
            // SAFETY: each address is the exported function of that name, whose signature is the one declared in
            // SecTrustedApplicationPriv.h and above.
            Ok(unsafe {
                Private {
                    create_from_requirement: std::mem::transmute::<
                        *mut c_void,
                        unsafe extern "C" fn(
                            *const c_char,
                            SecRequirementRef,
                            *mut SecTrustedApplicationRef,
                        ) -> OSStatus,
                    >(create),
                    copy_requirement: std::mem::transmute::<
                        *mut c_void,
                        unsafe extern "C" fn(SecTrustedApplicationRef, *mut SecRequirementRef) -> OSStatus,
                    >(copy),
                }
            })
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Why an access list wasn't made or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The framework's status.
    Status(OSStatus),
    /// This macOS doesn't export a private call the carry-across needs, by name.
    Unsupported(String),
}

impl From<OSStatus> for Refused {
    fn from(status: OSStatus) -> Self {
        Self::Status(status)
    }
}

/// What [`trusted`] names a decrypt entry that trusts any application: never a requirement, so never the house's.
pub(crate) const ANY_APPLICATION: &str = "<any application>";

/// The key under which an item's access goes into an add's dictionary.
pub(crate) fn attr_access() -> CFString {
    // SAFETY: an immutable CFString constant the framework exports; wrapped without taking ownership.
    unsafe { CFString::wrap_under_get_rule(kSecAttrAccess) }
}

/// A CF object this module was handed under the create rule, released when dropped.
fn owned(raw: *const c_void) -> Option<CFType> {
    // SAFETY: `raw` was returned by a Copy or Create call, so this side owns one reference.
    (!raw.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(raw) })
}

/// `text` as the framework spells a code requirement: parsed and printed back, so two spellings of one requirement
/// compare equal, and text that isn't one is refused with the framework's status.
pub(crate) fn requirement(text: &str) -> Result<String, OSStatus> {
    let text = CFString::new(text);
    let mut parsed: SecRequirementRef = std::ptr::null_mut();
    // SAFETY: a plain create with an out-parameter.
    let status = unsafe { SecRequirementCreateWithString(text.as_concrete_TypeRef(), 0, &mut parsed) };
    if status != 0 {
        return Err(status);
    }
    let parsed = owned(parsed).ok_or(status)?;
    printed(parsed.as_CFTypeRef().cast_mut())
}

/// A requirement's text, as the framework prints it: the one declaration of `SecRequirementCopyString` here.
pub(crate) fn printed(requirement: SecRequirementRef) -> Result<String, OSStatus> {
    let mut text: CFStringRef = std::ptr::null();
    // SAFETY: a plain copy with an out-parameter; `requirement` is alive for the call.
    let status = unsafe { SecRequirementCopyString(requirement, 0, &mut text) };
    if status != 0 || text.is_null() {
        return Err(status);
    }
    // SAFETY: a Copy call's result, owned here.
    Ok(unsafe { CFString::wrap_under_create_rule(text) }.to_string())
}

/// An access list trusting exactly `requirements`, described as `label` (the name a prompt would show, were one ever
/// shown). This binary is on it only with `with_self` (rows that must read what they wrote): an item a signing change
/// carries across trusts its team's requirements and nothing else (D m/37713), so a planted entry is never on a list
/// custody writes.
pub(crate) fn trusting(label: &str, requirements: &[&str], with_self: bool) -> Result<CFType, Refused> {
    let private = private().map_err(Refused::Unsupported)?;
    let mut apps = Vec::with_capacity(requirements.len() + 1);
    if with_self {
        let mut this: SecTrustedApplicationRef = std::ptr::null_mut();
        // SAFETY: a null path is the calling binary, as the API documents.
        let status = unsafe { SecTrustedApplicationCreateFromPath(std::ptr::null(), &mut this) };
        apps.push(owned(this).filter(|_| status == 0).ok_or(status)?);
    }
    for text in requirements {
        let cf = CFString::new(text);
        let mut parsed: SecRequirementRef = std::ptr::null_mut();
        // SAFETY: as in `requirement`.
        let status = unsafe { SecRequirementCreateWithString(cf.as_concrete_TypeRef(), 0, &mut parsed) };
        let parsed = owned(parsed).filter(|_| status == 0).ok_or(status)?;
        let name = CString::new(*text).map_err(|_| Refused::Status(-50))?;
        let mut app: SecTrustedApplicationRef = std::ptr::null_mut();
        // SAFETY: `parsed` lives for the call; the app is returned owned.
        let status =
            unsafe { (private.create_from_requirement)(name.as_ptr(), parsed.as_CFTypeRef().cast_mut(), &mut app) };
        apps.push(owned(app).filter(|_| status == 0).ok_or(status)?);
    }
    let apps = CFArray::from_CFTypes(&apps);
    let label = CFString::new(label);
    let mut access: SecAccessRef = std::ptr::null_mut();
    // SAFETY: both arguments live for the call; the access is returned owned.
    let status = unsafe { SecAccessCreate(label.as_concrete_TypeRef(), apps.as_concrete_TypeRef(), &mut access) };
    owned(access.cast()).filter(|_| status == 0).ok_or(Refused::Status(status))
}

/// The requirement a team's signature of `identifier` must meet, in the house's one shape (anemnez-xtask's
/// `team_requirement`, fabric-core's `app::requirement`): its identifier, anchored at Apple, the leaf's OU the team.
fn team_shape(team: &str, identifier: &str) -> String {
    format!(r#"identifier "{identifier}" and anchor apple generic and certificate leaf[subject.OU] = "{team}""#)
}

/// `text` as the framework prints it, when it is exactly a team's requirement for an Anemnez identifier and `table`
/// trusts that team under the Anemnez rule (D m/37713): its identifier, anchored at Apple, the leaf's OU the team,
/// nothing more and nothing less. Never a path, a cdhash, a leaf CN (a member, not the team) or another team. The
/// comparison is of printed forms, so a spelling that widens the requirement prints differently and is refused.
///
/// # Errors
/// Why `text` isn't one, by name.
pub(crate) fn team_pinned(text: &str, table: &crate::identity::TrustTable) -> Result<String, String> {
    let printed = requirement(text).map_err(|status| format!("'{text}' is no code requirement (OSStatus {status})"))?;
    let identifier = printed
        .strip_prefix("identifier \"")
        .and_then(|rest| rest.split('"').next())
        .filter(|id| id.starts_with(crate::identity::ANEMNEZ_PREFIX))
        .ok_or_else(|| format!("'{printed}' names no Anemnez identifier first"))?;
    let pinned = table.entries().iter().any(|t| match t {
        crate::identity::Trusted::Anemnez { team } => {
            requirement(&team_shape(team, identifier)).is_ok_and(|p| p == printed)
        }
        _ => false,
    });
    if pinned {
        Ok(printed)
    } else {
        Err(format!(
            "'{printed}' is not a trusted team's requirement for {identifier} (identifier, anchor apple generic, leaf OU)"
        ))
    }
}

/// The access list of `item`, read off its reference.
pub(crate) fn of(item: SecKeychainItemRef) -> Result<CFType, OSStatus> {
    let mut access: SecAccessRef = std::ptr::null_mut();
    // SAFETY: `item` is a live reference the caller holds; the access is returned owned.
    let status = unsafe { SecKeychainItemCopyAccess(item, &mut access) };
    owned(access.cast()).filter(|_| status == 0).ok_or(status)
}

/// The code requirements an access list trusts to read the value (its decrypt entries), each as the framework spells
/// it. A trusted application whose requirement can't be read is left out, never guessed.
pub(crate) fn trusted(access: &CFType) -> Result<Vec<String>, Refused> {
    let private = private().map_err(Refused::Unsupported)?;
    let mut acls: CFArrayRef = std::ptr::null();
    // SAFETY: `access` is alive for the call; the list is returned owned.
    let status = unsafe { SecAccessCopyACLList(access.as_CFTypeRef().cast_mut().cast(), &mut acls) };
    if status != 0 || acls.is_null() {
        return Err(status.into());
    }
    // SAFETY: a Copy call's result, owned here.
    let acls: CFArray<CFType> = unsafe { CFArray::wrap_under_create_rule(acls) };
    // SAFETY: an immutable CFString constant the framework exports.
    let decrypt = unsafe { CFString::wrap_under_get_rule(kSecACLAuthorizationDecrypt) };
    let mut found = Vec::new();
    for acl in acls.iter() {
        let acl = acl.as_CFTypeRef().cast_mut();
        // SAFETY: `acl` is alive while `acls` is; the list is returned owned (a Copy call).
        let auths = unsafe { SecACLCopyAuthorizations(acl) };
        if auths.is_null() {
            continue;
        }
        // SAFETY: as above.
        let auths: CFArray<CFString> = unsafe { CFArray::wrap_under_create_rule(auths) };
        if !auths.iter().any(|a| *a == decrypt) {
            continue;
        }
        let (mut apps, mut description, mut prompt): (CFArrayRef, CFStringRef, u16) =
            (std::ptr::null(), std::ptr::null(), 0);
        // SAFETY: out-parameters only; each result is owned here.
        let status = unsafe { SecACLCopyContents(acl, &mut apps, &mut description, &mut prompt) };
        let _description = owned(description.cast());
        if status != 0 {
            return Err(status.into());
        }
        // A null application list is "any application": never one custody writes, and never the house's, so it is
        // named, for a reader that judges every entry to refuse.
        let Some(apps) = owned(apps.cast()) else {
            found.push(ANY_APPLICATION.to_owned());
            continue;
        };
        // SAFETY: `apps` is a CFArray, as SecACLCopyContents documents.
        let apps: CFArray<CFType> = unsafe { CFArray::wrap_under_get_rule(apps.as_CFTypeRef().cast()) };
        for app in apps.iter() {
            let mut requirement: SecRequirementRef = std::ptr::null_mut();
            // SAFETY: `app` is alive while `apps` is; the requirement is returned owned.
            let status = unsafe { (private.copy_requirement)(app.as_CFTypeRef().cast_mut(), &mut requirement) };
            let Some(requirement) = owned(requirement).filter(|_| status == 0) else { continue };
            if let Ok(text) = printed(requirement.as_CFTypeRef().cast_mut()) {
                found.push(text);
            }
        }
    }
    found.sort();
    found.dedup();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::{Refused, private, resolve, trusting};

    /// A name this macOS doesn't export answers a named refusal, never a panic or a null call (E m/37742); the two
    /// private calls the carry-across needs resolve here.
    #[test]
    fn a_call_this_macos_doesnt_export_is_a_named_refusal() {
        let missing = resolve(c"SecTrustedApplicationNoSuchCall").expect_err("not exported");
        assert!(missing.contains("this macOS doesn't export SecTrustedApplicationNoSuchCall"), "{missing}");
        assert!(private().is_ok(), "this macOS exports both private calls");
        assert!(matches!(trusting("row", &[], false), Ok(_) | Err(Refused::Status(_))), "never Unsupported here");
    }

    /// By hand (D m/37751, 4): run as a test binary signed by the house team, it writes an item on a keychain of its
    /// own trusting only its team's requirement for its own identifier, this binary not on the list, and reads the value
    /// back with dialogs off: a team build reading a team-only list with no prompt, the reader's path. No person's key
    /// signs a test, so it never runs in a gate: sign the test binary as the team and run it with `--ignored`. F's
    /// step-1 read-back on release-signed builds is the same proof on every host.
    #[test]
    #[ignore = "by hand: needs a test binary signed by the house team"]
    fn a_team_build_reads_a_team_only_list_with_no_prompt() {
        use crate::Secret;
        use crate::custody::{Item, Keychain};
        let own = crate::identity::own().expect("this binary's identity");
        assert_eq!(own.team, crate::identity::ANEMNEZ_TEAM, "sign this test binary as the house team first");
        let team = format!(
            r#"identifier "{}" and anchor apple generic and certificate leaf[subject.OU] = "{}""#,
            own.identifier, own.team
        );
        let dir = tempfile::tempdir().expect("scratch");
        let k = Keychain::create_at(&dir.path().join("by-hand.keychain-db"), "proof-only").expect("its own");
        let item = Item::new("ai.anemnez.example.role", "by-hand@node");
        let made_by = crate::identity::own_requirement().expect("its requirement");
        k.add_trusting(
            &item,
            &Secret::new(b"77".repeat(32)),
            &made_by,
            &[&team],
            &crate::identity::TrustTable::house(),
        )
        .expect("made, trusting the team alone");
        assert!(!k.trusts(&item).expect("reads").iter().any(|r| r.starts_with("cdhash")), "this binary isn't listed");
        let read = k.get(&item).expect("read through the team's requirement, no prompt");
        assert_eq!(read.expose(|v| v.to_vec()), b"77".repeat(32));
    }
}
