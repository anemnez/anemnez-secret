//! A caller is known by its code signature, judged in one place (`docs/specs/SECRET.md`
//! `#a-caller-is-known-by-its-code-signature`; moved from fabric's step 0, `fabricd/src/writers.rs`).
//!
//! The code behind a local connection is found by the socket's audit token (`LOCAL_PEERTOKEN`), never by a
//! pid, which can be reused. It must be Apple-anchored and strictly valid (`SecCodeCheckValidity` with
//! `kSecCSStrictValidate`), run with the hardened runtime, and carry none of the entitlements that would let
//! another process change what it runs. Only then are its team and signing identifier read, so a caller can
//! never name itself. Which identities may do what is a [`TrustTable`]: data, never a constant in a
//! decision (fabric `ACCESS.md#no-decision-names-a-publisher`). A product's default trust is its own team,
//! read from its own signature by [`own`], never from a file another process could edit.
//!
//! A verdict vouches for the process that CONNECTED, at connect, not for whoever later holds the socket.
//! A verified process that passes its connection on (`SCM_RIGHTS`, or an fd inherited without CLOEXEC;
//! std and tokio sockets are CLOEXEC) lends its identity to the receiver, so a product never passes its
//! connection on.

/// The hardened runtime's code-signing flag (`CS_RUNTIME`).
pub const HARDENED_RUNTIME: u32 = 0x10000;

/// Entitlements that let another process change what a signed one runs (a debugger, injected libraries,
/// `DYLD_*` variables): a verified caller carries none of them.
pub const TAMPERING: [&str; 3] = [
    "com.apple.security.get-task-allow",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-dyld-environment-variables",
];

/// The requirement a verified caller's code meets: Apple-anchored, any team. Which teams are trusted is
/// the table's. A certificate a host made itself, an ad hoc signature or none at all fails it.
pub const APPLE_ANCHORED: &str = "anchor apple generic";

/// Who a verified caller is: read from its signature after the checks passed.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identity {
    pub team: String,
    pub identifier: String,
}

/// What a signature that met the requirement says, before [`judge`] decides whether it is untamperable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub team: String,
    pub identifier: String,
    pub flags: u32,
    pub entitlements: Vec<String>,
}

/// Whether a signature that met the requirement belongs to an untamperable caller: the hardened runtime
/// and none of [`TAMPERING`]. Err says why not.
pub fn judge(signature: Signature) -> Result<Identity, String> {
    if signature.flags & HARDENED_RUNTIME == 0 {
        return Err(format!(
            "{} does not run with the hardened runtime",
            signature.identifier
        ));
    }
    if let Some(entitlement) = signature
        .entitlements
        .iter()
        .find(|e| TAMPERING.contains(&e.as_str()))
    {
        return Err(format!("{} carries {entitlement}", signature.identifier));
    }
    Ok(Identity {
        team: signature.team,
        identifier: signature.identifier,
    })
}

/// The identity of the process at the other end of a local (unix) socket, or why it has none.
#[cfg(target_os = "macos")]
pub fn of_peer(socket: std::os::fd::BorrowedFd<'_>) -> Result<Identity, String> {
    judge(signature_of_peer(socket, APPLE_ANCHORED)?)
}

#[cfg(not(target_os = "macos"))]
pub fn of_peer(_: std::os::fd::BorrowedFd<'_>) -> Result<Identity, String> {
    Err("this OS has no code signatures to read".to_owned())
}

/// This process's own identity, by the same strict check (`SecCodeCopySelf`): what a product's default
/// trust is built on ("my own team"), so it never names a publisher and never reads one from config.
#[cfg(target_os = "macos")]
pub fn own() -> Result<Identity, String> {
    judge(macos::check(&macos::guest_self()?, APPLE_ANCHORED)?)
}

#[cfg(not(target_os = "macos"))]
pub fn own() -> Result<Identity, String> {
    Err("this OS has no code signatures to read".to_owned())
}

/// A local socket's peer's audit token, as the kernel recorded it at connect: an `audit_token_t`.
#[cfg(target_os = "macos")]
fn audit_token(socket: std::os::fd::BorrowedFd<'_>) -> Result<Vec<u8>, String> {
    use std::os::fd::AsRawFd;
    // sys/un.h: SOL_LOCAL 0, LOCAL_PEERTOKEN 6, an audit_token_t of eight u32s.
    let mut token = [0u8; 32];
    let mut len = token.len() as libc::socklen_t;
    // SAFETY: a valid socket fd, and a buffer of `len` bytes for getsockopt to fill.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            0,
            6,
            token.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "its audit token cannot be read: {}",
            std::io::Error::last_os_error()
        ));
    }
    let len = usize::try_from(len).map_err(|e| e.to_string())?;
    Ok(token[..len].to_vec())
}

/// The pid in a local socket's peer's audit token (its sixth word), from the kernel at connect: which
/// process connected, so a holder can require the one child it started (retrust).
#[cfg(target_os = "macos")]
pub fn peer_pid(socket: std::os::fd::BorrowedFd<'_>) -> Result<i32, String> {
    let token = audit_token(socket)?;
    let word = token
        .get(20..24)
        .ok_or_else(|| "its audit token is too short to name a pid".to_owned())?;
    Ok(i32::from_ne_bytes([word[0], word[1], word[2], word[3]]))
}

/// The signature of the code behind a local socket's peer, if it meets `requirement`.
#[cfg(target_os = "macos")]
pub fn signature_of_peer(
    socket: std::os::fd::BorrowedFd<'_>,
    requirement: &str,
) -> Result<Signature, String> {
    macos::check(&macos::guest_by_audit(&audit_token(socket)?)?, requirement)
}

/// One row of a host's trust table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trusted {
    /// The Anemnez rule for one team: its `ai.anemnez.<product>` writes what that product owns (who owns
    /// what is the caller's to say: [`TrustTable::admits`]'s `owner`).
    Anemnez { team: String },
    /// One other team's process, scoped to exactly one segment. Added by a person, never by code.
    Scoped {
        team: String,
        identifier: String,
        segment: String,
    },
}

/// Who a host trusts, and with what: data a person can change, never a constant in a decision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustTable {
    entries: Vec<Trusted>,
}

/// Every Anemnez signing identifier starts so: `ai.anemnez.<product>`.
pub const ANEMNEZ_PREFIX: &str = "ai.anemnez.";

impl TrustTable {
    pub fn new(entries: Vec<Trusted>) -> Self {
        Self { entries }
    }

    /// The default data: the Anemnez rule for `team` and nothing else (the User's interim policy, 2026-11-05:
    /// Anemnez-managed apps only). Where the team comes from (a host's trust policy) is the caller's.
    pub fn anemnez(team: &str) -> Self {
        Self::new(vec![Trusted::Anemnez {
            team: team.to_owned(),
        }])
    }

    pub fn entries(&self) -> &[Trusted] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `who` is under the Anemnez rule here (its team has an [`Trusted::Anemnez`] row).
    pub fn is_anemnez(&self, who: &Identity) -> bool {
        self.entries
            .iter()
            .any(|t| matches!(t, Trusted::Anemnez { team } if *team == who.team))
    }

    /// Whether `who` may write `segment`, whose owner under the Anemnez rule is the product `owner` (None
    /// when no product owns it). A scoped row admits exactly its one segment; the Anemnez rule admits
    /// `ai.anemnez.<owner>` of a trusted team; nothing else is admitted. Err says why not.
    pub fn admits(&self, who: &Identity, segment: &str, owner: Option<&str>) -> Result<(), String> {
        let scoped = self.entries.iter().any(|t| {
            matches!(t, Trusted::Scoped { team, identifier, segment: s }
                if *team == who.team && *identifier == who.identifier && s == segment)
        });
        if scoped {
            return Ok(());
        }
        let Identity { team, identifier } = who;
        if !self.is_anemnez(who) {
            return Err(format!(
                "{identifier} (team {team}) is no team this host trusts to write, so it may only read"
            ));
        }
        match owner {
            Some(product) if identifier.strip_prefix(ANEMNEZ_PREFIX) == Some(product) => Ok(()),
            Some(product) => Err(format!(
                "'{segment}' belongs to {product} ({ANEMNEZ_PREFIX}{product}), not {identifier}"
            )),
            None => Err(format!(
                "no product here owns '{segment}', so {identifier} may not write it"
            )),
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use core_foundation::base::{CFRelease, CFType, CFTypeRef, TCFType};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use security_framework_sys::code_signing::{
        SecCodeCheckValidity, SecCodeCopyGuestWithAttributes, SecCodeRef,
        SecRequirementCreateWithString, SecRequirementRef, kSecCSStrictValidate,
        kSecGuestAttributeAudit,
    };

    // Security.framework, not in security-framework-sys: the signing information of a (running) code.
    unsafe extern "C" {
        fn SecCodeCopySigningInformation(
            code: CFTypeRef,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> i32;
    }
    /// kSecCSSigningInformation | kSecCSRequirementInformation | kSecCSDynamicInformation.
    const INFORMATION: u32 = (1 << 1) | (1 << 2) | (1 << 3);

    /// A running code, owned (+1), released on drop.
    pub(super) struct Code(SecCodeRef);

    impl Drop for Code {
        fn drop(&mut self) {
            // SAFETY: ours (+1), released once.
            unsafe { CFRelease(self.0.cast()) };
        }
    }

    fn guest(attribute: CFString, value: CFType) -> Result<Code, String> {
        let attrs = CFDictionary::from_CFType_pairs(&[(attribute.as_CFType(), value)]);
        let mut code: SecCodeRef = std::ptr::null_mut();
        // SAFETY: a null host (the system) and a well-formed attribute dictionary; `code` is +1 on success.
        let status = unsafe {
            SecCodeCopyGuestWithAttributes(
                std::ptr::null_mut(),
                attrs.as_concrete_TypeRef(),
                0,
                &mut code,
            )
        };
        if status != 0 || code.is_null() {
            return Err(format!(
                "its running code cannot be found (OSStatus {status})"
            ));
        }
        Ok(Code(code))
    }

    /// This process's own running code.
    pub(super) fn guest_self() -> Result<Code, String> {
        let mut code: SecCodeRef = std::ptr::null_mut();
        // SAFETY: default flags; `code` is +1 on success.
        let status = unsafe { security_framework_sys::code_signing::SecCodeCopySelf(0, &mut code) };
        if status != 0 || code.is_null() {
            return Err(format!(
                "its own running code cannot be found (OSStatus {status})"
            ));
        }
        Ok(Code(code))
    }

    /// The running code an audit token names.
    pub(super) fn guest_by_audit(token: &[u8]) -> Result<Code, String> {
        // SAFETY: a static CFString constant.
        let key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributeAudit) };
        guest(key, CFData::from_buffer(token).as_CFType())
    }

    /// The running code a pid names: for tests only, which have no other process's audit token at hand.
    #[cfg(test)]
    pub(super) fn guest_by_pid(pid: i32) -> Result<Code, String> {
        use security_framework_sys::code_signing::kSecGuestAttributePid;
        // SAFETY: a static CFString constant.
        let key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributePid) };
        guest(key, CFNumber::from(pid).as_CFType())
    }

    /// Whether `code` meets `requirement`, validated strictly, and what its signature then says. Nothing is
    /// read from the signature before the check passes.
    pub(super) fn check(code: &Code, requirement: &str) -> Result<super::Signature, String> {
        let mut req: SecRequirementRef = std::ptr::null_mut();
        let text = CFString::new(requirement);
        // SAFETY: a well-formed requirement string; `req` is +1 on success.
        let status =
            unsafe { SecRequirementCreateWithString(text.as_concrete_TypeRef(), 0, &mut req) };
        if status != 0 || req.is_null() {
            return Err(format!(
                "the requirement does not parse (OSStatus {status})"
            ));
        }
        // SAFETY: both refs are valid.
        let status = unsafe { SecCodeCheckValidity(code.0, kSecCSStrictValidate, req) };
        // SAFETY: ours (+1), released once.
        unsafe { CFRelease(req.cast()) };
        if status != 0 {
            return Err(format!(
                "its code is not Apple-anchored and strictly valid (OSStatus {status})"
            ));
        }
        let mut info: CFDictionaryRef = std::ptr::null();
        // SAFETY: a valid code ref (a SecCode is accepted where a SecStaticCode is); `info` is +1 on success.
        let status =
            unsafe { SecCodeCopySigningInformation(code.0.cast(), INFORMATION, &mut info) };
        if status != 0 || info.is_null() {
            return Err(format!(
                "its signing information cannot be read (OSStatus {status})"
            ));
        }
        // SAFETY: a +1 dictionary, owned from here.
        let info: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_create_rule(info) };
        let get = |key: &str| info.find(CFString::new(key)).map(|v| v.clone());
        let text = |key: &str| {
            get(key)
                .and_then(|v| v.downcast::<CFString>())
                .map(|s| s.to_string())
        };
        let identifier = text("identifier").ok_or("its signature names no identifier")?;
        let team = text("teamid").ok_or("its signature names no team")?;
        let flags = get("flags")
            .and_then(|v| v.downcast::<CFNumber>())
            .and_then(|n| n.to_i64())
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(0);
        let entitlements = get("entitlements-dict")
            .and_then(|v| v.downcast::<CFDictionary>())
            .map(|d| {
                let (keys, _) = d.get_keys_and_values();
                keys.into_iter()
                    // SAFETY: the keys of an entitlements dictionary are CFStrings, borrowed from it.
                    .map(|k| unsafe { CFString::wrap_under_get_rule(k.cast()) }.to_string())
                    .collect()
            })
            .unwrap_or_default();
        Ok(super::Signature {
            team,
            identifier,
            flags,
            entitlements,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEAM: &str = "P9DJA3JCKP";

    fn signature(identifier: &str, flags: u32, entitlements: &[&str]) -> Signature {
        Signature {
            team: TEAM.to_owned(),
            identifier: identifier.to_owned(),
            flags,
            entitlements: entitlements.iter().map(|e| (*e).to_owned()).collect(),
        }
    }

    fn id(team: &str, identifier: &str) -> Identity {
        Identity {
            team: team.into(),
            identifier: identifier.into(),
        }
    }

    /// Only an untamperable signature is an identity: the hardened runtime, and none of the three
    /// entitlements that let another process change what it runs.
    #[test]
    fn only_a_hardened_untamperable_signature_is_an_identity() {
        let herald = id(TEAM, "ai.anemnez.herald");
        assert_eq!(
            judge(signature("ai.anemnez.herald", HARDENED_RUNTIME, &[])),
            Ok(herald.clone())
        );
        assert!(
            judge(signature("ai.anemnez.herald", 0, &[]))
                .expect_err("soft")
                .contains("hardened runtime")
        );
        for entitlement in TAMPERING {
            let open = judge(signature(
                "ai.anemnez.herald",
                HARDENED_RUNTIME,
                &[entitlement],
            ))
            .expect_err("open");
            assert!(open.contains(entitlement), "{open}");
        }
        let harmless = signature(
            "ai.anemnez.herald",
            HARDENED_RUNTIME,
            &["com.apple.security.network.client"],
        );
        assert_eq!(judge(harmless), Ok(herald));
    }

    /// The table decides, never a constant: the Anemnez rule admits a trusted team's product to what it
    /// owns; another team, or the same name from another team, only reads until a person scopes it to
    /// exactly one segment.
    #[test]
    fn the_trust_table_admits_an_owner_and_a_scoped_entry_and_nothing_else() {
        let table = TrustTable::anemnez(TEAM);
        let herald = id(TEAM, "ai.anemnez.herald");
        assert_eq!(table.admits(&herald, "herald", Some("herald")), Ok(()));
        assert!(
            table
                .admits(&herald, "artichoke", Some("artichoke"))
                .expect_err("foreign")
                .contains("belongs to artichoke")
        );
        assert!(
            table
                .admits(&herald, "nobody", None)
                .expect_err("unowned")
                .contains("no product here owns")
        );
        let posing = id("ABCDE12345", "ai.anemnez.herald");
        assert!(
            table
                .admits(&posing, "herald", Some("herald"))
                .expect_err("posing")
                .contains("no team this host trusts")
        );
        let theirs = id("ABCDE12345", "com.example.telegram");
        assert!(
            table.admits(&theirs, "telegram", None).is_err(),
            "read-only by default"
        );
        let mut entries = table.entries().to_vec();
        entries.push(Trusted::Scoped {
            team: "ABCDE12345".into(),
            identifier: "com.example.telegram".into(),
            segment: "telegram".into(),
        });
        let scoped = TrustTable::new(entries);
        assert_eq!(scoped.admits(&theirs, "telegram", None), Ok(()));
        assert!(
            scoped.admits(&theirs, "herald", Some("herald")).is_err(),
            "only its one segment"
        );
        assert!(!scoped.is_anemnez(&theirs) && scoped.is_anemnez(&herald));
        assert!(
            TrustTable::default()
                .admits(&herald, "herald", Some("herald"))
                .is_err(),
            "an empty table admits nobody"
        );
    }

    /// The real Security calls on a running Apple binary: it passes the strict Apple-anchored check and
    /// only then is its signature read, which names no team (a platform binary), so it is no identity. A
    /// requirement it does not meet stops it before anything is read.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_running_codes_signature_is_read_only_after_it_is_validated() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("sleep");
        let pid = i32::try_from(child.id()).expect("pid");
        let code = macos::guest_by_pid(pid).expect("its code");
        let anchored = macos::check(&code, APPLE_ANCHORED);
        let unmet = macos::check(&code, "identifier \"ai.anemnez.herald\"");
        drop(child.kill());
        drop(child.wait());
        assert!(
            anchored.expect_err("no team").contains("names no team"),
            "validated, then read"
        );
        assert!(
            unmet
                .expect_err("unmet")
                .contains("not Apple-anchored and strictly valid")
        );
    }

    /// `own()` reads this process's own code through the same strict check: the test binary is linker-signed
    /// ad hoc, so it is no identity, and a product's default trust can never come from such a build.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_process_knows_its_own_identity_by_the_same_check() {
        let mine = own().expect_err("an ad hoc test binary");
        assert!(mine.contains("not Apple-anchored"), "{mine}");
    }

    /// The audit-token path, for real: a socket pair inside this test, so the peer is this test binary,
    /// which is linker-signed ad hoc and so is no identity. Its audit token is read and its code found.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_peers_audit_token_finds_its_code_and_an_ad_hoc_peer_is_no_identity() {
        use std::os::fd::AsFd;
        let (ours, _theirs) = std::os::unix::net::UnixStream::pair().expect("a pair");
        let found = of_peer(ours.as_fd()).expect_err("an ad hoc test binary");
        assert!(
            found.contains("not Apple-anchored"),
            "the token was read and the code checked: {found}"
        );
    }
}
