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
//! **Every check here BLOCKS, and may take seconds**: a strict validation re-hashes the binary. Never
//! call [`of_peer`], [`of_peer_cached`], [`signature_of_peer`] or [`own`] on an async worker: run them
//! through `spawn_blocking` or a small bounded pool, so a burst of connections queues instead of
//! taking the threads other work needs (D, 2026-11-06: the swarm's quorum losses were raft starved by
//! these checks on its runtime). The crate stays synchronous on purpose; callers wrap it.
//!
//! [`Verdicts`] caches a check per process: keyed by the peer's full audit token (its pid and
//! pidversion, which changes on every exec), so a reconnecting process is checked once, and a reused
//! pid or an exec'd process never meets a stale verdict. Only lasting answers are cached (a verified
//! identity, or a refusal the signature itself gives), never a transient failure.
//!
//! A verdict vouches for the process the audit token named when it was read (a live read of whoever
//! holds the socket's peer pid then, not a record of the connector: [`audit_token_words`]), not for
//! whoever later holds the socket.
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
        return Err(format!("{} does not run with the hardened runtime", signature.identifier));
    }
    if let Some(entitlement) = signature.entitlements.iter().find(|e| TAMPERING.contains(&e.as_str())) {
        return Err(format!("{} carries {entitlement}", signature.identifier));
    }
    Ok(Identity { team: signature.team, identifier: signature.identifier })
}

/// The identity of the process at the other end of a local (unix) socket, or why it has none.
/// BLOCKS, possibly for seconds: never on an async worker (see the module docs).
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
/// BLOCKS, possibly for seconds: never on an async worker (see the module docs).
#[cfg(target_os = "macos")]
pub fn own() -> Result<Identity, String> {
    judge(macos::check(&macos::guest_self()?, APPLE_ANCHORED)?)
}

#[cfg(not(target_os = "macos"))]
pub fn own() -> Result<Identity, String> {
    Err("this OS has no code signatures to read".to_owned())
}

/// Refusals that come from the signature itself, so they hold for the life of the process and may be
/// cached. Anything else (a token that cannot be read, a process gone, an OS error) is transient.
const LASTING: [&str; 5] = [
    "does not run with the hardened runtime",
    " carries ",
    "is not Apple-anchored and strictly valid",
    "its signature names no identifier",
    "its signature names no team",
];

fn lasting(refusal: &str) -> bool {
    LASTING.iter().any(|p| refusal.contains(p))
}

/// One cached verdict: when it was checked, and what the check said.
type Held = std::collections::HashMap<Vec<u8>, (std::time::Instant, Result<Identity, String>)>;

/// Checks per process, keyed by the full audit token (see the module docs). Plain std: the lock is
/// never held while a check runs.
pub struct Verdicts {
    /// How long a verified identity is kept.
    ttl: std::time::Duration,
    /// How long a refusal is kept: shorter, since a running process can fail strict validity briefly
    /// while its binary on disk is being replaced (an upgrade), and that must clear quickly (D,
    /// 2026-11-06).
    refused_ttl: std::time::Duration,
    cap: usize,
    held: std::sync::Mutex<Held>,
}

impl Verdicts {
    /// A cache that keeps a verified identity for `ttl`, a refusal for `refused_ttl`, and at most `cap`
    /// verdicts (say 10 min, 60 s and 1024).
    pub fn new(ttl: std::time::Duration, refused_ttl: std::time::Duration, cap: usize) -> Self {
        Self { ttl, refused_ttl, cap, held: std::sync::Mutex::default() }
    }

    /// The verdict for `token`: the cached one while it is fresh, else `check`'s, cached when it is
    /// lasting.
    pub fn get_or_check(
        &self,
        token: &[u8],
        check: impl FnOnce() -> Result<Identity, String>,
    ) -> Result<Identity, String> {
        let now = std::time::Instant::now();
        if let Some((at, verdict)) = self.lock().get(token)
            && self.fresh(verdict, *at, now)
        {
            return verdict.clone();
        }
        let verdict = check();
        if verdict.as_ref().err().is_none_or(|e| lasting(e)) {
            let mut held = self.lock();
            if held.len() >= self.cap {
                held.retain(|_, (at, verdict)| self.fresh(verdict, *at, now));
                if held.len() >= self.cap
                    && let Some(oldest) = held.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| k.clone())
                {
                    held.remove(&oldest);
                }
            }
            held.insert(token.to_vec(), (now, verdict.clone()));
        }
        verdict
    }

    /// Whether a verdict checked at `at` still holds at `now`: a verified one for `ttl`, a refusal for
    /// the shorter `refused_ttl`.
    fn fresh(&self, verdict: &Result<Identity, String>, at: std::time::Instant, now: std::time::Instant) -> bool {
        let ttl = if verdict.is_ok() { self.ttl } else { self.refused_ttl };
        now.duration_since(at) < ttl
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// [`of_peer`] through `verdicts`: the audit token is read per connection (cheap), and the code-signing
/// check runs only on a miss. BLOCKS on a miss, possibly for seconds.
#[cfg(target_os = "macos")]
pub fn of_peer_cached(verdicts: &Verdicts, socket: std::os::fd::BorrowedFd<'_>) -> Result<Identity, String> {
    let token = audit_token(socket)?;
    verdicts.get_or_check(&token, || judge(macos::check(&macos::guest_by_audit(&token)?, APPLE_ANCHORED)?))
}

/// A local socket's peer's whole audit token (`audit_token_t`'s eight words: auid, euid, egid, ruid,
/// rgid, pid, asid, pidversion): the ONE `LOCAL_PEERTOKEN` read every product calls (anemnez-service
/// docs/specs/SHARED.md; anemnez-service `product::peer` re-exports it). Cheap: one getsockopt, no
/// signature check. A short answer is an error, never a zero-filled token.
///
/// It is a LIVE read, not a record made at connect (H, 2026-11-09, measured): the kernel builds it from
/// whatever process holds the socket's peer pid NOW, the last process to use the socket. After the
/// connector execs it names the new image (a new pidversion), and a forked child writing on an
/// inherited connection can be the one named. Read it at accept and keep what you read. What it proves is
/// "the process using this socket now, by its holder's choice" (agora AGORA.md
/// #what-a-peers-audit-token-proves); nothing authorizes on it alone before the PROC_PIDFDSOCKETINFO
/// socket match.
#[cfg(target_os = "macos")]
pub fn audit_token_words(socket: std::os::fd::BorrowedFd<'_>) -> Result<[u32; 8], String> {
    use std::os::fd::AsRawFd;
    let mut token = [0u32; 8];
    let mut len = std::mem::size_of_val(&token) as libc::socklen_t;
    // SAFETY: a valid socket fd, and a buffer of `len` bytes (an audit_token_t) for getsockopt to fill.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!("its audit token cannot be read: {}", std::io::Error::last_os_error()));
    }
    if len as usize != std::mem::size_of_val(&token) {
        return Err(format!("LOCAL_PEERTOKEN answered {len} bytes, not an audit token"));
    }
    Ok(token)
}

/// [`audit_token_words`] as the kernel's 32 bytes, for a daemon that hands its peer's token to Agora's
/// `WhoIs` (agora-client), which names a process by this token and never by a pid (LADON.md §5b).
#[cfg(target_os = "macos")]
pub fn audit_token(socket: std::os::fd::BorrowedFd<'_>) -> Result<Vec<u8>, String> {
    Ok(audit_token_words(socket)?.iter().flat_map(|w| w.to_ne_bytes()).collect())
}

/// A process, exactly: its pid and the version of that pid (a pid reused, or an exec, is another version).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Token {
    pub pid: i32,
    pub pidversion: i32,
}

#[cfg(target_os = "macos")]
impl Token {
    /// Whether this is the process that runs as `pid` now, as this process's own user (see [`current`]).
    pub fn is(&self, pid: i32) -> bool {
        current(pid).is_some_and(|now| now == *self)
    }

    /// The token's process, or None unless it runs as this process's effective user.
    fn from_words(t: &[u32; 8]) -> Option<Self> {
        // audit_token_to_euid, _pid and _pidversion (bsm/libbsm.h): words 1, 5 and 7.
        // SAFETY: geteuid has no preconditions.
        (t[1] == unsafe { libc::geteuid() }).then(|| Self { pid: t[5] as i32, pidversion: t[7] as i32 })
    }
}

/// The peer of `socket`, judged: the process holding its peer pid now (a live read, see
/// [`audit_token_words`]), refused unless it runs as this process's effective user.
#[cfg(target_os = "macos")]
pub fn peer(socket: std::os::fd::BorrowedFd<'_>) -> Result<Token, String> {
    Token::from_words(&audit_token_words(socket)?).ok_or_else(|| "the peer runs as another user".to_owned())
}

/// The process running as `pid` now, or `None` when there is none or it belongs to another user
/// (`task_name_for_pid`, then `TASK_AUDIT_TOKEN`).
#[cfg(target_os = "macos")]
pub fn current(pid: i32) -> Option<Token> {
    /// `TASK_AUDIT_TOKEN` and its count (mach/task_info.h); libc does not carry them.
    const TASK_AUDIT_TOKEN: libc::c_uint = 15;
    const TASK_AUDIT_TOKEN_COUNT: libc::mach_msg_type_number_t = 8;
    unsafe extern "C" {
        /// This task's own port: what the `mach_task_self()` macro reads.
        static mach_task_self_: libc::mach_port_t;
        fn task_name_for_pid(target: libc::mach_port_t, pid: libc::c_int, name: *mut libc::mach_port_t) -> libc::c_int;
        fn mach_port_deallocate(task: libc::mach_port_t, name: libc::mach_port_t) -> libc::c_int;
    }
    let mut name: libc::mach_port_t = 0;
    // SAFETY: plain mach calls on this task's own port; `name` is released below once it was granted.
    unsafe {
        let me = mach_task_self_;
        if task_name_for_pid(me, pid, &mut name) != 0 {
            return None;
        }
        let mut token = [0u32; 8];
        let mut count = TASK_AUDIT_TOKEN_COUNT;
        let rc = libc::task_info(name, TASK_AUDIT_TOKEN, token.as_mut_ptr().cast(), &mut count);
        mach_port_deallocate(me, name);
        // A short answer is no token, never a zero-filled one.
        if rc != 0 || count != TASK_AUDIT_TOKEN_COUNT {
            return None;
        }
        Token::from_words(&token)
    }
}

/// The pid in a local socket's peer's audit token (its sixth word), read live (see [`audit_token_words`]):
/// the process using the socket now, so a holder can require the one child it started (retrust).
#[cfg(target_os = "macos")]
pub fn peer_pid(socket: std::os::fd::BorrowedFd<'_>) -> Result<i32, String> {
    let token = audit_token(socket)?;
    let word = token.get(20..24).ok_or_else(|| "its audit token is too short to name a pid".to_owned())?;
    Ok(i32::from_ne_bytes([word[0], word[1], word[2], word[3]]))
}

/// The signature of the code behind a local socket's peer, if it meets `requirement`.
#[cfg(target_os = "macos")]
pub fn signature_of_peer(socket: std::os::fd::BorrowedFd<'_>, requirement: &str) -> Result<Signature, String> {
    macos::check(&macos::guest_by_audit(&audit_token(socket)?)?, requirement)
}

/// One row of a host's trust table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trusted {
    /// The Anemnez rule for one team: its `ai.anemnez.<product>` writes what that product owns (who owns
    /// what is the caller's to say: [`TrustTable::admits`]'s `owner`).
    Anemnez { team: String },
    /// One other team's process, scoped to exactly one segment. Added by a person, never by code.
    Scoped { team: String, identifier: String, segment: String },
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
        Self::new(vec![Trusted::Anemnez { team: team.to_owned() }])
    }

    pub fn entries(&self) -> &[Trusted] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `who` is under the Anemnez rule here (its team has an [`Trusted::Anemnez`] row).
    pub fn is_anemnez(&self, who: &Identity) -> bool {
        self.entries.iter().any(|t| matches!(t, Trusted::Anemnez { team } if *team == who.team))
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
            Some(product) => {
                Err(format!("'{segment}' belongs to {product} ({ANEMNEZ_PREFIX}{product}), not {identifier}"))
            }
            None => Err(format!("no product here owns '{segment}', so {identifier} may not write it")),
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
        SecCodeCheckValidity, SecCodeCopyGuestWithAttributes, SecCodeRef, SecRequirementCreateWithString,
        SecRequirementRef, kSecCSStrictValidate, kSecGuestAttributeAudit,
    };

    // Security.framework, not in security-framework-sys: the signing information of a (running) code.
    unsafe extern "C" {
        fn SecCodeCopySigningInformation(code: CFTypeRef, flags: u32, information: *mut CFDictionaryRef) -> i32;
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
        let status =
            unsafe { SecCodeCopyGuestWithAttributes(std::ptr::null_mut(), attrs.as_concrete_TypeRef(), 0, &mut code) };
        if status != 0 || code.is_null() {
            return Err(format!("its running code cannot be found (OSStatus {status})"));
        }
        Ok(Code(code))
    }

    /// This process's own running code.
    pub(super) fn guest_self() -> Result<Code, String> {
        let mut code: SecCodeRef = std::ptr::null_mut();
        // SAFETY: default flags; `code` is +1 on success.
        let status = unsafe { security_framework_sys::code_signing::SecCodeCopySelf(0, &mut code) };
        if status != 0 || code.is_null() {
            return Err(format!("its own running code cannot be found (OSStatus {status})"));
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
        let status = unsafe { SecRequirementCreateWithString(text.as_concrete_TypeRef(), 0, &mut req) };
        if status != 0 || req.is_null() {
            return Err(format!("the requirement does not parse (OSStatus {status})"));
        }
        // SAFETY: both refs are valid.
        let status = unsafe { SecCodeCheckValidity(code.0, kSecCSStrictValidate, req) };
        // SAFETY: ours (+1), released once.
        unsafe { CFRelease(req.cast()) };
        if status != 0 {
            return Err(format!("its code is not Apple-anchored and strictly valid (OSStatus {status})"));
        }
        let mut info: CFDictionaryRef = std::ptr::null();
        // SAFETY: a valid code ref (a SecCode is accepted where a SecStaticCode is); `info` is +1 on success.
        let status = unsafe { SecCodeCopySigningInformation(code.0.cast(), INFORMATION, &mut info) };
        if status != 0 || info.is_null() {
            return Err(format!("its signing information cannot be read (OSStatus {status})"));
        }
        // SAFETY: a +1 dictionary, owned from here.
        let info: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(info) };
        let get = |key: &str| info.find(CFString::new(key)).map(|v| v.clone());
        let text = |key: &str| get(key).and_then(|v| v.downcast::<CFString>()).map(|s| s.to_string());
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
        Ok(super::Signature { team, identifier, flags, entitlements })
    }
}

#[cfg(test)]
mod tests {
    /// (D, 2026-11-06) a verdict is checked once per process: a verified identity and a refusal the
    /// signature gives are cached per audit token; a transient failure is never cached; another token
    /// is another check; a stale verdict is checked again; and the cache keeps to its cap.
    #[test]
    fn a_process_is_checked_once_and_only_lasting_verdicts_are_kept() {
        use std::cell::Cell;
        let v = super::Verdicts::new(std::time::Duration::from_secs(600), std::time::Duration::from_secs(60), 2);
        let runs = Cell::new(0);
        let ok = || {
            runs.set(runs.get() + 1);
            Ok(super::Identity { team: "TEAM".into(), identifier: "ai.anemnez.x".into() })
        };
        assert!(v.get_or_check(b"tok-a", ok).is_ok());
        assert!(v.get_or_check(b"tok-a", ok).is_ok());
        assert_eq!(runs.get(), 1, "verified: checked once");
        let refused = || {
            runs.set(runs.get() + 1);
            Err("ai.anemnez.x does not run with the hardened runtime".to_owned())
        };
        assert!(v.get_or_check(b"tok-b", refused).is_err());
        assert!(v.get_or_check(b"tok-b", refused).is_err());
        assert_eq!(runs.get(), 2, "a lasting refusal: checked once");
        let transient = || {
            runs.set(runs.get() + 1);
            Err("its running code cannot be found (OSStatus -67068)".to_owned())
        };
        let _ = v.get_or_check(b"tok-c", transient);
        let _ = v.get_or_check(b"tok-c", transient);
        assert_eq!(runs.get(), 4, "a transient failure: never cached");
        assert!(v.lock().len() <= 2, "the cap holds: {}", v.lock().len());
        let stale = super::Verdicts::new(std::time::Duration::ZERO, std::time::Duration::ZERO, 8);
        let _ = stale.get_or_check(b"tok-d", ok);
        let _ = stale.get_or_check(b"tok-d", ok);
        assert_eq!(runs.get(), 6, "a stale verdict is checked again");
        // D, 2026-11-06: a refusal clears sooner than a verified identity (a binary mid-swap).
        let short = super::Verdicts::new(std::time::Duration::from_secs(600), std::time::Duration::ZERO, 8);
        let _ = short.get_or_check(b"tok-e", ok);
        let _ = short.get_or_check(b"tok-e", ok);
        assert_eq!(runs.get(), 7, "verified: still held");
        let _ = short.get_or_check(b"tok-f", refused);
        let _ = short.get_or_check(b"tok-f", refused);
        assert_eq!(runs.get(), 9, "refused: re-checked once its shorter time is up");
    }

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
        Identity { team: team.into(), identifier: identifier.into() }
    }

    /// Only an untamperable signature is an identity: the hardened runtime, and none of the three
    /// entitlements that let another process change what it runs.
    #[test]
    fn only_a_hardened_untamperable_signature_is_an_identity() {
        let herald = id(TEAM, "ai.anemnez.herald");
        assert_eq!(judge(signature("ai.anemnez.herald", HARDENED_RUNTIME, &[])), Ok(herald.clone()));
        assert!(judge(signature("ai.anemnez.herald", 0, &[])).expect_err("soft").contains("hardened runtime"));
        for entitlement in TAMPERING {
            let open = judge(signature("ai.anemnez.herald", HARDENED_RUNTIME, &[entitlement])).expect_err("open");
            assert!(open.contains(entitlement), "{open}");
        }
        let harmless = signature("ai.anemnez.herald", HARDENED_RUNTIME, &["com.apple.security.network.client"]);
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
        assert!(table.admits(&herald, "nobody", None).expect_err("unowned").contains("no product here owns"));
        let posing = id("ABCDE12345", "ai.anemnez.herald");
        assert!(
            table.admits(&posing, "herald", Some("herald")).expect_err("posing").contains("no team this host trusts")
        );
        let theirs = id("ABCDE12345", "com.example.telegram");
        assert!(table.admits(&theirs, "telegram", None).is_err(), "read-only by default");
        let mut entries = table.entries().to_vec();
        entries.push(Trusted::Scoped {
            team: "ABCDE12345".into(),
            identifier: "com.example.telegram".into(),
            segment: "telegram".into(),
        });
        let scoped = TrustTable::new(entries);
        assert_eq!(scoped.admits(&theirs, "telegram", None), Ok(()));
        assert!(scoped.admits(&theirs, "herald", Some("herald")).is_err(), "only its one segment");
        assert!(!scoped.is_anemnez(&theirs) && scoped.is_anemnez(&herald));
        assert!(
            TrustTable::default().admits(&herald, "herald", Some("herald")).is_err(),
            "an empty table admits nobody"
        );
    }

    /// The real Security calls on a running Apple binary: it passes the strict Apple-anchored check and
    /// only then is its signature read, which names no team (a platform binary), so it is no identity. A
    /// requirement it does not meet stops it before anything is read.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_running_codes_signature_is_read_only_after_it_is_validated() {
        let mut child = std::process::Command::new("/bin/sleep").arg("5").spawn().expect("sleep");
        let pid = i32::try_from(child.id()).expect("pid");
        let code = macos::guest_by_pid(pid).expect("its code");
        let anchored = macos::check(&code, APPLE_ANCHORED);
        let unmet = macos::check(&code, "identifier \"ai.anemnez.herald\"");
        drop(child.kill());
        drop(child.wait());
        assert!(anchored.expect_err("no team").contains("names no team"), "validated, then read");
        assert!(unmet.expect_err("unmet").contains("not Apple-anchored and strictly valid"));
    }

    /// `own()` reads this process's own code through the same strict check: the test binary is linker-signed
    /// ad hoc, so it is no identity, and a product's default trust can never come from such a build.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_process_knows_its_own_identity_by_the_same_check() {
        let mine = own().expect_err("an ad hoc test binary");
        assert!(mine.contains("not Apple-anchored"), "{mine}");
    }

    /// The token a daemon hands Agora's WhoIs: the kernel's 32 bytes, naming the process at the other
    /// end (here this test binary, so its pid word is this process's).
    #[cfg(target_os = "macos")]
    #[test]
    fn a_peers_audit_token_is_the_kernels_32_bytes_naming_that_process() {
        use std::os::fd::AsFd;
        let (ours, _theirs) = std::os::unix::net::UnixStream::pair().expect("a pair");
        let token = audit_token(ours.as_fd()).expect("a connected socket has a peer token");
        assert_eq!(token.len(), 32, "an audit_token_t is eight u32s");
        assert_eq!(peer_pid(ours.as_fd()), Ok(i32::try_from(std::process::id()).unwrap()));
    }

    /// A connection's peer, judged, is exactly the process using it: here this process, now, and its
    /// pid, pidversion and euid are the raw token's words 5, 7 and 1 (moved from anemnez-service
    /// product::peer, SHARED.md).
    #[cfg(target_os = "macos")]
    #[test]
    fn a_peer_is_the_process_using_the_socket_and_its_words_say_so() {
        use std::os::fd::AsFd;
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("a pair");
        let me = peer(a.as_fd()).expect("its peer");
        assert_eq!(me.pid, std::process::id() as i32);
        assert_eq!(current(me.pid), Some(me), "the same pid and pidversion, read live");
        assert!(me.is(me.pid));
        let words = audit_token_words(a.as_fd()).expect("its whole token");
        assert_eq!((words[5] as i32, words[7] as i32), (me.pid, me.pidversion));
        // SAFETY: geteuid has no preconditions.
        assert_eq!(words[1], unsafe { libc::geteuid() }, "word 1 is the effective user");
    }

    /// A child that connects for itself is its own token, never its parent's; once it is gone its
    /// token is no one.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_child_that_connects_is_not_its_parent() {
        use std::os::fd::AsFd;
        use std::process::{Command, Stdio};
        let dir = tempfile::tempdir().expect("scratch");
        let path = dir.path().join("c.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("listen");
        let mut child = Command::new("/usr/bin/nc")
            .arg("-U")
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("nc");
        let (stream, _) = listener.accept().expect("the child connects");
        let them = peer(stream.as_fd()).expect("its peer");
        let parent = current(std::process::id() as i32).expect("this process");
        assert_eq!(them.pid, child.id() as i32, "the child, by pid");
        assert_ne!(them, parent, "never its parent");
        assert!(them.is(child.id() as i32), "and the child, exactly, while it runs");
        child.kill().expect("the child is stopped");
        child.wait().expect("the child ends");
        drop(stream);
        assert!(!them.is(child.id() as i32), "a pid no process runs is no one");
    }

    /// Another user's process is never read, so it is never matched.
    #[cfg(target_os = "macos")]
    #[test]
    fn another_users_process_is_none() {
        assert_eq!(current(1), None, "launchd runs as root");
    }

    /// The audit-token path, for real: a socket pair inside this test, so the peer is this test binary,
    /// which is linker-signed ad hoc and so is no identity. Its audit token is read and its code found.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_peers_audit_token_finds_its_code_and_an_ad_hoc_peer_is_no_identity() {
        use std::os::fd::AsFd;
        let (ours, _theirs) = std::os::unix::net::UnixStream::pair().expect("a pair");
        let found = of_peer(ours.as_fd()).expect_err("an ad hoc test binary");
        assert!(found.contains("not Apple-anchored"), "the token was read and the code checked: {found}");
    }
}
