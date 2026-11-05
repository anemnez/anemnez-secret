//! Proving the owner (`docs/specs/SECRET.md#the-owner-is-proven-never-assumed`). An agent can run any
//! CLI, so "the owner" can never be a flag, a TTY or the user id: a person's decision (a Ladon
//! grant, SEALING's `extend`, a key handed to another team's build) passes the macOS owner check
//! (`LAContext`, `deviceOwnerAuthentication`: Touch ID or the login password). An agent can drive a
//! CLI and click dialogs through Minion, but cannot pass it.
//!
//! It sits behind [`OwnerCheck`] so proofs stand in for it. [`Refuse`] is the default everywhere the
//! real check is not wired, so an unproven owner is refused, never trusted.

/// Asks the person at this host to confirm `reason` (shown to them, naming exactly what changes).
pub trait OwnerCheck {
    fn confirm(&self, reason: &str) -> Result<(), String>;
}

/// No owner check is available: every person's decision is refused.
pub struct Refuse;

impl OwnerCheck for Refuse {
    fn confirm(&self, _reason: &str) -> Result<(), String> {
        Err("no owner check is available here, so no person's decision is trusted".into())
    }
}

/// The macOS owner check: Touch ID or the login password, presented by this process.
#[cfg(target_os = "macos")]
pub struct DeviceOwner {
    /// How long the person has to answer.
    pub timeout: std::time::Duration,
}

#[cfg(target_os = "macos")]
impl OwnerCheck for DeviceOwner {
    fn confirm(&self, reason: &str) -> Result<(), String> {
        use objc2::runtime::Bool;
        use objc2_foundation::{NSError, NSString};
        use objc2_local_authentication::{LAContext, LAPolicy};

        let policy = LAPolicy::DeviceOwnerAuthentication;
        // SAFETY: a fresh context, used on this thread for this one evaluation.
        let context = unsafe { LAContext::new() };
        // SAFETY: a valid context and a policy constant.
        unsafe { context.canEvaluatePolicy_error(policy) }.map_err(|e| {
            format!(
                "the owner check is not available: {}",
                e.localizedDescription()
            )
        })?;
        let (tx, rx) = std::sync::mpsc::channel();
        let reply = block2::RcBlock::new(move |ok: Bool, _error: *mut NSError| {
            let _ = tx.send(ok.as_bool());
        });
        // SAFETY: the reason and the reply block outlive the call; the block only sends on a channel.
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                policy,
                &NSString::from_str(reason),
                &reply,
            )
        };
        match rx.recv_timeout(self.timeout) {
            Ok(true) => Ok(()),
            Ok(false) => Err("the owner did not confirm it".into()),
            Err(_) => Err(format!("nobody confirmed it within {:?}", self.timeout)),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::OwnerCheck;

    /// A proof's stand-in: confirms or refuses, and remembers what it was asked.
    pub struct StandIn {
        pub confirms: bool,
        pub asked: std::cell::RefCell<Vec<String>>,
    }

    impl StandIn {
        pub fn new(confirms: bool) -> Self {
            Self {
                confirms,
                asked: Default::default(),
            }
        }
    }

    impl OwnerCheck for StandIn {
        fn confirm(&self, reason: &str) -> Result<(), String> {
            self.asked.borrow_mut().push(reason.into());
            if self.confirms {
                Ok(())
            } else {
                Err("the stand-in refused".into())
            }
        }
    }

    /// By hand only, at a Mac with a person in front of it: `cargo test -p anemnez-secret -- --ignored
    /// the_real_owner_check_asks_the_person`. Touch ID or the password must be offered, naming the
    /// reason; confirming passes, cancelling refuses.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "asks a person: run by hand"]
    fn the_real_owner_check_asks_the_person() {
        let check = super::DeviceOwner {
            timeout: std::time::Duration::from_secs(60),
        };
        let verdict =
            check.confirm("prove the anemnez-secret owner check (a by-hand test; nothing changes)");
        eprintln!("the owner check answered: {verdict:?}");
    }
}
