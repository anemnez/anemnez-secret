//! anemnez-secret (`docs/specs/SECRET.md`): how a product on the Anemnez Stack holds its OWN key
//! material, the keys that never travel. Shared credentials are Ladon's, used by reference.
//!
//! - [`secret`]: [`Secret`], a value that never prints and is zeroed on drop.
//! - [`custody`]: keychain items written by the owning binary, read back by it (macOS).
//! - [`handoff`] and [`retrust`]: a held key carried to a successor build, checked by its audit token
//!   and never left unheld (macOS).
//! - [`owner`]: the owner check, Touch ID or the login password, behind a trait (macOS).
//! - [`identity`]: a caller's code identity from its audit token, and the trust table that says what it
//!   may do (the one place a code signature is judged).

#[cfg(target_os = "macos")]
pub mod custody;
// handoff and retrust ship as a pair: a hand-off's successor is the child retrust has checked by its
// audit token (D, 2026-11-06).
#[cfg(target_os = "macos")]
pub mod handoff;
pub mod identity;
pub mod owner;
#[cfg(target_os = "macos")]
pub mod retrust;
pub mod secret;

pub use secret::Secret;
