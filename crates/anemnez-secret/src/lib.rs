//! anemnez-secret (`docs/specs/SECRET.md`): how a product on the Anemnez Stack holds its OWN key
//! material, the keys that never travel. Shared credentials are Ladon's, used by reference.
//!
//! - [`secret`]: [`Secret`], a value that never prints and is zeroed on drop.
//! - [`custody`]: keychain items written by the owning binary, read back by it (macOS).
//! - [`owner`]: the owner check, Touch ID or the login password, behind a trait (macOS).
//! - [`identity`]: a caller's code identity from its audit token, and the trust table that says what it
//!   may do (the one place a code signature is judged).

#[cfg(target_os = "macos")]
pub mod custody;
// Not exported until retrust lands: until the successor is checked by its audit token, a proof says only
// that someone holding the value answered (D, 2026-11-06). The two ship as a pair.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
mod handoff;
pub mod identity;
pub mod owner;
pub mod secret;

pub use secret::Secret;
