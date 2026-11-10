//! A secret's value, never printed (`docs/specs/SECRET.md#a-secret-never-prints`).
//!
//! `Secret` is the only type that holds a value. It is not `Clone`, not `Serialize`, and its `Debug`
//! and `Display` print a fixed placeholder, so a value that reaches a log line, an error, a status
//! answer or a test failure says nothing. Its bytes are overwritten when it is dropped. The one way to
//! read it is [`Secret::expose`], at the edge that injects it.

/// What every printing of a secret says.
pub const REDACTED: &str = "‹secret›";

/// A secret's value.
pub struct Secret(Vec<u8>);

impl Secret {
    /// A value, taken over (the caller's copy is moved in, never copied).
    pub fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    /// Use the value at the edge that injects it. It is lent for the call, never handed out.
    pub fn expose<T>(&self, use_it: impl FnOnce(&[u8]) -> T) -> T {
        use_it(&self.0)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: a valid, aligned, exclusively borrowed byte of this vector.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::{REDACTED, Secret};

    /// `SECRET.md#a-secret-never-prints`: printed any way, a secret says nothing.
    #[test]
    fn a_secret_printed_any_way_says_nothing() {
        let value = "github_pat_11AAAAA0123456789abcdefSECRET";
        let secret = Secret::new(value.as_bytes().to_vec());
        for printed in
            [format!("{secret}"), format!("{secret:?}"), format!("{secret:#?}"), format!("{:?}", Some(&secret))]
        {
            assert!(!printed.contains("SECRET") && !printed.contains("github_pat_"), "{printed}");
            assert!(printed.contains(REDACTED), "{printed}");
        }
        assert_eq!(secret.expose(|v| v.to_vec()), value.as_bytes(), "the edge still gets the value");
    }
}
