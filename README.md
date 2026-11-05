# anemnez-secret

How a product on the Anemnez Stack holds its own key material: `Secret` (a value that never prints
and is zeroed on drop), keychain custody by the owning build's code signature, and the owner check
(Touch ID or the login password). Part of the Anemnez SDK. See `docs/specs/SECRET.md`.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT)
at your option.
