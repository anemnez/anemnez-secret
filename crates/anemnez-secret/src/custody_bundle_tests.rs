//! The bundle form (F m/38513, D m/38511): what a placed build is, an app bundle, judged by the keychain from a fresh
//! process. This test binary is copied into an ad-hoc-signed probe bundle and run again as that bundle's main
//! executable, on [`probe`], which writes or reads one item of a scratch keychain and says only what it saw.
//!
//! What it holds: a bundle with a resource removed after signing (unsealed, `codesign --verify` failing), run fresh,
//! reads an item it wrote with [`Keychain::add_trusting_with_own`] by its own entry, beside the team's requirement;
//! and an item whose list names it by identifier alone admits it sealed or not, while a bundle of another identifier
//! is refused. So in a keychain at a path, an access list's requirement never sees the seal: the refusal on a placed,
//! unsealed bundle (F m/38513) lies in what this row can't pose, the team's anchor and OU (team signing reaches the
//! person's key) or the partitions securityd stamps only under ~/Library/Keychains, and is proven on a host
//! (D m/38511 point 1).

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{CustodyError, Item, Keychain};
use crate::Secret;

const VALUE: &str = "ed25519-seed-bundle-probe-value-0123456789";
const PASSWORD: &str = "proof-only";
const MAKER: &str = "identifier \"ai.anemnez.exampled\" and anchor apple generic";
const PROBE: &str = "custody::bundle::probe";

fn team(identifier: &str) -> String {
    format!(
        r#"identifier "{identifier}" and anchor apple generic and certificate leaf[subject.OU] = "{}""#,
        crate::identity::ANEMNEZ_TEAM
    )
}

/// The probe, run only as a bundle's main executable with its environment set; anywhere else it does nothing.
/// `write` adds the item with [`Keychain::add_trusting_with_own`]; `read` reads it and prints `admitted`,
/// `unavailable` or `other`, never the value.
#[test]
#[ignore = "the bundle probe: run only by an_unsealed_bundle_reads_its_own_entry_fresh_and_a_named_entry_never_sees_the_seal"]
fn probe() {
    let (Ok(path), Ok(action), Ok(account)) =
        (std::env::var("PROBE_KEYCHAIN"), std::env::var("PROBE_ACTION"), std::env::var("PROBE_ACCOUNT"))
    else {
        return;
    };
    let k = Keychain::open_at(Path::new(&path), PASSWORD).expect("the scratch keychain opens");
    let item = Item::new("ai.anemnez.example.bundle", account);
    let said = match action.as_str() {
        "write" => match k.add_trusting_with_own(
            &item,
            &Secret::new(VALUE.as_bytes().to_vec()),
            MAKER,
            &[&team("ai.anemnez.exampled")],
            &crate::identity::TrustTable::house(),
        ) {
            Ok(()) => "written".to_owned(),
            Err(e) => format!("other {e}"),
        },
        _ => match k.get(&item) {
            Ok(v) if v.expose(|b| b == VALUE.as_bytes()) => "admitted".to_owned(),
            Ok(_) => "other: a different value".to_owned(),
            Err(CustodyError::Unavailable { .. }) => "unavailable".to_owned(),
            Err(e) => format!("other {e}"),
        },
    };
    println!("PROBE-SAID {said}");
}

/// A probe bundle at `dir/<name>.app`, ad-hoc signed with its resources sealed; `unseal` removes one after signing.
fn bundle(dir: &Path, name: &str, unseal: bool) -> PathBuf {
    let app = dir.join(format!("{name}.app"));
    let contents = app.join("Contents");
    std::fs::create_dir_all(contents.join("MacOS")).unwrap();
    std::fs::create_dir_all(contents.join("Resources")).unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), contents.join("MacOS/probe")).unwrap();
    std::fs::write(contents.join("Resources/sealed.txt"), "a resource the seal covers").unwrap();
    std::fs::write(
        contents.join("Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>ai.anemnez.example-probe</string>
<key>CFBundleExecutable</key><string>probe</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
"#,
    )
    .unwrap();
    let signed = Command::new("/usr/bin/codesign")
        .args(["--sign", "-", "--force", "--identifier", "ai.anemnez.example-probe"])
        .arg(&app)
        .output()
        .unwrap();
    assert!(signed.status.success(), "codesign: {}", String::from_utf8_lossy(&signed.stderr));
    if unseal {
        std::fs::remove_file(contents.join("Resources/sealed.txt")).unwrap();
    }
    let verified = Command::new("/usr/bin/codesign").arg("--verify").arg(&app).status().unwrap();
    assert_eq!(verified.success(), !unseal, "{name}: the seal is as posed");
    app
}

/// Runs `app`'s main executable, a fresh process, on the probe.
fn run(app: &Path, keychain: &Path, action: &str, account: &str) -> String {
    let out = Command::new(app.join("Contents/MacOS/probe"))
        .args(["--exact", PROBE, "--ignored", "--nocapture", "--test-threads", "1"])
        .env("PROBE_KEYCHAIN", keychain)
        .env("PROBE_ACTION", action)
        .env("PROBE_ACCOUNT", account)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.split_once("PROBE-SAID ").map(|(_, said)| said))
        .map_or_else(|| format!("no answer: {text} {}", String::from_utf8_lossy(&out.stderr)), str::to_owned)
}

#[test]
fn an_unsealed_bundle_reads_its_own_entry_fresh_and_a_named_entry_never_sees_the_seal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proof.keychain-db");
    let k = Keychain::create_at(&path, PASSWORD).unwrap();
    let unsealed = bundle(dir.path(), "Unsealed", true);
    let sealed = bundle(dir.path(), "Sealed", false);
    let other = bundle(dir.path(), "Other", false);
    // `other` is the same code under another identifier.
    let resigned = Command::new("/usr/bin/codesign")
        .args(["--sign", "-", "--force", "--identifier", "ai.anemnez.example-other"])
        .arg(&other)
        .output()
        .unwrap();
    assert!(resigned.status.success(), "codesign: {}", String::from_utf8_lossy(&resigned.stderr));

    // An entry naming the bundle by identifier alone (the team's requirement's shape without its anchor, which an
    // ad-hoc bundle can't meet): enforced, since another identifier is refused, and blind to the seal.
    let by_identifier = Item::new("ai.anemnez.example.bundle", "by-identifier");
    let named = r#"identifier "ai.anemnez.example-probe""#;
    k.add_trusting_unpinned(&by_identifier, &Secret::new(VALUE.as_bytes().to_vec()), MAKER, &[named], false)
        .expect("made");
    assert_eq!(run(&other, &path, "read", "by-identifier"), "unavailable", "another identifier is refused");
    assert_eq!(run(&sealed, &path, "read", "by-identifier"), "admitted", "the named bundle, sealed");
    assert_eq!(
        run(&unsealed, &path, "read", "by-identifier"),
        "admitted",
        "and unsealed: the list never sees the seal"
    );

    // Written by the unsealed bundle itself, its own entry beside the team's requirement: a fresh process of it reads
    // it, and another identifier doesn't.
    assert_eq!(run(&unsealed, &path, "write", "with-own"), "written");
    assert_eq!(run(&unsealed, &path, "read", "with-own"), "admitted", "its own entry admits it, fresh");
    assert_eq!(run(&other, &path, "read", "with-own"), "unavailable", "and no one else");
    let trusts = k.trusts(&Item::new("ai.anemnez.example.bundle", "with-own")).expect("its list reads");
    let team_printed = crate::access::requirement(&team("ai.anemnez.exampled")).unwrap();
    assert!(trusts.contains(&team_printed), "the team's requirement, as printed: {trusts:?}");
    assert_eq!(trusts.len(), 2, "and its own entry beside it, nothing else: {trusts:?}");
}
