//! Retrust: a held key handed to a successor build, the successor checked by its code signature
//! (`docs/specs/SECRET.md#a-key-goes-only-to-a-checked-successor`; from Artichoke's retrust, F; D's
//! conditions, 2026-11-05 and -06).
//!
//! The holder starts the successor binary as a child and listens on a socket in a fresh directory
//! only it can enter; the child connects to the path in [`SOCKET_ENV`]. The connection's audit token is the CHILD's, read at
//! connect, so [`crate::identity`] judges the code that actually answered. A socketpair would not do:
//! both its ends carry the token of the process that made the pair, the holder itself.
//!
//! Who may receive is decided before the value moves:
//! - the successor's identifier must be the one the holder expects;
//! - a successor of the holder's OWN team is allowed as configured;
//! - a successor of any other team is allowed only through the owner check, which names the change.
//!
//! Then [`crate::handoff`] runs over the connection: the value and a fresh nonce go to the child, the
//! child keeps it under `<item>.next` and answers its proof, the holder removes its original only on
//! a proof that verifies, and the child moves `.next` into place.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use crate::Secret;
use crate::custody::{Item, Keychain};
use crate::handoff::{self, Successor};
use crate::identity::Identity;
use crate::owner::OwnerCheck;

/// The environment variable that tells a successor where to connect: a product's binary that finds it
/// set runs [`serve`] and nothing else.
pub const SOCKET_ENV: &str = "ANEMNEZ_RETRUST_SOCKET";

/// How long the child has to connect and answer each step.
const STEP: Duration = Duration::from_secs(30);

/// Whether `successor` may receive a key that `own` holds, expecting `expected` as its identifier.
pub fn allowed(
    successor: &Identity,
    own: &Identity,
    expected: &str,
    owner: &dyn OwnerCheck,
) -> Result<(), String> {
    if successor.identifier != expected {
        return Err(format!(
            "the successor is {} (team {}), not the expected {expected}; nothing is handed over",
            successor.identifier, successor.team
        ));
    }
    if successor.team == own.team {
        return Ok(());
    }
    let reason = format!(
        "hand {}'s key to {} of team {}, a different team from this build's ({})",
        own.identifier, successor.identifier, successor.team, own.team
    );
    owner
        .confirm(&reason)
        .map_err(|why| format!("the owner did not approve a hand-off across teams: {why}"))
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), String> {
    let len = u32::try_from(bytes.len()).map_err(|_| "a frame over 4 GiB".to_owned())?;
    stream
        .write_all(&len.to_be_bytes())
        .and_then(|()| stream.write_all(bytes))
        .map_err(|e| e.to_string())
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, String> {
    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(|e| format!("the other side stopped answering: {e}"))?;
    let len = u32::from_be_bytes(len) as usize;
    if len > 1 << 20 {
        return Err("a frame over 1 MiB: refused".into());
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

/// The holder's view of the child over its connection.
struct Remote {
    stream: UnixStream,
}

impl Successor for Remote {
    fn receive(&mut self, value: &Secret, nonce: &[u8; 32]) -> Result<Vec<u8>, String> {
        write_frame(&mut self.stream, b"receive")?;
        write_frame(&mut self.stream, nonce)?;
        value.expose(|v| write_frame(&mut self.stream, v))?;
        read_frame(&mut self.stream)
    }

    fn finish(&mut self) -> Result<(), String> {
        write_frame(&mut self.stream, b"finish")?;
        let answer = read_frame(&mut self.stream)?;
        if answer == b"ok" {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&answer).into_owned())
        }
    }
}

/// Accept the one connection that comes from process `pid` (the child the holder spawned, unreaped, so
/// its pid cannot be reused), within `within`. A connection from any other process, however it is
/// signed, is refused and dropped, and the wait goes on (D and F, 2026-11-06).
pub fn accept_from(
    listener: &UnixListener,
    pid: i32,
    within: Duration,
) -> Result<UnixStream, String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let deadline = std::time::Instant::now() + within;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if crate::identity::peer_pid(std::os::fd::AsFd::as_fd(&stream)) == Ok(pid) {
                    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
                    return Ok(stream);
                }
                drop(stream);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(format!("the successor never connected: {e}")),
        }
    }
}

/// How the holder learns who connected: [`crate::identity::of_peer`] in use, a stand-in in tests.
pub type Identify<'a> = &'a dyn Fn(&UnixStream) -> Result<Identity, String>;

/// The holder's side: hand `item` to the successor at `program`, started with `args` and
/// [`SOCKET_ENV`] naming the socket, which must answer as `expected`. `own` is this build's identity
/// ([`crate::identity::own`]).
#[allow(clippy::too_many_arguments)]
pub fn to(
    keychain: &Keychain,
    item: &Item,
    program: &Path,
    args: &[String],
    expected: &str,
    own: &Identity,
    owner: &dyn OwnerCheck,
    identify: Identify<'_>,
) -> Result<(), String> {
    let dir = tempfile::Builder::new()
        .prefix("retrust")
        .tempdir()
        .map_err(|e| e.to_string())?;
    // Only this process may enter the directory, so only a process it started can find the socket.
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .map_err(|e| e.to_string())?;
    let socket = dir.path().join("s");
    let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
    let mut child = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .envs(std::env::vars_os().filter(|(k, _)| k == "HOME" || k == "PATH"))
        .env(SOCKET_ENV, &socket)
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("the successor {} could not start: {e}", program.display()))?;
    let result = (|| {
        let pid = i32::try_from(child.id()).map_err(|e| e.to_string())?;
        let stream = accept_from(&listener, pid, STEP)?;
        // The one connection is taken: nothing else may reach the socket.
        let _ = std::fs::remove_file(&socket);
        stream.set_nonblocking(false).map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(STEP))
            .map_err(|e| e.to_string())?;
        let who = identify(&stream)?;
        allowed(&who, own, expected, owner)?;
        handoff::hand_off(keychain, item, &mut Remote { stream })
    })();
    let _ = child.wait();
    result
}

/// The successor's side, run by the new build when started with [`SOCKET_ENV`] set: receive the
/// value under `item` in `keychain`, prove it, and finish when told to. `made_by` is this build's
/// designated requirement, written on the items it makes.
pub fn serve(socket: &Path, keychain: &Keychain, item: &Item, made_by: &str) -> Result<(), String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(STEP))
        .map_err(|e| e.to_string())?;
    loop {
        let verb = match read_frame(&mut stream) {
            Ok(verb) => verb,
            Err(_) => return Ok(()),
        };
        match verb.as_slice() {
            b"receive" => {
                let nonce: [u8; 32] = read_frame(&mut stream)?
                    .try_into()
                    .map_err(|_| "a nonce is 32 bytes".to_owned())?;
                let value = Secret::new(read_frame(&mut stream)?);
                let proof = handoff::receive(keychain, item, &value, &nonce, made_by)?;
                write_frame(&mut stream, &proof)?;
            }
            b"finish" => {
                let answer = handoff::finish(keychain, item, made_by);
                write_frame(
                    &mut stream,
                    answer.as_ref().map_or_else(|e| e.as_bytes(), |()| b"ok"),
                )?;
                return answer;
            }
            other => {
                return Err(format!(
                    "an unknown step {:?}",
                    String::from_utf8_lossy(other)
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{allowed, serve, to};
    use crate::Secret;
    use crate::custody::{Item, Keychain};
    use crate::identity::Identity;
    use crate::owner::OwnerCheck;

    const VALUE: &str = "role-key-seed-ZZZtopSECRET";
    const SPEC: &str = "retrust-spec=";

    struct Owner(bool, std::cell::RefCell<Vec<String>>);

    impl OwnerCheck for Owner {
        fn confirm(&self, reason: &str) -> Result<(), String> {
            self.1.borrow_mut().push(reason.into());
            if self.0 {
                Ok(())
            } else {
                Err("refused".into())
            }
        }
    }

    fn id(team: &str, identifier: &str) -> Identity {
        Identity {
            team: team.into(),
            identifier: identifier.into(),
        }
    }

    /// `SECRET.md#a-key-goes-only-to-a-checked-successor`: the expected identifier, then the same team
    /// as configured, and another team only through the owner check, which names the change.
    #[test]
    fn a_successor_is_allowed_by_identifier_then_team_then_the_owner() {
        let own = id("TEAM", "ai.anemnez.example");
        let yes = Owner(true, Default::default());
        assert!(
            allowed(
                &id("TEAM", "ai.anemnez.exampled"),
                &own,
                "ai.anemnez.exampled",
                &yes
            )
            .is_ok()
        );
        assert!(yes.1.borrow().is_empty(), "the same team asks nobody");
        let wrong = allowed(
            &id("TEAM", "ai.anemnez.other"),
            &own,
            "ai.anemnez.exampled",
            &yes,
        )
        .unwrap_err();
        assert!(wrong.contains("not the expected"), "{wrong}");
        let no = Owner(false, Default::default());
        assert!(
            allowed(
                &id("OTHER", "ai.anemnez.exampled"),
                &own,
                "ai.anemnez.exampled",
                &no
            )
            .is_err()
        );
        assert!(
            no.1.borrow()[0].contains("team OTHER"),
            "the card names the team: {:?}",
            no.1.borrow()
        );
        assert!(
            allowed(
                &id("OTHER", "ai.anemnez.exampled"),
                &own,
                "ai.anemnez.exampled",
                &yes
            )
            .is_ok()
        );
    }

    /// `SECRET.md#a-key-goes-only-to-a-checked-successor`: only the spawned child's connection is
    /// taken. A process connecting first (this test process, however it is signed) is refused and
    /// dropped, and the child's connection is still taken after it.
    #[test]
    fn only_the_spawned_childs_connection_is_taken() {
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let mut first = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let mut child = std::process::Command::new("/usr/bin/nc")
            .arg("-U")
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        let taken = super::accept_from(&listener, pid, std::time::Duration::from_secs(10))
            .expect("the child's");
        assert_eq!(
            crate::identity::peer_pid(std::os::fd::AsFd::as_fd(&taken)),
            Ok(pid)
        );
        // A dropped connection reads as closed; macOS may even refuse a timeout on it (EINVAL).
        let _ = first.set_read_timeout(Some(std::time::Duration::from_secs(2)));
        let mut buf = [0u8; 1];
        assert!(
            first.read(&mut buf).map_or(true, |n| n == 0),
            "the first connection was dropped"
        );
        let none = super::accept_from(&listener, 1, std::time::Duration::from_millis(100));
        assert!(none.unwrap_err().contains("never connected"));
        drop(child.kill());
        drop(child.wait());
    }

    /// The child half, run by the test binary when started as the successor (never on its own).
    #[test]
    fn retrust_child() {
        let Ok(socket) = std::env::var(super::SOCKET_ENV) else {
            return;
        };
        // The keychain and item ride as an extra test-name filter, which matches no test.
        let spec = std::env::args().find(|a| a.starts_with(SPEC)).unwrap();
        let mut parts = spec[SPEC.len()..].splitn(3, '\u{1f}');
        let (keychain, service, account) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let k = Keychain::open_at(std::path::Path::new(keychain), "proof-only").unwrap();
        serve(
            std::path::Path::new(&socket),
            &k,
            &Item::new(service, account),
            "the child",
        )
        .unwrap();
    }

    /// `SECRET.md#a-key-goes-only-to-a-checked-successor`: end to end with a real child process over the
    /// socket. A successor judged as another identifier gets nothing and the original stays; the
    /// expected one receives, and the value ends under the item, made by the child.
    #[test]
    fn a_key_moves_to_a_checked_child_and_never_to_another() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proof.keychain-db");
        let k = Keychain::create_at(&path, "proof-only").unwrap();
        let item = Item::new("ai.anemnez.example.role", "promoter@node");
        k.add(&item, &Secret::new(VALUE.into()), "the holder")
            .unwrap();
        let me = std::env::current_exe().unwrap();
        let spec = format!(
            "{SPEC}{}\u{1f}{}\u{1f}{}",
            path.display(),
            item.service,
            item.account
        );
        let args = vec![
            "--exact".to_owned(),
            "retrust::tests::retrust_child".to_owned(),
            spec,
        ];
        let own = id("TEAM", "ai.anemnez.example");
        let owner = Owner(false, Default::default());

        let impostor = |_: &std::os::unix::net::UnixStream| Ok(id("TEAM", "ai.anemnez.other"));
        let refused = to(
            &k,
            &item,
            &me,
            &args,
            "ai.anemnez.exampled",
            &own,
            &owner,
            &impostor,
        )
        .unwrap_err();
        assert!(refused.contains("not the expected"), "{refused}");
        assert!(
            k.held(&item).unwrap() && !k.held(&item.next()).unwrap(),
            "nothing moved"
        );

        // The real check: this test binary is ad hoc signed, so it is no identity, and nothing moves.
        let real = |s: &std::os::unix::net::UnixStream| {
            crate::identity::of_peer(std::os::fd::AsFd::as_fd(s))
        };
        let unsigned = to(
            &k,
            &item,
            &me,
            &args,
            "ai.anemnez.exampled",
            &own,
            &owner,
            &real,
        )
        .unwrap_err();
        assert!(!unsigned.contains("ZZZtop"), "{unsigned}");
        assert!(
            k.held(&item).unwrap() && !k.held(&item.next()).unwrap(),
            "an unsigned child gets nothing"
        );

        let successor = |_: &std::os::unix::net::UnixStream| Ok(id("TEAM", "ai.anemnez.exampled"));
        to(
            &k,
            &item,
            &me,
            &args,
            "ai.anemnez.exampled",
            &own,
            &owner,
            &successor,
        )
        .expect("handed over");
        assert_eq!(
            k.get(&item).unwrap().expose(|v| v.to_vec()),
            VALUE.as_bytes()
        );
        assert!(!k.held(&item.next()).unwrap());
        assert_eq!(
            k.maker(&item).as_deref(),
            Some("the child"),
            "the child's item now"
        );
    }
}
