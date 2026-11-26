//! File helpers: private (0600) temporary outputs that are published only on success, key files.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("OS RNG");
    crate::hex(&b)
}

fn parent_of(p: &Path) -> PathBuf {
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// An anonymous (O_TMPFILE) or, as a fallback, a private dot-named 0600 file.
pub struct TempOut {
    pub file: File,
    named: Option<PathBuf>,
    dir: PathBuf,
    published: bool,
}

impl TempOut {
    /// A private temporary file in `dir`.
    pub fn new_in(dir: &Path, hint: &str) -> io::Result<TempOut> {
        let anon = OpenOptions::new()
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_TMPFILE | libc::O_CLOEXEC)
            .open(dir);
        let (file, named) = match anon {
            Ok(f) => (f, None),
            Err(_) => {
                let mut last = None;
                let mut got = None;
                for _ in 0..100 {
                    let p = dir.join(format!(".{}.{}.tmp", hint.chars().take(100).collect::<String>(), rand_hex(4)));
                    match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&p)
                    {
                        Ok(f) => {
                            got = Some((f, Some(p)));
                            break;
                        }
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
                        Err(e) => return Err(e),
                    }
                }
                got.ok_or_else(|| last.unwrap())?
            }
        };
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(TempOut { file, named, dir: dir.to_path_buf(), published: false })
    }

    /// A private temp file next to `dst` (same filesystem, so it can be published there).
    pub fn for_dst(dst: &Path) -> io::Result<TempOut> {
        let base = dst.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "out".into());
        TempOut::new_in(&parent_of(dst), &base)
    }

    /// fsync, then make the data visible as `dst`. Without `force` an existing `dst` is an error
    /// (never clobbered); with `force` it is replaced atomically (rename).
    pub fn publish(mut self, dst: &Path, force: bool) -> io::Result<()> {
        self.file.sync_all()?;
        let link_to = |to: &Path| -> io::Result<()> {
            match &self.named {
                Some(p) => std::fs::hard_link(p, to),
                None => {
                    let from = CString::new(format!("/proc/self/fd/{}", self.file.as_raw_fd())).unwrap();
                    let to_c = CString::new(to.as_os_str().as_bytes()).map_err(|_| io::Error::other("NUL in path"))?;
                    // SAFETY: valid NUL-terminated paths; linkat does not retain them.
                    let r = unsafe { libc::linkat(libc::AT_FDCWD, from.as_ptr(), libc::AT_FDCWD, to_c.as_ptr(), libc::AT_SYMLINK_FOLLOW) };
                    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
                }
            }
        };
        if force {
            let swap = self.dir.join(format!(".{}.{}.swap", dst.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(), rand_hex(4)));
            link_to(&swap)?;
            if let Err(e) = std::fs::rename(&swap, dst) {
                let _ = std::fs::remove_file(&swap);
                return Err(e);
            }
        } else {
            link_to(dst)?;
        }
        if let Some(p) = &self.named {
            let _ = std::fs::remove_file(p);
        }
        self.published = true;
        if let Ok(d) = File::open(&self.dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }
}

impl Drop for TempOut {
    fn drop(&mut self) {
        if !self.published {
            // wipe what we wrote before dropping it (best effort: the filesystem may keep old blocks)
            let _ = self.file.set_len(0);
            if let Some(p) = &self.named {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

/// (dev, ino) of a path if it exists (following symlinks).
pub fn ident(p: &Path) -> Option<(u64, u64)> {
    std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))
}
pub fn ident_file(f: &File) -> Option<(u64, u64)> {
    f.metadata().ok().map(|m| (m.dev(), m.ino()))
}

/// Open a key file safely: no symlink, regular file, at most 16384 bytes. Returns (bytes, warnings).
pub fn read_key_file(p: &Path) -> io::Result<(zeroize::Zeroizing<Vec<u8>>, Vec<String>)> {
    let mut warn = Vec::new();
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(p)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                io::Error::other(format!("key file {} is a symlink (refused)", p.display()))
            } else {
                io::Error::new(e.kind(), format!("cannot open key file {}: {e}", p.display()))
            }
        })?;
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(io::Error::other(format!("key file {} is not a regular file", p.display())));
    }
    if m.mode() & 0o077 != 0 {
        warn.push(format!("key file {} is readable or writable by group/others (chmod 600 it)", p.display()));
    }
    let mut data = zeroize::Zeroizing::new(Vec::with_capacity(16385));
    f.take(16385).read_to_end(&mut data)?;
    if data.len() > 16384 {
        return Err(io::Error::other(format!("key file {} is larger than 16384 bytes", p.display())));
    }
    Ok((data, warn))
}

/// Write `data` to a NEW file `p` with mode 0600 (never clobbers; nothing named exists until it
/// is complete and fsync'd).
pub fn write_new_secret(p: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    if std::fs::symlink_metadata(p).is_ok() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} already exists (refusing to overwrite a key)", p.display())));
    }
    let mut t = TempOut::for_dst(p)?;
    t.file.write_all(data)?;
    t.publish(p, false)
}
