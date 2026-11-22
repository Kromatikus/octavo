//! `octavo` command-line tool. Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.

use clap::{Args, Parser, Subcommand};
use octavo_cli::{earworm, fsio, policy, HONEST};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, IsTerminal, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const BANNER: &str = "WARNING: Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.";

#[derive(Parser)]
#[command(
    name = "octavo",
    version,
    about = "Octavo: a homemade, experimental, music-themed 1024-bit cipher (v9 rehearsal files).",
    before_help = BANNER,
    after_help = "Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.\n\nExit codes: 0 ok; 1 rejected or failed (bad key file, weak seed, auth/format error, I/O); 2 usage error."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make a new key: a 1024-bit seed from the OS CSPRNG, written as 256 hex digits to a NEW 0600 file.
    #[command(before_help = BANNER, after_help = HONEST)]
    Keygen {
        /// Key file to create (refuses to overwrite).
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Check a key file against the seed policy (never prints the key).
    #[command(before_help = BANNER, after_help = HONEST)]
    CheckKey {
        #[arg(short, long)]
        key: PathBuf,
    },
    /// Encrypt a file or stdin into an Octavo v9 rehearsal stream (byte-compatible with sneak_n2.py).
    #[command(before_help = BANNER, after_help = HONEST)]
    Seal(SealArgs),
    /// Decrypt and verify an Octavo v9 stream. Output appears only if the WHOLE stream verifies.
    #[command(before_help = BANNER, after_help = HONEST)]
    Open(OpenArgs),
    /// Play the "key earworm": a short tune derived one-way from the key, to check a key by ear.
    #[command(before_help = BANNER, after_help = HONEST)]
    Hear {
        #[arg(short, long)]
        key: PathBuf,
        /// Also write the tune as a WAV file (mode 0600; refuses to overwrite without --force).
        #[arg(long)]
        wav: Option<PathBuf>,
        /// Also write the tune as a standard MIDI file (format 0, one track; mode 0600; refuses to
        /// overwrite without --force).
        #[arg(long)]
        midi: Option<PathBuf>,
        /// General MIDI program (instrument) for --midi, 0..=127. Default 0 = Acoustic Grand Piano.
        #[arg(long, default_value_t = earworm::DEFAULT_PROGRAM, value_parser = clap::value_parser!(u8).range(0..=127))]
        program: u8,
        /// Also write the tune as a Commodore 64 PSID v2 .sid file (own 6502 player; 3 voices: melody,
        /// bass, arpeggio; PAL; loops). Mode 0600; refuses to overwrite without --force.
        #[arg(long)]
        sid: Option<PathBuf>,
        /// Also write that SID tune rendered to a WAV (44.1 kHz) by the built-in 6502 + SID-style synth.
        /// Mode 0600; refuses to overwrite without --force.
        #[arg(long)]
        sid_wav: Option<PathBuf>,
        /// Replace existing --wav / --midi / --sid / --sid-wav files (atomically).
        #[arg(short, long)]
        force: bool,
    },
    /// Print the weak-seed policy.
    #[command(before_help = BANNER, after_help = HONEST)]
    Policy,
}

#[derive(Args)]
struct Common {
    /// Key file (256 hex digits, 0600), e.g. from `octavo keygen`.
    #[arg(short, long)]
    key: PathBuf,
    /// Input file; `-` or omitted = stdin.
    input: Option<PathBuf>,
    /// Output file; `-` or omitted = stdout.
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Associated data (UTF-8 text), must match on open.
    #[arg(long, conflicts_with = "ad_hex")]
    ad: Option<String>,
    /// Associated data as hex.
    #[arg(long)]
    ad_hex: Option<String>,
    /// Worker threads (default: CPUs, at most 8). Output bytes do not depend on it.
    #[arg(short = 'j', long)]
    threads: Option<usize>,
    /// Replace an existing output file.
    #[arg(short, long)]
    force: bool,
    /// Chunks buffered per thread per batch (tuning; memory ~ threads x batch x chunk size).
    #[arg(long, default_value_t = 16, hide = true)]
    batch_chunks: usize,
}

#[derive(Args)]
struct SealArgs {
    #[command(flatten)]
    c: Common,
    /// Plaintext bytes per chunk: a multiple of 128 in 128..=1048576.
    #[arg(long, default_value_t = 65536)]
    chunk_size: usize,
    /// Allow the PUBLIC demo seed (samples and tests only).
    #[arg(long)]
    allow_demo_seed: bool,
}

#[derive(Args)]
struct OpenArgs {
    #[command(flatten)]
    c: Common,
    /// stdout only: write each verified chunk immediately instead of holding the plaintext in a
    /// private temporary file until the whole stream verifies. On a reject, stdout then holds a
    /// verified prefix you must discard.
    #[arg(long)]
    stream_verified_prefix: bool,
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("octavo: error: {msg}");
    ExitCode::from(1)
}

fn first_use_notice() {
    let dir = std::env::var_os("OCTAVO_HOME").map(PathBuf::from).or_else(|| {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(|d| PathBuf::from(d).join("octavo"))
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/octavo")))
    });
    let Some(dir) = dir else {
        eprintln!("{BANNER}");
        return;
    };
    let marker = dir.join("first-use-warning-shown");
    if marker.exists() {
        return;
    }
    eprintln!("{BANNER}\n(First run: this notice is shown once. It is also in `octavo --help`.)");
    if std::fs::create_dir_all(&dir).is_ok() {
        let _ = std::fs::write(&marker, format!("{HONEST}\n"));
    }
}

fn load_key(p: &Path) -> Result<octavo_cli::Seed, ExitCode> {
    match octavo_cli::load_key(p) {
        Ok((s, warns)) => {
            for w in warns {
                eprintln!("octavo: warning: {w}");
            }
            Ok(s)
        }
        Err(e) => Err(fail(e)),
    }
}

fn ad_bytes(c: &Common) -> Result<Vec<u8>, ExitCode> {
    if let Some(a) = &c.ad {
        return Ok(a.as_bytes().to_vec());
    }
    if let Some(h) = &c.ad_hex {
        let h = h.trim();
        if h.len() % 2 != 0 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(fail("--ad-hex must be an even number of hex digits"));
        }
        return Ok((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect());
    }
    Ok(Vec::new())
}

fn threads(c: &Common) -> usize {
    c.threads
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(8))
        .clamp(1, 64)
}

fn is_dash(p: &Option<PathBuf>) -> bool {
    p.as_ref().is_none_or(|p| p.as_os_str() == "-")
}

enum Input {
    Stdin(io::Stdin),
    File(File),
}

fn open_input(c: &Common) -> Result<Input, ExitCode> {
    if is_dash(&c.input) {
        return Ok(Input::Stdin(io::stdin()));
    }
    let p = c.input.clone().unwrap();
    match File::open(&p) {
        Ok(f) => Ok(Input::File(f)),
        Err(e) => Err(fail(format!("cannot open {}: {e}", p.display()))),
    }
}

/// Prepare a file output: refuse an existing dst without --force, refuse dst == input.
fn prepare_out(c: &Common, input: &Input) -> Result<Option<(PathBuf, fsio::TempOut)>, ExitCode> {
    if is_dash(&c.out) {
        return Ok(None);
    }
    let dst = c.out.clone().unwrap();
    if let Input::File(f) = input {
        if fsio::ident_file(f).is_some() && fsio::ident_file(f) == fsio::ident(&dst) {
            return Err(fail("input and output are the same file"));
        }
    }
    if let Ok(m) = std::fs::symlink_metadata(&dst) {
        if !c.force {
            return Err(fail(format!("{} exists (use --force to replace it)", dst.display())));
        }
        if m.is_dir() {
            return Err(fail(format!("{} is a directory", dst.display())));
        }
    }
    match fsio::TempOut::for_dst(&dst) {
        Ok(t) => Ok(Some((dst, t))),
        Err(e) => Err(fail(format!("cannot create a temporary file next to {}: {e}", dst.display()))),
    }
}

fn run_seal(a: SealArgs) -> ExitCode {
    let c = &a.c;
    let seed = match load_key(&c.key) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if policy::is_demo_seed(&*seed) && !a.allow_demo_seed {
        return fail("this is the PUBLIC demo seed, not a key (pass --allow-demo-seed for samples/tests; make a real key with `octavo keygen`)");
    }
    let ad = match ad_bytes(c) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let input = match open_input(c) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let out = match prepare_out(c, &input) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if out.is_none() && io::stdout().is_terminal() && !c.force {
        return fail("refusing to write binary ciphertext to a terminal (use -o FILE, a pipe, or --force)");
    }
    let opts = octavo_cli::StreamOptions { chunk_size: a.chunk_size, threads: threads(c), batch_chunks: c.batch_chunks.clamp(1, 64) };
    let pickup = octavo_cli::fresh16(b"SN2/P");
    let nonce = octavo_cli::fresh16(b"SN2/Q");
    let mut rd: Box<dyn Read> = match input {
        Input::Stdin(s) => Box::new(s.lock()),
        Input::File(f) => Box::new(f),
    };
    match out {
        Some((dst, mut t)) => {
            let r = {
                let mut w = BufWriter::with_capacity(1 << 20, &mut t.file);
                octavo_cli::seal_stream(&seed, &mut *rd, &mut w, &pickup, &nonce, &ad, &opts).and_then(|x| {
                    w.flush()?;
                    Ok(x)
                })
            };
            match r {
                Ok(_) => match t.publish(&dst, c.force) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(format!("cannot publish {}: {e}", dst.display())),
                },
                Err(e) => fail(e),
            }
        }
        None => {
            let so = io::stdout();
            let mut w = BufWriter::with_capacity(1 << 20, so.lock());
            match octavo_cli::seal_stream(&seed, &mut *rd, &mut w, &pickup, &nonce, &ad, &opts) {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => fail(e),
            }
        }
    }
}

fn run_open(a: OpenArgs) -> ExitCode {
    let c = &a.c;
    let seed = match load_key(&c.key) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if policy::is_demo_seed(&*seed) {
        eprintln!("octavo: warning: this is the PUBLIC demo seed; anything sealed with it is readable by anyone");
    }
    let ad = match ad_bytes(c) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let input = match open_input(c) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let out = match prepare_out(c, &input) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let opts = octavo_cli::StreamOptions { chunk_size: 65536, threads: threads(c), batch_chunks: c.batch_chunks.clamp(1, 64) };
    let mut rd: Box<dyn Read> = match input {
        Input::Stdin(s) => Box::new(BufReader::with_capacity(1 << 20, s.lock())),
        Input::File(f) => Box::new(BufReader::with_capacity(1 << 20, f)),
    };
    match out {
        Some((dst, mut t)) => {
            let r = {
                let mut w = BufWriter::with_capacity(1 << 20, &mut t.file);
                octavo_cli::open_stream(&seed, &mut *rd, &mut w, &ad, &opts).and_then(|x| {
                    w.flush()?;
                    Ok(x)
                })
            };
            match r {
                Ok(_) => match t.publish(&dst, c.force) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(format!("cannot publish {}: {e}", dst.display())),
                },
                Err(e) => fail(format!("{e}; nothing was written to {}", dst.display())), // temp file dropped
            }
        }
        None if a.stream_verified_prefix => {
            let so = io::stdout();
            let mut w = BufWriter::with_capacity(1 << 20, so.lock());
            match octavo_cli::open_stream(&seed, &mut *rd, &mut w, &ad, &opts) {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => fail(format!("{e}; stdout may hold a verified prefix: discard it")),
            }
        }
        None => {
            // spool verified plaintext to a private anonymous temp file, copy out only on success
            let tmpdir = std::env::temp_dir();
            let mut t = match fsio::TempOut::new_in(&tmpdir, "octavo-open") {
                Ok(t) => t,
                Err(e) => return fail(format!("cannot create a private temporary file in {}: {e}", tmpdir.display())),
            };
            let r = {
                let mut w = BufWriter::with_capacity(1 << 20, &mut t.file);
                octavo_cli::open_stream(&seed, &mut *rd, &mut w, &ad, &opts).and_then(|x| {
                    w.flush()?;
                    Ok(x)
                })
            };
            if let Err(e) = r {
                return fail(format!("{e}; nothing was written to stdout"));
            }
            let res = (|| -> io::Result<()> {
                t.file.rewind()?;
                let so = io::stdout();
                let mut lk = so.lock();
                io::copy(&mut t.file, &mut lk)?;
                lk.flush()
            })();
            match res {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(format!("writing stdout: {e}")),
            }
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if !matches!(cli.cmd, Cmd::Policy) {
        first_use_notice();
    }
    match cli.cmd {
        Cmd::Keygen { out } => {
            let seed = match octavo_cli::keygen_seed() {
                Ok(s) => s,
                Err(e) => return fail(e),
            };
            let text = octavo_cli::seed_file_text(&seed);
            match fsio::write_new_secret(&out, &text) {
                Ok(()) => {
                    eprintln!("octavo: wrote a new 1024-bit key to {} (mode 0600). The key is not printed; keep the file secret and backed up.", out.display());
                    eprintln!("{BANNER}");
                    ExitCode::SUCCESS
                }
                Err(e) => fail(format!("cannot write {}: {e}", out.display())),
            }
        }
        Cmd::CheckKey { key } => match load_key(&key) {
            Ok(seed) => {
                if policy::is_demo_seed(&*seed) {
                    println!("{}: passes the weak-seed rule, BUT it is the PUBLIC demo seed (not a key)", key.display());
                } else {
                    println!("{}: ok (1024-bit seed, passes the weak-seed rule; that is a sanity check, not proof of secrecy)", key.display());
                }
                ExitCode::SUCCESS
            }
            Err(e) => e,
        },
        Cmd::Seal(a) => run_seal(a),
        Cmd::Open(a) => run_open(a),
        Cmd::Hear { key, wav, midi, program, sid, sid_wav, force } => {
            let seed = match load_key(&key) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let t = earworm::tune(&seed);
            println!("{}", earworm::notes_text(&t));
            // private (0600) temp file next to the target, published only when complete; an existing
            // file is never clobbered unless --force (then replaced atomically)
            let write_out = |p: &std::path::Path, data: &[u8]| -> std::io::Result<()> {
                if !force && std::fs::symlink_metadata(p).is_ok() {
                    return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "file exists (use --force to replace it)"));
                }
                let mut t = fsio::TempOut::for_dst(p)?;
                t.file.write_all(data)?;
                t.publish(p, force)
            };
            let sid_wav_data = match sid_wav.as_ref().map(|_| octavo_cli::sid::sid_wav(&t)).transpose() {
                Ok(d) => d,
                Err(e) => return fail(format!("SID render failed: {e}")),
            };
            for (p, data) in [
                (wav.as_ref(), wav.as_ref().map(|_| earworm::wav(&t))),
                (midi.as_ref(), midi.as_ref().map(|_| earworm::midi(&t, program))),
                (sid.as_ref(), sid.as_ref().map(|_| octavo_cli::sid::psid(&t))),
                (sid_wav.as_ref(), sid_wav_data),
            ] {
                if let (Some(p), Some(data)) = (p, data) {
                    if let Err(e) = write_out(p, &data) {
                        return fail(format!("cannot write {}: {e}", p.display()));
                    }
                    eprintln!("octavo: wrote {}", p.display());
                }
            }
            ExitCode::SUCCESS
        }
        Cmd::Policy => {
            print!("{}", policy::POLICY_TEXT);
            ExitCode::SUCCESS
        }
    }
}
