//! `n3file`: seal/open files with the experimental N3 cipher (SN3F v1 container over the 0x1C AEAD).
//! Octavo is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.

use clap::{Args, Parser, Subcommand};
use octavo_n3_draft3::aead::{default_threads, Aead};
use octavo_n3_file::format::{self, FileError, FILE_NONCE_LEN};
use octavo_n3_file::{fsio, policy, HONEST};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const BANNER: &str = "WARNING: Octavo (N3 draft) is still homemade; for real secrets use AES-GCM-SIV, age, or libsodium.";
const IO_BUF: usize = 1 << 20;

#[derive(Parser)]
#[command(
    name = "n3file",
    version,
    about = "n3file: seal/open files with the experimental 1024-bit N3 cipher (SN3F v1 chunked container over the N3 0x1C AEAD).",
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
    /// Encrypt a file or stdin into an SN3F v1 file (chunked; each chunk sealed with the N3 0x1C AEAD).
    #[command(before_help = BANNER, after_help = HONEST)]
    Seal(SealArgs),
    /// Decrypt and verify an SN3F v1 file. The output file appears only if EVERY chunk and the end verify.
    #[command(before_help = BANNER, after_help = HONEST)]
    Open(OpenArgs),
    /// Print the weak-seed policy.
    #[command(before_help = BANNER, after_help = HONEST)]
    Policy,
}

#[derive(Args)]
struct Common {
    /// Key file (256 hex digits, 0600), e.g. from `n3file keygen`.
    #[arg(short, long)]
    key: PathBuf,
    /// Input file; `-` or omitted = stdin.
    input: Option<PathBuf>,
    /// Output file (`-` = stdout).
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Associated data (UTF-8 text), must match on open.
    #[arg(long, conflicts_with = "ad_hex")]
    ad: Option<String>,
    /// Associated data as hex.
    #[arg(long)]
    ad_hex: Option<String>,
    /// Worker threads (default: CPUs, at most 8). Output bytes do not depend on it.
    #[arg(short = 'j', long, value_parser = clap::value_parser!(u16).range(1..=256))]
    threads: Option<u16>,
    /// Replace an existing output file (atomically).
    #[arg(short, long)]
    force: bool,
}

#[derive(Args)]
struct SealArgs {
    #[command(flatten)]
    c: Common,
    /// Plaintext bytes per chunk: a multiple of 128 in 128..=1048576.
    #[arg(long, default_value_t = format::DEFAULT_CHUNK)]
    chunk_size: usize,
    /// Allow the PUBLIC demo seed (samples and tests only).
    #[arg(long)]
    allow_demo_seed: bool,
    /// TESTS ONLY: use this 32-hex-digit file nonce instead of a fresh OS-RNG one. Reusing a file
    /// nonce with the same key and AD makes equal files encrypt equally.
    #[arg(long, hide = true)]
    test_file_nonce: Option<String>,
}

#[derive(Args)]
struct OpenArgs {
    #[command(flatten)]
    c: Common,
    /// Allow `-o -` (stdout). Each chunk is written as soon as IT verifies, so if a later chunk
    /// fails (or the file was cut short), stdout already holds a verified prefix that cannot be
    /// withheld; n3file then exits 1 and you must discard that output.
    #[arg(long)]
    stdout_unverified_tail: bool,
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("n3file: error: {msg}");
    ExitCode::from(1)
}
fn usage(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("n3file: usage error: {msg}");
    ExitCode::from(2)
}

fn user_ad(c: &Common) -> Result<Vec<u8>, ExitCode> {
    match (&c.ad, &c.ad_hex) {
        (Some(t), _) => Ok(t.as_bytes().to_vec()),
        (None, Some(h)) => octavo_n3_file::unhex(h.trim()).ok_or_else(|| usage("--ad-hex is not an even-length hex string")),
        (None, None) => Ok(Vec::new()),
    }
}

fn load_key(p: &Path) -> Result<octavo_n3_file::Seed, ExitCode> {
    match octavo_n3_file::load_key(p) {
        Ok((seed, warn)) => {
            for w in warn {
                eprintln!("n3file: warning: {w}");
            }
            Ok(seed)
        }
        Err(e) => Err(fail(e)),
    }
}

fn is_stdio(p: &Option<PathBuf>) -> bool {
    p.as_ref().map_or(true, |p| p.as_os_str() == "-")
}

fn open_input(c: &Common) -> Result<Box<dyn Read>, ExitCode> {
    if is_stdio(&c.input) {
        return Ok(Box::new(BufReader::with_capacity(IO_BUF, io::stdin().lock())));
    }
    let p = c.input.as_ref().unwrap();
    match File::open(p) {
        Ok(f) => Ok(Box::new(BufReader::with_capacity(IO_BUF, f))),
        Err(e) => Err(fail(format!("cannot open {}: {e}", p.display()))),
    }
}

/// For a file output: refuse an existing file without --force, refuse output == input, and make
/// a private temp file next to it (published only on success).
fn prepare_out(c: &Common, dst: &Path) -> Result<fsio::TempOut, ExitCode> {
    if !c.force && std::fs::symlink_metadata(dst).is_ok() {
        return Err(fail(format!("{} exists (use --force to replace it)", dst.display())));
    }
    if !is_stdio(&c.input) {
        if let (Some(a), Some(b)) = (fsio::ident(c.input.as_ref().unwrap()), fsio::ident(dst)) {
            if a == b {
                return Err(fail("input and output are the same file"));
            }
        }
    }
    fsio::TempOut::for_dst(dst).map_err(|e| fail(format!("cannot create a temporary file next to {}: {e}", dst.display())))
}

type Job<'a> = dyn FnMut(&mut dyn Write) -> Result<format::Summary, FileError> + 'a;

/// Run `job` into `-o FILE` (temp + atomic publish) or stdout.
fn run_to(c: &Common, to_stdout: bool, job: &mut Job) -> ExitCode {
    if to_stdout {
        let out = io::stdout();
        let mut w = BufWriter::with_capacity(IO_BUF, out.lock());
        let r = job(&mut w);
        let flushed = w.flush();
        return match (r, flushed) {
            (Ok(_), Ok(())) => ExitCode::SUCCESS,
            (Err(e), _) => fail(e),
            (_, Err(e)) => fail(format!("writing stdout: {e}")),
        };
    }
    let dst = c.out.as_ref().unwrap();
    let mut t = match prepare_out(c, dst) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let r = {
        let mut w = BufWriter::with_capacity(IO_BUF, &mut t.file);
        match job(&mut w) {
            Ok(s) => w.flush().map(|_| s).map_err(FileError::Io),
            Err(e) => Err(e),
        }
    };
    match r {
        // dropping `t` without publishing wipes and removes the temp file: nothing is written
        Err(e) => fail(e),
        Ok(_) => match t.publish(dst, c.force) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(format!("cannot publish {}: {e}", dst.display())),
        },
    }
}

fn run_seal(a: SealArgs) -> ExitCode {
    let c = &a.c;
    if let Err(e) = format::check_chunk_size(a.chunk_size) {
        return usage(e);
    }
    let ad = match user_ad(c) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let mut nonce = [0u8; FILE_NONCE_LEN];
    match &a.test_file_nonce {
        Some(h) => match octavo_n3_file::unhex(h.trim()) {
            Some(v) if v.len() == FILE_NONCE_LEN => {
                nonce.copy_from_slice(&v);
                eprintln!("n3file: warning: --test-file-nonce is for tests only; never reuse a file nonce for real data");
            }
            _ => return usage("--test-file-nonce needs exactly 32 hex digits"),
        },
        None => {
            if let Err(e) = getrandom::getrandom(&mut nonce) {
                return fail(format!("OS RNG failed: {e}"));
            }
        }
    }
    let to_stdout = is_stdio(&c.out);
    if to_stdout && io::stdout().is_terminal() {
        return usage("refusing to write ciphertext to a terminal; use -o FILE or redirect stdout");
    }
    let seed = match load_key(&c.key) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if policy::is_demo_seed(&seed[..]) {
        if !a.allow_demo_seed {
            return fail("this key is the PUBLIC demo seed; anyone can open what it seals (pass --allow-demo-seed for samples/tests)");
        }
        eprintln!("n3file: warning: sealing with the PUBLIC demo seed: this protects nothing");
    }
    let threads = c.threads.map_or_else(default_threads, |t| t as usize);
    let aead = Aead::new(&seed).with_threads(1);
    drop(seed);
    let mut input = match open_input(c) {
        Ok(r) => r,
        Err(code) => return code,
    };
    run_to(c, to_stdout, &mut |w| format::seal_stream(&aead, &mut input, w, a.chunk_size, &ad, &nonce, threads))
}

fn run_open(a: OpenArgs) -> ExitCode {
    let c = &a.c;
    let ad = match user_ad(c) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let to_stdout = match &c.out {
        None => return usage("open needs -o FILE (or `-o - --stdout-unverified-tail` to stream to stdout)"),
        Some(p) if p.as_os_str() == "-" => {
            if !a.stdout_unverified_tail {
                return usage("`-o -` needs --stdout-unverified-tail (stdout cannot be withheld if a later chunk fails)");
            }
            true
        }
        Some(_) => {
            if a.stdout_unverified_tail {
                return usage("--stdout-unverified-tail only applies to `-o -`");
            }
            false
        }
    };
    if to_stdout {
        eprintln!(
            "n3file: warning: writing to stdout chunk by chunk; if a later chunk fails or the file was cut short, \
             stdout already holds a verified prefix that cannot be withheld. Exit code 1 means: discard the output."
        );
    }
    let seed = match load_key(&c.key) {
        Ok(s) => s,
        Err(code) => return code,
    };
    if policy::is_demo_seed(&seed[..]) {
        eprintln!("n3file: warning: this key is the PUBLIC demo seed: whatever it sealed is not secret");
    }
    let threads = c.threads.map_or_else(default_threads, |t| t as usize);
    let aead = Aead::new(&seed).with_threads(1);
    drop(seed);
    let mut input = match open_input(c) {
        Ok(r) => r,
        Err(code) => return code,
    };
    run_to(c, to_stdout, &mut |w| format::open_stream(&aead, &mut input, w, &ad, threads))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen { out } => {
            let seed = match octavo_n3_file::keygen_seed() {
                Ok(s) => s,
                Err(e) => return fail(e),
            };
            match fsio::write_new_secret(&out, &octavo_n3_file::seed_file_text(&seed)) {
                Ok(()) => {
                    eprintln!("n3file: wrote a new key to {} (mode 0600). Keep it secret; it is never printed.", out.display());
                    ExitCode::SUCCESS
                }
                Err(e) => fail(format!("cannot write {}: {e}", out.display())),
            }
        }
        Cmd::CheckKey { key } => match octavo_n3_file::load_key(&key) {
            Ok((seed, warn)) => {
                for w in warn {
                    eprintln!("n3file: warning: {w}");
                }
                if policy::is_demo_seed(&seed[..]) {
                    println!("key OK by the weak-seed rule, BUT it is the PUBLIC demo seed (seal refuses it without --allow-demo-seed)");
                } else {
                    println!("key OK: 1024-bit seed passes the weak-seed rule (a structure check, not an entropy test)");
                }
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        },
        Cmd::Seal(a) => run_seal(a),
        Cmd::Open(a) => run_open(a),
        Cmd::Policy => {
            print!("{}", policy::POLICY_TEXT);
            ExitCode::SUCCESS
        }
    }
}
