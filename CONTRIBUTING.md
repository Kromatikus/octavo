# Contributing

Octavo is an experimental, homemade cipher for learning and for fun.

**Do not use it to protect real data.** Use AES-GCM-SIV, age, or libsodium.

## Reporting a weakness or a bug

Please open a GitHub issue with a description and, if you can, a script that
reproduces it. Credible cryptographic findings are added to
[ATTACKS.md](ATTACKS.md) with credit. [SECURITY.md](SECURITY.md) has more on
what the self-checks do and do not guarantee.

## Running the tests

There is no CI on this repository yet. Please run the tests locally before
opening a pull request.

Python 3.10+ (numpy is needed only for the test suite):

```bash
pip install numpy
python3 -B quick_check.py
python3 -B test_octavo_app.py
python3 -B test_sneak_n2.py            # about 10–13 minutes
python3 -B independent_check/run_check.py
```

Rust 1.89 or newer ([rustup](https://rustup.rs)), from `rust/`:

```bash
cargo test --release --workspace --all-features
tools/run_all.sh
```

`sneak_n2.py` must stay at SHA-256
`19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee` unless the
change is a deliberate, documented cipher or format revision with new vectors.
