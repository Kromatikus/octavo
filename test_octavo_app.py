"""Tests for the app-ready octavo.seal / open_ API.

Run as part of test_sneak_n2.py (preferred) or standalone:
    python3 test_octavo_app.py

Does not change the cipher. All new checks go through octavo.py.
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import octavo
import sneak_n2 as N


def _run(check):
    # Isolate the one-time warning from any earlier import-time experiments.
    octavo._WARNED = False

    check("DEMO_ONLY is True", octavo.DEMO_ONLY is True)
    check("APP_KEY_INFO is the documented domain label",
          octavo.APP_KEY_INFO == b"Octavo app key v1")
    check("Rejected family is sneak_n2's",
          octavo.Rejected is N.Rejected and octavo.AuthError is N.AuthError
          and octavo.DecodeError is N.DecodeError
          and octavo.UnsupportedVersion is N.UnsupportedVersion
          and issubclass(octavo.AuthError, octavo.Rejected)
          and "open_" in octavo.__all__ and "seal" in octavo.__all__)

    # ---- generate_key / expand_key
    k = octavo.generate_key()
    k2 = octavo.generate_key()
    check("generate_key returns 32 distinct random bytes and does not write a file",
          type(k) is bytes and len(k) == 32 and k != k2 and k != b"\x00" * 32
          and not os.path.isfile(os.path.join(HERE, k.hex())))
    seed = octavo.expand_key(k)
    check("expand_key of a 32-byte key is a 128-byte seed, stable, and accepted by the cipher",
          type(seed) is bytes and len(seed) == 128
          and octavo.expand_key(k) == seed
          and octavo.expand_key(bytearray(k)) == seed
          and octavo.expand_key(memoryview(k)) == seed
          and bytes(N._seed_bytes(seed)) == seed)

    k64 = k + k2
    seed64 = octavo.expand_key(k64)
    check("expand_key of a 64-byte key is a different 128-byte seed",
          len(k64) == 64 and len(seed64) == 128 and seed64 != seed
          and octavo.expand_key(k64) == seed64)

    bad_types = []
    for bad in (None, "x" * 32, 32, 0, True, False, [0] * 32, 1):
        try:
            octavo.expand_key(bad)
            bad_types.append(("no-raise", type(bad).__name__))
        except TypeError:
            pass
        except Exception as e:
            bad_types.append((type(e).__name__, type(bad).__name__))
    bad_lens = []
    for n in (0, 16, 31, 33, 63, 65, 128, 31, 1):
        try:
            octavo.expand_key(b"\x01" * n)
            bad_lens.append(("no-raise", n))
        except ValueError:
            pass
        except Exception as e:
            bad_lens.append((type(e).__name__, n))
    zero_ok = []
    for n in (32, 64):
        try:
            octavo.expand_key(b"\x00" * n)
            zero_ok.append(("no-raise", n))
        except ValueError:
            pass
        except Exception as e:
            zero_ok.append((type(e).__name__, n))
    check("expand_key rejects str, None, int and other non-bytes types with TypeError",
          bad_types == [])
    check("expand_key rejects lengths other than 32 or 64 with ValueError",
          bad_lens == [])
    check("expand_key rejects an all-zero 32- or 64-byte key with ValueError",
          zero_ok == [])

    # ---- round trip, AD, wrong key, tampering, v6 only
    msg = b"hello app"
    ad = b"from:alice"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        blob = octavo.seal(k, msg, ad=ad)
        out = octavo.open_(k, blob, ad=ad)
        out2 = octavo.open(k, blob, ad=ad)
    check("seal/open_ (and module open) round-trip a message with AD as a v6 blob",
          out == msg and out2 == msg and blob[:4] == b"\x06SN2"
          and len(blob) == N.BLOB_LEN)

    e_ad = None
    e_key = None
    e_tamp = None
    e_v9 = None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        try:
            octavo.open_(k, blob, ad=b"from:bob")
        except Exception as e:
            e_ad = e
        try:
            octavo.open_(k2, blob, ad=ad)
        except Exception as e:
            e_key = e
        bad = bytearray(blob)
        bad[-1] ^= 1
        try:
            octavo.open_(k, bytes(bad), ad=ad)
        except Exception as e:
            e_tamp = e
        # A v9 rehearsal blob must not be opened by this API (no legacy modes).
        rpath = os.path.join(HERE, "rehearsal-demo.txt")
        rblob = None
        if os.path.isfile(rpath):
            for line in open(rpath, encoding="utf-8"):
                if line.startswith("blob"):
                    rblob = bytes.fromhex(line.split()[-1])
                    break
        if rblob is not None:
            try:
                octavo.open_(k, rblob)
            except Exception as e:
                e_v9 = e
        else:
            e_v9 = octavo.UnsupportedVersion("missing demo")
    check("open_ binds AD: the wrong AD raises AuthError('authentication failed')",
          isinstance(e_ad, octavo.AuthError) and str(e_ad) == "authentication failed"
          and isinstance(e_ad, octavo.Rejected))
    check("open_ with the wrong key raises AuthError('authentication failed')",
          isinstance(e_key, octavo.AuthError) and str(e_key) == "authentication failed")
    check("a tampered v6 blob raises AuthError('authentication failed')",
          isinstance(e_tamp, octavo.AuthError) and str(e_tamp) == "authentication failed")
    check("open_ does not enable legacy modes: a v9 blob raises UnsupportedVersion",
          isinstance(e_v9, octavo.UnsupportedVersion) and isinstance(e_v9, octavo.Rejected))

    # seal/open also reject bad keys the same way
    e_seal_none = None
    try:
        octavo.seal(None, b"hi")
    except Exception as e:
        e_seal_none = e
    e_open_zero = None
    try:
        octavo.open_(b"\x00" * 32, blob)
    except Exception as e:
        e_open_zero = e
    check("seal/open_ reject None and an all-zero key before touching the blob",
          isinstance(e_seal_none, TypeError) and isinstance(e_open_zero, ValueError))

    # ---- warning fires once
    octavo._WARNED = False
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        kk = octavo.generate_key()  # generate_key itself should not warn
        b1 = octavo.seal(kk, b"hi")
        octavo.open_(kk, b1)
        octavo.seal(kk, b"yo")
        msgs = [str(w.message) for w in rec if issubclass(w.category, UserWarning)
                and "homemade" in str(w.message).lower()]
    check("a one-time UserWarning on first seal/open says homemade / not for real secrets",
          len(msgs) == 1
          and "not for real secrets" in msgs[0].lower()
          and "AES-GCM-SIV" in msgs[0]
          and "libsodium" in msgs[0]
          and "age" in msgs[0])

    # ---- app vectors (key expansion + recorded blobs)
    app_path = os.path.join(HERE, "score", "app_vectors.json")
    app = json.load(open(app_path, encoding="utf-8"))
    keys = {e["id"]: e for e in app["keys"]}
    exp_ok = app["kdf"]["info"] == "Octavo app key v1" and len(keys) >= 2
    for e in app["keys"]:
        if octavo.expand_key(bytes.fromhex(e["key"])).hex() != e["seed"]:
            exp_ok = False
    open_ok = True
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        for b in app["blobs"]:
            key = bytes.fromhex(keys[b["key_id"]]["key"])
            ad_b = bytes.fromhex(b["ad_hex"]) if b["ad_hex"] else b""
            msg_b = bytes.fromhex(b["msg_hex"])
            blob_b = bytes.fromhex(b["blob"])
            if blob_b[:1] != b"\x06" or octavo.open_(key, blob_b, ad=ad_b) != msg_b:
                open_ok = False
    check("app key-expansion vectors in score/app_vectors.json match expand_key",
          exp_ok and not os.path.samefile(app_path, os.path.join(HERE, "score", "vectors.json")))
    check("recorded app blobs open with the published key, AD and message",
          open_ok and app["blobs"] and all(b.get("fmt_version") == 6 for b in app["blobs"]))

    # The 79-vector published score is untouched (app vectors live in a separate file).
    score = json.load(open(os.path.join(HERE, "score", "vectors.json"), encoding="utf-8"))
    check("published score still has 79 vectors and is not the app-vector file",
          score["counts"]["total"] == 79 and "keys" not in score)

    # ---- verify_install
    got = octavo.verify_install(HERE)
    check("verify_install passes on the clean tree and matches published SHAs",
          got["sneak_n2_sha256"] == score["sneak_n2_sha256"]
          == "19181bc1623115c075dc5dee25edec388f5413466777d47b7f19fa66d1e71eee"
          and got["etudes_sha256"] == score["etudes_sha256"]
          and got["generate_score_sha256"] == score["generate_score_sha256"])

    # One-byte edit in a scratch copy: hash check must fail. Do not import the edited file.
    with tempfile.TemporaryDirectory(prefix="n2_appready_") as td:
        os.makedirs(os.path.join(td, "score"))
        for name in ("sneak_n2.py", "etudes.py"):
            shutil.copy2(os.path.join(HERE, name), os.path.join(td, name))
        for name in ("vectors.json", "generate_score.py", "app_vectors.json"):
            shutil.copy2(os.path.join(HERE, "score", name), os.path.join(td, "score", name))
        # clean copy should pass
        clean_ok = True
        try:
            octavo.verify_install(td)
        except Exception:
            clean_ok = False
        path = os.path.join(td, "sneak_n2.py")
        data = bytearray(open(path, "rb").read())
        # Flip a byte in the trailing newline / last source byte so it stays valid-ish as a file.
        data[-1] ^= 0x01
        open(path, "wb").write(data)
        failed = False
        err = None
        try:
            octavo.verify_install(td)
        except RuntimeError as e:
            failed = True
            err = e
        check("verify_install fails on a one-byte edit of sneak_n2.py in a scratch copy",
              clean_ok and failed and "sneak_n2.py" in str(err)
              and "does not match" in str(err))


def run_checks(check):
    """Entry point used by test_sneak_n2.py."""
    _run(check)


if __name__ == "__main__":
    P = F = 0

    def check(name, cond):
        global P, F
        if cond:
            P += 1
            print("PASS", name)
        else:
            F += 1
            print("FAIL", name)

    _run(check)
    print(f"\n{P}/{P+F} passed, {F} failed, 0 skipped")
    sys.exit(1 if F else 0)
