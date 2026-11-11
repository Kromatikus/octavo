"""Études — reduced-round Octavo, for cryptanalysis only.

WARNING: These are intentionally weakened. NOT for any secret, even a toy one.
Do not use this module to protect data. The published études are 2, 4 and 6
rounds; 16-round études exist only so a lab can compare against the full
cipher core. They use distinct blob version bytes.

Key separation (conductor revision). An étude never runs under the live
round material. Every étude derives its own 128-byte étude key

    K_e = StaffSponge(b"E", seed, bytes([rounds]) || 15 zero bytes).take(128)

(squeezing further only in the astronomically unlikely case that the
first 128 bytes fail the weak-seed rule) and then uses K_e everywhere the
live code uses the seed: clef, commitment key, MAC key, Schedule (round
keys, S-boxes, whitening), theme, tweak, cadence and coda keys. Domain
letter E is unused by the live cipher, and the round count is in the
tweak, so études at different round counts do not share material either.
The étude version byte is also hashed into the SIV nonce:

    nonce = SHA-256(clef_e || version || pickup || encode_block(msg) || encode_ad(ad))[:16]
    (movements: ... || version || pickup || uint64be(len) || msg || encode_ad(ad))

So an étude handle cannot decrypt (or unpermute) a live ciphertext, and a
reduced-round étude given a live pickup no longer reproduces that blob's
nonce or Schedule. The 16-round étude permutation is still the live
16-round staff-core, just keyed by K_e: permute(block, seed, nonce) equals
encrypt_grid(block, Schedule(etude_key(seed, 16), nonce)).

Seeds. Études refuse seed=None and the public demo seed
(sneak1024-seed.txt, published in score/vectors.json) unless the handle
was made with etude(r, lab_seed=True). The published score uses that flag.

Version bytes. Current étude blobs start with 0x82/0x84/0x86/0x90
(single-block) or 0x83/0x85/0x87/0x91 (movements) and carry an AD-bound
(and nmov-bound) commitment like live v6/v7. Etude(r) opens only its own
round count; another étude's byte raises UnsupportedVersion("étude round
count mismatch"). Rejected outright: live v6/v7, the never-published
tuning-fix étude bytes 0xA2/0xA4/0xA6/0xB0 and 0xA3/0xA5/0xA7/0xB1, and the
unpublished tuning bytes 0xC*/0xD*. Published octavo009 étude blobs
(0xE2/0xE4/0xE6/0xF0 and 0xE3/0xE5/0xE7/0xF1) open only through
decrypt_legacy() / decrypt_movements_legacy() with
allow_noncommitting=True (LegacyFormatWarning); they were made with the
raw seed, before key separation, and are not key-committing.

Legacy end date (conductor-polish I1). The legacy étude helpers
(Etude.decrypt_legacy / decrypt_movements_legacy, bytes 0xE*/0xF*) are a
transition aid only. They are deprecated now and will be REMOVED in the
first revision after the conductor-polish freeze (octavo010) that touches
etudes.py, and in any case no later than 2027-03-01. After that the
octavo009 étude score opens only from the frozen octavo009 tree.

Seed gate. lab_seed is fixed when the handle is made and is read-only
afterwards (conductor-polish I6). etude_key(seed, r) is the deliberate,
documented ungated low-level path (no demo-seed check). Étude keys K_e are
_DerivedKey values: checked by the weak-seed rule on every use and never
put in the live seed memo (conductor-polish I5).

Lab hook: encrypt and encrypt_movements accept an optional fixed `pickup` so
published score vectors are deterministic. The normal APIs have no such
argument, by design.

Use:
    from etudes import etude
    E = etude(4, lab_seed=True)           # a 4-round étude on the demo seed
    ct = E.permute(block, seed, nonce)    # raw 128-byte keyed permutation (étude key)
    blob = E.encrypt(msg, seed, pickup=fixed_pickup)
    E.decrypt(blob, seed)
"""
import hashlib, hmac
import sneak_n2 as N

ETUDE_WARNING = (
    "ÉTUDE: weakened reduced-round Octavo for cryptanalysis only. "
    "NOT for secrets."
)
ETUDE_ROUNDS = (2, 4, 6, 16)
ETUDE_KEY_DOMAIN = b"E"      # unused by the live cipher (live: C G K M U T W D O)
# SHA-256 of the public demo seed (sneak1024-seed.txt). Refused unless lab_seed=True.
DEMO_SEED_SHA256 = "8d1f7c16876c149c2d445c2817a230ffaaec9d8a2fc9769e2f3aae155e3b8e24"

# Current (conductor) étude bytes: key-separated, version byte in the SIV nonce.
# High nibble 0x8 marks a committed reduced étude; 0x9 a committed full-round étude.
# Even values are single-block; odd values are movements.
ETUDE_FMT_BLOCK = {2: 0x82, 4: 0x84, 6: 0x86, 16: 0x90}
ETUDE_FMT_MOVEMENTS = {2: 0x83, 4: 0x85, 6: 0x87, 16: 0x91}
# Never-published tuning-fix étude bytes (shared live key material). Rejected.
ETUDE_FMT_BLOCK_TUNINGFIX = {2: 0xA2, 4: 0xA4, 6: 0xA6, 16: 0xB0}
ETUDE_FMT_MOVEMENTS_TUNINGFIX = {2: 0xA3, 4: 0xA5, 6: 0xA7, 16: 0xB1}
# Pre-tuning étude version bytes (no commitment, raw seed). decrypt_legacy() only.
ETUDE_FMT_BLOCK_LEGACY = {2: 0xE2, 4: 0xE4, 6: 0xE6, 16: 0xF0}
ETUDE_FMT_MOVEMENTS_LEGACY = {2: 0xE3, 4: 0xE5, 6: 0xE7, 16: 0xF1}
# Unpublished tuning-revision étude bytes (commitment without AD/nmov). Rejected.
ETUDE_FMT_BLOCK_TUNING = {2: 0xC2, 4: 0xC4, 6: 0xC6, 16: 0xD0}
ETUDE_FMT_MOVEMENTS_TUNING = {2: 0xC3, 4: 0xC5, 6: 0xC7, 16: 0xD1}
_BLOCK_ROUNDS = {v: r for r, v in ETUDE_FMT_BLOCK.items()}
_MOVEMENTS_ROUNDS = {v: r for r, v in ETUDE_FMT_MOVEMENTS.items()}
_BLOCK_ROUNDS_LEGACY = {v: r for r, v in ETUDE_FMT_BLOCK_LEGACY.items()}
_MOVEMENTS_ROUNDS_LEGACY = {v: r for r, v in ETUDE_FMT_MOVEMENTS_LEGACY.items()}


def _check_rounds(rounds):
    if rounds not in ETUDE_ROUNDS:
        raise ValueError("études are only published at 2, 4, 6 and 16 rounds")
    return rounds


def _pickup(pickup):
    if pickup is None:
        return N._fresh_pickup()
    pickup = N._as_bytes("pickup", pickup)
    if len(pickup) != N.PICKUP_LEN:
        raise ValueError("pickup must be 16 bytes")
    return pickup


def etude_key(seed, rounds) -> bytes:
    """K_e = StaffSponge(b"E", seed, bytes([rounds]) || 15 zero bytes).take(128).

    Squeezes the next 128 bytes if a candidate fails the weak-seed rule
    (probability far below 2^-100). Low-level and deliberately UNGATED: no
    demo-seed check here (the Etude handles add it). Returns a _DerivedKey,
    which the live seed memo never stores (conductor-polish I5)."""
    seed = N._seed_bytes(seed)
    sp = N.StaffSponge(ETUDE_KEY_DOMAIN, seed, bytes([_check_rounds(rounds)]) + bytes(N.NONCE_LEN - 1))
    while True:
        k = N._DerivedKey(sp.take(N.BLOCK_LEN))
        try:
            N._seed_bytes(k)
        except ValueError:
            continue
        return k


class Etude:
    """One published étude (2, 4, 6 or 16 rounds). Cryptanalysis only."""

    def __init__(self, rounds, lab_seed=False):
        self.rounds = _check_rounds(rounds)
        self._lab_seed = lab_seed is True
        self.fmt_block = ETUDE_FMT_BLOCK[self.rounds]
        self.fmt_movements = ETUDE_FMT_MOVEMENTS[self.rounds]
        self.fmt_block_legacy = ETUDE_FMT_BLOCK_LEGACY[self.rounds]
        self.fmt_movements_legacy = ETUDE_FMT_MOVEMENTS_LEGACY[self.rounds]
        self.warning = ETUDE_WARNING

    @property
    def lab_seed(self) -> bool:
        """Read-only (conductor-polish I6): set once by etude(r, lab_seed=True)."""
        return self._lab_seed

    # ---------------------------------------------------------------- keys
    def _seed(self, seed) -> bytes:
        """Refuse seed=None and the public demo seed unless lab_seed=True."""
        if seed is None and not self.lab_seed:
            raise ValueError("études need an explicit seed; seed=None (the public demo seed) requires etude(r, lab_seed=True)")
        s = N._seed_bytes(seed)
        if not self.lab_seed and hashlib.sha256(s).hexdigest() == DEMO_SEED_SHA256:
            raise ValueError("the public demo seed requires etude(r, lab_seed=True)")
        return s

    def key(self, seed) -> bytes:
        """This étude's derived key K_e (after the seed gate)."""
        return etude_key(self._seed(seed), self.rounds)

    def _check_version(self, v, own, others):
        if v == own:
            return
        if v in others:
            raise N.UnsupportedVersion("étude round count mismatch")
        raise N.UnsupportedVersion("unsupported version")

    # ---------------------------------------------------------------- raw permutation
    def permute(self, block, seed=None, nonce=None) -> bytes:
        """Raw 128-byte keyed permutation at this étude's round count, plus whitening.

        Uses the first `rounds` keys of a full 16-round Schedule(K_e, nonce),
        then that Schedule's whitening. 16-round output equals the live
        encrypt_grid under Schedule(etude_key(seed, 16), nonce), NOT under
        Schedule(seed, nonce): an étude cannot touch live round material.
        """
        block = N._as_bytes("block", block)
        nonce = N._as_bytes("nonce", nonce)
        if len(block) != N.BLOCK_LEN:
            raise ValueError("block must be 128 bytes")
        if len(nonce) != N.NONCE_LEN:
            raise ValueError("nonce must be 16 bytes")
        sch = N.Schedule(self.key(seed), nonce)
        return N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(block), sch, rounds=self.rounds))

    def unpermute(self, block, seed=None, nonce=None) -> bytes:
        """Inverse of permute for the same seed, nonce and round count (étude key, unauthenticated)."""
        block = N._as_bytes("block", block)
        nonce = N._as_bytes("nonce", nonce)
        if len(block) != N.BLOCK_LEN:
            raise ValueError("block must be 128 bytes")
        if len(nonce) != N.NONCE_LEN:
            raise ValueError("nonce must be 16 bytes")
        sch = N.Schedule(self.key(seed), nonce)
        return N.grid_to_bytes(N.decrypt_grid(N.bytes_to_grid(block), sch, rounds=self.rounds))

    # ---------------------------------------------------------------- single-block
    def siv_nonce(self, msg, pickup, seed=None, ad=b"") -> bytes:
        """SHA-256(clef_e || version || pickup || encode_block(msg) || encode_ad(ad))[:16]."""
        msg = N._as_bytes("msg", msg)
        pickup = N._as_bytes("pickup", pickup)
        if len(pickup) != N.PICKUP_LEN:
            raise ValueError("pickup must be 16 bytes")
        k = self.key(seed)
        return hashlib.sha256(N.staff_clef(k) + bytes([self.fmt_block]) + pickup + N.encode_block(msg)
                              + N._encode_ad(ad)).digest()[:N.NONCE_LEN]

    def encrypt(self, msg, seed=None, ad=b"", pickup=None, nonce=None) -> bytes:
        """Single-block AEAD étude under K_e. Optional `pickup` makes the blob deterministic.

        Layout matches version-6 blobs except the leading version byte is the
        étude flag (0x82/0x84/0x86/0x90). A caller nonce must equal the SIV
        nonce. Normal decrypt rejects the result as UnsupportedVersion.
        """
        msg = N._as_bytes("msg", msg)
        ad = N._normalize_ad(ad)
        k = self.key(seed)
        fmt = self.fmt_block
        block = N.encode_block(msg)
        adb = N._encode_ad(ad)
        clef = N.staff_clef(k)
        pickup = _pickup(pickup)
        syn = hashlib.sha256(clef + bytes([fmt]) + pickup + block + adb).digest()[:N.NONCE_LEN]
        if nonce is not None and not hmac.compare_digest(N._as_bytes("nonce", nonce), syn):
            raise ValueError("nonce must be the synthetic (SIV) nonce for this message and pickup")
        nonce = syn
        sch = N.Schedule(k, nonce)
        ct = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(block), sch, rounds=self.rounds))
        commit = N._commitment(N._commit_key(k), fmt, pickup, nonce, ad)
        tag = N._tag(sch.mac_key, pickup, nonce, ct, clef, N.key_signature(k), ad,
                     version=fmt, commit=commit)
        return bytes([fmt]) + N.VERSION + pickup + nonce + commit + ct + tag

    def decrypt(self, blob, seed=None, ad=b"") -> bytes:
        """Open a single-block étude blob made at THIS round count.

        The version byte must be this handle's own (another étude round
        count raises UnsupportedVersion("étude round count mismatch")).
        Like live decrypt, the commitment and the tag are both computed
        and compared before one combined AuthError is raised (equal-time
        reject); the Schedule is built only after both pass. Live v6
        blobs, never-published tuning-fix (0xA*/0xB*) and unpublished
        tuning (0xC*/0xD*) étude bytes, and legacy 0xE*/0xF* bytes raise
        UnsupportedVersion. Use decrypt_legacy(..., allow_noncommitting=True)
        for published octavo009 étude blobs.
        """
        blob = N._as_bytes("blob", blob)
        ad = N._normalize_ad(ad)
        if len(blob) < 1:
            raise N.AuthError("bad blob length")
        self._check_version(blob[0], self.fmt_block, _BLOCK_ROUNDS)
        k = self.key(seed)
        fmt = self.fmt_block
        if len(blob) != N.BLOB_LEN:
            raise N.AuthError("bad blob length")
        v, pickup, nonce, commit, ct, tag = N.split_blob(blob)
        if not hmac.compare_digest(v, bytes([fmt]) + N.VERSION):
            raise N.AuthError("bad version prefix")
        commit_ok = hmac.compare_digest(commit, N._commitment(N._commit_key(k), fmt, pickup, nonce, ad))
        clef = N.staff_clef(k)
        mac_key = N.StaffSponge(b"M", k, nonce).take(32)
        tag_ok = hmac.compare_digest(tag, N._tag(mac_key, pickup, nonce, ct, clef, N.key_signature(k), ad,
                                                 version=fmt, commit=commit))
        if not (commit_ok & tag_ok):
            raise N.AuthError("authentication failed")
        sch = N.Schedule(k, nonce)
        b = N.grid_to_bytes(N.decrypt_grid(N.bytes_to_grid(ct), sch, rounds=self.rounds))
        ok, msg = N._unpad_block(b)
        if not ok:
            raise N.DecodeError("tag valid but block malformed")
        if not hmac.compare_digest(nonce, hashlib.sha256(clef + bytes([fmt]) + pickup + N.encode_block(msg) + N._encode_ad(ad)).digest()[:N.NONCE_LEN]):
            raise N.AuthError("SIV nonce mismatch")
        return msg

    def decrypt_legacy(self, blob, seed=None, ad=b"", *, allow_noncommitting=False) -> bytes:
        """Open a published pre-tuning étude blob (0xE2/0xE4/0xE6/0xF0) at this round count.

        Transition helper only. Not key-committing: there is no tuning
        field, the blob was made with the raw seed (before key
        separation), and tags bind the frozen octavo009 key_sig. Requires
        allow_noncommitting=True and emits LegacyFormatWarning. Default
        decrypt() rejects these blobs with UnsupportedVersion.
        """
        N._require_noncommitting(allow_noncommitting, "Etude.decrypt_legacy", warn=False)
        blob = N._as_bytes("blob", blob)
        ad = N._normalize_ad(ad)
        if len(blob) < 1:
            raise N.AuthError("bad blob length")
        self._check_version(blob[0], self.fmt_block_legacy, _BLOCK_ROUNDS_LEGACY)
        return self._decrypt_legacy_block(blob, seed, ad, allow_noncommitting=allow_noncommitting)

    def _decrypt_legacy_block(self, blob, seed, ad, *, allow_noncommitting=False):
        """Private body, gated and pinned on its own (conductor-polish I2): needs
        allow_noncommitting=True (LegacyFormatWarning), applies the demo-seed gate,
        and opens only this handle's own legacy byte (blob[0] == fmt_block_legacy)."""
        N._require_noncommitting(allow_noncommitting, "Etude.decrypt_legacy")
        blob = N._as_bytes("blob", blob)
        ad = N._normalize_ad(ad)
        if len(blob) < 1:
            raise N.AuthError("bad blob length")
        self._check_version(blob[0], self.fmt_block_legacy, _BLOCK_ROUNDS_LEGACY)
        fmt = self.fmt_block_legacy
        seed = self._seed(seed)
        rounds = self.rounds
        if len(blob) != N.V2_BLOB_LEN:
            raise N.AuthError("bad blob length")
        v, pickup, nonce, ct, tag = blob[:N.PK0], blob[N.PK0:N.N0], blob[N.N0:N.V2_CT0], blob[N.V2_CT0:N.V2_CT1], blob[N.V2_CT1:]
        if not hmac.compare_digest(v, bytes([fmt]) + N.VERSION):
            raise N.AuthError("bad version prefix")
        clef = N.staff_clef(seed)
        mac_key = N.StaffSponge(b"M", N._seed_bytes(seed), nonce).take(32)
        if not hmac.compare_digest(tag, N._tag(mac_key, pickup, nonce, ct, clef, N._legacy_key_signature(seed), ad,
                                               version=fmt, commit=b"")):
            raise N.AuthError("authentication failed")
        sch = N.Schedule(seed, nonce)
        b = N.grid_to_bytes(N.decrypt_grid(N.bytes_to_grid(ct), sch, rounds=rounds))
        ok, msg = N._unpad_block(b)
        if not ok:
            raise N.DecodeError("tag valid but block malformed")
        if not hmac.compare_digest(nonce, hashlib.sha256(clef + pickup + N.encode_block(msg) + N._encode_ad(ad)).digest()[:N.NONCE_LEN]):
            raise N.AuthError("SIV nonce mismatch")
        return msg

    # ---------------------------------------------------------------- movements
    def encrypt_movements(self, msg, seed=None, ad=b"", pickup=None, nonce=None) -> bytes:
        """Movements-mode AEAD étude under K_e. Optional `pickup` makes the blob deterministic.

        Layout matches format version 7 except the leading version byte is the
        étude flag (0x83/0x85/0x87/0x91). Normal decrypt_movements rejects
        the result as UnsupportedVersion.
        """
        msg = N._as_bytes("msg", msg)
        ad = N._normalize_ad(ad)
        k = self.key(seed)
        fmt = self.fmt_movements
        chunks = N._chunk_movements(msg)
        nmov = len(chunks)
        adb = N._encode_ad(ad)
        clef = N.staff_clef(k)
        key_sig = N.key_signature(k)
        pickup = _pickup(pickup)
        syn = hashlib.sha256(clef + bytes([fmt]) + pickup + len(msg).to_bytes(8, "big") + msg + adb).digest()[:N.NONCE_LEN]
        if nonce is not None and not hmac.compare_digest(N._as_bytes("nonce", nonce), syn):
            raise ValueError("nonce must be the synthetic (SIV) nonce for this message and pickup")
        nonce = syn
        commit = N._commitment(N._commit_key(k), fmt, pickup, nonce, ad, nmov=nmov)
        theme = N._theme_start(k, nonce)
        cad_key = N._cadence_key(k, nonce)
        coda_key = N._coda_key(k, nonce)
        sch = N.Schedule(k, nonce)
        parts, cts, cadences = [], [], []
        for i, chunk in enumerate(chunks):
            final = (i == nmov - 1)
            tweak = N._movement_tweak(k, nonce, i, final)
            block = N.encode_block(chunk)
            xored = N._xor_bytes(N._xor_bytes(block, theme), tweak)
            ct = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(xored), sch, rounds=self.rounds))
            cadence = N._cadence_tag(cad_key, pickup, nonce, i, final, theme, ct, clef, key_sig, ad,
                                     version=fmt, commit=commit)
            parts.append(ct + cadence)
            cts.append(ct)
            cadences.append(cadence)
            theme = N._theme_next(k, theme, ct, i, final)
        coda = N._coda_tag(coda_key, pickup, nonce, nmov, b"".join(cts), b"".join(cadences), clef, key_sig, ad,
                           version=fmt, commit=commit)
        return bytes([fmt]) + N.VERSION + pickup + nonce + commit + nmov.to_bytes(4, "big") + b"".join(parts) + coda

    def decrypt_movements(self, blob, seed=None, ad=b"") -> bytes:
        """Open a movements étude blob made at THIS round count.

        Another étude round count raises UnsupportedVersion("étude round
        count mismatch"). Like live v7 (conductor-polish), the commitment AND
        the coda are both computed and combined before one AuthError; then
        every cadence; the Schedule is built only after all pass. Live v7 blobs and the tuning-fix / tuning /
        legacy étude bytes raise UnsupportedVersion.
        """
        blob = N._as_bytes("blob", blob)
        ad = N._normalize_ad(ad)
        if len(blob) < 1:
            raise N.AuthError("bad blob length")
        self._check_version(blob[0], self.fmt_movements, _MOVEMENTS_ROUNDS)
        k = self.key(seed)
        fmt = self.fmt_movements
        if len(blob) < N.MOVEMENTS_HDR_LEN + N.MOVEMENT_STRIDE + N.TAG_LEN:
            raise N.AuthError("bad blob length")
        if blob[1:4] != N.VERSION:
            raise N.AuthError("bad version prefix")
        pickup = blob[4:20]
        nonce = blob[20:36]
        commit = blob[N.CM0:N.CM1]
        nmov = int.from_bytes(blob[N.NMOV0:N.MOVEMENTS_HDR_LEN], "big")
        if nmov < 1 or nmov > N.MAX_MOVEMENTS:
            raise N.AuthError("bad movement count")
        expected = N.MOVEMENTS_HDR_LEN + nmov * N.MOVEMENT_STRIDE + N.TAG_LEN
        if len(blob) != expected:
            raise N.AuthError("bad blob length")
        # Equal-time reject (conductor-polish L1): commitment AND coda, combined, one raise.
        commit_ok = hmac.compare_digest(commit, N._commitment(N._commit_key(k), fmt, pickup, nonce, ad, nmov=nmov))
        body = blob[N.MOVEMENTS_HDR_LEN:-N.TAG_LEN]
        coda = blob[-N.TAG_LEN:]
        cts, cadences = [], []
        for i in range(nmov):
            off = i * N.MOVEMENT_STRIDE
            cts.append(body[off:off + N.BLOCK_LEN])
            cadences.append(body[off + N.BLOCK_LEN:off + N.MOVEMENT_STRIDE])
        clef = N.staff_clef(k)
        key_sig = N.key_signature(k)
        coda_key = N._coda_key(k, nonce)
        coda_ok = hmac.compare_digest(
            coda,
            N._coda_tag(coda_key, pickup, nonce, nmov, b"".join(cts), b"".join(cadences), clef, key_sig, ad,
                        version=fmt, commit=commit),
        )
        if not (commit_ok & coda_ok):
            raise N.AuthError("authentication failed")
        cad_key = N._cadence_key(k, nonce)
        theme = N._theme_start(k, nonce)
        cad_ok = True
        themes = []
        for i in range(nmov):
            final = (i == nmov - 1)
            themes.append(theme)
            cad_ok = hmac.compare_digest(
                cadences[i],
                N._cadence_tag(cad_key, pickup, nonce, i, final, theme, cts[i], clef, key_sig, ad,
                               version=fmt, commit=commit),
            ) and cad_ok
            theme = N._theme_next(k, theme, cts[i], i, final)
        if not cad_ok:
            raise N.AuthError("authentication failed")
        sch = N.Schedule(k, nonce)
        pieces = []
        dec_ok = True
        for i in range(nmov):
            final = (i == nmov - 1)
            tweak = N._movement_tweak(k, nonce, i, final)
            xored = N.grid_to_bytes(N.decrypt_grid(N.bytes_to_grid(cts[i]), sch, rounds=self.rounds))
            block = N._xor_bytes(N._xor_bytes(xored, themes[i]), tweak)
            ok, piece = N._unpad_block(block)
            dec_ok &= ok
            pieces.append(piece)
        if not dec_ok:
            raise N.DecodeError("tag valid but block malformed")
        msg = b"".join(pieces)
        if not hmac.compare_digest(
            nonce,
            hashlib.sha256(clef + bytes([fmt]) + pickup + len(msg).to_bytes(8, "big") + msg + N._encode_ad(ad)).digest()[:N.NONCE_LEN],
        ):
            raise N.AuthError("SIV nonce mismatch")
        return msg

    def decrypt_movements_legacy(self, blob, seed=None, ad=b"", *, allow_noncommitting=False) -> bytes:
        """Open a published pre-tuning movements étude blob (0xE3/0xE5/0xE7/0xF1) at this round count.

        Transition helper only. Not key-committing (raw seed, no tuning
        field, frozen octavo009 key_sig). Requires allow_noncommitting=True
        and emits LegacyFormatWarning.
        """
        N._require_noncommitting(allow_noncommitting, "Etude.decrypt_movements_legacy", warn=False)
        blob = N._as_bytes("blob", blob)
        ad = N._normalize_ad(ad)
        if len(blob) < 1:
            raise N.AuthError("bad blob length")
        self._check_version(blob[0], self.fmt_movements_legacy, _MOVEMENTS_ROUNDS_LEGACY)
        return self._decrypt_legacy_movements(blob, seed, ad, allow_noncommitting=allow_noncommitting)

    def _decrypt_legacy_movements(self, blob, seed, ad, *, allow_noncommitting=False):
        """Private body, gated and pinned on its own (conductor-polish I2): needs
        allow_noncommitting=True (LegacyFormatWarning), applies the demo-seed gate,
        and opens only this handle's own legacy byte (blob[0] == fmt_movements_legacy)."""
        N._require_noncommitting(allow_noncommitting, "Etude.decrypt_movements_legacy")
        blob = N._as_bytes("blob", blob)
        ad = N._normalize_ad(ad)
        if len(blob) < 1:
            raise N.AuthError("bad blob length")
        self._check_version(blob[0], self.fmt_movements_legacy, _MOVEMENTS_ROUNDS_LEGACY)
        seed = self._seed(seed)
        rounds = self.rounds
        fmt = self.fmt_movements_legacy
        if len(blob) < N.V3_MOVEMENTS_HDR_LEN + N.MOVEMENT_STRIDE + N.TAG_LEN:
            raise N.AuthError("bad blob length")
        if blob[1:4] != N.VERSION:
            raise N.AuthError("bad version prefix")
        pickup = blob[4:20]
        nonce = blob[20:36]
        nmov = int.from_bytes(blob[N.V3_NMOV0:N.V3_MOVEMENTS_HDR_LEN], "big")
        if nmov < 1 or nmov > N.MAX_MOVEMENTS:
            raise N.AuthError("bad movement count")
        expected = N.V3_MOVEMENTS_HDR_LEN + nmov * N.MOVEMENT_STRIDE + N.TAG_LEN
        if len(blob) != expected:
            raise N.AuthError("bad blob length")
        body = blob[N.V3_MOVEMENTS_HDR_LEN:-N.TAG_LEN]
        coda = blob[-N.TAG_LEN:]
        cts, cadences = [], []
        for i in range(nmov):
            off = i * N.MOVEMENT_STRIDE
            cts.append(body[off:off + N.BLOCK_LEN])
            cadences.append(body[off + N.BLOCK_LEN:off + N.MOVEMENT_STRIDE])
        clef = N.staff_clef(seed)
        key_sig = N._legacy_key_signature(seed)
        coda_key = N._coda_key(seed, nonce)
        if not hmac.compare_digest(
            coda,
            N._coda_tag(coda_key, pickup, nonce, nmov, b"".join(cts), b"".join(cadences), clef, key_sig, ad,
                        version=fmt, commit=b""),
        ):
            raise N.AuthError("authentication failed")
        cad_key = N._cadence_key(seed, nonce)
        theme = N._theme_start(seed, nonce)
        cad_ok = True
        themes = []
        for i in range(nmov):
            final = (i == nmov - 1)
            themes.append(theme)
            cad_ok = hmac.compare_digest(
                cadences[i],
                N._cadence_tag(cad_key, pickup, nonce, i, final, theme, cts[i], clef, key_sig, ad,
                               version=fmt, commit=b""),
            ) and cad_ok
            theme = N._theme_next(seed, theme, cts[i], i, final)
        if not cad_ok:
            raise N.AuthError("authentication failed")
        sch = N.Schedule(seed, nonce)
        pieces = []
        dec_ok = True
        for i in range(nmov):
            final = (i == nmov - 1)
            tweak = N._movement_tweak(seed, nonce, i, final)
            xored = N.grid_to_bytes(N.decrypt_grid(N.bytes_to_grid(cts[i]), sch, rounds=rounds))
            block = N._xor_bytes(N._xor_bytes(xored, themes[i]), tweak)
            ok, piece = N._unpad_block(block)
            dec_ok &= ok
            pieces.append(piece)
        if not dec_ok:
            raise N.DecodeError("tag valid but block malformed")
        msg = b"".join(pieces)
        if not hmac.compare_digest(
            nonce,
            hashlib.sha256(clef + pickup + len(msg).to_bytes(8, "big") + msg + N._encode_ad(ad)).digest()[:N.NONCE_LEN],
        ):
            raise N.AuthError("SIV nonce mismatch")
        return msg


def etude(rounds, lab_seed=False) -> Etude:
    """Return a lab handle for the published étude at `rounds` (2, 4, 6 or 16).

    The handle is the only supported way to run reduced-round Octavo. It is
    clearly weakened, runs under its own derived key, and its blobs cannot
    be opened by the normal APIs. lab_seed=True is required to use
    seed=None or the public demo seed.
    """
    return Etude(rounds, lab_seed=lab_seed)


__all__ = (
    "ETUDE_WARNING",
    "ETUDE_ROUNDS",
    "ETUDE_KEY_DOMAIN",
    "DEMO_SEED_SHA256",
    "ETUDE_FMT_BLOCK",
    "ETUDE_FMT_MOVEMENTS",
    "ETUDE_FMT_BLOCK_TUNINGFIX",
    "ETUDE_FMT_MOVEMENTS_TUNINGFIX",
    "ETUDE_FMT_BLOCK_LEGACY",
    "ETUDE_FMT_MOVEMENTS_LEGACY",
    "ETUDE_FMT_BLOCK_TUNING",
    "ETUDE_FMT_MOVEMENTS_TUNING",
    "Etude",
    "etude",
    "etude_key",
)
