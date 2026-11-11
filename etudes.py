"""Études — reduced-round Octavo, for cryptanalysis only.

WARNING: These are intentionally weakened. NOT for any secret, even a toy one.
Do not use this module to protect data. The published études are 2, 4 and 6
rounds; 16-round études exist only so a lab can compare against the full
cipher. They still use distinct blob version bytes.

Normal encrypt / decrypt and encrypt_movements / decrypt_movements cannot
produce or consume étude blobs. Current étude blobs start with a version
byte in 0xC2/0xC4/0xC6/0xD0 (single-block) or 0xC3/0xC5/0xC7/0xD1
(movements), and they carry a tuning commitment like live v4/v5 blobs.
The normal APIs reject those as UnsupportedVersion. Étude decrypt likewise
rejects ordinary version-4 and version-5 blobs. Legacy étude version bytes
(0xE2/0xE4/0xE6/0xF0 and 0xE3/0xE5/0xE7/0xF1, no commitment) still open,
using the frozen octavo009 key_sig; they are not key-committing.

The 16-round block permutation (and the ciphertext of a 16-round étude with
the same seed, nonce and input) is byte-identical to the live full-round
cipher. Tags and commitments differ because they bind the étude version byte.

Lab hook: encrypt and encrypt_movements accept an optional fixed `pickup` so
published score vectors are deterministic. The normal APIs have no such
argument, by design.

Use:
    from etudes import etude
    E = etude(4)                          # a 4-round étude
    ct = E.permute(block, seed, nonce)    # raw 128-byte keyed permutation
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

# Distinct from FMT_VERSION=4 and FMT_MOVEMENTS=5, from legacy v2/v3, and
# from historical v1. High nibble 0xC marks a committed reduced étude;
# 0xD marks a committed full-round étude. Even values are single-block;
# odd values are movements.
ETUDE_FMT_BLOCK = {2: 0xC2, 4: 0xC4, 6: 0xC6, 16: 0xD0}
ETUDE_FMT_MOVEMENTS = {2: 0xC3, 4: 0xC5, 6: 0xC7, 16: 0xD1}
# Pre-tuning étude version bytes (no commitment). Still decryptable.
ETUDE_FMT_BLOCK_LEGACY = {2: 0xE2, 4: 0xE4, 6: 0xE6, 16: 0xF0}
ETUDE_FMT_MOVEMENTS_LEGACY = {2: 0xE3, 4: 0xE5, 6: 0xE7, 16: 0xF1}
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


class Etude:
    """One published étude (2, 4, 6 or 16 rounds). Cryptanalysis only."""

    def __init__(self, rounds):
        self.rounds = _check_rounds(rounds)
        self.fmt_block = ETUDE_FMT_BLOCK[self.rounds]
        self.fmt_movements = ETUDE_FMT_MOVEMENTS[self.rounds]
        self.fmt_block_legacy = ETUDE_FMT_BLOCK_LEGACY[self.rounds]
        self.fmt_movements_legacy = ETUDE_FMT_MOVEMENTS_LEGACY[self.rounds]
        self.warning = ETUDE_WARNING

    def permute(self, block, seed=None, nonce=None) -> bytes:
        """Raw 128-byte keyed permutation at this étude's round count, plus whitening.

        Uses the first `rounds` keys of a full 16-round Schedule(seed, nonce),
        then the same whitening the full cipher uses (squeezed after all 16
        rounds of schedule material). 16-round output matches encrypt_grid.
        """
        block = N._as_bytes("block", block)
        nonce = N._as_bytes("nonce", nonce)
        if len(block) != N.BLOCK_LEN:
            raise ValueError("block must be 128 bytes")
        if len(nonce) != N.NONCE_LEN:
            raise ValueError("nonce must be 16 bytes")
        sch = N.Schedule(seed, nonce)
        return N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(block), sch, rounds=self.rounds))

    def unpermute(self, block, seed=None, nonce=None) -> bytes:
        """Inverse of permute for the same seed, nonce and round count."""
        block = N._as_bytes("block", block)
        nonce = N._as_bytes("nonce", nonce)
        if len(block) != N.BLOCK_LEN:
            raise ValueError("block must be 128 bytes")
        if len(nonce) != N.NONCE_LEN:
            raise ValueError("nonce must be 16 bytes")
        sch = N.Schedule(seed, nonce)
        return N.grid_to_bytes(N.decrypt_grid(N.bytes_to_grid(block), sch, rounds=self.rounds))

    def encrypt(self, msg, seed=None, ad=b"", pickup=None, nonce=None) -> bytes:
        """Single-block AEAD étude. Optional `pickup` makes the blob deterministic.

        Layout matches version-4 blobs except the leading version byte is the
        étude flag (0xC2/0xC4/0xC6/0xD0). A caller nonce must equal the SIV
        nonce. Normal decrypt rejects the result as UnsupportedVersion.
        """
        msg = N._as_bytes("msg", msg)
        ad = N._normalize_ad(ad)
        block = N.encode_block(msg)
        adb = N._encode_ad(ad)
        clef = N.staff_clef(seed)
        pickup = _pickup(pickup)
        syn = hashlib.sha256(clef + pickup + block + adb).digest()[:N.NONCE_LEN]
        if nonce is not None and not hmac.compare_digest(N._as_bytes("nonce", nonce), syn):
            raise ValueError("nonce must be the synthetic (SIV) nonce for this message and pickup")
        nonce = syn
        sch = N.Schedule(seed, nonce)
        ct = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(block), sch, rounds=self.rounds))
        commit = N._commitment(N._commit_key(seed), self.fmt_block, pickup, nonce)
        tag = N._tag(sch.mac_key, pickup, nonce, ct, clef, N.key_signature(seed), ad,
                     version=self.fmt_block, commit=commit)
        return bytes([self.fmt_block]) + N.VERSION + pickup + nonce + commit + ct + tag

    def decrypt(self, blob, seed=None, ad=b"") -> bytes:
        """Open a single-block étude blob. Round count is read from the version byte.

        Current (committed) étude blobs check the tuning commitment before
        the tag, and the tag is checked before the Schedule is built.
        Ordinary version-4 blobs raise UnsupportedVersion. Legacy pre-tuning
        étude version bytes still open (no commitment; frozen octavo009 key_sig).
        """
        blob = N._as_bytes("blob", blob)
        ad = N._normalize_ad(ad)
        if len(blob) < 1:
            raise N.AuthError("bad blob length")
        if blob[0] in _BLOCK_ROUNDS_LEGACY:
            return self._decrypt_legacy_block(blob, seed, ad)
        if blob[0] not in _BLOCK_ROUNDS:
            raise N.UnsupportedVersion("unsupported version")
        rounds = _BLOCK_ROUNDS[blob[0]]
        if len(blob) != N.BLOB_LEN:
            raise N.AuthError("bad blob length")
        v, pickup, nonce, commit, ct, tag = N.split_blob(blob)
        if not hmac.compare_digest(v, bytes([blob[0]]) + N.VERSION):
            raise N.AuthError("bad version prefix")
        if not hmac.compare_digest(commit, N._commitment(N._commit_key(seed), blob[0], pickup, nonce)):
            raise N.CommitError("commitment mismatch")
        clef = N.staff_clef(seed)
        mac_key = N.StaffSponge(b"M", N._seed_bytes(seed), nonce).take(32)
        if not hmac.compare_digest(tag, N._tag(mac_key, pickup, nonce, ct, clef, N.key_signature(seed), ad,
                                               version=blob[0], commit=commit)):
            raise N.AuthError("tag mismatch")
        sch = N.Schedule(seed, nonce)
        b = N.grid_to_bytes(N.decrypt_grid(N.bytes_to_grid(ct), sch, rounds=rounds))
        L = b[0]
        if L > N.MAX_MSG or any(b[1 + L:]):
            raise N.DecodeError("tag valid but block malformed")
        msg = b[1:1 + L]
        if not hmac.compare_digest(nonce, hashlib.sha256(clef + pickup + N.encode_block(msg) + N._encode_ad(ad)).digest()[:N.NONCE_LEN]):
            raise N.AuthError("SIV nonce mismatch")
        return msg

    def _decrypt_legacy_block(self, blob, seed, ad):
        rounds = _BLOCK_ROUNDS_LEGACY[blob[0]]
        if len(blob) != N.V2_BLOB_LEN:
            raise N.AuthError("bad blob length")
        v, pickup, nonce, ct, tag = blob[:N.PK0], blob[N.PK0:N.N0], blob[N.N0:N.V2_CT0], blob[N.V2_CT0:N.V2_CT1], blob[N.V2_CT1:]
        if not hmac.compare_digest(v, bytes([blob[0]]) + N.VERSION):
            raise N.AuthError("bad version prefix")
        clef = N.staff_clef(seed)
        mac_key = N.StaffSponge(b"M", N._seed_bytes(seed), nonce).take(32)
        if not hmac.compare_digest(tag, N._tag(mac_key, pickup, nonce, ct, clef, N._legacy_key_signature(seed), ad,
                                               version=blob[0], commit=b"")):
            raise N.AuthError("tag mismatch")
        sch = N.Schedule(seed, nonce)
        b = N.grid_to_bytes(N.decrypt_grid(N.bytes_to_grid(ct), sch, rounds=rounds))
        L = b[0]
        if L > N.MAX_MSG or any(b[1 + L:]):
            raise N.DecodeError("tag valid but block malformed")
        msg = b[1:1 + L]
        if not hmac.compare_digest(nonce, hashlib.sha256(clef + pickup + N.encode_block(msg) + N._encode_ad(ad)).digest()[:N.NONCE_LEN]):
            raise N.AuthError("SIV nonce mismatch")
        return msg

    def encrypt_movements(self, msg, seed=None, ad=b"", pickup=None, nonce=None) -> bytes:
        """Movements-mode AEAD étude. Optional `pickup` makes the blob deterministic.

        Layout matches format version 5 except the leading version byte is the
        étude flag (0xC3/0xC5/0xC7/0xD1). Normal decrypt_movements rejects
        the result as UnsupportedVersion.
        """
        msg = N._as_bytes("msg", msg)
        ad = N._normalize_ad(ad)
        chunks = N._chunk_movements(msg)
        nmov = len(chunks)
        adb = N._encode_ad(ad)
        clef = N.staff_clef(seed)
        key_sig = N.key_signature(seed)
        pickup = _pickup(pickup)
        syn = hashlib.sha256(clef + pickup + len(msg).to_bytes(8, "big") + msg + adb).digest()[:N.NONCE_LEN]
        if nonce is not None and not hmac.compare_digest(N._as_bytes("nonce", nonce), syn):
            raise ValueError("nonce must be the synthetic (SIV) nonce for this message and pickup")
        nonce = syn
        commit = N._commitment(N._commit_key(seed), self.fmt_movements, pickup, nonce)
        theme = N._theme_start(seed, nonce)
        cad_key = N._cadence_key(seed, nonce)
        coda_key = N._coda_key(seed, nonce)
        sch = N.Schedule(seed, nonce)
        parts, cts, cadences = [], [], []
        fmt = self.fmt_movements
        for i, chunk in enumerate(chunks):
            final = (i == nmov - 1)
            tweak = N._movement_tweak(seed, nonce, i, final)
            block = N.encode_block(chunk)
            xored = N._xor_bytes(N._xor_bytes(block, theme), tweak)
            ct = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(xored), sch, rounds=self.rounds))
            cadence = N._cadence_tag(cad_key, pickup, nonce, i, final, theme, ct, clef, key_sig, ad,
                                     version=fmt, commit=commit)
            parts.append(ct + cadence)
            cts.append(ct)
            cadences.append(cadence)
            theme = N._theme_next(seed, theme, ct, i, final)
        coda = N._coda_tag(coda_key, pickup, nonce, nmov, b"".join(cts), b"".join(cadences), clef, key_sig, ad,
                           version=fmt, commit=commit)
        return bytes([fmt]) + N.VERSION + pickup + nonce + commit + nmov.to_bytes(4, "big") + b"".join(parts) + coda

    def decrypt_movements(self, blob, seed=None, ad=b"") -> bytes:
        """Open a movements étude blob. Round count is read from the version byte.

        Current (committed) étude blobs check the tuning commitment first,
        then the coda (then every cadence) before the Schedule is built.
        Ordinary version-5 blobs raise UnsupportedVersion. Legacy pre-tuning
        étude version bytes still open (no commitment; frozen octavo009 key_sig).
        """
        blob = N._as_bytes("blob", blob)
        ad = N._normalize_ad(ad)
        if len(blob) < 1:
            raise N.AuthError("bad blob length")
        if blob[0] in _MOVEMENTS_ROUNDS_LEGACY:
            return self._decrypt_legacy_movements(blob, seed, ad)
        if blob[0] not in _MOVEMENTS_ROUNDS:
            raise N.UnsupportedVersion("unsupported version")
        rounds = _MOVEMENTS_ROUNDS[blob[0]]
        fmt = blob[0]
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
        if not hmac.compare_digest(commit, N._commitment(N._commit_key(seed), fmt, pickup, nonce)):
            raise N.CommitError("commitment mismatch")
        body = blob[N.MOVEMENTS_HDR_LEN:-N.TAG_LEN]
        coda = blob[-N.TAG_LEN:]
        cts, cadences = [], []
        for i in range(nmov):
            off = i * N.MOVEMENT_STRIDE
            cts.append(body[off:off + N.BLOCK_LEN])
            cadences.append(body[off + N.BLOCK_LEN:off + N.MOVEMENT_STRIDE])
        clef = N.staff_clef(seed)
        key_sig = N.key_signature(seed)
        coda_key = N._coda_key(seed, nonce)
        if not hmac.compare_digest(
            coda,
            N._coda_tag(coda_key, pickup, nonce, nmov, b"".join(cts), b"".join(cadences), clef, key_sig, ad,
                        version=fmt, commit=commit),
        ):
            raise N.AuthError("coda mismatch")
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
                               version=fmt, commit=commit),
            ) and cad_ok
            theme = N._theme_next(seed, theme, cts[i], i, final)
        if not cad_ok:
            raise N.AuthError("cadence mismatch")
        sch = N.Schedule(seed, nonce)
        pieces = []
        for i in range(nmov):
            final = (i == nmov - 1)
            tweak = N._movement_tweak(seed, nonce, i, final)
            xored = N.grid_to_bytes(N.decrypt_grid(N.bytes_to_grid(cts[i]), sch, rounds=rounds))
            block = N._xor_bytes(N._xor_bytes(xored, themes[i]), tweak)
            L = block[0]
            if L > N.MAX_MSG or any(block[1 + L:]):
                raise N.DecodeError("tag valid but block malformed")
            pieces.append(block[1:1 + L])
        msg = b"".join(pieces)
        if not hmac.compare_digest(
            nonce,
            hashlib.sha256(clef + pickup + len(msg).to_bytes(8, "big") + msg + N._encode_ad(ad)).digest()[:N.NONCE_LEN],
        ):
            raise N.AuthError("SIV nonce mismatch")
        return msg

    def _decrypt_legacy_movements(self, blob, seed, ad):
        rounds = _MOVEMENTS_ROUNDS_LEGACY[blob[0]]
        fmt = blob[0]
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
            raise N.AuthError("coda mismatch")
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
            raise N.AuthError("cadence mismatch")
        sch = N.Schedule(seed, nonce)
        pieces = []
        for i in range(nmov):
            final = (i == nmov - 1)
            tweak = N._movement_tweak(seed, nonce, i, final)
            xored = N.grid_to_bytes(N.decrypt_grid(N.bytes_to_grid(cts[i]), sch, rounds=rounds))
            block = N._xor_bytes(N._xor_bytes(xored, themes[i]), tweak)
            L = block[0]
            if L > N.MAX_MSG or any(block[1 + L:]):
                raise N.DecodeError("tag valid but block malformed")
            pieces.append(block[1:1 + L])
        msg = b"".join(pieces)
        if not hmac.compare_digest(
            nonce,
            hashlib.sha256(clef + pickup + len(msg).to_bytes(8, "big") + msg + N._encode_ad(ad)).digest()[:N.NONCE_LEN],
        ):
            raise N.AuthError("SIV nonce mismatch")
        return msg


def etude(rounds) -> Etude:
    """Return a lab handle for the published étude at `rounds` (2, 4, 6 or 16).

    The handle is the only supported way to run reduced-round Octavo. It is
    clearly weakened, and its blobs cannot be opened by the normal APIs.
    """
    return Etude(rounds)


__all__ = (
    "ETUDE_WARNING",
    "ETUDE_ROUNDS",
    "ETUDE_FMT_BLOCK",
    "ETUDE_FMT_MOVEMENTS",
    "ETUDE_FMT_BLOCK_LEGACY",
    "ETUDE_FMT_MOVEMENTS_LEGACY",
    "Etude",
    "etude",
)
