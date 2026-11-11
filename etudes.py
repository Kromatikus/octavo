"""Études — reduced-round Octavo, for cryptanalysis only.

WARNING: These are intentionally weakened. NOT for any secret, even a toy one.
Do not use this module to protect data. The published études are 2, 4 and 6
rounds; 16-round études exist only so a lab can compare against the full
cipher. They still use distinct blob version bytes.

Normal encrypt / decrypt and encrypt_movements / decrypt_movements cannot
produce or consume étude blobs. Étude blobs start with a version byte in
0xE2/0xE4/0xE6/0xF0 (single-block) or 0xE3/0xE5/0xE7/0xF1 (movements). The
normal APIs reject those as UnsupportedVersion. Étude decrypt likewise
rejects ordinary version-2 and version-3 blobs.

The 16-round block permutation (and the ciphertext of a 16-round étude with
the same seed, nonce and input) is byte-identical to the live full-round
cipher. Tags differ because they bind the étude version byte.

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

# Distinct from FMT_VERSION=2 and FMT_MOVEMENTS=3 (and from historical v1).
# High nibble 0xE marks a reduced étude; 0xF marks a full-round étude.
# Even values are single-block; odd values are movements.
ETUDE_FMT_BLOCK = {2: 0xE2, 4: 0xE4, 6: 0xE6, 16: 0xF0}
ETUDE_FMT_MOVEMENTS = {2: 0xE3, 4: 0xE5, 6: 0xE7, 16: 0xF1}
_BLOCK_ROUNDS = {v: r for r, v in ETUDE_FMT_BLOCK.items()}
_MOVEMENTS_ROUNDS = {v: r for r, v in ETUDE_FMT_MOVEMENTS.items()}


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


def _etude_tag(fmt, mac_key, pickup, nonce, ct, clef, key_sig, ad=b""):
    return hmac.new(
        mac_key,
        clef + key_sig + bytes([fmt]) + N.VERSION + pickup + nonce + ct + N._encode_ad(ad),
        hashlib.sha256,
    ).digest()


def _etude_cadence_tag(fmt, cad_key, pickup, nonce, index, final, theme, ct, clef, key_sig, ad=b""):
    return hmac.new(
        cad_key,
        clef + key_sig + bytes([fmt]) + N.VERSION + pickup + nonce
        + index.to_bytes(8, "big") + N._final_flag(final) + theme + ct + N._encode_ad(ad),
        hashlib.sha256,
    ).digest()


def _etude_coda_tag(fmt, coda_key, pickup, nonce, nmov, cts, cadences, clef, key_sig, ad=b""):
    return hmac.new(
        coda_key,
        clef + key_sig + bytes([fmt]) + N.VERSION + pickup + nonce
        + nmov.to_bytes(4, "big") + cts + cadences + N._encode_ad(ad),
        hashlib.sha256,
    ).digest()


class Etude:
    """One published étude (2, 4, 6 or 16 rounds). Cryptanalysis only."""

    def __init__(self, rounds):
        self.rounds = _check_rounds(rounds)
        self.fmt_block = ETUDE_FMT_BLOCK[self.rounds]
        self.fmt_movements = ETUDE_FMT_MOVEMENTS[self.rounds]
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

        Layout matches version-2 blobs except the leading version byte is the
        étude flag (0xE2/0xE4/0xE6/0xF0). A caller nonce must equal the SIV
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
        tag = _etude_tag(self.fmt_block, sch.mac_key, pickup, nonce, ct, clef, N.key_signature(seed), ad)
        return bytes([self.fmt_block]) + N.VERSION + pickup + nonce + ct + tag

    def decrypt(self, blob, seed=None, ad=b"") -> bytes:
        """Open a single-block étude blob. Round count is read from the version byte.

        The tag is checked before the Schedule is built. Ordinary version-2
        blobs raise UnsupportedVersion.
        """
        blob = N._as_bytes("blob", blob)
        ad = N._normalize_ad(ad)
        if len(blob) < 1:
            raise N.AuthError("bad blob length")
        if blob[0] not in _BLOCK_ROUNDS:
            raise N.UnsupportedVersion("unsupported version")
        rounds = _BLOCK_ROUNDS[blob[0]]
        if len(blob) != N.BLOB_LEN:
            raise N.AuthError("bad blob length")
        v, pickup, nonce, ct, tag = N.split_blob(blob)
        if not hmac.compare_digest(v, bytes([blob[0]]) + N.VERSION):
            raise N.AuthError("bad version prefix")
        clef = N.staff_clef(seed)
        mac_key = N.StaffSponge(b"M", N._seed_bytes(seed), nonce).take(32)
        if not hmac.compare_digest(tag, _etude_tag(blob[0], mac_key, pickup, nonce, ct, clef, N.key_signature(seed), ad)):
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

        Layout matches format version 3 except the leading version byte is the
        étude flag (0xE3/0xE5/0xE7/0xF1). Normal decrypt_movements rejects
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
            cadence = _etude_cadence_tag(fmt, cad_key, pickup, nonce, i, final, theme, ct, clef, key_sig, ad)
            parts.append(ct + cadence)
            cts.append(ct)
            cadences.append(cadence)
            theme = N._theme_next(seed, theme, ct, i, final)
        coda = _etude_coda_tag(fmt, coda_key, pickup, nonce, nmov, b"".join(cts), b"".join(cadences), clef, key_sig, ad)
        return bytes([fmt]) + N.VERSION + pickup + nonce + nmov.to_bytes(4, "big") + b"".join(parts) + coda

    def decrypt_movements(self, blob, seed=None, ad=b"") -> bytes:
        """Open a movements étude blob. Round count is read from the version byte.

        The coda (then every cadence) is checked before the Schedule is built.
        Ordinary version-3 blobs raise UnsupportedVersion.
        """
        blob = N._as_bytes("blob", blob)
        ad = N._normalize_ad(ad)
        if len(blob) < 1:
            raise N.AuthError("bad blob length")
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
        nmov = int.from_bytes(blob[36:40], "big")
        if nmov < 1 or nmov > N.MAX_MOVEMENTS:
            raise N.AuthError("bad movement count")
        expected = N.MOVEMENTS_HDR_LEN + nmov * N.MOVEMENT_STRIDE + N.TAG_LEN
        if len(blob) != expected:
            raise N.AuthError("bad blob length")
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
            _etude_coda_tag(fmt, coda_key, pickup, nonce, nmov, b"".join(cts), b"".join(cadences), clef, key_sig, ad),
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
                _etude_cadence_tag(fmt, cad_key, pickup, nonce, i, final, theme, cts[i], clef, key_sig, ad),
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
    "Etude",
    "etude",
)
