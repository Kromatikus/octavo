"""Independent Octavo formats (v6 single block, v7 movements, v9 rehearsal, étude block/movements),
written from SPEC.md only, on top of ic_core.py. Deterministic: pickup/nonce are passed in so the
published score can be rebuilt. NOT for real secrets: use AES-GCM-SIV, age or libsodium."""
import hashlib, hmac
import ic_core as C

KEY_SIG_NONCE = bytes.fromhex('fe93996970ecd92693b5f8f43ffb2cad5e96867f258a38b12637f1014b12b4c6')
REH_SIG_NONCE = bytes.fromhex('a21cf6e768a88cc21b4698b54426cf2d1527936f101f783862a609efa8bbad45')
MAGIC = b"SN2"

class Reject(ValueError): pass

def H(*a): return hashlib.sha256(b''.join(a)).digest()
def mac(k, *a): return hmac.new(k, b''.join(a), 'sha256').digest()
def enc_ad(ad): return len(ad).to_bytes(8, 'big') + ad
def enc_block(m):
    if len(m) > 127: raise ValueError('too long')
    return bytes([len(m)]) + m + bytes(127 - len(m))
def dec_block(b):
    L = b[0]
    if L > 127 or any(b[1 + L:]): raise Reject('decode')
    return b[1:1 + L]
def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))

def key_sig(k): return C.sponge(b"G", k, KEY_SIG_NONCE, 16)
def rehearsal_sig(k): return C.sponge(b"H", k, REH_SIG_NONCE, 16)
def clef(k): return C.sponge(b"C", k, bytes(16), 16)
def k_commit(k): return C.sponge(b"U", k, bytes(16), 32)
def etude_key(seed, rounds): return C.sponge(b"E", seed, bytes([rounds]) + bytes(15), 128)

class Ctx:
    """Key material for a live seed (rounds=16, version 6/7) or an étude (K_e, its version bytes)."""
    def __init__(self, seed, rounds=16, etude=False):
        self.rounds, self.etude = rounds, etude
        self.k = etude_key(seed, rounds) if etude else seed
        self.v_block = ({2: 0x82, 4: 0x84, 6: 0x86, 16: 0x90}[rounds] if etude else 6)
        self.v_mov = ({2: 0x83, 4: 0x85, 6: 0x87, 16: 0x91}[rounds] if etude else 7)
        self.clef, self.kc, self.ks = clef(self.k), k_commit(self.k), key_sig(self.k)
    def vb(self, v):  # étude version byte goes into the SIV nonce
        return bytes([v]) if self.etude else b""

# ---------- single block (v6 / étude block) ----------
def seal_block(ctx, msg, pickup, ad=b""):
    ver = bytes([ctx.v_block]); eb = enc_block(msg)
    nonce = H(ctx.clef, ctx.vb(ctx.v_block), pickup, eb, enc_ad(ad))[:16]
    commit = mac(ctx.kc, b"U", ver, MAGIC, pickup, nonce, enc_ad(ad))
    ct = C.encrypt_grid(eb, C.Schedule(ctx.k, nonce), ctx.rounds)
    tag = mac(C.sponge(b"M", ctx.k, nonce, 32), ctx.clef, ctx.ks, ver, MAGIC, pickup, nonce, commit, ct, enc_ad(ad))
    return ver + MAGIC + pickup + nonce + commit + ct + tag

def open_block(ctx, blob, ad=b""):
    if len(blob) != 228 or blob[0] != ctx.v_block or blob[1:4] != MAGIC: raise Reject('format')
    ver, pickup, nonce, commit, ct, tag = blob[:1], blob[4:20], blob[20:36], blob[36:68], blob[68:196], blob[196:]
    ok1 = hmac.compare_digest(commit, mac(ctx.kc, b"U", ver, MAGIC, pickup, nonce, enc_ad(ad)))
    ok2 = hmac.compare_digest(tag, mac(C.sponge(b"M", ctx.k, nonce, 32), ctx.clef, ctx.ks, ver, MAGIC, pickup, nonce, commit, ct, enc_ad(ad)))
    if not (ok1 and ok2): raise Reject('auth')
    msg = dec_block(C.decrypt_grid(ct, C.Schedule(ctx.k, nonce), ctx.rounds))
    if H(ctx.clef, ctx.vb(ctx.v_block), pickup, enc_block(msg), enc_ad(ad))[:16] != nonce: raise Reject('siv')
    return msg

# ---------- movements (v7 / étude movements) ----------
def _mov_core(ctx, nonce, chunks_or_cts, decrypt=False):
    k = ctx.k; sch = C.Schedule(k, nonce); theme = C.sponge(b"T", k, nonce, 128); out = []
    n = len(chunks_or_cts)
    for i, item in enumerate(chunks_or_cts):
        idx = i.to_bytes(8, 'big'); fin = bytes([i == n - 1])
        tw = C.sponge(b"W", k, H(b"SN2/I", nonce, idx, fin)[:16], 128)
        if decrypt:
            ct = item; pt = dec_block(xor(xor(C.decrypt_grid(ct, sch, ctx.rounds), theme), tw)); out.append((pt, theme, idx, fin, ct))
        else:
            ct = C.encrypt_grid(xor(xor(enc_block(item), theme), tw), sch, ctx.rounds); out.append((item, theme, idx, fin, ct))
        theme = C.sponge(b"T", k, H(b"SN2/T", theme, ct, idx, fin)[:16], 128)
    return out

def seal_movements(ctx, msg, pickup, ad=b""):
    ver = bytes([ctx.v_mov]); chunks = [msg[i:i + 127] for i in range(0, len(msg), 127)] or [b""]
    nm = len(chunks).to_bytes(4, 'big')
    nonce = H(ctx.clef, ctx.vb(ctx.v_mov), pickup, len(msg).to_bytes(8, 'big'), msg, enc_ad(ad))[:16]
    commit = mac(ctx.kc, b"U", ver, MAGIC, pickup, nonce, enc_ad(ad), nm)
    hdr = ctx.clef + ctx.ks + ver + MAGIC + pickup + nonce + commit
    ck = C.sponge(b"D", ctx.k, nonce, 32); ok = C.sponge(b"O", ctx.k, nonce, 32)
    rows = _mov_core(ctx, nonce, chunks)
    cads = [mac(ck, hdr, idx, fin, th, ct, enc_ad(ad)) for _, th, idx, fin, ct in rows]
    coda = mac(ok, hdr, nm, *[r[4] for r in rows], *cads, enc_ad(ad))
    return ver + MAGIC + pickup + nonce + commit + nm + b"".join(r[4] + c for r, c in zip(rows, cads)) + coda

def open_movements(ctx, blob, ad=b""):
    if len(blob) < 72 + 160 + 32 or blob[0] != ctx.v_mov or blob[1:4] != MAGIC: raise Reject('format')
    ver, pickup, nonce, commit, nm = blob[:1], blob[4:20], blob[20:36], blob[36:68], blob[68:72]
    n = int.from_bytes(nm, 'big')
    if n < 1 or len(blob) != 72 + 160 * n + 32: raise Reject('format')
    cts = [blob[72 + 160 * i:200 + 160 * i] for i in range(n)]; cads = [blob[200 + 160 * i:232 + 160 * i] for i in range(n)]
    hdr = ctx.clef + ctx.ks + ver + MAGIC + pickup + nonce + commit
    ok1 = hmac.compare_digest(commit, mac(ctx.kc, b"U", ver, MAGIC, pickup, nonce, enc_ad(ad), nm))
    ok2 = hmac.compare_digest(blob[-32:], mac(C.sponge(b"O", ctx.k, nonce, 32), hdr, nm, *cts, *cads, enc_ad(ad)))
    if not (ok1 and ok2): raise Reject('auth')
    rows = _mov_core(ctx, nonce, cts, decrypt=True)
    ck = C.sponge(b"D", ctx.k, nonce, 32)
    for (pt, th, idx, fin, ct), cad in zip(rows, cads):
        if not hmac.compare_digest(cad, mac(ck, hdr, idx, fin, th, ct, enc_ad(ad))): raise Reject('cadence')
    msg = b"".join(r[0] for r in rows)
    if H(ctx.clef, ctx.vb(ctx.v_mov), pickup, len(msg).to_bytes(8, 'big'), msg, enc_ad(ad))[:16] != nonce: raise Reject('siv')
    return msg

# ---------- rehearsal v9 ----------
def _reh_keys(seed, pickup, nonce, cs32, i, final, add, nblocks):
    out = C.sponge(b"R", seed, b"chunk\x09" + pickup + nonce + cs32 + i.to_bytes(8, 'big') + bytes([final]) + add, 32 + 128 * nblocks)
    return out[:32], [out[32 + 128 * b:160 + 128 * b] for b in range(nblocks)]

def seal_rehearsal(seed, msg, pickup, nonce, chunk_size, ad=b""):
    cs32 = chunk_size.to_bytes(4, 'big'); add = H(b"SN2/A", enc_ad(ad))
    commit = mac(k_commit(seed), b"U", b"\x09", MAGIC, pickup, nonce, enc_ad(ad), cs32)
    sch = C.Schedule(seed, C.sponge(b"R", seed, b"sched\x09" + pickup + nonce + cs32 + add, 16))
    cl, rs = clef(seed), rehearsal_sig(seed)
    nfull = len(msg) // chunk_size  # every full chunk is non-final; final carries 0..cs-1 bytes
    pieces = [msg[i * chunk_size:(i + 1) * chunk_size] for i in range(nfull)]
    last = msg[nfull * chunk_size:] + b"\x80"; last += bytes((-len(last)) % 128); pieces.append(last)
    out = [b"\x09" + MAGIC + pickup + nonce + commit + cs32]; prev = bytes(32)
    for i, p in enumerate(pieces):
        fin = int(i == len(pieces) - 1); nb = len(p) // 128
        mk, tws = _reh_keys(seed, pickup, nonce, cs32, i, fin, add, nb)
        ct = b"".join(xor(C.encrypt_grid(xor(p[128 * b:128 * b + 128], tws[b]), sch), tws[b]) for b in range(nb))
        tag = mac(mk, cl, rs, b"\x09", MAGIC, pickup, nonce, commit, cs32, i.to_bytes(8, 'big'), bytes([fin]), add, prev, ct)
        out.append(ct + tag); prev = tag
    return b"".join(out), prev

def open_rehearsal(seed, blob, ad=b""):
    if len(blob) < 72 + 160 or blob[0] != 9 or blob[1:4] != MAGIC: raise Reject('format')
    pickup, nonce, commit, cs32 = blob[4:20], blob[20:36], blob[36:68], blob[68:72]
    cs = int.from_bytes(cs32, 'big'); add = H(b"SN2/A", enc_ad(ad))
    if not hmac.compare_digest(commit, mac(k_commit(seed), b"U", b"\x09", MAGIC, pickup, nonce, enc_ad(ad), cs32)): raise Reject('auth')
    body = blob[72:]; chunks = []
    while len(body) > cs + 32: chunks.append(body[:cs + 32]); body = body[cs + 32:]
    chunks.append(body)
    if (len(body) - 32) % 128 or len(body) < 160: raise Reject('format')
    sch = C.Schedule(seed, C.sponge(b"R", seed, b"sched\x09" + pickup + nonce + cs32 + add, 16))
    cl, rs = clef(seed), rehearsal_sig(seed); prev = bytes(32); pt = []
    for i, ch in enumerate(chunks):
        fin = int(i == len(chunks) - 1); ct, tag = ch[:-32], ch[-32:]; nb = len(ct) // 128
        if not fin and len(ct) != cs: raise Reject('format')
        mk, tws = _reh_keys(seed, pickup, nonce, cs32, i, fin, add, nb)
        if not hmac.compare_digest(tag, mac(mk, cl, rs, b"\x09", MAGIC, pickup, nonce, commit, cs32, i.to_bytes(8, 'big'), bytes([fin]), add, prev, ct)): raise Reject('auth')
        prev = tag
        pt.append(b"".join(xor(C.decrypt_grid(xor(ct[128 * b:128 * b + 128], tws[b]), sch), tws[b]) for b in range(nb)))
    last = pt[-1].rstrip(b"\x00")
    if not last.endswith(b"\x80"): raise Reject('pad')
    pt[-1] = last[:-1]
    if len(pt[-1]) >= cs: raise Reject('pad')
    return b"".join(pt)

# ---------- app layer key expansion (score/app_vectors.json "kdf") ----------
def app_seed(key):
    prk = hmac.new(bytes(64), key, 'sha512').digest()
    okm, t, i = b"", b"", 1
    while len(okm) < 128:
        t = hmac.new(prk, t + b"Octavo app key v1" + bytes([i]), 'sha512').digest(); okm += t; i += 1
    return okm[:128]
