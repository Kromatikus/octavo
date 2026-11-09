# SM4 reference cipher (GB/T 32907-2016), used ONLY by test_sneak_n2.py to authenticate the SM4 S-box table
# against published test vectors. N2 itself does not use SM4 (only its S-box table as an affine-keyed base).
def sm4_table_ok(S):
    rotl = lambda x, n: ((x << n) | (x >> (32 - n))) & 0xffffffff
    tau = lambda x: int.from_bytes(bytes(S[b] for b in x.to_bytes(4, "big")), "big")
    T = lambda x: (lambda t: t ^ rotl(t, 2) ^ rotl(t, 10) ^ rotl(t, 18) ^ rotl(t, 24))(tau(x))
    Tp = lambda x: (lambda t: t ^ rotl(t, 13) ^ rotl(t, 23))(tau(x))
    FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
    CK = [int.from_bytes(bytes(((4 * i + j) * 7) % 256 for j in range(4)), "big") for i in range(32)]
    def enc(key, pt):
        K = [int.from_bytes(key[4 * i:4 * i + 4], "big") ^ FK[i] for i in range(4)]; rk = []
        for i in range(32): K.append(K[i] ^ Tp(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i])); rk.append(K[-1])
        X = [int.from_bytes(pt[4 * i:4 * i + 4], "big") for i in range(4)]
        for i in range(32): X.append(X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]))
        return b"".join(x.to_bytes(4, "big") for x in X[35:31:-1])
    k1 = bytes.fromhex("0123456789abcdeffedcba9876543210"); k2 = bytes.fromhex("fedcba98765432100123456789abcdef")
    return (enc(k1, k1).hex() == "681edf34d206965e86b3e94f536e4246"
            and enc(k2, bytes(range(16))).hex() == "f766678f13f01adeac1b3ea955adb594")
