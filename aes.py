import os


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a


def _build_log_tables():
    exp = [0] * 510
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = exp[i + 255] = x
        log[x] = i
        x ^= _xtime(x)
    return exp, log


_EXP, _LOG = _build_log_tables()


def gmul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox():
    sbox = [0] * 256
    for a in range(256):
        inv = 0 if a == 0 else _EXP[255 - _LOG[a]]
        sbox[a] = (inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2)
                   ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63)
    return sbox


SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

MUL = {n: [gmul(n, x) for x in range(256)] for n in (2, 3, 9, 11, 13, 14)}


def _add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]


def _sub_bytes(state):
    return [SBOX[b] for b in state]


def _inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def _shift_rows(state):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
    return out


def _inv_shift_rows(state):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * ((c + r) % 4)] = state[r + 4 * c]
    return out


def _mix_columns(state):
    out = [0] * 16
    m2, m3 = MUL[2], MUL[3]
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = state[c:c + 4]
        out[c] = m2[a0] ^ m3[a1] ^ a2 ^ a3
        out[c + 1] = a0 ^ m2[a1] ^ m3[a2] ^ a3
        out[c + 2] = a0 ^ a1 ^ m2[a2] ^ m3[a3]
        out[c + 3] = m3[a0] ^ a1 ^ a2 ^ m2[a3]
    return out


def _inv_mix_columns(state):
    out = [0] * 16
    m9, m11, m13, m14 = MUL[9], MUL[11], MUL[13], MUL[14]
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = state[c:c + 4]
        out[c] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
        out[c + 1] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
        out[c + 2] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
        out[c + 3] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]
    return out


class AES:
    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("panjang key harus 16, 24, atau 32 byte")
        self.rounds = len(key) // 4 + 6
        self.round_keys = self._expand_key(key)

    def _expand_key(self, key):
        nk = len(key) // 4
        words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        rcon = 1
        for i in range(nk, 4 * (self.rounds + 1)):
            temp = list(words[i - 1])
            if i % nk == 0:
                temp = [SBOX[b] for b in temp[1:] + temp[:1]]
                temp[0] ^= rcon
                rcon = _xtime(rcon)
            elif nk > 6 and i % nk == 4:
                temp = [SBOX[b] for b in temp]
            words.append([a ^ b for a, b in zip(words[i - nk], temp)])
        return [sum(words[4 * r:4 * r + 4], []) for r in range(self.rounds + 1)]

    def encrypt_block(self, block):
        state = _add_round_key(list(block), self.round_keys[0])
        for r in range(1, self.rounds):
            state = _sub_bytes(state)
            state = _shift_rows(state)
            state = _mix_columns(state)
            state = _add_round_key(state, self.round_keys[r])
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _add_round_key(state, self.round_keys[self.rounds])
        return bytes(state)

    def decrypt_block(self, block):
        state = _add_round_key(list(block), self.round_keys[self.rounds])
        for r in range(self.rounds - 1, 0, -1):
            state = _inv_shift_rows(state)
            state = _inv_sub_bytes(state)
            state = _add_round_key(state, self.round_keys[r])
            state = _inv_mix_columns(state)
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, self.round_keys[0])
        return bytes(state)


def pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def unpad(data):
    if not data or len(data) % 16:
        raise ValueError("panjang data tidak valid")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("padding tidak valid (key salah atau data rusak)")
    return data[:-n]


def encrypt_cbc(key, plaintext):
    cipher = AES(key)
    iv = os.urandom(16)
    data = pad(plaintext)
    previous = iv
    out = [iv]
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], previous))
        previous = cipher.encrypt_block(block)
        out.append(previous)
    return b"".join(out)


def decrypt_cbc(key, blob):
    if len(blob) < 32 or len(blob) % 16:
        raise ValueError("ciphertext tidak valid")
    cipher = AES(key)
    previous = blob[:16]
    out = []
    for i in range(16, len(blob), 16):
        block = blob[i:i + 16]
        out.append(bytes(a ^ b for a, b in zip(cipher.decrypt_block(block), previous)))
        previous = block
    return unpad(b"".join(out))


def check_key(text):
    try:
        raw = text.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("key harus berupa karakter ASCII")
    if len(raw) not in (16, 24, 32):
        raise ValueError("panjang key harus 16, 24, atau 32 karakter ASCII")
    return raw


def encrypt_text(key_text, plaintext):
    return encrypt_cbc(check_key(key_text), plaintext.encode("ascii")).hex()


def decrypt_text(key_text, cipher_hex):
    blob = bytes.fromhex(cipher_hex)
    return decrypt_cbc(check_key(key_text), blob).decode("ascii")


def self_test():
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    vectors = [
        (16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
        (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
        (32, "8ea2b7ca516745bfeafc49904b496089"),
    ]
    for size, expected in vectors:
        cipher = AES(bytes(range(size)))
        out = cipher.encrypt_block(plain)
        assert out.hex() == expected, (size, out.hex())
        assert cipher.decrypt_block(out) == plain
    key = "kunci-rahasia-16"
    for message in ("", "a", "halo bob", "x" * 16, "y" * 33):
        assert decrypt_text(key, encrypt_text(key, message)) == message
    return True


if __name__ == "__main__":
    print("self-test AES (FIPS-197 + CBC):", "OK" if self_test() else "GAGAL")
