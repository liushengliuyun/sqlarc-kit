"""SM4 block cipher (GB/T 32907-2016). SBOX extracted from Weixin.dll."""
import os, struct

_H = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_H, "sm4_sbox.bin"), "rb") as f:
    _SBOX = f.read()
assert len(_SBOX) == 256

_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)

_CK = tuple(
    ((((4 * i + 0) * 7) % 256) << 24)
    | ((((4 * i + 1) * 7) % 256) << 16)
    | ((((4 * i + 2) * 7) % 256) << 8)
    | ((((4 * i + 3) * 7) % 256))
    for i in range(32)
)


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _tau(A):
    return (
        (_SBOX[(A >> 24) & 0xFF] << 24)
        | (_SBOX[(A >> 16) & 0xFF] << 16)
        | (_SBOX[(A >> 8) & 0xFF] << 8)
        | _SBOX[A & 0xFF]
    )



def _T(x):
    t = _tau(x)
    return t ^ _rotl(t, 2) ^ _rotl(t, 10) ^ _rotl(t, 18) ^ _rotl(t, 24)


def _Ttick(x):
    t = _tau(x)
    return t ^ _rotl(t, 13) ^ _rotl(t, 23)


def expand_key(key16):
    mk = struct.unpack(">4I", key16)
    K = [mk[i] ^ _FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        v = K[0] ^ _Ttick(K[1] ^ K[2] ^ K[3] ^ _CK[i])
        rk.append(v)
        K = [K[1], K[2], K[3], v]
    return rk


def _crypt_block(rk, block, decrypt=False):
    if decrypt:
        rk = rk[::-1]
    X = list(struct.unpack(">4I", block))
    for i in range(32):
        X = [X[1], X[2], X[3], X[0] ^ _T(X[1] ^ X[2] ^ X[3] ^ rk[i])]
    return struct.pack(">4I", *X[::-1])


def expand_and_ecb_decrypt(rk, data):
    return _crypt_block(rk, data, decrypt=True)


def cbc_decrypt(rk, ct, iv):
    out = bytearray()
    prev = iv
    for i in range(0, len(ct) - 15, 16):
        blk = ct[i:i+16]
        pt = bytes(a ^ b for a, b in zip(_crypt_block(rk, blk, decrypt=True), prev))
        out += pt
        prev = blk
    return bytes(out)


def ecb_decrypt(rk, data):
    return b"".join(_crypt_block(rk, data[i:i+16], True) for i in range(0, len(data) - 15, 16))


if __name__ == "__main__":
    rk = expand_key(bytes.fromhex("0123456789abcdeffedcba9876543210"))
    ct = _crypt_block(rk, bytes.fromhex("0123456789abcdeffedcba9876543210"))
    print("SM4 KAT:", ct.hex(), "expect 681edf34d206965e86b3e94f536e4246")
    pt = _crypt_block(rk, ct, decrypt=True)
    print("dec roundtrip:", pt.hex())
