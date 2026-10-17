"""WeChat 4.x (WCDB / SQLCipher 4) page decryption.

Encrypted page layout (page_size=4096, reserve=80 = IV 16 + HMAC-SHA512 64):
  page 1   : [salt 16][ciphertext 4000][IV 16][HMAC 64]
  page N>1 : [ciphertext 4016][IV 16][HMAC 64]
IV is always at page[4016:4032].

The key used here is the per-database DERIVED enc_key (32 raw bytes) as cached
by WCDB in process memory as x'<64hex enc_key><32hex salt>'.
HMAC verification: mac_key = PBKDF2-HMAC-SHA512(enc_key, salt^0x3a, 2 iters).
"""
import hashlib
import hmac
import os
import struct

from Crypto.Cipher import AES

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80
SQLITE_HDR = b"SQLite format 3\x00"


def derive_mac_key(enc_key, salt):
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def verify_page1_hmac(page1, enc_key):
    """True if enc_key is the correct derived key for this db."""
    if len(page1) < PAGE_SZ:
        return False
    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    data = page1[SALT_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    stored = page1[PAGE_SZ - HMAC_SZ:]
    h = hmac.new(mac_key, data, hashlib.sha512)
    h.update(struct.pack("<I", 1))
    return h.digest() == stored


def decrypt_page(enc_key, page_data, pgno):
    """Decrypt one page to a 4096-byte standard SQLite page."""
    if len(page_data) < PAGE_SZ:
        page_data = page_data + b"\x00" * (PAGE_SZ - len(page_data))
    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    if pgno == 1:
        ct = page_data[SALT_SZ: PAGE_SZ - RESERVE_SZ]
    else:
        ct = page_data[: PAGE_SZ - RESERVE_SZ]
    pt = AES.new(enc_key, AES.MODE_CBC, iv).decrypt(ct)
    if pgno == 1:
        return SQLITE_HDR + pt + b"\x00" * RESERVE_SZ
    return pt + b"\x00" * RESERVE_SZ


def decrypt_db(db_path, out_path, enc_key):
    """Decrypt a full database file. Returns page count, raises on bad key."""
    with open(db_path, "rb") as f:
        page1 = f.read(PAGE_SZ)
    if not verify_page1_hmac(page1, enc_key):
        raise ValueError("HMAC verification failed for %s" % db_path)
    n = 0
    with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
        pgno = 0
        while True:
            page = fin.read(PAGE_SZ)
            if not page:
                break
            pgno += 1
            fout.write(decrypt_page(enc_key, page, pgno))
            n += 1
    return n


def decrypt_wal(wal_path, enc_key):
    """Decrypt committed frames of a -wal file.

    Returns list of (pgno, plaintext_4096_page); (-1, dbsize_bytes) marks a
    commit boundary. Frames after the last commit are dropped by merge_wal.
    """
    out = []
    if not os.path.exists(wal_path):
        return out
    with open(wal_path, "rb") as f:
        hdr = f.read(32)
        if len(hdr) < 32:
            return out
        magic, fmt, wpage, ckpt, s1, s2, c1, c2 = struct.unpack(">8I", hdr)
        if magic not in (0x377F0682, 0x377F0683) or wpage != PAGE_SZ:
            return out
        fsize = os.fstat(f.fileno()).st_size
        while f.tell() + 24 + PAGE_SZ <= fsize:
            fh = f.read(24)
            pgno, dbsize, fs1, fs2 = struct.unpack(">4I", fh[:16])
            page_enc = f.read(PAGE_SZ)
            if fs1 != s1 or fs2 != s2:
                break  # frame from an older WAL generation
            out.append((pgno, decrypt_page(enc_key, page_enc, pgno)))
            if dbsize != 0:
                out.append((-1, struct.pack(">I", dbsize)))
    return out


def merge_wal(db_path, wal_frames):
    """Apply decrypted WAL frames (up to last commit) onto plaintext db."""
    last_commit = -1
    for i, (pgno, _) in enumerate(wal_frames):
        if pgno == -1:
            last_commit = i
    if last_commit < 0:
        return 0
    applied = 0
    with open(db_path, "r+b") as f:
        for pgno, page in wal_frames[:last_commit]:
            if pgno == -1:
                continue
            off = (pgno - 1) * PAGE_SZ
            f.seek(0, os.SEEK_END)
            cur = f.tell()
            if cur < off:
                f.write(b"\x00" * (off - cur))
            f.seek(off)
            f.write(page)
            applied += 1
    return applied
