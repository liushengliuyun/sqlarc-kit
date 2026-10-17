"""Extract WeChat 4.x per-database derived enc_keys from a running Weixin.exe.

WCDB caches per-db keys in process memory as hex literals x'<hex>'. A 96-char
literal is enc_key(64 hex) + salt(32 hex). Candidates are verified per-DB with
cheap HMAC (PBKDF2 2 iterations).
"""
import ctypes
import json
import os
import re
import subprocess
import sys
import time

import sqlcipher

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
k32.ReadProcessMemory.restype = ctypes.c_bool
k32.ReadProcessMemory.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
]


class MBI64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64),
        ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", ctypes.c_uint32),
        ("__align1", ctypes.c_uint32),
        ("RegionSize", ctypes.c_uint64),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("__align2", ctypes.c_uint32),
    ]


PROC_QUERY = 0x0400
PROC_VM_READ = 0x0010
MEM_COMMIT = 0x1000
READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}

HEXLIT_RE = re.compile(rb"x'([0-9A-Fa-f]{64,192})'")


def find_weixin_pids():
    r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                       capture_output=True, text=True)
    pids = []
    for line in r.stdout.splitlines():
        if "Weixin.exe" in line:
            parts = line.strip('"').split('","')
            try:
                name = parts[0].strip('"')
                pid = int(parts[1])
                mem = int(parts[4].replace(",", "").replace(" K", "").strip() or 0)
                pids.append((pid, mem))
            except (IndexError, ValueError):
                continue
    pids.sort(key=lambda x: -x[1])
    return [p for p, _ in pids]


def open_proc(pid):
    h = k32.OpenProcess(PROC_QUERY | PROC_VM_READ, False, pid)
    if not h:
        raise OSError("OpenProcess failed, err=%d" % ctypes.get_last_error())
    return h


def read_regions(h):
    regions = []
    addr = 0
    mbi = MBI64()
    while addr < 0x7FFFFFFFFFFF:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        size = mbi.RegionSize
        if (mbi.State == 0x1000 and mbi.Protect in READABLE and 0 < size < 500 * 1024 * 1024):
            buf = ctypes.create_string_buffer(size)
            n = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(h, ctypes.c_void_p(mbi.BaseAddress), buf, size, ctypes.byref(n)) and n.value:
                regions.append((mbi.BaseAddress, buf.raw[:n.value]))
        addr = nxt
    return regions


def collect_literals(pid):
    h = open_proc(pid)
    hexes = set()
    total = 0
    for _, data in read_regions(h):
        total += len(data)
        for m in HEXLIT_RE.finditer(data):
            hexes.add(m.group(1).decode())
    close(h)
    return hexes, total


def close(h):
    k32.CloseHandle(h)


def collect_db_salts(db_dir):
    """Walk db_storage, return {rel_path: salt_hex} and {salt_hex: [rel_paths]}."""
    salt_to_dbs = {}
    db_list = []
    for root, dirs, files in os.walk(db_dir):
        for f in files:
            if f.endswith(".db") and not f.endswith(("-wal", "-shm")):
                path = os.path.join(root, f)
                try:
                    if os.path.getsize(path) < 4096:
                        continue
                    with open(path, "rb") as fh:
                        page1 = fh.read(4096)
                except OSError:
                    continue
                salt = page1[:16].hex()
                rel = os.path.relpath(path, db_dir)
                db_list.append((rel, path, salt))
                salt_to_dbs.setdefault(salt, []).append(rel)
    return db_list, salt_to_dbs


def find_keys(db_dir, progress=print):
    """Scan Weixin memory, return {rel_db_path: enc_key_hex}. Requires running WeChat."""
    db_list, salt_to_dbs = collect_db_salts(db_dir)
    progress("found %d databases, %d distinct salts" % (len(db_list), len(salt_to_dbs)))
    keys = {}
    for pid in find_weixin_pids():
        if len(keys) == len(salt_to_dbs):
            break
        try:
            hexes, total = collect_literals(pid)
        except OSError as e:
            progress("pid %d: %s" % (pid, e))
            continue
        progress("pid %d: %.0fMB scanned, %d hex literals" % (pid, total / 1048576, len(hexes)))
        for hx in hexes:
            if len(hx) == 96:
                enc_hex, salt_hex = hx[:64].lower(), hx[64:].lower()
                if salt_hex in salt_to_dbs and salt_hex not in keys:
                    # verify with HMAC against the matching db
                    rel = salt_to_dbs[salt_hex][0]
                    path = next(p for r, p, s in db_list if r == rel)
                    with open(path, "rb") as fh:
                        page1 = fh.read(4096)
                    if sqlcipher.verify_page1_hmac(page1, bytes.fromhex(enc_hex)):
                        keys[salt_hex] = enc_hex
                        progress("  key found for %s (x'..' literal, %d dbs)" % (", ".join(salt_to_dbs[salt_hex]), len(salt_to_dbs[salt_hex])))
        # 64-char literals: test each as derived enc_key for every unknown salt
        for hx in hexes:
            if len(hx) == 64 and len(keys) < len(salt_to_dbs):
                enc = bytes.fromhex(hx)
                for salt_hex, rels in salt_to_dbs.items():
                    if salt_hex in keys:
                        continue
                    rel = rels[0]
                    path = next(p for r, p, s in db_list if r == rel)
                    with open(path, "rb") as fh:
                        page1 = fh.read(4096)
                    if sqlcipher.verify_page1_hmac(page1, enc):
                        keys[salt_hex] = hx.lower()
                        progress("  key found for %s (64-hex candidate)" % ", ".join(rels))
    return keys, salt_to_dbs, db_list


def main():
    acc = os.path.expandvars(
        r"%USERPROFILE%\Documents\xwechat_files\__WXID___5a3d")
    db_dir = os.path.join(acc, "db_storage")
    if not os.path.isdir(db_dir):
        print("db_storage not found:", db_dir)
        return 1
    t0 = time.time()
    keys, salt_to_dbs, db_list = find_keys(db_dir)
    if not keys:
        print("NO KEYS FOUND - make sure Weixin.exe is running and logged in")
        return 2
    print("FOUND %d/%d keys in %.1fs" % (len(keys), len(salt_to_dbs), time.time() - t0))
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "all_keys.json")
    with open(out, "w") as f:
        json.dump(keys, f, indent=2)
    print("saved to", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())


def scan_salt_adjacent(db_list, salt_to_dbs, pids=None, progress=print):
    """Search memory for each db's 16-byte salt; HMAC-verify 32B windows nearby."""
    import sqlcipher as _sq
    page1_cache = {}
    def page1_of(rel):
        if rel not in page1_cache:
            path = next(p for r, p, s in db_list if r == rel)
            with open(path, "rb") as fh:
                page1_cache[rel] = fh.read(4096)
        return page1_cache[rel]

    keys = {}
    if pids is None:
        pids = find_weixin_pids()
    for pid in pids:
        if len(keys) == len(salt_to_dbs):
            break
        try:
            h = open_proc(pid)
        except OSError as e:
            progress("pid %d: %s" % (pid, e))
            continue
        n_hits = 0
        for addr, data in read_regions(h):
            for rel, _p, salt_hex in db_list:
                if rel in keys or salt_hex not in salt_to_dbs:
                    continue
                salt = bytes.fromhex(salt_hex)
                pos = data.find(salt)
                while pos != -1:
                    n_hits += 1
                    lo = max(0, pos - 256)
                    hi = min(len(data) - 32, pos + 256)
                    for off in range(lo, hi, 4):
                        cand = data[off:off + 32]
                        if _sq.verify_page1_hmac(page1_of(rel), cand):
                            keys[rel] = cand.hex()
                            progress("  KEY for %s (adjacent to salt @pid %d)" % (rel, pid))
                            break
                    pos = data.find(salt, pos + 1)
        close(h)
        progress("pid %d: %d salt hits" % (pid, n_hits))
        if len(keys) == len(salt_to_dbs):
            break
    return keys


def enum_regions(h):
    """Return [(base, size)] of committed readable regions without reading data."""
    regions = []
    addr = 0
    mbi = MBI64()
    while addr < 0x7FFFFFFFFFFF:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        size = mbi.RegionSize
        if (mbi.State == 0x1000 and mbi.Protect in READABLE and 0 < size < 500 * 1024 * 1024):
            regions.append((mbi.BaseAddress, size))
        addr = nxt
    return regions
