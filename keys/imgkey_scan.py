"""Scan via keyscan.read_regions (proven working) for image AES key."""
import os
import re
import sys
import time

from Crypto.Cipher import AES

sys.path.insert(0, r"C:\Users\__USER__\wechat2epub\wx2epub")
import keyscan

DAT = os.environ.get("IMGKEY_TEST_DAT", r"%s") % os.path.join("__ACC__", "msg", "attach", "__CHATMD5__", "2025-11", "Img", "sample.dat")
test_block = open(DAT, "rb").read(31)[15:31]
MAGICS = (b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"RIFF")

def try_key(k):
    pt = AES.new(k, AES.MODE_ECB).decrypt(test_block)
    return any(pt.startswith(m) for m in MAGICS)

ASCII_RE = re.compile(rb"(?<![a-zA-Z0-9])([a-zA-Z0-9]{16})(?![a-zA-Z0-9])")
ASCII32_RE = re.compile(rb"(?<![a-zA-Z0-9])([a-zA-Z0-9]{32})(?![a-zA-Z0-9])")
tested = set()
t0 = time.time()
while time.time() - t0 < 7200:
    pids = keyscan.find_weixin_pids()
    found = None
    for pid in pids[:2]:
        try:
            h = keyscan.open_proc(pid)
        except OSError:
            continue
        n_before = len(tested)
        try:
            for base, chunk in keyscan.read_regions(h):
                for m in ASCII_RE.finditer(chunk):
                    k = m.group(1)
                    if k in tested:
                        continue
                    tested.add(k)
                    if try_key(k):
                        found = k
                        break
                if found:
                    break
            if not found:
                try:
                    h2 = keyscan.open_proc(pid)
                except OSError:
                    h2 = None
                if h2:
                    for base, chunk in keyscan.read_regions(h2):
                        for m in ASCII32_RE.finditer(chunk):
                            k32 = m.group(1)
                            k = k32[:16]
                            if k in tested:
                                continue
                            tested.add(k)
                            if try_key(k):
                                found = k
                                break
                    keyscan.close(h2)
        except Exception:
            pass
        keyscan.close(h)
        if found:
            break
        print("pid %d: +%d candidates (total %d) %.0fs" % (
            pid, len(tested) - n_before, len(tested), time.time() - t0), flush=True)
    if found:
        print("IMAGE KEY FOUND:", found.decode(), flush=True)
        open(r"C:\Users\__USER__\wechat2epub\image_key.txt", "wb").write(found)
        break
    time.sleep(5)
print("exit", flush=True)
