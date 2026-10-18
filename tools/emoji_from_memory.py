# -*- coding: utf-8 -*-
"""Recover emoji stickers that have no cdnurl by catching their wxgf (HEVC) stream
from the live WeChat render process memory while the sticker animates on screen.

Steps: scan MEM_PRIVATE heap for wxgf magic -> ffmpeg-extract frames -> re-pack GIF.
Usage:
  python tools/emoji_from_memory.py            # scans all Weixin processes for 10s
Requires: admin (ReadProcessMemory), ffmpeg on PATH.
Verified case: 316x316 'baby question' sticker, 20 frames -> 475 KB GIF.
"""
import ctypes, os, subprocess, sys, time, glob

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from keys import dbkey_scan as keyscan  # repo layout
except ImportError:
    import dbkey_scan as keyscan  # flat layout

FFMPEG = os.environ.get("WX2HTML_FFMPEG", "ffmpeg")
OUTD = os.path.abspath("emoji_memcap")
os.makedirs(OUTD, exist_ok=True)

MAGICS = (b"wxgf",)


def weixin_pids():
    import psutil
    return [p.pid for p in psutil.process_iter(["name"]) if "weixin" in (p.info["name"] or "").lower()]


def private_regions(h):
    regions = []
    addr = 0
    mbi = keyscan.MBI64()
    while addr < 0x7FFFFFFFFFFF:
        if not keyscan.k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        if mbi.State == 0x1000 and mbi.Protect in keyscan.READABLE and mbi.Type == 0x20000:
            regions.append((mbi.BaseAddress, min(mbi.RegionSize, 64 * 1024 * 1024)))
        addr = nxt
    return regions


def scan_once(pids, cap=4 * 1024 * 1024):
    blobs = []  # (addr, bytes)
    for pid in pids:
        try:
            h = keyscan.open_proc(pid)
        except OSError:
            continue
        for base, size in private_regions(h):
            cur, rem = base, size
            CHUNK = 4 * 1024 * 1024
            while rem > 0:
                take = min(CHUNK, rem)
                buf = ctypes.create_string_buffer(take)
                n = ctypes.c_size_t(0)
                if not keyscan.k32.ReadProcessMemory(h, ctypes.c_void_p(cur), buf, take, ctypes.byref(n)) or not n.value:
                    rem -= take
                    cur += take
                    continue
                data = buf.raw[:n.value]
                i = 0
                while True:
                    i = data.find(b"wxgf", i)
                    if i == -1:
                        break
                    blobs.append((cur + i, data[i:i + cap]))
                    i += 4
                rem -= n.value
                cur += n.value
        keyscan.close(h)
    return blobs


def decode_frames(hevc_path, seq_dir):
    subprocess.run([FFMPEG, "-y", "-loglevel", "error", "-probesize", "10M", "-analyzeduration", "10M",
                    "-f", "hevc", "-i", hevc_path, "-q:v", "2", os.path.join(seq_dir, "f%03d.jpg")],
                   capture_output=True)
    return sorted(glob.glob(os.path.join(seq_dir, "f*.jpg")))


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=10, help="seconds to keep scanning")
    ap.add_argument("--min-frames", type=int, default=3)
    args = ap.parse_args()
    t0 = time.time()
    pids = weixin_pids()
    blobs = {}
    while time.time() - t0 < args.window:
        for addr, blob in scan_once(pids):
            blobs[addr] = blob
        time.sleep(1)
    print("wxgf buffers:", len(blobs))
    done = 0
    for addr, blob in sorted(blobs.items()):
        i = blob.find(b"\x00\x00\x01", 8)
        if i == -1:
            continue
        tag = "%x" % addr
        hevc = os.path.join(OUTD, tag + ".hevc")
        seq = os.path.join(OUTD, "seq_" + tag)
        os.makedirs(seq, exist_ok=True)
        open(hevc, "wb").write(blob[i:] + b"\x00" * 512)
        frames = decode_frames(hevc, seq)
        if len(frames) < args.min_frames:
            continue
        gif = os.path.join(OUTD, tag + ".gif")
        subprocess.run([FFMPEG, "-y", "-loglevel", "error", "-framerate", "10",
                        "-i", os.path.join(seq, "f%03d.jpg"), "-loop", "0", gif],
                       capture_output=True)
        print("recovered:", tag, len(frames), "frames ->", gif, os.path.getsize(gif), "bytes")
        done += 1
    print("stickers recovered:", done)


if __name__ == "__main__":
    main()
