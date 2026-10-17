"""Final export: all chats, sender names, embedded images."""
import hashlib
import os
import re
import sqlite3
import struct
import sys
import zstandard as zstd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import epubgen

DEC = r"C:\Users\__USER__\wechat2epub\decrypted"
OUTD = os.path.join(os.path.dirname(DEC), "books_img")
os.makedirs(OUTD, exist_ok=True)
ATT = r"C:\Users\__USER__\Documents\xwechat_files\__WXID___5a3d\msg\attach"
IMGKEY = open(r"C:\Users\__USER__\wechat2epub\image_key.txt", "rb").read().strip()
IMGD = os.path.join(os.path.dirname(DEC), "images_out")
os.makedirs(IMGD, exist_ok=True)

from Crypto.Cipher import AES
from Crypto.Util import Padding

MAGICS = ((b"\xff\xd8\xff", "jpg"), (b"\x89PNG", "png"), (b"GIF8", "gif"),
          (b"RIFF", "webp"), (b"wxgf", "hevc"), (b"BM", "bmp"))

def v2_decrypt_bytes(data):
    if len(data) < 15 or data[:4] != b"\x07\x08V2":
        return None, None
    aes_size, xor_size = struct.unpack_from("<LL", data, 6)
    aligned = aes_size - ~(~aes_size % 16)
    if 15 + aligned > len(data):
        return None, None
    try:
        dec = Padding.unpad(AES.new(IMGKEY[:16], AES.MODE_ECB).decrypt(data[15:15 + aligned]), 16)
    except Exception:
        return None, None
    offset = 15 + aligned
    raw_end = max(offset, len(data) - xor_size)
    raw = data[offset:raw_end]
    xor_part = bytes(b ^ 0x88 for b in data[raw_end:])
    out = dec + raw + xor_part
    fmt = "bin"
    for magic, f in MAGICS:
        if out.startswith(magic):
            fmt = f
            break
    return out, fmt

_zstd = zstd.ZstdDecompressor()

def maybe_zstd(b):
    if isinstance(b, bytes) and b[:4] == b"(\xb5/\xfd":
        try:
            return _zstd.decompress(b).decode("utf-8", "replace")
        except Exception:
            return ""
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else (b or "")


def build_maps():
    names = {}
    con = sqlite3.connect(os.path.join(DEC, "contact_contact.db"))
    for u, n, rm in con.execute("SELECT username, nick_name, remark FROM contact"):
        nm = rm if isinstance(rm, str) and rm else (n if isinstance(n, str) else None)
        if u and nm:
            names[u] = nm
    con.close()
    # sender maps: per-db Name2Id rowid -> username
    smaps = {}
    for db in ("message_message_0.db", "message_message_1.db", "message_biz_message_0.db"):
        p = os.path.join(DEC, db)
        if not os.path.exists(p):
            continue
        con = sqlite3.connect(p)
        m = {}
        try:
            for rid, u in con.execute("SELECT rowid, user_name FROM Name2Id"):
                m[rid] = u
        except Exception:
            pass
        con.close()
        smaps[db] = m
    return names, smaps


def build_image_map():
    """(chat_hash, local_id) -> dat path via MessageResourceInfo."""
    m = {}
    con = sqlite3.connect(os.path.join(DEC, "message_message_resource.db"))
    chatmap = dict(con.execute("SELECT rowid, user_name FROM ChatName2Id"))
    rows = con.execute(
        "SELECT chat_id, message_local_id, packed_info FROM MessageResourceInfo "
        "WHERE message_local_type=3").fetchall()
    con.close()
    dat_index = {}
    for root, dirs, files in os.walk(ATT):
        for f in files:
            if f.endswith(".dat") and not f.endswith(("_t.dat", "_h.dat")):
                dat_index[f[:-4].lower()] = os.path.join(root, f)
    for chat_id, local_id, pi in rows:
        talker = chatmap.get(chat_id)
        if not talker:
            continue
        chash = hashlib.md5(talker.encode()).hexdigest()
        if not pi:
            continue
        pb = pi if isinstance(pi, bytes) else pi.encode()
        md5s = re.findall(rb"[0-9a-f]{32}", pb)
        for md5v in md5s:
            k = md5v.decode().lower()
            if k in dat_index:
                m[(chash, local_id)] = dat_index[k]
                break
    return m


def main():
    names, smaps = build_maps()
    print("names:", len(names), "smaps:", {k: len(v) for k, v in smaps.items()}, flush=True)
    imgmap = build_image_map()
    print("image map:", len(imgmap), flush=True)
    # chat hash -> talker via contact
    hash2talker = {}
    con = sqlite3.connect(os.path.join(DEC, "contact_contact.db"))
    for (u,) in con.execute("SELECT username FROM contact"):
        hash2talker[hashlib.md5(u.encode()).hexdigest()] = u
    con.close()
    try:
        con = sqlite3.connect(os.path.join(DEC, "session_session.db"))
        for (u,) in con.execute("SELECT username FROM SessionTable"):
            hash2talker.setdefault(hashlib.md5(u.encode()).hexdigest(), u)
        con.close()
    except Exception:
        pass

    con = sqlite3.connect(os.path.join(DEC, "message_message_0.db"))
    m1 = sqlite3.connect(os.path.join(DEC, "message_message_1.db"))
    mb = sqlite3.connect(os.path.join(DEC, "message_biz_message_0.db"))

    tables0 = [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")]
    tables1 = [r[0] for r in m1.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")]
    tablesb = [r[0] for r in mb.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")]
    all_hashes = set(t[4:] for t in tables0) | set(t[4:] for t in tables1) | set(t[4:] for t in tablesb)
    print("chats:", len(all_hashes), flush=True)

    total = 0
    n_books = 0
    imgs_embedded = 0
    for h in sorted(all_hashes, key=lambda x: -len(x) * 0):
        talker = hash2talker.get(h)
        name = names.get(talker) if talker else None
        title = (name or (talker or "未知_" + h[:8]))
        # merge rows from all dbs
        rows = []
        for conn, tables in ((con, tables0), (m1, tables1), (mb, tablesb)):
            t = "Msg_" + h
            if t not in tables:
                continue
            try:
                rows.extend(conn.execute(
                    "SELECT local_id, local_type, create_time, real_sender_id, "
                    "message_content FROM [%s] ORDER BY create_time" % t).fetchall())
            except Exception:
                continue
        rows.sort(key=lambda r: (r[2] or 0))
        if len(rows) < 2:
            continue
        # dedup by (time, content-hash)
        seen = set()
        body = []
        book_images = []
        img_added = set()
        import datetime
        n_imgs = 0
        for lid, lt, ct, sid, content in rows:
            try:
                tstr = datetime.datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M")
            except Exception:
                tstr = "?"
            sender_uid = smaps.get("message_message_0.db", {}).get(sid) or \
                         smaps.get("message_message_1.db", {}).get(sid) or \
                         smaps.get("message_biz_message_0.db", {}).get(sid)
            if not sender_uid:
                who = name or talker or "?"
            elif sender_uid == MINE_H:
                who = "我"
            else:
                who = names.get(sender_uid, sender_uid)
            txt = maybe_zstd(content)
            if lt == 1:
                # strip "sender:\n" prefix for group text
                txt = re.sub(r"^([^:\n]{1,32}):\n", "", txt)
            else:
                txt = render_non_text(lt, txt)
            img_tag = ""
            if lt == 3:
                img_path = imgmap.get((h, lid))
                if img_path and os.path.exists(img_path):
                    try:
                        dat = open(img_path, "rb").read()
                        dec, fmt = v2_decrypt_bytes(dat)
                        if dec and fmt in ("jpg", "png", "gif", "webp"):
                            iname = "%s_%d.%s" % (h[:8], lid, fmt)
                            ipath = os.path.join(IMGD, iname)
                            if not os.path.exists(ipath):
                                open(ipath, "wb").write(dec)
                            if iname not in img_added:
                                img_added.add(iname)
                                book_images.append((iname, dec))
                            img_tag = '<br/><img src="images/%s"/>' % iname
                            imgs_embedded += 1
                            n_imgs += 1
                    except Exception:
                        pass
                if not img_tag:
                    txt = "[图片]"
            key = (ct, hash(txt))
            if key in seen:
                continue
            seen.add(key)
            body.append('<p class="msg"><span class="who">%s</span> '
                        '<span class="time">%s</span><br/>%s%s</p>' %
                        (epubgen.escape(str(who)), tstr,
                         epubgen.escape(txt).replace("\n", "<br/>"), img_tag))
        if len(body) < 2:
            continue
        total += len(body)
        n_books += 1
        safe = re.sub(r"[\/:*?\"<>|]", "_", title)[:40]
        fname = "%04d_%s.epub" % (n_books, safe)
        path = os.path.join(OUTD, fname)
        epubgen.build_epub(path, title + " (%d条)" % len(body), "WeChat",
                           [("content.xhtml", title, "\n".join(body))], book_images)
        if n_books % 10 == 0:
            print("books %d msgs %d imgs %d" % (n_books, total, imgs_embedded), flush=True)
    print("DONE: %d books, %d msgs, %d images embedded" % (n_books, total, imgs_embedded), flush=True)


MINE_H = hashlib.md5(MINE.encode()).hexdigest() if (MINE := "__WXID__") else None


def render_non_text(lt, txt):
    if lt == 3:
        return "[图片]"
    if lt == 34:
        return "[语音]"
    if lt == 43:
        return "[视频]"
    if lt == 47:
        return "[表情]"
    if lt == 10000:
        return txt[:150]
    if lt == 49:
        m = re.search(r"<title>([^<]+)</title>", txt)
        return "[链接] " + (m.group(1) if m else "")
    return txt[:100]


if __name__ == "__main__":
    main()
