# -*- coding: utf-8 -*-
"""指定聊天 HTML 生成器（通用版）
用法: python chat2html.py <联系人或群名> [起始日期] [结束日期]
日期格式 YYYY-MM-DD，省略则导出全部。
"""
import base64, datetime, hashlib, html as _h, os, re, sqlite3, subprocess, sys, tempfile
import zstandard as zstd
from Crypto.Cipher import AES
from Crypto.Util import Padding

ROOT = os.environ.get("WX2HTML_ROOT", ".")
DEC = os.path.join(ROOT, "decrypted")
IMGKEY = open(os.path.join(ROOT, IMGKEY_PATH), "rb").read().strip()
MINE = os.environ.get("WX2HTML_ME", "wxid_your_id_here")
MYDIR = os.environ.get("WX2HTML_ACCTDIR", "wxid_xxxxxxxx_xxxx")
FFMPEG = os.environ.get("WX2HTML_FFMPEG", "ffmpeg")
XOR_KEY = 0x9A
_z = zstd.ZstdDecompressor()
CACHE = os.path.join(tempfile.gettempdir(), "wximg_cache")
os.makedirs(CACHE, exist_ok=True)

MY_DBS = ["message_message_0.db", "message_message_1.db"]

# image-media AES key (16 ascii chars) captured from Weixin process memory;
# discover yours by memory-scanning for 16-char hex strings tested against .dat headers
IMGKEY_PATH = os.environ.get("WX2HTML_IMGKEY", "image_key.txt")


def esc(s):
    return _h.escape(str(s or ""))


def unesc(s):
    s = re.sub(r"&lt;", "<", s or "")
    s = re.sub(r"&gt;", ">", s)
    s = re.sub(r"&amp;", "&", s)
    return s


def v2dec(p):
    data = open(p, "rb").read()
    if data[:4] != b"\x07\x08V2":
        return None, "old"
    aes_size = int.from_bytes(data[6:10], "little")
    xor_size = int.from_bytes(data[10:14], "little")
    aligned = aes_size - ~(~aes_size % 16)
    try:
        dec = Padding.unpad(AES.new(IMGKEY[:16], AES.MODE_ECB).decrypt(data[15:15 + aligned]), 16)
    except Exception:
        return None, "err"
    off = 15 + aligned
    out = dec + data[off:max(off, len(data) - xor_size)] + bytes(b ^ XOR_KEY for b in data[max(off, len(data) - xor_size):])
    if out[:3] == b"\xff\xd8\xff":
        return out, "jpg"
    if out[:4] == b"\x89PNG":
        return out, "png"
    if out[:4] == b"wxgf":
        return out, "wxgf"
    if out[:4] == b"RIFF":
        return out, "webp"
    return out, "bin"


def wxgf_to_jpg(dec):
    h = os.path.join(CACHE, "t.hevc")
    j = os.path.join(CACHE, "t.jpg")
    i = dec.find(b"\x00\x00\x01", 4)
    if i == -1:
        i = 4
    open(h, "wb").write(dec[i:])
    if os.path.exists(j):
        os.remove(j)
    try:
        subprocess.run([FFMPEG, "-y", "-loglevel", "error", "-f", "hevc", "-i", h,
                        "-frames:v", "1", "-update", "1", "-q:v", "2", j],
                       capture_output=True, timeout=30)
    except Exception:
        return None
    if os.path.exists(j) and os.path.getsize(j) > 100:
        return open(j, "rb").read()
    return None


def load_names():
    con = sqlite3.connect(os.path.join(DEC, "contact_contact.db"))
    names = {}
    for u, n, rm in con.execute("SELECT username, nick_name, remark FROM contact"):
        nm = rm if isinstance(rm, str) and rm else (n if isinstance(n, str) else None)
        if u and nm:
            names[u] = nm
    con.close()
    return names


def find_talker(name):
    """Find username by nickname/remark (exact first, then fuzzy)."""
    names = load_names()
    if name in names:
        return name
    for u, n in names.items():
        if n == name:
            return u
    cands = [(u, n) for u, n in names.items() if name in (n or "")]
    if not cands:
        return None
    cands.sort(key=lambda x: -len(x[1]))
    best = cands[0][0]
    if len(cands) > 1:
        print("匹配到多个，选最含全名的: %s -> %s (%s)" % (name, best, cands[0][1]))
    return best


def render_flat_quote(txt, NAMES):
    m = re.match(r"^(.*?)\s*view (\d+) (?:(\d+) ){2,6}(\d{10,30}) (\S+) (\S+) (.+)$", txt, re.S)
    if not m:
        return None
    reply = m.group(1).strip()
    fromusr = m.group(5)
    rest = m.group(7)
    rest = re.split(r"\s*(?:&amp;)?&lt;msgsource", rest)[0]
    rest = re.split(r"\s+view \d+\s", rest)[0].strip()
    qwho = None
    if fromusr in NAMES:
        qwho = NAMES[fromusr]
        if rest.startswith(qwho):
            rest = rest[len(qwho):].lstrip()
    else:
        toks = rest.split(" ", 1)
        if len(toks) == 2 and 1 <= len(toks[0]) <= 30:
            qwho, rest = toks[0], toks[1]
    return "%s<div class='quote'><b>引用 %s：</b>%s</div>" % (
        esc(reply), esc(qwho or fromusr), esc(rest.strip()[:300]))


def render_appmsg(txt, NAMES):
    if "<appmsg" not in txt and "<refermsg" not in txt:
        return None
    tm = re.search(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", txt, re.S)
    title = tm.group(1).strip() if tm else ""
    at = re.search(r"<type>\s*(\d+)\s*</type>", txt)
    atype = int(at.group(1)) if at else 0
    rm = re.search(r"<refermsg[^>]*>(.*?)</refermsg>", txt, re.S)
    if atype == 57 and rm:
        ref = rm.group(1)
        dn = re.search(r"<displayname>(.*?)</displayname>", ref, re.S)
        fu = re.search(r"<fromusr>(.*?)</fromusr>", ref, re.S)
        co = re.search(r"<content>(.*?)</content>", ref, re.S)
        raw = unesc(co.group(1)) if co else ""
        qc = ""
        # quoted content may be: plain text, flattened quote, or ESCAPED XML (nested quote)
        if raw.startswith("<"):
            # escaped XML of a whole appmsg — take its <title> only
            tm2 = re.search(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", raw, re.S)
            if tm2:
                qc = tm2.group(1).strip()
                # if that nested msg is itself a quote, append "(引用…)" marker is unnecessary;
                # title already is the right text
            if not qc:
                tm3 = re.search(r"<title>(.*?)</title>", re.sub(r"<[^>]+>", " ", raw), re.S)
                qc = raw  # fallback: leave raw for trimming below
        else:
            qc = re.split(r"\s+view \d+\s", re.sub(r"\s+", " ", raw))[0].strip()
        qc = re.sub(r"\s+", " ", qc)[:300].strip()
        # display name: shown name, else NAMES[fromusr], else '?'→ keep raw wxid instead
        qwho = (dn.group(1) if dn else "").strip()
        if not qwho:
            fuid = (fu.group(1) if fu else "").strip()
            qwho = NAMES.get(fuid, fuid) if fuid else "?"
            if fuid == MINE:
                qwho = "我"
        return "quote::%s||%s||%s" % (title.strip(), qwho, qc[:300])
    if atype == 6:
        return "file::" + title[:120]
    dm = re.search(r"<des>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</des>", txt, re.S)
    des = dm.group(1).strip() if dm else ""
    des = re.sub(r"<[^>]+>", " ", des)
    des = re.sub(r"\s+", " ", des).strip()
    if title and des:
        return "share::%s::%s" % (title[:120], des[:150])
    if title:
        return "title::" + title[:150]
    return None


PAGE = """<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8"><title>__TITLE__</title>
<style>
body{margin:0;font-family:-apple-system,'Segoe UI','Microsoft YaHei',sans-serif;background:#e5e5e5;}
#nav{width:150px;overflow-y:auto;background:#2e2e2e;padding:12px 8px;position:fixed;top:0;bottom:0;box-sizing:border-box;}
#nav a{display:block;color:#bbb;text-decoration:none;padding:5px 6px;font-size:12px;border-radius:4px;}
#search{width:100%;box-sizing:border-box;margin-bottom:8px;padding:6px;border-radius:5px;border:1px solid #555;background:#1a1a1a;color:#eee;font-size:12px;}
#main{margin-left:168px;max-width:740px;padding:20px 24px;}
h1{font-size:20px;color:#333;}
h2{font-size:15px;color:#888;border-bottom:1px solid #ccc;padding-bottom:4px;margin:30px 0 12px;}
.msg{margin:10px 0;}
.meta{font-size:12px;color:#888;margin-bottom:3px;}
.meta b{color:#555;}
.msg.me .meta b{color:#3a7bd5;}
.msg.peer .meta b{color:#0a8f5b;}
.meta2{font-size:12px;color:#888;margin-top:4px;}
.bubble{background:#fff;border-radius:8px;padding:8px 12px;display:inline-block;max-width:70%;box-shadow:0 1px 1px rgba(0,0,0,.06);word-break:break-word;font-size:14px;color:#222;}
.msg.me .bubble{background:#d9f1d1;}
.quote{border-left:3px solid #bbb;background:#f2f2f2;border-radius:5px;padding:6px 10px;margin:4px 0;font-size:13px;color:#555;}
img{max-width:420px;border-radius:6px;display:block;}
.sys,.des{color:#999;}
</style></head><body>
<div id="nav"><b style="color:#fff;padding:4px 6px;display:block">__TITLE__</b>
<input id="search" placeholder="搜索消息...">
<div id="navdays">__TOC__</div></div>
<div id="main"><h1>__TITLE__</h1>__SECTIONS__</div>
<script>
document.getElementById('search').addEventListener('input',function(){var q=this.value.trim().toLowerCase();var days=document.querySelectorAll('#main h2');if(!q){location.reload();return;}var msgs=document.querySelectorAll('#main .msg');msgs.forEach(function(m){m.style.display=m.textContent.toLowerCase().indexOf(q)!==-1?'':'none';});days.forEach(function(h){var el=h.nextElementSibling,show=false;while(el&&el.tagName!=='H2'){if(el.style.display!=='none')show=true;el=el.nextElementSibling;}h.style.display=show?'':'none';});});
</script></body></html>"""


_DIMS_CACHE = {}
_USED_DATS = set()
ATT_ROOT = os.path.join(os.path.expanduser('~'), 'Documents', 'xwechat_files', MYDIR, 'msg', 'attach')

def _jpg_dims(d):
    i = 2
    while i < min(len(d), 65536):
        if d[i] != 0xFF:
            i += 1
            continue
        mk = d[i + 1]
        if mk in (0xC0, 0xC2):
            return int.from_bytes(d[i+7:i+9], "big"), int.from_bytes(d[i+5:i+7], "big")
        sz = int.from_bytes(d[i+2:i+4], "big")
        if sz < 2:
            break
        i += 2 + sz
    return None


def match_by_time(lid, txt, chat_md5, ct):
    """ResourceInfo sync lag fallback: match unmapped chat dats to message by file mtime."""
    import os as _o
    target_dir = _o.path.join(ATT_ROOT, chat_md5)
    cand = []
    for root, dirs, fw in _o.walk(target_dir):
        for f in fw:
            if f.endswith(".dat") and not f.endswith(("_t.dat", "_h.dat")):
                fp = _o.path.join(root, f)
                if fp in _USED_DATS:
                    continue
                cand.append((abs(_o.path.getmtime(fp) - ct), fp))
    cand.sort()
    for diff, fp in cand[:3]:
        if diff < 3600:  # within 1 hour
            _USED_DATS.add(fp)
            return fp
    return None




def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("聊天名")
        sys.exit(1)
    name = sys.argv[1]
    d1 = sys.argv[2] if len(sys.argv) > 2 else None
    d2 = sys.argv[3] if len(sys.argv) > 3 else None

    NAMES = load_names()
    talker = find_talker(name)
    if not talker:
        print("找不到联系人/群: %s" % name)
        sys.exit(2)
    peer = NAMES.get(talker, name)
    H = hashlib.md5(talker.encode()).hexdigest()

    # image resource mapping
    con = sqlite3.connect(os.path.join(DEC, "message_message_resource.db"))
    cid = next((k for k, v in con.execute("SELECT rowid, user_name FROM ChatName2Id") if v == talker), None)
    rrows = con.execute("SELECT message_local_id, packed_info FROM MessageResourceInfo WHERE chat_id=? AND message_local_type=3", (cid,)).fetchall()
    con.close()
    ATT = os.path.join(os.path.expanduser("~"), "Documents", "xwechat_files", MYDIR, "msg", "attach", H)
    dat_index = {}
    for root, dirs, files in os.walk(ATT):
        for f in files:
            if f.endswith(".dat") and not f.endswith(("_t.dat", "_h.dat")):
                dat_index[f[:-4].lower()] = os.path.join(root, f)
    THUMBS = os.path.join(ROOT, "thumbs_out")
    imgmap = {}
    for lid, pi in rrows:
        pb = pi if isinstance(pi, bytes) else (pi or "").encode()
        for md5v in re.findall(rb"[0-9a-f]{32}", pb):
            k = md5v.decode().lower()
            if k in dat_index:
                imgmap[lid] = dat_index[k]
            break

    # video + emoji mappings
    videomap = {}
    con = sqlite3.connect(os.path.join(DEC, "message_message_resource.db"))
    vrows = con.execute("SELECT message_local_id, packed_info FROM MessageResourceInfo WHERE chat_id=? AND message_local_type=43", (cid,)).fetchall()
    con.close()
    for lid, pi in vrows:
        pb = pi if isinstance(pi, bytes) else (pi or "").encode()
        for md5v in re.findall(rb"[0-9a-f]{32}", pb):
            k = md5v.decode().lower()
            videomap[lid] = k  # md5 only; file lookup by walk later
            break
    video_files = {}
    for root, dirs, fw in os.walk(os.path.join(os.path.expanduser("~"), "Documents", "xwechat_files", MYDIR, "msg", "video")):
        for f in fw:
            if f.endswith(".mp4"):
                video_files[f[:-4]] = os.path.join(root, f)
    for lid, k in videomap.items():
        videomap[lid] = video_files.get(k)  # path or None

    emoji_index = {}
    for root, dirs, fw in os.walk(os.path.join(os.path.expanduser("~"), "Documents", "xwechat_files", MYDIR, "cache")):
        if "Emoticon" in root:
            for f in fw:
                emoji_index[f.lower()] = os.path.join(root, f)
    allrows = []
    for db in MY_DBS:
        c = sqlite3.connect(os.path.join(DEC, db))
        smap = dict(c.execute("SELECT rowid, user_name FROM Name2Id"))
        try:
            rows = c.execute("SELECT local_id, local_type, create_time, real_sender_id, message_content FROM [Msg_%s]" % H).fetchall()
        except Exception:
            rows = []
        c.close()
        for r in rows:
            allrows.append((db, smap, r[0], r[1], r[2], r[3], r[4]))
    allrows.sort(key=lambda r: r[4])  # create_time

    days = {}
    for db, smap, lid, lt, ct, sid, content in allrows:
        d = datetime.datetime.fromtimestamp(ct).strftime("%Y-%m-%d") if ct else "?"
        if d1 and d < d1:
            continue
        if d2 and d > d2:
            continue
        days.setdefault(d, []).append((lid, lt, ct, sid, content, smap, db))

    n_img = 0
    n_fail = 0
    n_vid = 0
    n_emoji = 0
    EMO_OUT = os.path.join(ROOT, "emoji_out")
    out_html_path = os.path.join(ROOT, "%s.html" % peer.replace("/", "_").replace("\\", "_"))
    out_media = os.path.join(ROOT, "media")
    os.makedirs(out_media, exist_ok=True)
    groups = []
    for day in sorted(days):
        blocks = []
        for lid, lt, ct, sid, content, smap, db in days[day]:
            ts = datetime.datetime.fromtimestamp(ct).strftime("%H:%M") if ct else "?"
            uid = smap.get(sid)
            who = NAMES.get(uid, uid) if uid else peer
            cls = "me" if uid == MINE else "peer"
            bt = lt & 0x3F
            txt = ""
            if isinstance(content, bytes) and content[:4] == b"(\xb5/\xfd":
                try:
                    txt = _z.decompress(content).decode("utf-8", "replace")
                except Exception:
                    txt = ""
            elif isinstance(content, bytes):
                txt = content.decode("utf-8", "replace")
            elif isinstance(content, str):
                txt = content
            html = None
            if bt == 1:
                t = txt.strip()
                # strip group-chat "wxid_xxx:" system prefix (keep rest of message)
                t = re.sub(r"^wxid_[0-9a-z]+:\s*\n?", "", t, count=1)
                t = re.sub(r"^@[^:，,:\s]{1,40}\s*", "", t, count=1)  # leading @mention
                fq = render_flat_quote(t, NAMES)
                if fq:
                    html = "<div class='msg %s'>%s<div class='meta2'>%s · %s</div></div>" % (cls, fq, esc(who), ts)
                elif t:
                    html = "<div class='msg %s'><div class='meta'><b>%s</b> <span>%s</span></div><div class='bubble'>%s</div></div>" % (
                        cls, esc(who), ts, esc(t).replace("\n", "<br/>"))
            elif bt == 3:
                p = imgmap.get(lid)
                # fallback: match by thumbnail aspect ratio against unmapped dats + XML dims
                if not p:
                    p = match_by_time(lid, txt, H, ct)
                ok = False
                if p and os.path.exists(p):
                    dec, fmt = v2dec(p)
                    data64 = None
                    if dec:
                        if fmt == "wxgf":
                            jpg = wxgf_to_jpg(dec)
                            if jpg:
                                data64 = base64.b64encode(jpg).decode()
                        elif fmt in ("jpg", "png", "gif", "webp"):
                            data64 = base64.b64encode(dec).decode()
                    if data64:
                        ok = True
                        n_img += 1
                        html = "<div class='msg %s'><div class='meta'><b>%s</b> <span>%s</span></div><div class='bubble'><img src='data:image/jpeg;base64,%s'/></div></div>" % (
                            cls, esc(who), ts, data64)
                if not ok:
                    # fallback: local-id thumb dats (YYYY_..._t.dat) stored alongside images
                    lp = os.path.join(ATT, H, "Img")
                    import glob as _g
                    for candi in ((lid - 1), lid, (lid + 1)):
                        for cand in _g.glob(os.path.join(lp, "%d_*_t.dat" % candi)):
                            dec, fmt = v2dec(cand)
                            if dec and fmt in ("jpg", "png", "gif", "webp"):
                                ok = True
                                n_img += 1
                                html = "<div class='msg %s'><div class='meta'><b>%s</b> <span>%s</span></div><div class='bubble'><img src='data:image/jpeg;base64,%s'/></div></div>" % (
                                    cls, esc(who), ts, base64.b64encode(dec).decode())
                                break
                        if ok:
                            break
                if not ok:
                    n_fail += 1
                    html = "<div class='msg %s'><div class='meta'><b>%s</b> <span>%s</span></div><div class='bubble sys'>[图片-缺失]</div></div>" % (
                        cls, esc(who), ts)
            elif bt == 47:
                # emoji: md5 from XML; prefer CDN-downloaded (emoji_out), else encrypted cache
                m = re.search(r'md5\s*=\s*"([0-9a-f]{32})"', txt)
                if m:
                    gid = m.group(1)
                    ep = os.path.join(EMO_OUT, gid + ".dat")
                    if not os.path.exists(ep):
                        cu = re.search(r'cdnurl\s*=\s*"([^"]+)"', txt)
                        if cu:
                            ep = download_emoji_from_cdn(gid, cu.group(1).replace("&amp;", "&"), EMO_OUT)
                    if os.path.exists(ep):
                        d = open(ep, "rb").read()
                        mime = None
                        if d[:3] == b"GIF":
                            mime = "image/gif"
                        elif d[:4] == b"\x89PNG":
                            mime = "image/png"
                        elif d[:3] == b"\xff\xd8\xff":
                            mime = "image/jpeg"
                        elif d[:4] == b"RIFF":
                            mime = "image/webp"
                        if mime:
                            n_emoji += 1
                            html = "<div class='msg %s'><div class='meta'><b>%s</b> <span>%s</span></div><div class='bubble'><img class='emoji' src='data:%s;base64,%s'/></div></div>" % (
                                cls, esc(who), ts, mime, base64.b64encode(d).decode())
                            blocks.append(html)
                            continue
                html = "<div class='msg %s'><div class='meta'><b>%s</b> <span>%s</span></div><div class='bubble sys'>[表情-加密]</div></div>" % (
                    cls, esc(who), ts)
            elif bt == 43:
                # video: FULLY inline mp4 as base64 data-URI (single-file shareable)
                p = videomap.get(lid)
                if p and os.path.exists(p):
                    n_vid += 1
                    vdata = base64.b64encode(open(p, "rb").read()).decode()
                    thumb = p[:-4] + "_thumb.jpg"
                    poster = ("poster='data:image/jpeg;base64,%s' " % base64.b64encode(open(thumb, "rb").read()).decode()) if os.path.exists(thumb) else ""
                    html = "<div class='msg %s'><div class='meta'><b>%s</b> <span>%s</span></div><div class='bubble'><video controls preload='metadata' %ssrc='data:video/mp4;base64,%s'></video></div></div>" % (
                        cls, esc(who), ts, poster, vdata)
                else:
                    html = "<div class='msg %s'><div class='meta'><b>%s</b> <span>%s</span></div><div class='bubble sys'>[视频-缺失]</div></div>" % (
                        cls, esc(who), ts)
            elif bt == 49:
                r = render_appmsg(txt)
                if not r:
                    r = render_flat_quote(txt, NAMES)
                if r:
                    kind, _, restpart = r.partition("::")
                    if kind == "quote":
                        qwho, qc = restpart.split("::", 1)
                        html = "<div class='msg %s'><div class='quote'><b>引用 %s：</b>%s</div><div class='meta2'>%s · %s</div></div>" % (
                            cls, esc(qwho), esc(qc), esc(who), ts)
                    elif kind == "file":
                        html = "<div class='msg %s'><b>[文件]</b> %s<div class='meta2'>%s · %s</div></div>" % (
                            cls, esc(restpart), esc(who), ts)
                    elif kind == "share":
                        t_, des = restpart.split("::", 1)
                        html = "<div class='msg %s'><b>[分享]</b> %s<br/><span class='des'>%s</span><div class='meta2'>%s · %s</div></div>" % (
                            cls, esc(t_), esc(des), esc(who), ts)
                    else:  # title
                        html = "<div class='msg %s'>%s<div class='meta2'>%s · %s</div></div>" % (cls, esc(restpart), esc(who), ts)
                else:
                    inner = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", txt)).strip()[:150]
                    html = "<div class='msg %s'><span class='sys'>[消息]</span> %s<div class='meta2'>%s · %s</div></div>" % (
                        cls, esc(inner), esc(who), ts)
            else:
                t = {34: "[语音]", 43: "[视频]", 47: "[表情]", 50: "[通话]"}.get(bt)
                if t is None:
                    t = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", txt)).strip()[:150] or ("[%d]" % bt)
                html = "<div class='msg %s'><div class='meta'><b>%s</b> <span>%s</span></div><div class='bubble'>%s</div></div>" % (
                    cls, esc(who), ts, esc(t))
            if html:
                blocks.append(html)
        groups.append((day, "\n".join(blocks)))

    toc = "".join("<a href='#d%s'>%s</a>" % (d.replace("-", ""), esc(d)) for d, _ in groups)
    secs = "".join("<h2 id='d%s'>%s</h2>%s" % (d.replace("-", ""), esc(d), b) for d, b in groups)
    out = PAGE.replace("__TITLE__", esc(peer)).replace("__TOC__", toc).replace("__SECTIONS__", secs)
    outp = os.path.join(ROOT, "%s.html" % peer.replace("/", "_").replace("\\", "_"))
    open(outp, "w", encoding="utf-8").write(out)
    print("DONE:", outp)
    print("days: %d  messages: %d  images ok: %d  failed: %d  size: %.1f MB" % (
        len(groups), sum(len(b.splitlines()) for _, b in groups), n_img, n_fail,
        len(out.encode()) / 1048576))


if __name__ == "__main__":
    main()
