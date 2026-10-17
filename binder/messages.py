"""Parse scraped plaintext b-tree pages into rows."""
import struct


def varint(buf, off):
    r = 0
    for i in range(9):
        if off + i >= len(buf):
            raise ValueError("oob")
        b = buf[off + i]
        if i == 8:
            return (r << 8) | b, off + 9
        r = (r << 7) | (b & 0x7F)
        if not (b & 0x80):
            return r, off + i + 1


def parse_leaf_rows(page):
    """Parse a b-tree leaf page (type 13) into (rowid, [values])."""
    out = []
    if page[0] != 13:
        return out
    ncell = int.from_bytes(page[3:5], "big")
    for ci in range(ncell):
        try:
            cp = int.from_bytes(page[8 + ci * 2:10 + ci * 2], "big")
            plen, o = varint(page, cp)
            rowid, o = varint(page, o)
            hlen, ho = varint(page, o)
            hend = ho + hlen
            if hend > 4016:
                continue
            types = []
            while ho < hend:
                t, ho = varint(page, ho)
                types.append(t)
            vals = []
            po = hend
            ok = True
            for t in types:
                if t == 0:
                    vals.append(None)
                elif 1 <= t <= 6:
                    n = (1, 2, 3, 4, 6, 8)[t - 1]
                    if po + n > 4016:
                        ok = False
                        break
                    v = int.from_bytes(page[po:po + n], "big", signed=True)
                    vals.append(v)
                    po += n
                elif t == 7:
                    po += 8
                    vals.append(None)
                elif t >= 12:
                    n = (t - 12) // 2
                    if po + n > 4016:
                        ok = False
                        break
                    vals.append(bytes(page[po:po + n]))
                    po += n
                else:
                    ok = False
                    break
            if ok:
                out.append((rowid, vals))
        except Exception:
            continue
    return out


def is_message_row(vals):
    """Heuristic: Msg_ table row signature.

    cols: local_id, server_id, local_type, sort_seq, real_sender_id,
          create_time, status, message_content, ...
    """
    if len(vals) < 8:
        return False
    lt = vals[2]
    ct = vals[5]
    if not isinstance(lt, int):
        return False
    if not (isinstance(ct, int) and 1500000000 < ct < 1900000000):
        return False
    return True


MSG_TYPES = {
    1: "text", 3: "image", 34: "voice", 43: "video", 47: "sticker",
    48: "location", 49: "link", 50: "call", 10000: "system",
}


def describe_row(vals):
    """Msg_ row -> (create_time, local_type, sender_id, content_str).

    cols: 0 local_id, 1 server_id, 2 local_type, 3 sort_seq,
          4 real_sender_id, 5 create_time, ..., 11 source,
          12 message_content, 14 packed_info_data
    """
    lt = vals[2]
    sid = vals[4] if len(vals) > 4 else 0
    ct = vals[5]
    content = vals[12] if len(vals) > 12 else b""
    if isinstance(content, int) or content is None:
        content = b""
    try:
        s = content.decode("utf-8", "replace")
    except Exception:
        s = ""
    return ct, lt, sid, s
