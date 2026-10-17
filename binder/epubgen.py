"""Minimal EPUB 3 generator (stdlib only)."""
import zipfile
import uuid
from xml.sax.saxutils import escape

XHTML_TMPL = ('<?xml version="1.0" encoding="utf-8"?>'
              '<!DOCTYPE html>'
              '<html xmlns="http://www.w3.org/1999/xhtml"><head>'
              '<meta charset="utf-8"/><title>%s</title>'
              '<style>body{font-family:serif;}'
              '.msg{margin:0.4em 0;}'
              '.who{font-weight:bold;color:#1a5fb4;}'
              '.me .who{color:#b58900;}'
              '.time{color:#888;font-size:0.8em;}'
              '.sys{color:#888;font-style:italic;}'
              'img{max-width:100%%;}</style></head>'
              '<body><h2>%s</h2>%s</body></html>')

NAV_TMPL = ('<?xml version="1.0" encoding="utf-8"?>'
            '<!DOCTYPE html>'
            '<html xmlns="http://www.w3.org/1999/xhtml" '
            'xmlns:epub="http://www.idpf.org/2007/ops"><head>'
            '<meta charset="utf-8"/><title>%s</title></head><body>'
            '<nav epub:type="toc" id="toc"><h2>%s</h2><ol>%s</ol>'
            '</nav></body></html>')

OPF_TMPL = ('<?xml version="1.0" encoding="UTF-8"?>'
            '<package xmlns="http://www.idpf.org/2007/opf" '
            'version="3.0" unique-identifier="uid"><metadata '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            '<dc:identifier id="uid">urn:uuid:%s</dc:identifier>'
            '<dc:title>%s</dc:title>'
            '<dc:creator>%s</dc:creator>'
            '<dc:language>zh-CN</dc:language>'
            '<meta property="dcterms:modified">%s</meta></metadata>'
            '<manifest>%s</manifest><spine>%s</spine></package>')


def build_epub(out_path, title, author, chapters, images=None):
    chapters = chapters or []
    images = images or []
    b = zipfile.ZipFile(out_path, "w")
    b.writestr(zipfile.ZipInfo("mimetype"), "application/epub+zip",
               compress_type=zipfile.ZIP_STORED)
    b.writestr("META-INF/container.xml",
               '<?xml version="1.0" encoding="UTF-8"?>'
               '<container version="1.0" xmlns="http://www.idpf.org/2007/opf">'
               '<rootfiles><rootfile full-path="OEBPS/content.opf" '
               'media-type="application/oebps-package+xml"/>'
               '</rootfiles></container>')
    manifest = ['<item id="nav" href="nav.xhtml" '
                'media-type="application/xhtml+xml" properties="nav"/>']
    spine = ['<itemref idref="nav"/>']
    for i, (fn, t, body) in enumerate(chapters):
        b.writestr("OEBPS/" + fn, XHTML_TMPL % (escape(t), escape(t), body))
        manifest.append('<item id="c%d" href="%s" '
                        'media-type="application/xhtml+xml"/>' % (i, fn))
        spine.append('<itemref idref="c%d"/>' % i)
    for j, (name, data) in enumerate(images):
        ext = name.rsplit(".", 1)[-1].lower()
        mt = {"jpg": "image/jpeg", "png": "image/png", "gif": "image/gif",
              "webp": "image/webp"}.get(ext, "application/octet-stream")
        b.writestr("OEBPS/images/" + name, data)
        manifest.append('<item id="im%d" href="images/%s" '
                        'media-type="%s"/>' % (j, name, mt))
    nav_items = "".join(
        '<li><a href="%s">%s</a></li>' % (fn, escape(t))
        for fn, t, _b in chapters)
    b.writestr("OEBPS/nav.xhtml",
               NAV_TMPL % (escape(title), escape(title), nav_items))
    opf = OPF_TMPL % (uuid.uuid4(), escape(title), escape(author),
                      time_str(), "".join(manifest), "".join(spine))
    b.writestr("OEBPS/content.opf", opf)
    b.close()
    return out_path

def time_str():
    import datetime
    return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")



def render_chapter(title, msgs, self_id="self", name_of=None):
    """msgs: [(time, type, sender_key, text)] -> xhtml body"""
    import datetime
    out = []
    cur_day = None
    for (ts, typ, sender, text) in msgs:
        day = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
        who = "我" if sender == self_id else (name_of(sender) if name_of else str(sender))
        if typ == 10000:
            out.append('<p class="sys">%s</p>' % escape(text or ""))
            continue
        cls = "msg me" if sender == self_id else "msg"
        head = '<span class="who">%s</span> <span class="time">%s</span>' % (escape(who or "?"), day)
        out.append('<p class="%s">%s<br/>%s</p>' % (cls, head, escape(text or "").replace("\n", "<br/>")))
    return "\n".join(out)
