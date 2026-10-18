# sqlarc-kit

Local chat-database recovery toolkit for WeChat 4.x (Windows): recover **your own**
chat history (text / quotes / full-res images / stickers / videos) from encrypted
local databases into a searchable single-file HTML archive.

Use only on your own machine and own account.

## Layout

```
docs/method.md             FULL reproduction guide (read this first!)
keys/                      runtime key capture
  dbkey_hook.py            frida vtable hook → dump per-db 32B enc_keys (admin shell required)
  dbkey_scan.py            memory page-scanner for key hunting (fallback)
  imgkey_scan.py           memory scan for the 16-ascii image AES key
export/
  decrypt_grid.py          captured 32B values × all .db — page-1 HMAC verification (fast, no PBKDF2)
  chat2html.py             single-chat HTML renderer: dates/senders/quotes/images/emoji/video
  export_book.py           bulk exporter (all chats → per-chat HTML/EPUB)
tools/
  emoji_from_memory.py     recover no-cdnurl stickers from live render-process memory (wxgf→GIF)
binder/
  sqlcipher.py             SQLCipher4 page decryptor + WAL merge
  messages.py              message-table helpers
  epubgen.py               EPUB builder
  emoji_map.py             emoji-code → unicode
  sm4.py                   SM4 block cipher (reference)
```

## Full tutorial: [docs/method.md](docs/method.md)

## Quick start

```bash
pip install pycryptodome zstandard psutil frida-tools

# 1) key capture (admin shell, WeChat running/vector hooking)
python keys/dbkey_hook.py          # dumps to vtslot2/ while you use WeChat normally

# 2) match keys → databases, decrypt
python export/decrypt_grid.py      # direct page-1 HMAC; keys that verify decrypt the db

# 3) render any single chat
set WX2HTML_ROOT=...
set WX2HTML_IMGKEY=image_key.txt   # 16-ascii image key captured from process memory
python export/chat2html.py "聊天名" [起始日期 YYYY-MM-DD] [结束日期]
```

## Method summary

### Database layer
- WeChat 4.1.x = **standard SQLCipher 4**: AES-256-CBC + HMAC-SHA512, 4096-page,
  reserve 80; page1 = `[salt16][ct4000][IV16][HMAC64]@4016/4032`.
- Per-db enc_key (32B) never appears on disk; it exists only in memory while WCDB
  runs. Hook the WCDB **cipher vtable** (16 slots) — slots 5/7 pass the per-db
  derived enc_key as `arg2` — and dump `args[1]/args[2]` (4096 B buffers).
- **Verify with direct page-1 HMAC** (fast). Don't PBKDF2-derive per candidate;
  the dumps already hold derived keys.

### Media layer
- Images: `.dat` V2 format `[6B sig][aes_size][xor_size][pad][AES-128-ECB][raw][XOR tail]`,
  XOR key = **0x9A, account-level constant**; wxgf = HEVC container → ffmpeg first frame.
- Emoji (type 47): XML carries a **no-auth Tencent CDN direct link** (`cdnurl`);
  download directly, skip the locally AES-encrypted cache. Stickers WITHOUT a
  cdnurl (raw type=2 sends) decrypt only at display time — catch the **wxgf (HEVC)
  stream in the render process memory** and re-pack frames into a GIF:
  `python tools/emoji_from_memory.py` (sticker must be visible/animating on screen).
- Videos (type 43): **plaintext mp4** on disk; copy next to the HTML and use a
  relative `src` (Chrome blocks `file:///` video from a data-URI page).
- Message `local_type` is 64-bit packed: real type = `lt & 0x3F`; high bits carry
  appmsg subtype (quote = 57). Content may be zstd-compressed.
- Image mapping: `MessageResourceInfo` (chat via ChatName2Id rowid, packed_info has file
  md5) → `msg/attach/<md5(talker)>/<YYYY-MM>/Img/<md5>.dat`. When the index lags for
  fresh messages, match by **file mtime** (aspect-ratio matching mis-assigns).

## Notes / gotchas

- frida attach requires **admin elevation** (VirtualAllocEx 0x5 otherwise), works on
  live processes — no WeChat restart needed.
- Hooked buffers must be dumped per-slot; frida `send()` only takes a single
  ArrayBuffer per message.
- Verify crypto guesses **by eye** — HEVC/ffmpeg error metrics bury the right key.
- Chinese window titles break naive UI automation; logins were manual.

## License / scope

Personal recovery use. Don't use against accounts you don't own.
