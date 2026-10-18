# Full method — reproducing the pipeline from this repo

This is the complete, step-by-step reproduction guide. Every step maps to a file
in this repo; gaps that used to live only in the author's head are written here.

## 0. Background: what WeChat 4.x encrypts

- Databases under `<account_dir>\db_storage\**\*.db` are **standard SQLCipher 4**:
  AES-256-CBC + HMAC-SHA512, 4096-byte pages, reserve 80.
  Page1 = `[salt16][ct4000][IV16][HMAC64] @4016/4032`; other pages
  `[ct4016][IV16][HMAC64]`.
  HMAC key = `PBKDF2-SHA512(enc_key, salt ^ 0x3a, 2 rounds)`.
- The 32-byte per-db `enc_key` is **PBKDF2(password, db_salt, 256000, 32)** when a
  password existed in older flows — but in 4.1.x the derived key simply travels
  through memory. It never touches disk.
- Images (`.dat`) use a separate AES-128-ECB key (16 **ASCII hex** chars captured
  from process memory) + an account-level XOR constant (0x9A) on the tail.
- Emojis and videos: see media section — emoji needs no local key at all.

## 1. Capture per-db keys (keys/dbkey_hook.py)

Admin shell (required — non-admin frida attach fails with VirtualAllocEx 0x5):

```bash
python keys/dbkey_hook.py
```

- Finds all Weixin.exe processes, attaches frida, waits for `Weixin.dll`.
- Hooks the WCDB **cipher vtable**: 16 member function RVAs (4.1.15.55).
  Slots 5 and 7 receive the per-db derived enc_key as `arg2` (32-byte buffer);
  hooking all 16 and dumping `args[1]/args[2]` (4096 B, cap 100000) covers all.
- Dumps: `vtslot2/s<slot>_k<NNNNN>_a<argidx>_<in|out>.bin` + `meta.jsonl`.
- Keep it running while you use WeChat normally; new connections (new dbs,
  re-logins) produce new keys. 261k dumps captured 22700 unique candidates.

### 1a. If Weixin.dll version differs — finding the vtable again

The 16 RVAs are version-specific. To rediscover them on another build:

1. Copy the installed `Weixin.dll` to disk for safe static analysis.
2. Find the cipher vtable base: search for a `sqlite3IoMethods`/`sqlite3_vfs`
   **xLock/xUnlock-style 16-slot cluster near SQLCipher pragma string refs**
   (`PRAGMA cipher`, `PRAGMA key`) — in 4.1.15.55 it sits at RVA 0x592CA50–0x592D050.
3. Practical shortcut: hook **pragma dispatcher (RVA 0x35D9990 in 4.1.15.55)** —
   its `rcx` reveals the KDF parameter struct `{0, 256000, 2, 16, 32, 16, 1, 256}`;
   nearby code establishes the vtable. Or Stalker-trace code both called when a
   db opens and reading from a vtable address range.
4. Verify candidate: attach all 16 slots, dump, run `decrypt_grid.py` —
   a hit (HMAC ok) confirms you found the right slots.

## 2. Match keys → databases, decrypt (export/decrypt_grid.py)

```bash
python export/decrypt_grid.py
```

- Reads every `*_in.bin`/`*_out.bin` in the slot dir, dedupes 32-byte prefixes,
  and HMAC-verifies page 1 of every db (direct HMAC — fast, thousands/sec;
  don't PBKDF2 each candidate, dumps already hold the derived keys).
- Writes decrypted file to `../decrypted/<rel-with-underscores>.db`,
  decrypts `-wal` and merges frames in.
- Verify: `sqlite3 decrypted/message_message_0.db "select count(*) from sqlite_master"`.

## 3. Image key (keys/imgkey_scan.py)

Scan live Weixin memory for 16-ascii-hex strings; test candidates against a
sample `.dat` (AES-128-ECB decrypt of the header region must yield a
known magic: JPEG/PNG/GIF/RIFF). Save the hit to `image_key.txt`.

## 4. Render any chat (export/chat2html.py)

```bash
# environment knobs
set WX2HTML_ROOT=.                # output root
set WX2HTML_ACCTDIR=wxid_xxxx_xxx # your account dir under xwechat_files
set WX2HTML_IMGKEY=image_key.txt  # 16-ascii image key
set WX2HTML_FFMPEG=ffmpeg         # or full path

python export/chat2html.py "聊天或群名" [开始日期 YYYY-MM-DD] [结束日期]
```

What it does internally:

1. Resolves the talker by nickname/remark from `contact_contact.db`.
2. Builds image map: `MessageResourceInfo` (chat via ChatName2Id rowid,
   packed_info md5) → `msg/attach/<md5(talker)>/<YYYY-MM>/Img/<md5>.dat`;
   decrypts with `v2dec` (V2 header → AES-128-ECB with image key on the
   `aes_size` region → XOR 0x9A on the tail). wxgf = HEVC → ffmpeg first frame.
3. Fallback chain when ResourceInfo lags (fresh messages):
   **file mtime matching** (not aspect ratio — that mis-assigns),
   then `<lid-1>/<lid>/<lid+1>_<ts>_t.dat` local-id thumbnails.
4. Emoji (type 47): reads `md5=` + `cdnurl=` from XML, downloads from Tencent
   CDN with UA "MicroMessenger Client" — no auth needed. Cached in `emoji_out/`.
5. Video (type 43): plaintext mp4 at `msg/video/<YYYY-MM>/<md5>.mp4`; copies to
   `media/` and embeds relative `src` (data-URI pages + `file:///` video is
   blocked by Chrome's origin policy).
6. Emits one HTML: date-chapter TOC, search box, sender names (Name2Id rowid →
   username → contact nick/remark), flat-quote parsing (4.x flattens quote
   messages to `reply view NN flags svrid fromusr chatusr displayname text
   <escaped xml>` — split on `\s+view \d+\s`), share links (title+desc).

## 5. Gotchas that cost real time

- **wxgf blank first frame**: progressive-rendered pics store a blank first HEVC frame in
  the mid-size .dat; the real picture is in `<md5>_h.dat` or in frame 2/3. Decode up to
  3 frames, keep the largest, and CLEAR frame files between messages (stale-cache reuse
  actually displayed the previous message's image).
- **Locally-composed images** never land in msg/attach (nothing is downloaded for images
  you sent from this PC) — the mid-size HEVC copy + `_h.dat` exist locally, but for files
  matching by mtime from the send source dir (~/Pictures) as a fallback.
- **Message write lag**: freshly sent/received messages can take hours to reach the db
  (WAL not checkpointed); a full WeChat exit forces the flush. Re-decrypt after exit.

- frida `send()` takes ONE ArrayBuffer per message (arrays arrive empty).
- GBK console: never print raw binary; hex-prefix only.
- `AppActivate('WeChat')` fails on Chinese titles; login is manual.
- WCDB bypasses user-mode file I/O hooks (direct syscalls) — don't chase ReadFile.
- NtReadFile / ReadFile hooks: zero hits for db reads.
- HEVC/ffmpeg error-count is a bad decrypt oracle; verify crypto guesses by eye.
- Aspect-ratio image matching mis-assigns similar screenshots; use mtime.
- HMAC verify is fast; PBKDF2 per candidate is 0.5 s each — avoid.
