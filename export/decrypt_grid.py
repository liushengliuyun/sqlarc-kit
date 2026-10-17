"""Try all captured keys x all dbs, decrypt every one that matches."""
import hashlib, hmac, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sqlcipher as sc

HERE = os.path.dirname(os.path.abspath(__file__))
OUTD = os.path.join(os.path.dirname(HERE), "decrypted")
os.makedirs(OUTD, exist_ok=True)
DBDIR = os.path.expandvars(r"%USERPROFILE%\Documents\xwechat_files\__WXID___5a3d\db_storage")

SLOT = os.path.join(os.path.dirname(HERE), "vtslot")
keys = set()
for f in os.listdir(SLOT):
    if f.endswith("_in.bin") or f.endswith("_out.bin"):
        d = open(os.path.join(SLOT, f), "rb").read()
        for ln in (32, 16):
            if len(d) >= ln:
                keys.add(d[:ln])
keys = list(keys)
print("keys:", len(keys), flush=True)

ok, fail = [], []
for root, dirs, files in os.walk(DBDIR):
    for fn in files:
        if not fn.endswith(".db") or fn.endswith(("-wal", "-shm")):
            continue
        path = os.path.join(root, fn)
        rel = os.path.relpath(path, DBDIR)
        with open(path, "rb") as fh:
            p1 = fh.read(4096)
        hit = None
        for k in keys:
            if len(k) == 32 and sc.verify_page1_hmac(p1, k):
                hit = (rel, k, "direct32")
                break
        if not hit:
            for k in keys:
                if len(k) != 32:
                    continue
                dk = hashlib.pbkdf2_hmac("sha512", k, p1[:16], 256000, dklen=32)
                if sc.verify_page1_hmac(p1, dk):
                    hit = (rel, dk, "pbkdf2")
                if hit:
                    break
        if not hit:
            fail.append(rel)
            print("%-42s NO KEY" % rel, flush=True)
            continue
        enc_key = hit[1]
        out_path = os.path.join(OUTD, rel.replace(os.sep, "_"))
        n = sc.decrypt_db(path, out_path, enc_key)
        wal = path + "-wal"
        merged = 0
        if os.path.exists(wal):
            frames = sc.decrypt_wal(wal, enc_key)
            merged = sc.merge_wal(out_path, frames)
        print("%-42s KEY OK  %d pages wal+%d" % (rel, n, merged), flush=True)
        ok.append(rel)

print("\nOK=%d FAIL=%d" % (len(ok), len(fail)), flush=True)
