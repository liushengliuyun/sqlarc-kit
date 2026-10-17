"""Hook all 16 cipher vtable slots; capture args+buffers for offline decrypt-slot ID."""
import frida, hashlib, json, os, subprocess, sys, time

SLOTS = [0x592CA50, 0x592CAC0, 0x592CB20, 0x592D050, 0x592CB30, 0x592CB70,
         0x592CCA0, 0x592CD40, 0x592CE70, 0x592CE90, 0x592CEA0, 0x592CEB0,
         0x592CEC0, 0x592CF10, 0x592CF20, 0x592CF30]

JS_TEMPLATE = """
var SLOTS = %(slots)s;
var n = 0;
function init() {
    var m = Process.findModuleByName('Weixin.dll');
    if (!m) { setTimeout(init, 100); return; }
    SLOTS.forEach(function (rva, si) {
        Interceptor.attach(m.base.add(rva), {
            onEnter: function (args) {
                if (n >= 100000) return;
                this.k = ++n;
                var a = [];
                for (var i = 0; i < 4; i++) {
                    try { a.push(args[i].toString()); } catch (e) { a.push('?'); }
                }
                send({type: 'meta', slot: si, k: this.k, args: a});
                // dump buffers at args[1] and args[2] (enter)
                for (var ai = 1; ai <= 2; ai++) {
                    (function (slot, k, argidx) {
                        try {
                            send({type: 'buf', slot: slot, k: k, arg: argidx, ph: 'in'},
                                 args[argidx].readByteArray(4096));
                        } catch (e) {}
                    })(si, this.k, ai);
                }
            },
            onLeave: function (r) {
                if (!this.k) return;
                var self = this;
                for (var ai = 1; ai <= 2; ai++) {
                    (function (slot, k, argidx) {
                        try {
                            send({type: 'buf', slot: slot, k: k, arg: argidx, ph: 'out'},
                                 self.context.rcx ? Memory.readByteArray(ptr('%(arg1)s'), 0) : null);
                        } catch (e) {}
                    })(si, this.k, ai);
                }
            }
        });
    });
    send({type: 'note', msg: 'all slots hooked'});
}
init();
"""
# NOTE: onLeave buffer re-read needs saved arg pointers; simpler: save them in onEnter via this.*
JS = """
var SLOTS = %(slots)s;
var n = 0;
function init() {
    var m = Process.findModuleByName('Weixin.dll');
    if (!m) { setTimeout(init, 100); return; }
    SLOTS.forEach(function (rva, si) {
        Interceptor.attach(m.base.add(rva), {
            onEnter: function (args) {
                if (n >= 100000) return;
                n++;
                this.k = n;
                this.si = si;
                this.p1 = args[1];
                this.p2 = args[2];
                var a = [];
                for (var i = 0; i < 4; i++) {
                    try { a.push(args[i].toString()); } catch (e) { a.push('?'); }
                }
                send({type: 'meta', slot: si, k: this.k, args: a});
                var self = this;
                [1, 2].forEach(function (ai) {
                    var p = ai === 1 ? self.p1 : self.p2;
                    try {
                        send({type: 'buf', slot: self.si, k: self.k, arg: ai, ph: 'in'},
                             p.readByteArray(4096));
                    } catch (e) {}
                });
            },
            onLeave: function (r) {
                if (!this.k) return;
                var self = this;
                [1, 2].forEach(function (ai) {
                    var p = ai === 1 ? self.p1 : self.p2;
                    try {
                        send({type: 'buf', slot: self.si, k: self.k, arg: ai, ph: 'out'},
                             p.readByteArray(4096));
                    } catch (e) {}
                });
                send({type: 'ret', slot: this.si, k: this.k, ret: this.returnValue.toInt32()});
            }
        });
    });
    send({type: 'note', msg: 'all slots hooked'});
}
init();
"""

JS = JS % {"slots": json.dumps(SLOTS), "cap": 100000}

OUTD = r"C:\Users\__USER__\wechat2epub\vtslot2"
os.makedirs(OUTD, exist_ok=True)
count = [0]

def on_msg(m, d):
    if m.get("type") != "send":
        return
    p = m["payload"]
    t = p.get("type")
    if t == "note":
        print("[*]", p["msg"], flush=True)
    elif t == "meta":
        count[0] += 1
        if count[0] <= 10 or count[0] % 200 == 0:
            print("[#%d] slot %d args=%s" % (p["k"], p["slot"], p["args"]), flush=True)
        with open(os.path.join(OUTD, "meta.jsonl"), "a") as f:
            f.write(json.dumps(p) + "\n")
    elif t == "buf":
        data = bytes(d) if d else b""
        fn = os.path.join(OUTD, "s%02d_k%05d_a%d_%s.bin" % (p["slot"], p["k"], p["arg"], p["ph"]))
        open(fn, "wb").write(data)
    elif t == "ret":
        with open(os.path.join(OUTD, "meta.jsonl"), "a") as f:
            f.write(json.dumps(p) + "\n")

def weixin_pids():
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True).stdout
    return [int(l.split('","')[1].strip('"')) for l in out.splitlines() if "Weixin" in l]

def main():
    armed = set()
    t0 = time.time()
    while time.time() - t0 < 14400:
        for pid in set(weixin_pids()) - armed:
            armed.add(pid)
            try:
                s = frida.attach(pid)
                sc = s.create_script(JS)
                sc.on("message", on_msg)
                sc.load()
                print("[*] attached", pid, flush=True)
            except Exception as e:
                print("attach %d: %s" % (pid, str(e)[:50]), flush=True)
        time.sleep(1)

main()
