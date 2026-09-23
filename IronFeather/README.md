# Holmes CTF 2026 — Sherlock 07 "Iron Feather"

## 1. TL;DR

The extracted PX4 flight-controller image (`px4`) and the two files it generates, `dataman.encrypted` (mission/waypoint data) and `flight.ulg.encrypted` (flight logs), are protected by a custom `PX4DMENC` container format using **AES-256-GCM**. The AES key is not stored directly. Instead, it is dynamically generated at runtime via a specific 32-bit mixing algorithm (comprising 384 rounds of computation and seeded with a file-specific salt). This algorithm expands the data into a 104-byte pseudo-passphrase, which is then processed using **PBKDF2-HMAC-SHA256** (with 8,192 iterations) to produce the final 32-byte key. By modifying the dynamic flags of the stripped PIE binary and using `dlopen()` to directly invoke the key derivation function, the key can be extracted, enabling the decryption and GCM integrity verification of the aforementioned files. Analysis of the `dataman` file revealed a mission consisting of 24 entries (stored in bank 0), with the 10th entry designated to trigger a payload release command (`MAV_CMD_DO_SET_ACTUATOR`). The decrypted `.ulg` flight log shows that the drone took off and released its payload mid-flight; after traveling between 224 and 277 meters, it received a forged `MAV_CMD_INJECT_FAILURE` command, causing the motors to stop and the drone to crash at 51.5017° N, 0.1621° W (just a stone's throw from Knightsbridge), where it was manually disarmed nine seconds after impact.

---

## 2. Environment Setup

### 2.1 What You Get

```
IronFeather.zip
├── Holmes CTF 2026 - Sherlock 07 - Mission Vault.pdf   # story
├── px4                                                 # stripped x86-64 PIE ELF (PX4 SITL binary)
├── dataman.encrypted                                   # 1.2 MB — encrypted mission/waypoint store
└── flight.ulg.encrypted                                # 68.8 MB — encrypted ULog flight recording
```

### 2.2 Tooling

```bash
pip install unicorn pycryptodome pyulog pymap3d --break-system-packages
apt-get install -y gcc binutils   # objdump / readelf / gcc for the dlopen harness
```

`px4` is stripped, PIE, and dynamically linked. `objdump -d` and `readelf` are enough to locate the interesting function; actually **running** it natively is the fastest way to recover the key.

---

## 3. Vulnerability / Format Analysis

### 3.1 The Container Format (Q1, Q2)

Both `.encrypted` files share a 60-byte (`0x3C`) header:

```
offset  size  field
0x00    8     magic   "PX4DMENC"
0x08    4     format version
0x0C    4     plaintext length
0x10    16    salt (fed to the KDF)
0x20    12    AES-GCM nonce
0x2C    16    AES-GCM authentication tag
0x3C    …     ciphertext
```

The first 0x2C bytes (magic + version + length + salt + nonce) are used as **AAD** for the GCM tag, so the header can't be tampered with independently of the ciphertext.

> **Q1** `PX4DMENC`  
> **Q2** `AES-256-GCM`

### 3.2 Locating the Custom KDF (Q3)

Both strings `PX4DMENC` cross-references in `px4` land inside `dataman_main`'s decrypt path. Walking the call graph backward from the header-parsing code leads to a small, self-contained function that takes the 16-byte salt and writes a much larger buffer, the actual key-derivation routine — at:

```
RVA 0x170AF0
```

> **Q3** `0x170AF0`

### 3.3 The Custom Mixing Loop (Q4)

Disassembling `0x170AF0` shows an 8×32-bit state array seeded from the salt bytes and mixed with golden-ratio-style constants (`0x9E3779B9`-class add/xor/rotate operations, no table lookups, no branches other than the loop counter). The loop counter is compared against `0x180`:

```
0x180 = 384
```

384 iterations later, the 8×32-bit state is serialized out as a 104-byte "stretched" buffer that stands in for a human passphrase.

> **Q4** `384`

### 3.4 The Standard KDF Wrapping It (Q5)

The 104-byte stretched buffer produced by the custom loop is _not_ used as the AES key directly. It is fed as the password into:

```
PBKDF2-HMAC-SHA256(password = 104-byte stretched buffer,
                    salt     = header salt (16 bytes),
                    iterations = 8192,
                    dklen      = 32)
```

> **Q5** `PBKDF2-HMAC-SHA256`

### 3.5 Recovering the Key Without Reimplementing the Mixer (Q6)

Rather than hand-porting the 384-round mixing loop, the fastest path is to **call the real function**. `px4` is a PIE binary marked `DF_1_PIE` in `DT_FLAGS_1`, which stops the loader from `dlopen()`-ing it as a plain shared object. Clearing that one flag lets it load like any other `.so`:

```python
# clear DF_1_PIE (0x08000000) in the DT_FLAGS_1 dynamic-section entry
import struct
p = 'px4_lib'
d = bytearray(open(p, 'rb').read())
e_phoff = struct.unpack_from('<Q', d, 0x20)[0]
e_phnum = struct.unpack_from('<H', d, 0x38)[0]
for i in range(e_phnum):
    o = e_phoff + i * 56
    if struct.unpack_from('<I', d, o)[0] == 2:          # PT_DYNAMIC
        off, sz = struct.unpack_from('<QQ', d, o + 8)[0], struct.unpack_from('<Q', d, o + 32)[0]
        for j in range(0, sz, 16):
            tag, val = struct.unpack_from('<QQ', d, off + j)
            if tag == 0x6ffffffb:                        # DT_FLAGS_1
                struct.pack_into('<Q', d, off + j + 8, val & ~0x08000000)
open(p, 'wb').write(d)
```

A tiny C harness then `dlopen()`s the patched library and calls straight into `RVA 0x170AF0`:

```c
typedef int (*fn_t)(const unsigned char*, unsigned char*);
void *h = dlopen("./px4_lib", RTLD_NOW | RTLD_LOCAL);
struct link_map *lm;
dlinfo(h, RTLD_DI_LINKMAP, &lm);
fn_t f = (fn_t)((char*)lm->l_addr + 0x170AF0);
unsigned char salt[16] = { /* 16 bytes from the .encrypted header */ };
unsigned char key[32];
f(salt, key);
```

Running it against `dataman.encrypted`'s header salt (`60c200309e3f464c11d14645a355bfe8`) yields:

```
a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce
```

Feeding that key into AES-256-GCM with the header's nonce/AAD/tag decrypts and **verifies** both `dataman.encrypted` and `flight.ulg.encrypted` (they share the same underlying secret).

> **Q6** `a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce`

```python
from Crypto.Cipher import AES
key = bytes.fromhex("a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce")
for f in ("dataman.encrypted", "flight.ulg.encrypted"):
    d = open(f, "rb").read()
    aad, nonce, tag, ct = d[:0x2c], d[0x20:0x2c], d[0x2c:0x3c], d[0x3c:]
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    c.update(aad)
    pt = c.decrypt_and_verify(ct, tag)          # raises on tamper, succeeds here
    open(f.replace(".encrypted", ""), "wb").write(pt)
```

### 3.6 Parsing the Mission Store (Q7, Q8, Q9)

`dataman` is PX4's flat key/value store. Each dataman "key" has a fixed per-item record size; scanning for the non-zero regions of the decrypted file shows three populated tables, with the mission-items table living at offset `0x2118` as 60-byte records (4-byte length prefix + 56-byte `mission_item_s`):

```python
import struct
d = open("dataman", "rb").read()
for i in range(24):
    o = 0x2118 + i * 60
    sz = struct.unpack_from("<I", d, o)[0]
    lat, lon = struct.unpack_from("<dd", d, o + 4)
    nav_cmd  = struct.unpack_from("<f", d, o + 4 + 16)[0]
    print(i, sz, round(lat, 7), round(lon, 7), nav_cmd)
```

PX4 stores two mission "banks" (`DM_KEY_WAYPOINTS_OFFBOARD_0` / `_1`); the mission-state record (a separate 40-byte entry elsewhere in the file) records which bank is active and how many items it holds. Bank **0** is active, holding **24** items.

> **Q7** `0`  
> **Q8** `24`

Item 10 is the only item whose command is `MAV_CMD_DO_SET_ACTUATOR` with `param1 = 1` — the PX4 idiom for firing a gripper/servo release.

> **Q9** `10`

### 3.7 The Planned Landing Point (Q10)

Item 23 (the last item, `MAV_CMD_NAV_LAND`) stores the same coordinates as the takeoff point — the mission was designed to return the drone home.

> **Q10** `51.49970,-0.16080`

### 3.8 Reading the Flight Log (Q11–Q17)

`flight.ulg` is a standard PX4 ULog; `pyulog` decodes it directly:

```python
from pyulog import ULog
u = ULog("flight.ulg", ["vehicle_global_position", "vehicle_local_position",
                         "vehicle_land_detected", "actuator_armed",
                         "gripper", "vehicle_command", "distance_sensor",
                         "vehicle_acceleration"])
D = {d.name: d.data for d in u.data_list}
```

**Takeoff point.** `vehicle_land_detected.landed` flips `1 → 0` at `t = 287.072 s`; the estimated global position at that exact instant is the takeoff fix.

> **Q11** `51.4996987,-0.1607999`

**Payload release position.** The `gripper` topic's release command lands at `t = 446.656 s`, matching mission item 10 executing; `vehicle_global_position` at that instant:

> **Q12** `51.5035602,-0.1608417`

**The injected command.** `vehicle_command` logs a `MAV_CMD_INJECT_FAILURE` (command id 420) at `t = 520.764 s` with `from_external = true`, `param1 = 101` (motor subsystem) and `param2 = 1` (off) — a spoofed MAVLink message, not anything the mission or the autopilot's own failsafe logic issued.

> **Q13** `MAV_CMD_INJECT_FAILURE`

**Distance traveled between the two events.** Integrating the horizontal path length of `vehicle_local_position` between the release timestamp (446.656 s) and the injection timestamp (520.764 s):

> **Q14** `277` m

**Crash site.** `distance_sensor.current_distance` crosses zero at `t ≈ 525.84 s`, coincident with a large spike in `vehicle_acceleration` — the true moment of ground impact, well before the debounced `vehicle_land_detected.landed` flag catches up ~50 s later. Reading `vehicle_global_position` at that exact instant (not the debounced "landed" timestamp) gives the crash coordinates:

> **Q15** `51.5016938,-0.1620929`

**Post-crash disarm.** `actuator_armed.armed` flips `1 → 0` at:

> **Q16** `576.968` s

**Nearest road.** Reverse-geocoding the crash coordinates places the wreck on the west side of Hyde Park Corner, directly alongside:

> **Q17** `Knightsbridge`

---

## 4. Attack Method

### Step 1 — Extract the container header fields

```python
d = open("dataman.encrypted", "rb").read(0x3C)
magic, version, ptlen = d[:8], d[8:12], d[12:16]
salt, nonce, tag       = d[0x10:0x20], d[0x20:0x2C], d[0x2C:0x3C]
```

### Step 2 — Locate and neutralize the KDF's PIE restriction

```bash
cp px4 px4_lib
python3 clear_pie_flag.py px4_lib      # see §3.5
gcc -o harness harness.c -ldl
```

### Step 3 — Recover the AES key natively

```bash
./harness   # prints the 32-byte key derived from the dataman salt
```

### Step 4 — Decrypt both files with AES-256-GCM

```bash
python3 decrypt_both.py   # see §3.5
```

### Step 5 — Parse the mission store

```bash
python3 parse_dataman.py   # walks the 60-byte mission_item_s records at 0x2118
```

### Step 6 — Parse the flight log with pyulog

```bash
python3 analyze_flight.py  # extracts takeoff, release, injection, crash, disarm events
```

### Step 7 — Reverse-geocode the crash site

```bash
# any mapping/geocoding service against 51.5016938, -0.1620929
```

---

## 5. Full Exploit

|Q|Topic|Answer|
|---|---|---|
|Q1|Encrypted datastore magic|`PX4DMENC`|
|Q2|Authenticated encryption algorithm|`AES-256-GCM`|
|Q3|RVA of the custom key-derivation function|`0x170AF0`|
|Q4|Rounds in the custom 32-bit mixing loop|`384`|
|Q5|Standard KDF that produces the AES key|`PBKDF2-HMAC-SHA256`|
|Q6|AES-256 key for the supplied image|`a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce`|
|Q7|Active PX4 mission bank|`0`|
|Q8|Mission items in the active bank|`24`|
|Q9|Mission item that triggers payload release|`10`|
|Q10|Planned landing point|`51.49970,-0.16080`|
|Q11|Takeoff point|`51.4996987,-0.1607999`|
|Q12|Position when payload release was triggered|`51.5035602,-0.1608417`|
|Q13|Injected MAVLink command|`MAV_CMD_INJECT_FAILURE`|
|Q14|Distance traveled, release → injection|`277` m|
|Q15|Crash site|`51.5016938,-0.1620929`|
|Q16|Disarm time after crash|`576.968` s|
|Q17|Nearest road to the crash site|`Knightsbridge`|