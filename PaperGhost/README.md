# Holmes CTF 2026 — Sherlock 04 "Paper Ghost"

## 1. TL;DR

Junior analyst Clara Voss plugged a USB drive—placed by a contractor posing as IT support (using the alias Elias Venn)—into her desk computer. The drive (asset tag `CO-USB-0091`, serial number `RS200000000627E4&0`) contained an executable disguised as a "driver update package" located at `E:\CO-LT-0469 update package\update.exe`. Believing this to be a routine procedure, Voss executed the program; subsequently, an implant named VON BORK established a command-and-control (C2) connection and utilized microphone and camera APIs to monitor her—recording approximately 2 minutes and 55 seconds of audio and 127 seconds of video—before exfiltrating **172.064531 MB** of data to a riverside relay node. The final flag was not obtained through real-time monitoring but was recovered from an overlooked forensic side-channel: the Windows search index file (`Windows.edb`) had cached an `AutoSummary` snippet of `EXT-0419.pdf`—a DIOGENES contractor document Voss had previously consulted—which exposed a developer's plaintext credentials: `tainsworth:D10g3n3s_T1ck3ts#2026`.


---

## 2. Environment Setup

### 2.1 What You Get

```
PaperGhost.zip
├── Holmes CTF 2026 - Sherlock 04 - The False Employee.pdf   # story
└── PaperGhost/
    └── Triage/                      # KAPE-style triage collection
        ├── ConsoleLog / CopyLog / SkipLog .txt
        └── C/
            ├── Windows/System32/config/       # SAM, SECURITY, SOFTWARE, SYSTEM
            ├── Windows/System32/SRU/           # SRUDB.dat (ESE)
            ├── ProgramData/Microsoft/search/data/applications/windows/  # Windows.edb (ESE)
            └── Users/cvoss/
                ├── NTUSER.DAT
                ├── AppData/Local/Microsoft/Windows/UsrClass.dat
                └── AppData/Roaming/Microsoft/Windows/Recent/
                    ├── *.lnk
                    ├── AutomaticDestinations/*.automaticDestinations-ms
                    └── CustomDestinations/*.customDestinations-ms
```

No live file content (no PDFs, no browser cache, no chat logs) is present, only **registry hives, USB/LNK/JumpList metadata, and SRUM**. Every flag has to be pulled out of side-channel artifacts left behind by those subsystems.

### 2.2 Tooling

```bash
pip install --break-system-packages regipy[full] python-registry \
    LnkParse3 olefile pylnk3 dissect.esedb
```

- **regipy**: SYSTEM / SOFTWARE / SAM / NTUSER / UsrClass hive parsing (USB device tree, UserAssist, CapabilityAccessManager, shellbags)
- **LnkParse3 + olefile**: `.lnk` files and OLE-compound-file JumpLists (`automaticDestinations-ms` / `customDestinations-ms`)
- **dissect.esedb**: pure-Python ESE database reader for `SRUDB.dat` and `Windows.edb`

---

## 3. Vulnerability / Artifact Analysis

### 3.1 The Shape of the Chain

```
Elias Venn (contractor, cover ID EXT-0431 / CO-LT-0431)
└── Drops USB "CO-USB-0091" at Voss's desk
    └── E:\CO-LT-0469 update package\update.exe   ← VON BORK payload
        ├── C2 beacon established
        ├── Microphone capture (meetings)
        ├── Webcam capture (office/desk mapping)
        └── Outbound exfil to riverside relay
Meanwhile: Voss reviews DIOGENES_26\EXT-0419.pdf (contractor file, dev Tom Ainsworth)
            → indexed by Windows Search → AutoSummary caches the credentials in plaintext
```

### 3.2 First USB Connection (Flag 1)

USB device history lives under `SYSTEM\ControlSet001\Enum\USBSTOR`, with the modern DEVPKEY timestamps stored under the `{83da6326-97a6-4088-9453-a1923f573b29}` property GUID (property `0064` = _first install / first connect_):

```python
from regipy.registry import RegistryHive
hive = RegistryHive('SYSTEM')
hive.get_key(
    'ROOT\\ControlSet001\\Enum\\USBSTOR\\'
    'Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00\\'
    'RS200000000627E4&0\\Properties\\'
    '{83da6326-97a6-4088-9453-a1923f573b29}\\0064'
)
# (default) = 2026-08-19 15:35:50.428692+00:00
```

> **Flag 1** `2026-08-19 15:35:50`

### 3.3 The Serial Number (Flag 2)

The serial number is the registry key **name itself**, taken as a whole, found under `SYSTEM\ControlSet001\Enum\USBSTOR`:

```
HKLM\SYSTEM\ControlSet001\Enum\USBSTOR\
    Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00\
        RS200000000627E4&0
```

This is cross-referenced by the raw DEVPKEY instance ID (`000A`), which carries the un-suffixed form reported by the USB descriptor itself:

```
USB\VID_21C4&PID_0CD1\RS200000000627E4
```

> **Flag 2** `RS200000000627E4&0`

### 3.4 The Fake Update Package (Flag 3, Flag 4)

`NTUSER.DAT`'s **UserAssist** key (`{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`) ROT13-encodes every GUI-launched executable path plus a Win7+ binary blob with run count and last-run FILETIME at offset 60:

```python
import struct, datetime
raw = bytes.fromhex(
    "00000000010000000000000000000000000080bf000080bf000080bf000080bf"
    "000080bf000080bf000080bf000080bf000080bf000080bfffffffff90b5cd7ef02fdd0100000000"
)
run_count = struct.unpack('<I', raw[4:8])[0]                 # 1
last_run  = struct.unpack('<Q', raw[60:68])[0]                # FILETIME
EPOCH, HNS = 116444736000000000, 10000000
print(datetime.datetime(1970,1,1) + datetime.timedelta(
    microseconds=(last_run-EPOCH)/10))
# 2026-08-19 15:36:25.705000
```

The decoded (ROT13) value name is:

```
E:\CO-LT-0469 update package\update.exe
```

This is independently confirmed by the SRUM **`SruDbIdMapTable`**, which resolves the app-usage AppId to a full NT device path:

```
\Device\HarddiskVolume5\CO-LT-0469 update package\update.exe
```

> **Flag 3** `E:\CO-LT-0469 update package\update.exe` 
> **Flag 4** `2026-08-19 15:36:25`

### 3.5 The DIOGENES Asset Tag (Flag 5)

The generic USBSTOR `FriendlyName` just reads _"Lexar USB Flash Drive USB Device"_ — not the internal asset tag. The corporate-assigned name surfaces one layer up, under the **WPDBUSENUM** device node (the "Windows Portable Devices" enumerator, which is what actually drives the label Explorer shows on connection):

```python
hive.get_key(
    'ROOT\\ControlSet001\\Enum\\SWD\\WPDBUSENUM\\'
    '...RS200000000627E4...\\FriendlyName'
)
# CO-USB-0091
```

This matches the corporate asset-tagging convention seen elsewhere in the case (`CO-LT-0469` for the laptop, `CO-LT-0431` for Venn's cover device).

> **Flag 5** `CO-USB-0091`

### 3.6 Microphone Hijack (Flag 6)

Per-app microphone/webcam usage windows are tracked in `NTUSER.DAT` under **CapabilityAccessManager\ConsentStore**, keyed by the _NonPackaged_ full executable path:

```python
hive.get_key(
    'ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\'
    'CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged\\'
    'E:#CO-LT-0469 update package#update.exe'
)
# LastUsedTimeStart = 134316274881131799  → 2026-08-19 15:38:08.113180
# LastUsedTimeStop  = 134316276632589248  → 2026-08-19 15:41:03.258925
```

> **Flag 6** `2026-08-19 15:38:08`

### 3.7 Webcam Office Mapping (Flag 7)

Same consent-store mechanism, `webcam` capability:

```python
cam_start = 134316277486814313   # 2026-08-19 15:42:28.681431
cam_stop  = 134316278756619812   # 2026-08-19 15:44:35.661981
duration_s = (cam_stop - cam_start) / 10_000_000
# 126.9805499
```

> **Flag 7** `≈127` (126.98 s)

### 3.8 Exfiltration Volume (Flag 8)

SRUM's Network Data Usage table (`{973F5D5C-1D90-4944-BE8E-24B94231A174}` in `SRUDB.dat`) records per-app bytes sent/received. Resolving the `AppId` via `SruDbIdMapTable` isolates the row for `update.exe`:

```python
from dissect.esedb import EseDB
db = EseDB(open('SRUDB.dat', 'rb'))
t = db.table('{973F5D5C-1D90-4944-BE8E-24B94231A174}')
for rec in t.records():
    if rec.get('AppId') == 436:      # update.exe, per SruDbIdMapTable
        print(rec.get('BytesSent'))  # 172064531
```

`172,064,531` bytes → `172.064531` **decimal** MB.

> **Flag 8** `172.064531`

### 3.9 The Leaked Credentials (Flag 9)

The critical insight: even though the actual reviewed PDFs (`EXT-0419.pdf`, `IT_SUPPORT.pdf`, `Schedule.pdf`, `Driver Update Package.pdf`) were never collected, **Windows Search indexed their content while Voss had them open**, and cached a snippet in `Windows.edb`'s `SystemIndex_PropertyStore` table under column `4625-System_Search_AutoSummary` — keyed by `WorkID`, joinable to `11-System_FileName`:

```python
from dissect.esedb import EseDB
db = EseDB(open('Windows.edb', 'rb'))
t = db.table('SystemIndex_PropertyStore')
for rec in t.records():
    fn = rec.get('11-System_FileName')
    if fn and fn.lower().endswith('.pdf'):
        print(fn, '->', rec.get('4625-System_Search_AutoSummary'))
```

The `EXT-0419.pdf` row's `AutoSummary` contains the plaintext contractor record for developer **Tom Ainsworth** (DIOGENES ticketing support, contractor ID `EXT-0419`), including his login for `srv-diogenes-tickets-01.internal`:

```
Username: tainsworth
Password: D10g3n3s_T1ck3ts#2026
```

> **Flag 9** `tainsworth:D10g3n3s_T1ck3ts#2026`

---

## 4. Attack / Investigation Method

### Step 1 — Extract and orient

```bash
unzip PaperGhost.zip
find PaperGhost/Triage -type f | sort
```

Confirm the KAPE target set: `RegistryHives`, `LNKFilesAndJumpLists`, `SRUM` — no filesystem/MFT, no PDFs, no browser artifacts.

### Step 2 — USB history (Flags 1, 2, 5)

```python
from regipy.registry import RegistryHive
hive = RegistryHive('SYSTEM')
# walk Enum\USBSTOR for the device node, then its Properties\{83da6326...} subkeys
# walk Enum\SWD\WPDBUSENUM for the WPD FriendlyName (asset tag)
```

### Step 3 — Execution evidence (Flags 3, 4)

```python
hive = RegistryHive('NTUSER.DAT')
# Explorer\UserAssist\{CEBFF5CD-...}\Count → ROT13 decode value names,
# parse the Win7+ 72-byte blob for RunCount (offset 4) and LastRunTime (offset 60)
```

Cross-check against SRUM's `SruDbIdMapTable` for the resolved NT device path.

### Step 4 — Spying window (Flags 6, 7)

```python
hive = RegistryHive('NTUSER.DAT')
# Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\
#   {microphone|webcam}\NonPackaged\<escaped exe path>
# LastUsedTimeStart / LastUsedTimeStop (FILETIME)
```

### Step 5 — Exfil volume (Flag 8)

```python
from dissect.esedb import EseDB
db = EseDB(open('SRUDB.dat','rb'))
# SruDbIdMapTable  → resolve AppId 436/438 to update.exe
# {973F5D5C-1D90-4944-BE8E-24B94231A174} → BytesSent for that AppId
```

### Step 6 — The hidden credential (Flag 9)

```python
from dissect.esedb import EseDB
db = EseDB(open('Windows.edb','rb'))
t = db.table('SystemIndex_PropertyStore')
# join on WorkID: 11-System_FileName + 4625-System_Search_AutoSummary
```

This is the step most write-ups miss — a first pass of `strings`/`grep` across `Windows.edb` only turns up indexed _file paths_ from `SystemIndex_Gthr`, because the full-text index itself (`SystemIndex_1_DATA_XX` / `OCC_XX`) is tokenized, not plaintext. The **AutoSummary** property is the one place Windows Search caches a readable content snippet, and it survives even when the source PDF itself is gone.

---

## 5. Full Exploit / Flag Table

|#|Topic|Artifact Source|Answer|
|---|---|---|---|
|1|First USB connect|`SYSTEM\Enum\USBSTOR\...\Properties\{83da6326...}\0064`|`2026-08-19 15:35:50`|
|2|USB serial number|`SYSTEM\Enum\USBSTOR` instance key name|`RS200000000627E4&0`|
|3|Payload full path|UserAssist (NTUSER) + SRUM `SruDbIdMapTable`|`E:\CO-LT-0469 update package\update.exe`|
|4|Execution timestamp|UserAssist Win7+ blob, offset 60 (FILETIME)|`2026-08-19 15:36:25`|
|5|DIOGENES asset tag|`SYSTEM\Enum\SWD\WPDBUSENUM\...\FriendlyName`|`CO-USB-0091`|
|6|Mic capture start|NTUSER `CapabilityAccessManager\ConsentStore\microphone`|`2026-08-19 15:38:08`|
|7|Webcam stream duration|NTUSER `CapabilityAccessManager\ConsentStore\webcam`|`≈127` seconds|
|8|Exfil volume (decimal MB)|SRUM Network Data Usage table, `BytesSent`|`172.064531`|
|9|Leaked developer credentials|`Windows.edb → SystemIndex_PropertyStore → AutoSummary`|`tainsworth:D10g3n3s_T1ck3ts#2026`|