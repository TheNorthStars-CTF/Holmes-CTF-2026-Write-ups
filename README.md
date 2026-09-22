# Holmes CTF 2026 — Write-ups

Write-ups by **TheNorthStars** for Holmes CTF 2026.

This repository contains the complete English write-ups and reproducible solver scripts for the challenges solved by our team member (`letztek` and `threetwoone`).

## Solved Challenges

| # | Challenge | Category / Focus | Final Flag / Outcome | Write-up | Solution Script |
|---|---|---|---|:---:|:---:|
| **Sherlock 01** | **SilentDividend** | Electron/NSIS Reversing, LuaJIT FFI Malware, Win32 API Analysis, Web3 Wallet Phishing | 10/10 flags answered | [Write-up](SilentDividend/README.md) | Not Applicable |
| **Sherlock 03** | **whisper-chain** | XMPP, Prosody, OTR/Crypto, CDX Wayback Forensics | 8/8 flags answered | [Write-up](whisper-chain/README.md) | [`solve.py`](whisper-chain/solve.py) |
| **Sherlock 04** | **PaperGhost** | USB Device Artifacts, SRUM/ESE Analysis, Windows Search Index Recovery | 9/9 flags answered | [Write-up](PaperGhost/README.md) | Not Applicable |
| **Sherlock 05** | **PoisonedBranch** | Software Supply Chain, Linux Auditd, bkcrack Known-Plaintext | `HTB{P0150N3D_BR4NCH_N3V3R_D135}` | [Write-up](PoisonedBranch/README.md) | [`solve.py`](PoisonedBranch/solve.py) |
| **Sherlock 06** | **SilentPassenger** | Android Automotive Forensics, MQTT, Reverse Engineering | 20/20 questions answered | [Write-up](SilentPassenger/README.md) | [`solve.py`](SilentPassenger/solve.py) |
| **Sherlock 09** | **LastLight / DIOGENES** | Active Directory Live Response, Memory Forensics, RBCD | `HTB{3v3n_Th3_F0g_Kn0ws_D10g3n3s}` | [Write-up](LastLight/README.md) | [`solve.py`](LastLight/solve.py) |

---

## Challenge Overviews

### 1. [Sherlock 01: SilentDividend](SilentDividend/README.md)
- **Concept**: A malicious Electron installer delivers a LuaJIT FFI credential stealer, a Web3 token stealing phishing page, and decrypts hidden shell commands using a key obtained from the Sepolia smart contract. A second contract is hidden behind the owner's address obtained through an XOR operation.
- **Key Techniques**: NSIS/asar static unpacking, Lua virtual machine sandbox tracing, Win32 API recovery. Log recording via ffi.cdef, known plaintext ROL8-XOR cipher attack, EIP-55 checksum derivation, and keccak256 stream cipher decryption.

### 2. [Sherlock 03: whisper-chain](whisper-chain/README.md)
- **Concept**: An undercover chat network built on Prosody XMPP with TLS SAN routing, XEP-0077 self-registration, public chat rooms, leaked passwords, PDF author metadata, XEP-0048 bookmark recovery, and PubSub command channels encrypted with OpenSSL AES-CBC.
- **Key Techniques**: In-band XMPP registration, multi-user chat room scraping, Wayback Machine CDX API artifact recovery, PBKDF2 120,000 iteration key derivation.

### 3. [Sherlock 04: PaperGhost](PaperGhost/README.md)
- **Concept**: A junior analyst connected a USB drive—pre-planted by a contractor posing as IT support—thereby triggering the "VON BORK" implant via a counterfeit driver update package. The malware exploited Windows' "capability-consent" API to hijack the microphone and camera and exfiltrated data through a C2 relay; additionally, a forgotten Windows search index cache exposed a developer's plaintext credentials, which originated from a contractor document the analyst had previously accessed.
- **Key Techniques**: USBSTOR/WPDBUSENUM device-history parsing, UserAssist ROT13/FILETIME decoding, JumpList (`automaticDestinations-ms`/`customDestinations-ms`) OLE stream extraction, SRUM (`SRUDB.dat`) ESE table analysis via `dissect.esedb`, CapabilityAccessManager consent-store timeline reconstruction, and Windows Search (`Windows.edb`) `SystemIndex_PropertyStore.AutoSummary` content-cache recovery.

### 4. [Sherlock 05: PoisonedBranch](PoisonedBranch/README.md)
- **Concept**: Supply-chain attack via a poisoned internal Python ticket parser repo dropping a Mettle implant, auditd forensic reconstruction of the attacker's path traversal and operator cookie, and cracking an encrypted zip with `bkcrack` known-plaintext attack.
- **Key Techniques**: Python bytecode/source XOR extraction, Linux auditd command reconstruction, path traversal replay against victim Flask service, ZipCrypto known-plaintext cracking.

### 5. [Sherlock 06: SilentPassenger](SilentPassenger/README.md)
- **Concept**: Forensic investigation of a compromised Android Automotive Head Unit (TOPWAY / Allwinner T3). Tracks a multi-stage backdoor chain delivered over retained MQTT topics into a privileged system app (`TWCore`), decrypting hidden DEX modules, C2 network traffic, and extracting relay GPS coordinates.
- **Key Techniques**: Android priv-app analysis, APK/DEX deobfuscation, custom RSA/AES protocol reversing, binary packet framing & coordinate decryption.

### 6. [Sherlock 09: LastLight / DIOGENES](LastLight/README.md)
- **Concept**: Full intrusion reconstruction from a 3.2 GB Domain Controller memory dump, Sysmon/Security event logs, and an NTDS database. Traces a UPN-spoofing password reset, service implant deployment, token impersonation, Golden Ticket generation, and Resource-Based Constrained Delegation (RBCD) backdoor.
- **Key Techniques**: Volatility 3 kernel object walking (`_TOKEN`, `_ETHREAD`), offline Kerberos ccache ticket carving & PAC decryption via `impacket`, NTDS.dit offline extraction via `dissect.esedb`.

---

## Structure

Each challenge directory contains:
- `README.md`: The complete, standalone English write-up with methodology, command logs, and lessons learned.
- `solve.py`: The standalone Python solution script.
- `screenshots/`: Evidence screenshots captured during analysis (if applicable).
