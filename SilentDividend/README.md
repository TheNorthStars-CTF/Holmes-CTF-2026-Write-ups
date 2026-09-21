# Holmes CTF 2026 — Sherlock 01 "Silent Dividend"

## 1. TL;DR

A malicious Electron application distributed as a Windows NSIS installer ("TrustSettle 1.0.0.exe") targets cryptocurrency wallet holders through a three-pronged attack. First, a LuaJIT FFI backdoor silently monitors `C:\Users\Public\.env` for private key material and exfiltrates it via WinHTTP. Second, a phishing HTML page styled as a Terms of Service agreement tricks the victim into calling `approve(attacker, MaxUint256)` on a fake token contract, granting the attacker unlimited spending authority over their wallet. Third, the Electron preload script fetches a decryption key from an on-chain smart contract (`resolveState()`), decrypts an embedded payload, and executes it — the plaintext being a shell command that both launches the phishing page and leaks the campaign credentials. The final flag is recovered by computing the hidden owner address of a second on-chain contract (`x2 XOR x3`), then calling its view function `x9()` with that address, which streams a keccak256-keyed ciphertext and returns the coordinates `51.5049,0.0348`.

---

## 2. Environment Setup

### 2.1 What You Get

```
SilentDividend.zip
├── Holmes CTF 2026 Sherlock 01.pdf   # story;
├── DANGER.txt                        # warns not to run the binary and gives the zip password
└── danger.zip                        # password-protected
    ├── README.md                     # instructs victim to fill in C:\Users\Public\.env
    └── TrustSettle 1.0.0.exe         # NSIS self-extracting installer, 91 MB
```

The password for `danger.zip` is embedded in the story PDF: `E9$LQ2@Mr7A!`.

### **2.2 Unpacking the Installer**

`TrustSettle 1.0.0.exe` is a Nullsoft NSIS installer. **NEVER** run it, 7-Zip reads NSIS archives directly:

bash

```bash
# Step 1: unpack the NSIS installer
7z x 'TrustSettle 1.0.0.exe'

# Step 2: unpack the Electron bundle
7z x app-64.7z

# Step 3: extract app.asar
npx @electron/asar extract resources/app.asar asar_out
```

After extraction:

```
asar_out/
├── main.js
├── preload.js
├── package.json
├── src/
│   └── settlement.html
└── node_modules/
    └── ethers/
```

### **2.3 Tooling**

bash

```bash
sudo apt install p7zip-full lua5.1
pip install pycryptodome
npm install -g @electron/asar
```

---
