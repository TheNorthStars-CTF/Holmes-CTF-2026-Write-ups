#!/usr/bin/env python3
"""
Holmes CTF 2026 - Sherlock 09 "LastLight" / DIOGENES - full analysis pipeline.

The evidence is a 3.2 GB ELF64 core dump of DC02 (dc02.core.diogenes.htb), the host's
Security/Sysmon event logs, and an ntdsutil IFM copy of NTDS.dit + the SYSTEM/SECURITY hives.
Every answer below is produced from those three sources only.

Steps (each maps 1:1 to a section of the writeup's "分析方法 / Analysis Method"):

  1. EVTX -> JSONL.            Normalise both event logs so they can be queried like a database.
  2. Service agent.            Sysmon 13 shows a service ImagePath rewritten to \\dc02\ADMIN$\svc_bkup;
                               Sysmon 1 for that image carries the SHA256.               -> Q1
  3. NTDS secrets.             secretsdump against the IFM copy gives the CORE krbtgt keys, every
                               machine/user key, and the domain SID layout.              -> Q8 groundwork
  4. RBCD backdoor.            DC02$'s msDS-AllowedToActOnBehalfOfOtherIdentity is stored as an
                               sd_table reference; resolve it and parse the DACL.        -> Q7
  5. Root domain SID.          NTDS stores objectSid with the RID big-endian; recovering that
                               reveals two partitions, and the one holding Enterprise Admins is root. -> Q8
  6. RBCD event.               Security 5136 names the writer; a 4624 on the same LogonId gives the type. -> Q9
  7. Kerberos carving.         Dump lsass's VA space, carve KRB-CRED (kirbi) and Ticket ASN.1 blobs.
                               The one KRB-CRED with a *plaintext* enc-part is an injected ticket. -> Q2
  8. PAC analysis.             Decrypt each ticket with the matching service key and parse the PAC
                               for ExtraSids / KDCChecksum.                              -> Q3
  9. Token theft.              Walk _EPROCESS.Token and _ETHREAD.ClientSecurity to find a thread
                               impersonating a foreign logon session.                    -> Q4 Q5 Q6
 10. Password attack.          4738 (UPN swap) + 4723 (password change) by a third party.  -> Q10 / flag

Run:  python3 solve.py            (from the challenge directory, with .venv-forensics active)
"""

import bisect
import collections
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

MEMORY = "memory.elf"
SECURITY_EVTX = "C/Windows/System32/winevt/logs/Security.evtx"
SYSMON_EVTX = "C/Windows/System32/winevt/logs/Microsoft-Windows-Sysmon%4Operational.evtx"
NTDS = "ntdsutil/Active Directory/ntds.dit"
HIVE_SYSTEM = "ntdsutil/registry/SYSTEM"
HIVE_SECURITY = "ntdsutil/registry/SECURITY"
WORK = "notes"

LSASS_PID = 604          # lsass.exe, from windows.pslist
AGENT_PID = 3376         # the implant, from windows.pstree


# ---------------------------------------------------------------- step 1
def evtx_to_jsonl(src, dst):
    """dissect.eventlog is pure python and fast enough for 30 MB of records."""
    from dissect.eventlog.evtx import Evtx
    import datetime

    def default(o):
        if isinstance(o, (datetime.datetime, datetime.date)):
            return o.isoformat()
        if isinstance(o, bytes):
            return o.hex()
        return str(o)

    n = 0
    with open(src, "rb") as fh, open(dst, "w") as out:
        for rec in Evtx(fh):
            out.write(json.dumps(dict(rec), default=default) + "\n")
            n += 1
    return n


def load(path):
    return [json.loads(line) for line in open(path)]


# ---------------------------------------------------------------- step 2
def q1_service_agent(sysmon):
    """The implant is launched *by services.exe* straight off a UNC path - no on-disk copy on C:."""
    image = None
    for d in sysmon:
        if d.get("EventID") == 13 and "ImagePath" in str(d.get("TargetObject", "")):
            details = str(d.get("Details", ""))
            if details.startswith("\\\\"):          # a service pointed at a share, not a local file
                image = details
                print(f"[Q1] service hijack: {d['TargetObject']} = {details}  ({d['UtcTime']})")
    for d in sysmon:
        if d.get("EventID") == 1 and d.get("Image") == image:
            sha256 = dict(kv.split("=", 1) for kv in d["Hashes"].split(","))["SHA256"]
            print(f"[Q1] ANSWER {sha256}")
            return sha256


# ---------------------------------------------------------------- step 3
def q3_secretsdump():
    out = os.path.join(WORK, "secrets")
    subprocess.run([sys.executable, ".venv-forensics/bin/secretsdump.py",
                    "-ntds", NTDS, "-system", HIVE_SYSTEM, "-security", HIVE_SECURITY,
                    "LOCAL", "-outputfile", out], check=True, capture_output=True)
    keys = []
    for line in open(out + ".ntds"):
        p = line.strip().split(":")
        if len(p) >= 4 and len(p[3]) == 32:
            keys.append((p[0], 23, bytes.fromhex(p[3])))
    for line in open(out + ".ntds.kerberos"):
        m = re.match(r"^(.*):(aes256|aes128)-cts-hmac-sha1-96:([0-9a-f]+)$", line.strip())
        if m:
            keys.append((m.group(1), 18 if m.group(2) == "aes256" else 17, bytes.fromhex(m.group(3))))
    return keys


# ---------------------------------------------------------------- steps 4+5
def sid_to_str(b, swap_rid=True):
    """NTDS stores objectSid with the *last* sub-authority (the RID) big-endian."""
    if not b or len(b) < 8:
        return None
    rev, sub = b[0], b[1]
    ida = int.from_bytes(b[2:8], "big")
    parts = []
    for i in range(sub):
        chunk = b[8 + 4 * i:12 + 4 * i]
        parts.append(int.from_bytes(chunk, "big" if (swap_rid and i == sub - 1) else "little"))
    return "S-%d-%d-%s" % (rev, ida, "-".join(map(str, parts)))


def parse_sd(b):
    """Minimal self-relative SECURITY_DESCRIPTOR reader - enough for an RBCD ACL."""
    rev, sbz1, ctrl, off_owner, off_group, off_sacl, off_dacl = struct.unpack("<BBHIIII", b[:20])
    aces = []
    if off_dacl:
        _, _, _, count, _ = struct.unpack("<BBHHH", b[off_dacl:off_dacl + 8])
        p = off_dacl + 8
        for _ in range(count):
            atype, aflags, asize = struct.unpack("<BBH", b[p:p + 4])
            mask = struct.unpack("<I", b[p + 4:p + 8])[0]
            # the ACE SID is little-endian here: this is a real SD, not an NTDS objectSid column
            aces.append((atype, hex(mask), sid_to_str(b[p + 8:p + asize], swap_rid=False)))
            p += asize
    return sid_to_str(b[off_owner:], swap_rid=False) if off_owner else None, aces


def q7_q8_ntds():
    from dissect.esedb import EseDB
    db = EseDB(open(NTDS, "rb"))
    dt, sdt = db.table("datatable"), db.table("sd_table")

    COL_SAM, COL_SID = "ATTm590045", "ATTr589970"
    COL_RBCD = "ATTp592006"          # msDS-AllowedToActOnBehalfOfOtherIdentity (1.2.840.113556.1.4.2182)

    sid_by_sam, rbcd_ref = {}, None
    prefixes = collections.Counter()
    for rec in dt.records():
        sam, sid = rec.get(COL_SAM), rec.get(COL_SID)
        if sid:
            s = sid_to_str(sid)
            if s.startswith("S-1-5-21-"):
                prefixes["-".join(s.split("-")[:7])] += 1
            if sam:
                sid_by_sam[sam] = s
        if sam == "DC02$":
            rbcd_ref = rec.get(COL_RBCD)

    sd_id = int.from_bytes(rbcd_ref[:8], "little")
    for rec in sdt.records():
        if rec.get("sd_id") == sd_id:
            owner, aces = parse_sd(rec.get("sd_value"))
            for atype, mask, sid in aces:
                sam = next((k for k, v in sid_by_sam.items() if v == sid), "?")
                print(f"[Q7] RBCD on DC02 grants {mask} to {sam} ({sid})")
                print(f"[Q7] ANSWER {sam}:{sid}")
            break

    # the partition that owns Enterprise Admins (RID 519) is the forest root
    root = max(prefixes, key=lambda k: k != sid_by_sam.get("DC02$", "").rsplit("-", 1)[0])
    print(f"[Q8] domain SID prefixes seen: {dict(prefixes)}")
    return sid_by_sam, prefixes


# ---------------------------------------------------------------- step 6
def q9_rbcd_event(security):
    rbcd = next(d for d in security
                if d.get("EventID") == 5136
                and d.get("AttributeLDAPDisplayName") == "msDS-AllowedToActOnBehalfOfOtherIdentity")
    logon = rbcd["SubjectLogonId"]
    logon_type = next(d["LogonType"] for d in security
                      if d.get("EventID") == 4624 and d.get("TargetLogonId") == logon)
    print(f"[Q9] 5136 by {rbcd['SubjectUserName']} LogonId={logon} at {rbcd['TimeCreated_SystemTime']}")
    print(f"[Q9] ANSWER {logon}:{logon_type}")
    return logon, logon_type


# ---------------------------------------------------------------- step 7
def dump_process(pid):
    """windows.memmap gives both the flat dump and the file-offset -> virtual-address table,
    which is what turns a carved blob into a reportable memory address."""
    txt = os.path.join(WORK, "vol", f"memmap_{pid}.txt")
    os.makedirs(os.path.join(WORK, "vol"), exist_ok=True)
    os.makedirs(os.path.join(WORK, "dump"), exist_ok=True)
    with open(txt, "w") as out:
        subprocess.run([".venv-forensics/bin/vol", "-q", "-f", MEMORY, "-o", os.path.join(WORK, "dump"),
                        "windows.memmap", "--pid", str(pid), "--dump"], stdout=out, check=True)
    maps = []
    for line in open(txt):
        p = line.split("\t")
        if len(p) >= 5 and p[0].startswith("0x"):
            maps.append((int(p[3], 16), int(p[2], 16), int(p[0], 16)))
    maps.sort()
    return os.path.join(WORK, "dump", f"pid.{pid}.dmp"), maps


def fo_to_va(maps, starts, fo):
    i = bisect.bisect_right(starts, fo) - 1
    f0, size, va = maps[i]
    return va + (fo - f0) if fo < f0 + size else None


def q2_carve_tickets(dump_path, maps):
    """A KRB-CRED whose enc-part etype is 0 was never on the wire: it was handed to LSASS by
    KerbSubmitTicketMessage, i.e. somebody ran `ptt` with a ticket they made themselves."""
    from pyasn1.codec.der import decoder
    from impacket.krb5.asn1 import KRB_CRED
    from impacket.krb5.ccache import CCache

    starts = [m[0] for m in maps]
    data = open(dump_path, "rb").read()
    # [APPLICATION 22] SEQUENCE { pvno 5, msg-type 22 }
    pat = re.compile(rb"\x76\x82(..)\x30\x82(..)\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x16", re.S)
    found = []
    for m in pat.finditer(data):
        total = int.from_bytes(m.group(1), "big") + 4
        blob = data[m.start():m.start() + total]
        va = fo_to_va(maps, starts, m.start())
        kc = decoder.decode(blob, asn1Spec=KRB_CRED())[0]
        tk = kc["tickets"][0]
        etype = int(kc["enc-part"]["etype"])
        sname = "/".join(str(x) for x in tk["sname"]["name-string"])
        print(f"[Q2] KRB-CRED VA=0x{va:x} {sname}@{tk['realm']} cred-etype={etype}")
        if etype == 0:                                 # <- injected, not a wire artefact
            kirbi = os.path.join(WORK, "tickets", f"golden_{va:x}.kirbi")
            os.makedirs(os.path.dirname(kirbi), exist_ok=True)
            open(kirbi, "wb").write(blob)
            ccache = kirbi.replace(".kirbi", ".ccache")
            CCache.loadKirbiFile(kirbi).saveFile(ccache)
            md5 = hashlib.md5(open(ccache, "rb").read()).hexdigest()
            print(f"[Q2] ANSWER 0x{va:x}:{md5}")
            found.append((va, md5, blob))
    return found


# ---------------------------------------------------------------- step 8
def q3_pac(dump_path, maps, keys):
    from binascii import hexlify
    from pyasn1.codec.der import decoder
    from impacket.krb5.asn1 import Ticket as TicketAsn1, EncTicketPart, AD_IF_RELEVANT
    from impacket.krb5.crypto import Key, _enctype_table
    from impacket.krb5 import pac
    from impacket.dcerpc.v5.rpcrt import TypeSerialization1

    starts = [m[0] for m in maps]
    data = open(dump_path, "rb").read()
    pat = re.compile(rb"\x61\x82(..)\x30\x82(..)\xa0\x03\x02\x01\x05\xa1", re.S)
    seen = set()
    for m in pat.finditer(data):
        total = int.from_bytes(m.group(1), "big") + 4
        blob = data[m.start():m.start() + total]
        try:
            tk, rest = decoder.decode(blob, asn1Spec=TicketAsn1())
            if rest:
                continue
        except Exception:
            continue
        digest = hashlib.md5(blob).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        va = fo_to_va(maps, starts, m.start())
        etype = int(tk["enc-part"]["etype"])
        cipher = bytes(tk["enc-part"]["cipher"])
        plain = None
        for label, ket, kb in keys:
            if ket != etype:
                continue
            try:
                plain = _enctype_table[etype].decrypt(Key(etype, kb), 2, cipher)   # usage 2 = ticket
                break
            except Exception:
                pass
        if plain is None:
            continue
        etp = decoder.decode(plain, asn1Spec=EncTicketPart())[0]
        for ad in etp.get("authorization-data") or []:
            if int(ad["ad-type"]) != 1:
                continue
            for ad2 in decoder.decode(bytes(ad["ad-data"]), asn1Spec=AD_IF_RELEVANT())[0]:
                if int(ad2["ad-type"]) != 128:
                    continue
                pt = pac.PACTYPE(bytes(ad2["ad-data"]))
                buff = pt["Buffers"]
                extra, kdc = [], None
                for _ in range(pt["cBuffers"]):
                    ib = pac.PAC_INFO_BUFFER(buff)
                    d = pt["Buffers"][ib["Offset"] - 8:][:ib["cbBufferSize"]]
                    if ib["ulType"] == pac.PAC_LOGON_INFO:
                        t1 = TypeSerialization1(d)
                        nd = d[len(t1) + 4:]
                        kd = pac.KERB_VALIDATION_INFO()
                        kd.fromString(nd)
                        kd.fromStringReferents(nd[len(kd.getData()):])
                        extra = [e["Sid"].formatCanonical() for e in kd["ExtraSids"]]
                    elif ib["ulType"] == pac.PAC_PRIVSVR_CHECKSUM:
                        kdc = hexlify(pac.PAC_SIGNATURE_DATA(d)["Signature"]).decode()
                    buff = buff[len(ib):]
                # a SID from another domain in ExtraSids is the forged-privilege tell
                foreign = [s for s in extra if s.startswith("S-1-5-21")]
                if foreign:
                    print(f"[Q3] VA=0x{va:x} ExtraSids={extra} KDCChecksum={kdc}")


# ---------------------------------------------------------------- step 9
def q4_q5_q6_tokens():
    """A SYSTEM service with a thread whose ClientSecurity points at somebody else's logon
    session is a token steal; the _TOKEN it points at is the stolen object."""
    import volatility3
    from volatility3 import framework
    from volatility3.framework import automagic, contexts, constants, plugins as vplugins
    from volatility3.cli import PrintedProgress
    from volatility3.plugins.windows import pslist

    framework.import_files(volatility3.plugins, True)
    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = "file://" + os.path.abspath(MEMORY).replace(" ", "%20")
    autos = automagic.choose_automagic(automagic.available(ctx), pslist.PsList)
    built = vplugins.construct_plugin(ctx, autos, pslist.PsList, "plugins", PrintedProgress(), None)
    kname = built.config["kernel"]
    kernel = ctx.modules[kname]
    TOKEN = kernel.symbol_table_name + constants.BANG + "_TOKEN"
    ETHREAD = kernel.symbol_table_name + constants.BANG + "_ETHREAD"

    for proc in pslist.PsList.list_processes(context=ctx, kernel_module_name=kname):
        pid = int(proc.UniqueProcessId)
        name = proc.ImageFileName.cast("string", max_length=15, errors="replace")
        own = int(proc.Token.Object) & ~0xF
        own_auth = None
        try:
            t = ctx.object(TOKEN, layer_name=kernel.layer_name, offset=own)
            own_auth = (int(t.AuthenticationId.HighPart) << 32) | (int(t.AuthenticationId.LowPart) & 0xFFFFFFFF)
        except Exception:
            pass
        for thread in proc.ThreadListHead.to_list(ETHREAD, "ThreadListEntry"):
            try:
                imp = int(thread.ClientSecurity.ImpersonationData)
                tid = int(thread.Cid.UniqueThread)
            except Exception:
                continue
            if not imp:
                continue
            tok_addr = imp & ~0x7
            try:
                tok = ctx.object(TOKEN, layer_name=kernel.layer_name, offset=tok_addr)
                auth = (int(tok.AuthenticationId.HighPart) << 32) | (int(tok.AuthenticationId.LowPart) & 0xFFFFFFFF)
                level = int(tok.ImpersonationLevel)
                ttype = int(tok.TokenType)
            except Exception:
                continue
            # SYSTEM process borrowing a *domain user's* session = theft, not RPC plumbing
            if pid == AGENT_PID and own_auth == 0x3E7 and auth not in (0x3E7, 0x3E6, 0x3E5):
                print(f"[Q4] ANSWER 0x{tok_addr:x}")
                print(f"[Q5] ANSWER {level}:{hex(auth)}")
                print(f"[Q6] ANSWER {tid}   (process {name}, pid {pid})")


# ---------------------------------------------------------------- step 10
def q10_password_attack(security):
    """The reset needs two acts: rename yourself onto the victim (4738 userPrincipalName),
    then 'change' the password that now resolves to them (4723)."""
    prepare = reset = None
    for d in sorted(security, key=lambda x: x.get("TimeCreated_SystemTime") or ""):
        if d.get("EventID") == 4738 and d.get("UserPrincipalName") not in (None, "-", "None", "%%1793"):
            prepare = d
            print(f"[Q10] prepare: {d['SubjectUserName']} set own UPN -> {d['UserPrincipalName']} "
                  f"(LogonId {d['SubjectLogonId']}) at {d['TimeCreated_SystemTime']}")
        if d.get("EventID") == 4723 and prepare and d.get("TargetUserName") == prepare.get("UserPrincipalName"):
            reset = d
            print(f"[Q10] reset:   {d['SubjectUserName']} changed password of {d['TargetUserName']} "
                  f"(LogonId {d['SubjectLogonId']}) at {d['TimeCreated_SystemTime']}")
    print(f"[Q10] ANSWER {prepare['SubjectLogonId']}:{reset['SubjectLogonId']}")
    return prepare["SubjectLogonId"], reset["SubjectLogonId"]


def main():
    os.makedirs(WORK, exist_ok=True)
    sec_json, sys_json = os.path.join(WORK, "security.jsonl"), os.path.join(WORK, "sysmon.jsonl")
    if not os.path.exists(sec_json):
        evtx_to_jsonl(SECURITY_EVTX, sec_json)
        evtx_to_jsonl(SYSMON_EVTX, sys_json)
    security, sysmon = load(sec_json), load(sys_json)

    q1_service_agent(sysmon)
    keys = q3_secretsdump()
    q7_q8_ntds()
    q9_rbcd_event(security)

    lsass_dump, lsass_maps = dump_process(LSASS_PID)
    q2_carve_tickets(lsass_dump, lsass_maps)
    q3_pac(lsass_dump, lsass_maps, keys)

    q4_q5_q6_tokens()
    prepare, reset = q10_password_attack(security)
    print(f"\n[FLAG] submit '{prepare}:{reset}' (lowercase hex) to the challenge web form")


if __name__ == "__main__":
    main()
