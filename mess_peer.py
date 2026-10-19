import base64
import hashlib
import json
import os
import socket
import uuid
from collections import deque
from datetime import datetime
from threading import Thread, Lock

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


SEEN_LIMIT = 10000
SIGNED_FIELDS = ('id', 'from', 'sign', 'dh', 'eph', 'nonce', 'ct', 'keys')


def b64e(data):
    return base64.b64encode(data).decode()


def b64d(text):
    return base64.b64decode(text, validate=True)


def raw(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(sign_pub, dh_pub):
    # Node id is the hash of its public keys, so nobody can put
    # their own keys under somebody else's id
    return hashlib.sha256(sign_pub + dh_pub).hexdigest()[:32]


def short(pid):
    return pid[:8]


# A new identity on every start, nothing is saved to disk
sign_key = Ed25519PrivateKey.generate()
dh_key = X25519PrivateKey.generate()
sign_pub = raw(sign_key.public_key())
dh_pub = raw(dh_key.public_key())
node_id = fingerprint(sign_pub, dh_pub)

name = input('Enter your name: ')
local_port = int(input('Your port: '))
first_peer = input('Peer ip:port (empty if you are the first): ').strip()

peers = {}            # node id -> Peer, direct connections
connecting = set()    # node ids we are connecting to right now
keys = {}             # node id -> X25519 public key, who we encrypt messages for
names = {}            # node id -> last name seen in his messages
peers_lock = Lock()

seen = set()          # ids of messages we already got
seen_order = deque()
seen_lock = Lock()


class Peer:
    def __init__(self, sock, outgoing):
        self.sock = sock
        self.outgoing = outgoing
        self.id = None
        self.addr = None
        self.sign = None
        self.dh = None
        self.send_lock = Lock()

    def send(self, packet):
        data = (json.dumps(packet, ensure_ascii=False) + '\n').encode()
        with self.send_lock:
            try:
                self.sock.sendall(data)
            except OSError:
                pass

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


def parse_identity(pid, sign_b64, dh_b64):
    """Return (sign_pub, dh_pub) if these keys really belong to node pid"""
    try:
        sign = b64d(sign_b64)
        dh = b64d(dh_b64)
    except (TypeError, ValueError):
        return None
    if len(sign) != 32 or len(dh) != 32 or fingerprint(sign, dh) != pid:
        return None
    return sign, dh


def remember(pid, dh):
    if pid == node_id:
        return
    with peers_lock:
        keys[pid] = dh


def wrap_key(shared, eph_pub, pid):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub,
                info=b'anon-mess wrap ' + pid.encode())
    return hkdf.derive(shared)


def signed_bytes(packet):
    fields = {k: packet[k] for k in SIGNED_FIELDS}
    return json.dumps(fields, sort_keys=True, separators=(',', ':')).encode()


def seal(text):
    """Encrypt a message for every node we know and sign it"""
    mess_id = uuid.uuid4().hex
    payload = json.dumps({
        'name': name,
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'text': text,
    }, ensure_ascii=False).encode()

    content_key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(content_key).encrypt(nonce, payload, mess_id.encode())

    # A one-time key per message: the content key is wrapped
    # separately for each recipient
    eph = X25519PrivateKey.generate()
    eph_pub = raw(eph.public_key())
    with peers_lock:
        recipients = dict(keys)
    wrapped = {}
    for pid, dh in recipients.items():
        try:
            shared = eph.exchange(X25519PublicKey.from_public_bytes(dh))
        except ValueError:
            continue
        key = wrap_key(shared, eph_pub, pid)
        wrapped[pid] = b64e(ChaCha20Poly1305(key).encrypt(bytes(12), content_key, mess_id.encode()))

    packet = {
        'type': 'msg',
        'id': mess_id,
        'from': node_id,
        'sign': b64e(sign_pub),
        'dh': b64e(dh_pub),
        'eph': b64e(eph_pub),
        'nonce': b64e(nonce),
        'ct': b64e(ct),
        'keys': wrapped,
    }
    packet['sig'] = b64e(sign_key.sign(signed_bytes(packet)))
    return packet


def verify(packet):
    """Return sender keys if the message is signed by its sender"""
    if not all(isinstance(packet.get(k), str) for k in SIGNED_FIELDS + ('sig',) if k != 'keys'):
        return None
    if not isinstance(packet.get('keys'), dict):
        return None
    identity = parse_identity(packet['from'], packet['sign'], packet['dh'])
    if identity is None:
        return None
    try:
        Ed25519PublicKey.from_public_bytes(identity[0]).verify(b64d(packet['sig']), signed_bytes(packet))
    except (InvalidSignature, ValueError):
        return None
    return identity


def unseal(packet):
    """Decrypt a message addressed to us, return its payload or None"""
    wrapped = packet['keys'].get(node_id)
    if not isinstance(wrapped, str):
        return None
    mess_id = packet['id'].encode()
    try:
        shared = dh_key.exchange(X25519PublicKey.from_public_bytes(b64d(packet['eph'])))
        key = wrap_key(shared, b64d(packet['eph']), node_id)
        content_key = ChaCha20Poly1305(key).decrypt(bytes(12), b64d(wrapped), mess_id)
        payload = ChaCha20Poly1305(content_key).decrypt(b64d(packet['nonce']), b64d(packet['ct']), mess_id)
        payload = json.loads(payload)
    except (InvalidTag, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    if not all(isinstance(payload.get(k), str) for k in ('name', 'time', 'text')):
        return None
    return payload


def mark_seen(mess_id):
    with seen_lock:
        if mess_id in seen:
            return False
        seen.add(mess_id)
        seen_order.append(mess_id)
        if len(seen_order) > SEEN_LIMIT:
            seen.discard(seen_order.popleft())
        return True


def other_peers(exclude=None):
    with peers_lock:
        return [p for p in peers.values() if p is not exclude]


def peer_info(peer):
    return [peer.addr[0], peer.addr[1], peer.id, b64e(peer.sign), b64e(peer.dh)]


def register(peer, packet):
    pid = packet.get('id')
    port = packet.get('port')
    if not isinstance(pid, str) or not isinstance(port, int) or pid == node_id:
        return False
    identity = parse_identity(pid, packet.get('sign'), packet.get('dh'))
    if identity is None:
        return False

    peer.sign, peer.dh = identity
    peer.addr = (peer.sock.getpeername()[0], port)
    replaced = None
    with peers_lock:
        connecting.discard(pid)
        old = peers.get(pid)
        if old is not None:
            # Both nodes connected to each other at the same time. Keep the
            # connection opened by the node with the smaller id, the other
            # node makes the same choice
            initiator = node_id if peer.outgoing else pid
            if initiator != min(node_id, pid):
                return False
            replaced = old
        peer.id = pid
        peers[pid] = peer
        keys[pid] = peer.dh
        known = [peer_info(p) for p in peers.values() if p is not peer]
        others = [p for p in peers.values() if p is not peer]

    if replaced is not None:
        replaced.close()
    else:
        print(f'* {short(pid)} {peer.addr[0]}:{peer.addr[1]} joined')

    # The new node learns about everyone we know and everyone learns about it
    peer.send({'type': 'peers', 'peers': known})
    for p in others:
        p.send({'type': 'peers', 'peers': [peer_info(peer)]})
    return True


def unregister(peer):
    with peers_lock:
        if peer.id is None or peers.get(peer.id) is not peer:
            return
        del peers[peer.id]
        keys.pop(peer.id, None)
    print(f'* {names.get(peer.id, "?")} ({short(peer.id)}) left')


def process(peer, packet):
    kind = packet.get('type')
    if kind == 'peers':
        for item in packet.get('peers', []):
            if not isinstance(item, list) or len(item) != 5:
                continue
            ip, port, pid, sign, dh = item
            if not (isinstance(ip, str) and isinstance(port, int) and isinstance(pid, str)):
                continue
            identity = parse_identity(pid, sign, dh)
            if identity is None:
                continue
            remember(pid, identity[1])
            with peers_lock:
                if pid == node_id or pid in peers or pid in connecting:
                    continue
                connecting.add(pid)
            Thread(target=connect, args=(ip, port, pid), daemon=True).start()
    elif kind == 'msg':
        identity = verify(packet)
        if identity is None:
            return
        if not mark_seen(packet['id']):
            return
        sender = packet['from']
        remember(sender, identity[1])
        # Pass it further, so it reaches nodes we are not connected to.
        # They can't read it unless it is encrypted for them
        for p in other_peers(exclude=peer):
            p.send(packet)
        payload = unseal(packet)
        if payload is not None:
            names[sender] = payload['name']
            print(f'[{payload["time"]}]{payload["name"]} ({short(sender)}): {payload["text"]}')


def handle(peer):
    peer.send({'type': 'hello', 'id': node_id, 'sign': b64e(sign_pub),
               'dh': b64e(dh_pub), 'port': local_port})
    reader = peer.sock.makefile('r', encoding='utf-8', errors='replace')
    try:
        for line in reader:
            try:
                packet = json.loads(line)
            except ValueError:
                continue
            if not isinstance(packet, dict):
                continue
            if peer.id is None:
                if packet.get('type') != 'hello' or not register(peer, packet):
                    break
                continue
            process(peer, packet)
    except OSError:
        pass
    finally:
        unregister(peer)
        reader.close()
        peer.close()


def connect(ip, port, pid=None):
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        sock.settimeout(None)
    except OSError as e:
        if pid is None:
            print(f'* Can not connect to {ip}:{port}: {e}')
        with peers_lock:
            connecting.discard(pid)
        return
    peer = Peer(sock, outgoing=True)
    handle(peer)
    with peers_lock:
        connecting.discard(pid)


def accept_loop(listener):
    while True:
        try:
            sock, _ = listener.accept()
        except OSError:
            return
        Thread(target=handle, args=(Peer(sock, outgoing=False),), daemon=True).start()


listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(('0.0.0.0', local_port))
listener.listen(5)
Thread(target=accept_loop, args=(listener,), daemon=True).start()
print(f'Listening on port {local_port}. Commands: /peers, /quit')
print(f'Your fingerprint: {node_id}')

if first_peer:
    ip, _, port = first_peer.rpartition(':')
    Thread(target=connect, args=(ip, int(port)), daemon=True).start()

try:
    while True:
        to_send = input('Enter message to send: ')
        if to_send == '/quit':
            break
        if to_send == '/peers':
            for p in other_peers():
                print(f'* {names.get(p.id, "?")} {p.addr[0]}:{p.addr[1]} {p.id}')
            continue
        if not to_send:
            continue
        packet = seal(to_send)
        if not packet['keys']:
            print('* Nobody to send to')
            continue
        mark_seen(packet['id'])
        for p in other_peers():
            p.send(packet)
except (EOFError, KeyboardInterrupt):
    pass
finally:
    listener.close()
    for p in other_peers():
        p.close()
