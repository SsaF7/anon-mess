import json
import socket
import uuid
from collections import deque
from datetime import datetime
from threading import Thread, Lock


SEEN_LIMIT = 10000

node_id = uuid.uuid4().hex

name = input('Enter your name: ')
local_port = int(input('Your port: '))
first_peer = input('Peer ip:port (empty if you are the first): ').strip()

peers = {}            # node id -> Peer
connecting = set()    # node ids we are connecting to right now
peers_lock = Lock()

seen = set()          # ids of messages we already got
seen_order = deque()
seen_lock = Lock()


class Peer:
    def __init__(self, sock, outgoing):
        self.sock = sock
        self.outgoing = outgoing
        self.id = None
        self.name = None
        self.addr = None
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
    return [peer.addr[0], peer.addr[1], peer.id]


def register(peer, packet):
    pid = packet.get('id')
    port = packet.get('port')
    if not isinstance(pid, str) or not isinstance(port, int) or pid == node_id:
        return False

    peer.name = str(packet.get('name', '?'))
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
        known = [peer_info(p) for p in peers.values() if p is not peer]
        others = [p for p in peers.values() if p is not peer]

    if replaced is not None:
        replaced.close()
    else:
        print(f'* {peer.name} {peer.addr[0]}:{peer.addr[1]} joined')

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
    print(f'* {peer.name} left')


def process(peer, packet):
    kind = packet.get('type')
    if kind == 'peers':
        for item in packet.get('peers', []):
            if not isinstance(item, list) or len(item) != 3:
                continue
            ip, port, pid = item
            if not (isinstance(ip, str) and isinstance(port, int) and isinstance(pid, str)):
                continue
            with peers_lock:
                if pid == node_id or pid in peers or pid in connecting:
                    continue
                connecting.add(pid)
            Thread(target=connect, args=(ip, port, pid), daemon=True).start()
    elif kind == 'msg':
        mess_id = packet.get('id')
        fields = (mess_id, packet.get('name'), packet.get('time'), packet.get('text'))
        if not all(isinstance(f, str) for f in fields):
            return
        if not mark_seen(mess_id):
            return
        print(f'[{packet["time"]}]{packet["name"]}: {packet["text"]}')
        # Pass it further, so it reaches nodes we are not connected to
        for p in other_peers(exclude=peer):
            p.send(packet)


def handle(peer):
    peer.send({'type': 'hello', 'id': node_id, 'name': name, 'port': local_port})
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
                print(f'* {p.name} {p.addr[0]}:{p.addr[1]}')
            continue
        if not to_send:
            continue
        packet = {
            'type': 'msg',
            'id': uuid.uuid4().hex,
            'name': name,
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'text': to_send,
        }
        mark_seen(packet['id'])
        for p in other_peers():
            p.send(packet)
except (EOFError, KeyboardInterrupt):
    pass
finally:
    listener.close()
    for p in other_peers():
        p.close()
