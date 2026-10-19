import socket
from threading import Thread, Lock


local_port = int(input('Enter your port number: '))

socket_clients = set()
clients_lock = Lock()

suck = socket.socket()
suck.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
suck.bind(('0.0.0.0', local_port))
suck.listen(5)
print(f'Server listening on port {local_port}')


def broadcast(mess, sender):
    data = (mess + '\n').encode()
    with clients_lock:
        clients = list(socket_clients)
    for client in clients:
        if client is sender:
            continue
        try:
            client.sendall(data)
        except OSError:
            pass


def listen(client, address):
    # Each message is one line, so recv() splitting a message
    # (or a multibyte UTF-8 character) does not matter
    reader = client.makefile('r', encoding='utf-8', errors='replace')
    try:
        for line in reader:
            mess = line.rstrip('\n')
            if mess:
                broadcast(mess, client)
    except OSError:
        pass
    finally:
        with clients_lock:
            socket_clients.discard(client)
        reader.close()
        client.close()
        print(f'{address} leave')


try:
    while True:
        socket_client, address = suck.accept()
        with clients_lock:
            socket_clients.add(socket_client)
        print(f'{address} connected')
        t = Thread(target=listen, args=(socket_client, address))
        t.daemon = True
        t.start()
except KeyboardInterrupt:
    pass
finally:
    suck.close()
