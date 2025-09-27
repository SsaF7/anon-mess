import socket
from threading import Thread


hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

local_port = int(input('Enter your port number: '))
print(local_ip)


socket_clients = set()
suck = socket.socket()
suck.bind((local_ip, local_port))

suck.listen(5)


def listen(client):
    while True:
        try:
            mess = suck.recv(1024).decode()
        except Exception as e:
            socket_clients.remove(client)
            print(f'{socket_client} leave')
        else:
            for client in socket_clients:
                suck.send(mess.encode())




while True:
    socket_client,address = suck.accept()
    socket_clients.add(socket_client)
    print(f'{address} connected')
    t = Thread(target=listen, args=(socket_client,))
    t.daemon = True
    t.start()
    if len(socket_clients) == 0:
        break

suck.close()














