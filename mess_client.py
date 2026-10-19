import os
import socket
from datetime import datetime
from threading import Thread


suck = socket.socket()

name = input('Enter your name: ')
server_ip = input('Server ip: ')
server_port = int(input('Server port: '))

suck.connect((server_ip, server_port))


def lis_mess():
    # Messages are separated by '\n', makefile() puts split chunks back together
    reader = suck.makefile('r', encoding='utf-8', errors='replace')
    try:
        for line in reader:
            print(line.rstrip('\n'))
    except OSError:
        return
    print('Disconnected from server')
    os._exit(0)


t = Thread(target=lis_mess)
t.daemon = True
t.start()

try:
    while True:
        to_send = input('Enter message to send: ')
        if to_send == '/quit':
            break
        if not to_send:
            continue
        datanow = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        to_send = f'[{datanow}]{name}: {to_send}\n'
        suck.sendall(to_send.encode())
except (EOFError, KeyboardInterrupt, OSError):
    pass
finally:
    suck.close()
