import socket
from datetime import datetime
from threading import Thread


suck = socket.socket()

name = input('Enter your name: ')
server_ip = input('Server ip: ')
server_port = int(input('Server port: '))

suck.connect((server_ip, server_port))

def lis_mess():
    mess = suck.recv(1024).decode()
    print(mess)

t = Thread(target=lis_mess)

t.daemon = True
t.start()

while True:
    to_send = input('Enter message to send: ')
    if to_send == '/quit':
        break
    datanow = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    to_send = (f'[{datanow}]{name}: {to_send}')
    suck.send(to_send.encode())

suck.close()



