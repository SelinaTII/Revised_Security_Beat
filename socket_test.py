import socket
import threading
import cryptography.exceptions
from primitives import *


def node_1():
    # Sending from 1 to 2
    data = b"a secret message from 1 to 2"
    print('data sent to node 2: ', data)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 6002))
        message = encrypt_response(data, secret_1_2)
        s.sendall(message)

    # Sending from 1 to 3
    data = b"a secret message from 1 to 3"
    print('data sent to node 3: ', data)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 6003))
        message = encrypt_response(data, secret_1_3)
        s.sendall(message)

    # Sending from 1 to 4
    data = b"a secret message from 1 to 4"
    print('data sent to node 4: ', data)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 6004))
        message = encrypt_response(data, secret_1_4)
        s.sendall(message)

def node_2():
    # Open a socket and get data from node 1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('localhost', 6002))
        s.listen(1)
        conn, addr = s.accept()

        message = conn.recv(4096)
        data = decrypt_response(message, secret_1_2)
        print('Decrypted data at node 2: ', data)

def node_3():
    # Open a socket and get data from node 1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('localhost', 6003))
        s.listen(1)
        conn, addr = s.accept()

        message = conn.recv(4096)
        data = decrypt_response(message, secret_1_3)
        print('Decrypted data at node 3: ', data)

def node_4():
    # Open a socket and get data from node 1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('localhost', 6004))
        s.listen(1)
        conn, addr = s.accept()

        message = conn.recv(4096)

        try:
            data = decrypt_response(message, secret_1_2)
            print('Decrypted data at node 4: ', data)

        except cryptography.exceptions.InvalidTag:
            print("Failed")

node_2_thread = threading.Thread(target=node_2, args=())
node_2_thread.start()

node_3_thread = threading.Thread(target=node_3, args=())
node_3_thread.start()

node_4_thread = threading.Thread(target=node_4, args=())
node_4_thread.start()

node_1_thread = threading.Thread(target=node_1, args=())
node_1_thread.start()



