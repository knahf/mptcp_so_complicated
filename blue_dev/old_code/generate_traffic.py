from __future__ import print_function

import socket
import threading
import subprocess
import time

PORT = 6792

print()
print('hello world')

def sender(stop_event, port=PORT):
    sock = socket.socket()
    sock.connect((subprocess.check_output(("hostname", "--all-ip-addresses")), port))
    while not stop_event.is_set():
        sock.send(b"blahblahblah\n")
        time.sleep(1.5)
    sock.send(b"bye\n")
    sock.send(b"bye\n")
    sock.send(b"bye\n")

def listener(stop_event, port=PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0',port))
    sock.listen(0)
    connected_sock, addr = sock.accept()
    while not stop_event.is_set():
        connected_sock.recv(1024)


def start_traffic():
    stop_event = threading.Event()
    listen_thread = threading.Thread(target=listener, args=(stop_event,))
    sender_thread = threading.Thread(target=sender, args=(stop_event,))
    listen_thread.start()
    sender_thread.start()
    input("Press enter to stop.")
    stop_event.set()

if __name__ == '__main__':
    start_traffic()