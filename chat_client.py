#!/usr/bin/env python
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from chat_common import *
import os
import sys

msg_to_send = ""
messages = []

"Receiving message"
def receive():
    while True:
        try:
            "The max size of the message 1024 byte (?)"
            msg = client_socket.recv(BUFSIZ).decode("utf8")
            "Add the message to the list"
            messages.append(msg)
            print_messages()
        except OSError:
            break

"Send message"
def send(msg, event=None):
    "We send the message using the socket which"
    "is connected to one of the server's sockets"
    client_socket.send(bytes(msg, "utf8"))
    "Quit scenario"
    if msg == "{quit}":
        client_socket.close()
        

def print_messages():
    os.system('cls')
    for msg in messages:
        print(msg)

"Application startup requires the user to type in the server's address and port"
HOST = input('Enter host: ')
PORT = input('Enter port: ')
if not PORT:
    PORT = 33000  # Default value.
else:
    PORT = int(PORT)
BUFSIZ = 1024
ADDR = (HOST, PORT)
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)
os.system('cls')
receive_thread = Thread(target=receive)
receive_thread.start()

"Client loop -> if there's an input, send it"
while True:
    msg_to_send = input()
    if (msg_to_send != ''):
        send(msg_to_send)
        if (msg_to_send == "{quit}"):
            break
        else:
            msg_to_send = ""
