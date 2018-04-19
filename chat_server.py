#!/usr/bin/env python
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from chat_common import *

"We can store the user's names and addresses in these containers"
clients = {}
addresses = {}

"Basic attributes of the server"
HOST = ''
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)
SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

"Handle client connection"
def accept_incoming_connections():
    "We would like to use this method while the server is running"
    "That's why it's an endless loop"
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected!" % client_address)
        client.send(bytes("Greetings from the cave!\nNow type your name and press ENTER!", "utf8"))
        addresses[client] = client_address
        "Asynchronous client handling"
        Thread(target=handle_client, args=(client, )).start()

"Handle client after connection to the server"
def handle_client(client):
    name = client.recv(BUFSIZ).decode("utf8") #The user's name
    welcome = 'Welcome %s! If you ever want to quit, type {quit} to exit' % name
    "We can send message directly to the client"
    client.send(bytes(welcome, "utf8"))
    msg = "%s has joined the chat!" % name
    "Or use this method, to broadcast it to every known (connected) client"
    broadcast(bytes(msg, "utf8"))
    "Store the user's name"
    clients[client] = name
    "This loop handles the messages of this particular client only"
    "The server's always 'listening' to the client -> endless loop"
    while True:
        msg = client.recv(BUFSIZ)
        if msg != bytes("{quit}", "utf8"):
            broadcast(msg, name+": ")
        else:
            "Quit scenario"
            client.send(bytes("{quit}", "utf8"))
            "Closing the socket"
            client.close()
            "Deleting the data of the client from the storage"
            del clients[client]
            broadcast(bytes("%s has left the chat." % name, "utf8"))
            break

"Sending a message to all connected user"
def broadcast(msg, prefix=""):
    for sock in clients:
        sock.send(bytes(prefix, "utf8")+msg)


if __name__ == "__main__":
    SERVER.listen(5)
    print("Waiting for connections...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()