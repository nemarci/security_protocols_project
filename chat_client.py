#!/usr/bin/env python
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from chat_common import *
import os
import sys


# Reading cryptographic keys
kfile = open('server_signing_pubkey.pem', 'r')
signing_key_str = kfile.read()
kfile.close()
server_public_signkey = RSA.importKey(signing_key_str)
kfile = open('server_encryption_pubkey.pem', 'r')
encryption_key_str = kfile.read()
kfile.close()
server_public_enckey = RSA.importKey(encryption_key_str)

# Generating own key
signing_key = RSA.generate(2048)
signing_key_pubstr = signing_key.publickey().exportKey(format='DER')

msg_to_send = ""
messages = []

available_commands = [ 
    '/list_channels',
    '/list_channel_members',
    '/join_channel',
    '/leave_channel',
    '/set_name',
    '/create_channel',
    '/quit'
]


def process_msg_from_server(msg):
    # getting signature from the end of message
    sign = msg[-RSA_sign_length:]
    msg = msg[:-RSA_sign_length]
    # verify signature
    rsa_verify(server_public_signkey, msg, sign)
    # getting timestamp from the end of message
    ts = msg[-timestamp_length:]
    msg = msg[:-timestamp_length]
    # checking timestamp
    check_timestamp(ts)
    return msg.decode('utf8')
        

def receive():
    while True:
        try:
            msg = client_socket.recv(BUFSIZ)
            msg = process_msg_from_server(msg)
            messages.append(msg)
            print_messages()
        except OSError:
            break
        except (InvalidTimestampError, WrongSignatureError):
            break 

def send(msg, event=None):
    msg_parts = msg.split(' ')
    result = ''
    if len(msg_parts) == 1:
        if msg not in available_commands:
            result = '/message %s' % msg
        else:
            result = msg
    else:
        if msg_parts[0] in available_commands:
            if msg_parts[0] == '/set_name':
                result = msg_parts[1]
            else:
                result = msg
        else:
            result = '/message %s' % msg        
    
    client_socket.send(bytes(result, "utf8"))

    if msg == '/quit':
        client_socket.close()
        sys.exit()
        

def print_messages():
    os.system('cls')
    for msg in messages:
        print(msg)


# Encoding/decoding related methods

def encode_msg(msg):
    print("encoding the msg...")
    return msg

def decode_msg(msg):
    print("decoding the msg...")
    return msg


## Generate cryptographic keys

key = RSA.generate(2048)


"Application startup requires the user to type in the server's address and port"
# HOST = input('Enter host: ')
# PORT = input('Enter port: ')
HOST = '127.0.0.1'
PORT = 33000
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

# Send public key to server
client_socket.send(signing_key_pubstr)
"Client loop -> if there's an input, send it"
while True:
    msg_to_send = input()
    if (msg_to_send != ''):
        send(msg_to_send)
