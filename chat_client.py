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

channel_key = ''
password = ''


# Generating own key
signing_key = RSA.generate(rsa_keylength)
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
    '/channel_key'
    '/password_request'
    '/password'
    '/nopassword'
    '/set_password'
    '/pubkey_request'
    '/pubkey'
]

def generate_channel_key():
    channel_key = get_random_bytes(32)
    channel_iv = get_random_bytes(AES.block_size)

def send_to_server(msg, enc):
    client_socket.send(prepare_msg(msg, enc))

def send_encrypted_to_server(msg):
    client_socket.send(process_encrypted_msg_to_server(msg))

def prepare_msg(msg, enc):
    ts = timestamp()
    if type(msg) == str:
        b = bytes(msg, 'utf8')
    else:   
        b = msg
    b_list = b.split(b' ')
    prefix = b_list[0]
    b = b' '.join(b_list[1:])
    b = b + ts
    if enc=='server':
        b = rsa_enc(server_public_enckey, b)
    elif enc=='client_assym':
        client_public_enckey = get_pubkey_of_channel_owner()
        b = rsa_enc(client_public_enckey, b)
    elif enc=='client_sym':
        b = aes_enc(channel_key, b)
    b = prefix + b' ' + b
    signature = rsa_sign(signing_key, b)
    return b+signature

def get_pubkey_of_channel_owner():
    send_encrypted_to_server("/pubkey_request", enc='server')
    
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
            if msg_parts[0] == '/create_channel':
                generate_channel_key()
            if msg_parts[0] == '/password':
                if len(msg_parts)==1:
                    password = ''
                else:
                    password = ''.join(msg_parts[1:])
                result = msg_parts[0]  # Inform server that the password has been set, but do not send the actual password
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
send_to_server(b'/pubkey ' + signing_key_pubstr, None)
"Client loop -> if there's an input, send it"
while True:
    msg_to_send = input()
    if (msg_to_send != ''):
        send(msg_to_send)
