#!/usr/bin/env python
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from chat_common import *
import os
import sys
from time import sleep


# Reading cryptographic keys
kfile = open('server_signing_pubkey.pem', 'r')
signing_key_str = kfile.read()
kfile.close()
server_public_signkey = RSA.importKey(signing_key_str)
kfile = open('server_encryption_pubkey.pem', 'r')
encryption_key_str = kfile.read()
kfile.close()
server_public_enckey = RSA.importKey(encryption_key_str)

my_name = ''
channel_key = b'\x00'*32
password = ''


# Generating own key
signing_key = RSA.generate(rsa_keylength)
signing_key_pubstr = signing_key.publickey().exportKey(format='DER')
encryption_key = RSA.generate(rsa_keylength)
encryption_key_pubstr = encryption_key.publickey().exportKey(format='DER')

msg_to_send = ""
messages = []

available_commands = [ 
    '/list_channels',
    '/list_channel_members',
    '/join_channel',
    '/leave_channel',
    '/set_name',
    '/create_channel',
    '/quit',
    '/channel_key',
    '/password',
    '/nopassword',
    '/pubkey_request',
    '/pubkey'
]

def generate_channel_key():
    global channel_key
    channel_key = get_random_bytes(32)
    Debug(channel_key)

def send_to_server(msg, enc, client_public_enckey=None):
    client_socket.send(prepare_msg(msg, enc, client_public_enckey))

def prepare_msg(msg, enc, client_public_enckey=None):
    if type(msg) == str:
        b = bytes(msg, 'utf8')
    else:   
        b = msg
    b_list = b.split(b' ')
    prefix = b_list[0]
    b = b' '.join(b_list[1:])
    ts = timestamp()
    b = b + ts
    if enc=='server':
        b = rsa_enc(server_public_enckey, b)
    elif enc=='client_assym':
        b = rsa_enc(client_public_enckey, b)
    elif enc=='client_sym':
        b = aes_enc(channel_key, b)
    b = prefix + b' ' + b
    signature = rsa_sign(signing_key, b)
    return b+signature

def key_request(channel, pw):
    enckey = get_pubkey_of_channel_owner(channel, 'enc')
    send_to_server("/key_request " + name + ' ' + pw, 'client_assym', enckey)
    response = process_msg_from_client(client_socket.recv(BUFSIZ), 'assym')
    prefix = response.split(b' ')[0]
    if prefix == b'/channel_key':
        # cut down prefix and name
        global channel_key
        channel_key = b' '.join(response.split(b' ')[2:])


def key_response(channel, client, pw): 
    enckey = get_pubkey_of_client(client, 'enc')
    if pw == password:
        msg = prepare_msg("/channel_key " + name + " " + channel_key, enc='assym', client_public_enckey=enckey)
    else:
        msg = prepare_msg("/wrong_pw " + name, enc='assym', client_public_enckey=enckey)
    client_socket.send(msg)
        
        

def get_pubkey_of_channel_owner(channel, keytype='sign'):
    # If pubkey_request is sent without client name, the server will send back the channel owner's key
    if keytype == 'enc':
        send_to_server("/enc_pubkey_request_owner " + channel, enc='server')
    else:
        send_to_server("/pubkey_request_owner " + channel, enc='server')
    msg = client_socket.recv(BUFSIZ)
    client_pubkey_str = process_msg_from_server(msg)
    client_pubkey = RSA.importKey(client_pubkey_str)
    return client_pubkey
    
def get_pubkey_of_client(client, keytype='sign'):
    if keytype=='enc':
        send_to_server("/enc_pubkey_request " + client, enc='server')
    else:
        send_to_server("/pubkey_request " + client, enc='server')
    msg = client_socket.recv(BUFSIZ)
    client_pubkey_str = process_msg_from_server(msg)
    client_pubkey = RSA.importKey(client_pubkey_str)
    return client_pubkey

def process_msg_from_server(msg):
    # getting signature from the end of message
    if msg.startswith(b'/message'):
        msg = process_msg_from_client(msg)
        return msg
    sign = msg[-RSA_sign_length:]
    msg = msg[:-RSA_sign_length]
    # verify signature
    rsa_verify(server_public_signkey, msg, sign)
    # getting timestamp from the end of message
    ts = msg[-timestamp_length:]
    msg = msg[:-timestamp_length]
    # checking timestamp
    check_timestamp(ts)
    if msg.startswith(b"/no_pw_required"):
        return b''
        
    return msg

def process_msg_from_client(msg, enc='sym'):
    msg_parts = msg.split(b' ')
    prefix, sender = msg_parts[0:2]
    sender = sender.decode('utf8')
    sign = msg[-RSA_sign_length:]
    msg = msg[:-RSA_sign_length]
    sender_pubkey = get_pubkey_of_client(sender)
    rsa_verify(sender_pubkey, msg, sign)
    if enc=='assym':
        sender_enc_pubkey_str = get_pubkey_of_client(sender, keytype='enc')
        msg = rsa_dec(sender_enc_pubkey_str, msg)
    else:
        Debug(msg)
        Debug(channel_key)
        msg = aes_dec(channel_key, msg)
    ts = msg[-timestamp_length:]
    msg = msg[:-timestamp_length]
    check_timestamp(ts)
    return msg


def receive():
    while True:
        try:
            msg = client_socket.recv(BUFSIZ)
            msg = process_msg_from_server(msg)
            if msg != b'':
                Debug(msg)
                msg = msg.decode('utf8')
                messages.append(msg)
                print_messages()
        except OSError:
            break
        except (InvalidTimestampError, WrongSignatureError):
            break 

def join_channel(channel, msg):
    client_socket.send(prepare_msg(msg, 'server'))
    pw_msg = process_msg_from_server(client_socket.recv(BUFSIZ)).decode('utf8')
    if pw_msg == '/pw_required':
        pw = input('Enter password:')
        try:
            channel_key = key_request(channel, password)
        except WrongPassword:
            print('Cannot join channel, wrong password')

def send(msg, event=None):
    msg_parts = msg.split(' ')
    result = ''
    if len(msg_parts) == 1:
        if msg not in available_commands:
            result = '/message %s' % msg
            result = prepare_msg(result, 'client_sym')
        else:
            # Space needed because server looks for a space when checking prefix
            result = msg + ' '
            result = prepare_msg(result, 'server')
    else:
        global password
        if msg_parts[0] in available_commands:
            result = prepare_msg(msg, 'server')
            if msg_parts[0] == '/create_channel':
                generate_channel_key()
                password = get_random_bytes(128)
                result = ''
                client_socket.send(prepare_msg(msg, 'server'))
            if msg_parts[0] == '/password':
                if len(msg_parts)==1:
                    password = ''
                else:
                    password = ''.join(msg_parts[1:])
                result = prepare_msg(msg_parts[0], 'server')  # Inform server that the password has been set, but do not send the actual password
            if msg_parts[0] == '/join_channel':
                result = ''
                join_channel(msg_parts[1], msg)
            if msg_parts[0] == '/message':
                result = prepare_msg(msg, 'client_sym')
        else:
            result = '/message %s' % msg        
            result = prepare_msg(result, 'client_sym')
    if result != '' and result != b'':
        if type(result) == str:
            result = bytes(result, 'utf8') 
        client_socket.send(result)

    if msg == '/quit':
        client_socket.close()
        sys.exit()
        

def print_messages():
    clear()
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
clear()
receive_thread = Thread(target=receive)
receive_thread.start()

# Send public key to server
send_to_server(b'/sign_pubkey ' + signing_key_pubstr, None)
sleep(0.1)
send_to_server(b'/enc_pubkey ' + encryption_key_pubstr, None)
"Client loop -> if there's an input, send it"
while True:
    msg_to_send = input()
    if (msg_to_send != ''):
        send(msg_to_send)
