#!/usr/bin/env python
from time import sleep
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from chat_common import *

# Reading cryptographic keys
kfile = open('server_signing_key.pem', 'r')
signing_key_str = kfile.read()
kfile.close()
signing_key = RSA.importKey(signing_key_str)
kfile = open('server_encryption_key.pem', 'r')
encryption_key_str = kfile.read()
kfile.close()
encryption_key = RSA.importKey(encryption_key_str)

"We can store the user's names and addresses in these containers"
clients = {}
addresses = {}
sign_keys = {}
enc_keys = {}

"We store the channels in this container"
channels = {}

"Basic attributes of the server"
HOST = ''
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)
SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)


def prepare_message(msg):
    if type(msg) == str:
        msg = bytes(msg, "utf8")
    msg_list = msg.split(b' ')
    prefix = msg_list[0]
    if prefix == b'/message':  # Message is already encrypted and signed by client
        pass
    else:
        msg += timestamp()
        msg += rsa_sign(signing_key, msg)
    return msg

def send_to_client(client, msg):
    client.send(prepare_message(msg))
    
def process_message(client_t, msg):
    if type(msg) == str:
        msg = bytes(msg, 'utf8')
    msg_list = msg.split(b' ')
    prefix = msg_list[0]
    Debug(prefix)
    msg = b' '.join(msg_list[1:])
    if prefix in [b'/message']:  # Message is encrypted with client keys, server cannot perform any more processing
        return (prefix, msg)
    sign = msg[-RSA_sign_length:]
    msg = msg[:-RSA_sign_length]
    # verify signature
    rsa_verify(client_t['sign_key'], msg, sign)
    # Public keys are not encrypted
    if prefix in [b'/sign_pubkey', b'/enc_pubkey']:
        pass
    else:
        msg = rsa_dec(encryption_key, msg)
    # getting timestamp from the end of message
    ts = msg[-timestamp_length:]
    msg = msg[:-timestamp_length]
    # checking timestamp
    check_timestamp(ts)
    return (prefix, msg)

"Handle client connection"
def accept_incoming_connections():
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected!" % client_address)
        send_to_client(client, "Greetings from the server!\nNow type /set_name <your name> and press ENTER!\n")
        addresses[client] = client_address
        "Asynchronous client handling"
        Thread(target=handle_client, args=(client, )).start()

"Handle client after connection to the server"
def handle_client(client):
    # first message is always the public key
    # Special actions needed because the client's public key is not known yet
    msg = client.recv(BUFSIZ)
    client_pubkey_str = msg[:-RSA_sign_length]
    # drop prefix and timestamp (will be verified later)
    client_pubkey_str = client_pubkey_str[len('/sign_pubkey '):-timestamp_length]
    client_pubkey = RSA.import_key(client_pubkey_str)
    client_t = {
        'client': client,
        'name': None,
        'channel': None,
        'sign_key': client_pubkey,
        'enc_key': None
    }
    # Now that we know the client's pubkey, we can verify the first message
    _ = process_message(client_t, msg)
    # Second message is the encryption key
    msg = client.recv(BUFSIZ)
    _, client_enc_pubkey_str = process_message(client_t, msg)
    client_enc_pubkey = RSA.import_key(client_enc_pubkey_str)
    client_t['enc_key'] = client_enc_pubkey
    # Third message is always the name
    msg = client.recv(BUFSIZ)
    _, name = process_message(client_t, msg)
    name = name.decode('utf8')
    while name in clients:
        # The name is already taken -> let the user know!
        send_to_client(client, 'This name is already taken!\nPlease choose another!')
        _, name = process_message(client_t, msg)
        name = name.decode('utf8')
    
    client_t['name'] = name
    
    clients[client] = name
    sign_keys[name] = client_pubkey
    enc_keys[name] = client_enc_pubkey
    welcome = 'Welcome %s! If you ever want to quit, type /quit to exit\n' % name
    welcome += 'You are now in the lobby, use the following commands:\n'
    welcome += '/list_channels\n'
    welcome += '/list_channel_members <channel_name>\n'
    welcome += '/create_channel <channel_name>\n'
    welcome += '/join_channel <channel_name>\n'
    welcome += '/leave_channel\n'
    send_to_client(client, welcome)
    start_client_loop(client_t)

def start_client_loop(client_t):
    client = client_t['client']
    while client in clients:
        msg = client.recv(BUFSIZ)
        order, msg = process_message(client_t, msg)
        order = order.decode('utf8')
        if msg == b'':
            order_dictionary.get(order)(None, client_t)
        # cannot decode /message
        elif order == '/message':
            order_dictionary.get(order)(msg, client_t)
        else:
            params = msg.decode('utf8')
            order_dictionary.get(order)(params, client_t)

"Sending a message to every channel members"
def broadcast(msg, channel, prefix=""):
    for client_t in channel.values():
        send_to_client(client_t['client'], prefix+msg)

def create_channel(channel, client_t):
    if channel in channels:
        send_to_client(client_t['client'], 'This channel name is already taken!\nPlease choose another!')
        return
    print("Creating new channel: %s" % channel)
    new_channel = {
        'name': channel,
        'members': {},
        'owner': client_t,
        'password_protected': False
    }
    channels[channel] = new_channel
    send_to_client(client_t['client'], "Channel created with name: %s" % channel)
    send_to_client(client_t['client'], "Your channel is password protected by default. A random password has been set, so currently nobody can join your channel. You can set the password like this: /password <password>. You can also disable password with /nopassword")
    # Without sleep the client treats two consecutive message as one
    sleep(0.1)
    join_channel(channel, client_t)
    channels[channel]['password_protected'] = True

def leave_channel(params, client_t):
    if client_t['channel'] == None:
        send_to_client(client_t['client'], 'You have to be in a channel for this function!')
        return
    channel_to_check = client_t['channel']
    client_t['channel'] = None
    del channels[channel_to_check]['members'][client_t['name']]
    if len(channels[channel_to_check]['members']) == 0:
        print("Deleting channel: %s" % channel_to_check)
        del channels[channel_to_check]
    else:
        msg = '%s has left the channel!' % client_t['name']
        if channels[channel_to_check]['owner'] == client_t:
            # if the owner left the group, pick a new owner
            new_owner = next(iter(channels[channel_to_check]['members'].values()))
            channels[channel_to_check]['owner'] = new_owner
            msg += "He/she was the owner. The new owner is %s." % new_owner['name']
        broadcast(msg, channels[channel_to_check]['members'])

def list_channels(params, client_t):
    result = ''
    if len(channels) == 0:
        result = 'There is no channel yet! Create one yourself!'    
    else:
        result = 'Available channels:\n'
        for channel in channels.values():
            result += '- %s\n' % channel['name']
    send_to_client(client_t['client'], result)

def list_channel_members(channel, client_t):
    result = ''
    if channel not in channels:
        result = 'This channel does not exist!'
    else:
        result = '%s members:\n' % channel
        for member in channels[channel]['members'].values():
            result += '%s\n' % member['name']
    send_to_client(client_t['client'], result) 

def check_password(channel, client_t):
    channel_owner_t = channel['owner']

    owner_key_s = channel_owner_t['enc_key'].exportKey(format='DER')
    req_msg = '/pw_required %s' % owner_key_s
    send_to_client(client_t['client'],  req_msg)

    # Ezt a részt kell még ellenőrizni

    pw_msg = client_t['client'].recv(BUFSIZ)
    _, msg = process_message(client_t, pw_msg)
    send_to_client(channel_owner_t['client'], msg)
    pw_valid_msg = channel_owner_t['client'].recv(BUFSIZ)
    _, answer = process_message(channel_owner_t, pw_valid_msg)
    prefix = answer.split(b' ')[0]
    if prefix == b'/channel_key':
        return True
    else:
        return False
    
def join_channel(channel, client_t):
    # leave channel before joining another one
    if client_t['channel'] != None:
        leave_channel(None, client_t)
    if channel not in channels:
        send_to_client(client_t['client'], 'This channel does not exist!') 
    else:
        if channels[channel]['password_protected']:
            if check_password(channels[channel], client_t):
                channels[channel]['members'][client_t['name']] = client_t
                client_t['channel'] = channel
                send_to_client(client_t['client'], 'You are now in the channel \"%s\"' % channel) 
                msg = '%s has joined the channel!' % client_t['name']
                broadcast(msg, channels[channel]['members'])
            else:
                send_to_client(client_t['client'], "Wrong password!")
        else:
            send_to_client(client_t['client'], '/no_pw_required %s' % channels[channel]['owner']['enc_key'])
            channels[channel]['members'][client_t['name']] = client_t
            client_t['channel'] = channel
            send_to_client(client_t['client'], 'You are now in the channel \"%s\"' % channel) 
            sleep(0.1)
            msg = '%s has joined the channel!' % client_t['name']
            broadcast(msg, channels[channel]['members'])


def send_message(msg, client_t):
    if client_t['channel'] != None:
        channel = channels[client_t['channel']]
        # Cut down message prefix, we'll add it back
        Debug(len(msg)); Debug(msg)
        broadcast(msg, channel['members'], b'/message ' + bytes(client_t['name'], 'utf8') + b' ')
    else:
        send_to_client(client_t['client'], 'You have to be in a channel to access this function!')

def quit_app(params, client_t):
    print("%s has quit" % client_t['name'])
    send_to_client(client_t['client'], '/quit')
    client_t['client'].close()
    del clients[client_t['client']]
    if client_t['channel'] != None:
        broadcast('%s disconnected' % client_t['name'], channels[client_t['channel']]['members'])
        del channels[client_t['channel']]['members'][client_t['name']]
    del client_t

def password_on(params, client_t):
    if channels[client_t['channel']]['owner'] == client_t:
        channels[client_t['channel']]['password_protected'] = True
        send_to_client(client_t['client'], "Password set successfully!")
    else:
        send_to_client(client_t['client'], "You need to be channel owner to do that!")

def password_off(params, client_t):
    if channels[client_t['channel']]['owner'] == client_t:
        channels[client_t['channel']]['password_protected'] = False
        send_to_client(client_t['client'], "Password turned off for this channel!")
    else:
        send_to_client(client_t['client'], "You need to be channel owner to do that!")

def pubkey_request(params, client_t):
    Debug(sign_keys)
    send_to_client(client_t['client'], sign_keys[params].exportKey(format='DER'))
    Debug("Pubkey sent to client %s" % client_t['name'])

def enc_pubkey_request(params, client_t):
    send_to_client(client_t['client'], enc_keys[params].exportKey(format='DER'))

def pubkey_request_owner(params, client_t):
    channel = params
    send_to_client(client_t['client'], channels[channel]['owner']['sign_key'].exportKey(format='DER'))
    
def enc_pubkey_request_owner(params, client_t):
    channel = params
    send_to_client(client_t['client'], channels[channel]['owner']['enc_key'].exportKey(format='DER'))
    

order_dictionary = {
    '/create_channel':          create_channel,
    '/list_channels':           list_channels,
    '/list_channel_members':    list_channel_members,
    '/leave_channel':           leave_channel,
    '/message':                 send_message,
    '/join_channel':            join_channel,
    '/quit':                    quit_app,
    '/password':                password_on,
    '/nopassword':              password_off,
    '/pubkey_request':          pubkey_request,
    '/pubkey_request_owner':    pubkey_request_owner,
    '/enc_pubkey_request':      enc_pubkey_request,
    '/enc_pubkey_request_owner':enc_pubkey_request_owner
}

if __name__ == "__main__":
    SERVER.listen(5)
    print("Waiting for connections...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
