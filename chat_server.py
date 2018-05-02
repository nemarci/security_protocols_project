#!/usr/bin/env python
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

"We store the channels in this container"
channels = {}

"Basic attributes of the server"
HOST = ''
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)
SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

def send_to_client(client, text):
    if type(text) == str:
        b = bytes(text, "utf8")
    else:
        b = text
    data = b + timestamp()
    data += rsa_sign(signing_key, data)
    client.send(data)


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
    name = client.recv(BUFSIZ).decode("utf8") #The user's name
    
    while name in clients:
        # The name is already taken -> let the user know!
        send_to_client(client, 'This name is already taken!\nPlease choose another!')
        name = client.recv(BUFSIZ).decode("utf8") #The user's new name
    
    clients[client] = name
    welcome = 'Welcome %s! If you ever want to quit, type /quit to exit\n' % name
    welcome += 'You are now in the lobby, use the following commands:\n'
    welcome += '/list_channels\n'
    welcome += '/list_channel_members <channel_name>\n'
    welcome += '/create_channel <channel_name>\n'
    welcome += '/join_channel <channel_name>\n'
    welcome += '/leave_channel\n'
    send_to_client(client, welcome)
    client_t = {
        'client': client,
        'name': name,
        'channel': None,
        'enc_key': None,
        'sign_key': None
    }
    start_client_loop(client_t)

def start_client_loop(client_t):
    client = client_t['client']
    while client in clients:
        msg = client.recv(BUFSIZ)
        msg_parts = msg.decode('utf8').split(' ')
        order = msg_parts[0]
        if len(msg_parts) == 1:
            order_dictionary.get(order)(None, client_t)
        elif len(msg_parts) == 2:
            param = msg_parts[1]
            order_dictionary.get(order)(param, client_t)
        else:
            params = ''
            for word in msg_parts[1:]:
                params += ' %s' % word
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
        'owner': client_t
    }
    channels[channel] = new_channel
    send_to_client(client_t['client'], "Channel created with name: %s" % channel)
    join_channel(channel, client_t)

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

def join_channel(channel, client_t):
    # leave channel before joining another one
    if client_t['channel'] != None:
        leave_channel(None, client_t)
    if channel not in channels:
        send_to_client(client_t['client'], 'This channel does not exist!') 
    else:
        channels[channel]['members'][client_t['name']] = client_t
        client_t['channel'] = channel
        send_to_client(client_t['client'], 'You are now in the channel \"%s\"' % channel) 
        msg = '%s has joined the channel!' % client_t['name']
        broadcast(msg, channels[channel]['members'])


def send_message(msg, client_t):
    if client_t['channel'] != None:
        channel = channels[client_t['channel']]
        broadcast(msg, channel['members'], '%s: ' % client_t['name'])
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

order_dictionary = {
    '/create_channel':          create_channel,
    '/list_channels':           list_channels,
    '/list_channel_members':    list_channel_members,
    '/leave_channel':           leave_channel,
    '/message':                 send_message,
    '/join_channel':            join_channel,
    '/quit':                    quit_app
}

if __name__ == "__main__":
    SERVER.listen(5)
    print("Waiting for connections...")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    SERVER.close()
