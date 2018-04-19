#!/usr/bin/env python
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from chat_common import *
import tkinter

"Receiving message"
def receive():
    while True:
        try:
            "The max size of the message 1024 byte (?)"
            msg = client_socket.recv(BUFSIZ).decode("utf8")
            "Show the message on the UI"
            msg_list.insert(tkinter.END, msg)
        except OSError:
            break

"Send message"
def send(event=None):
    "Get the message text from the textbox"
    msg = my_msg.get()
    my_msg.set("")
    "We send the message using the socket which"
    "is connected to one of the server's sockets"
    client_socket.send(bytes(msg, "utf8"))
    "Quit scenario"
    if msg == "{quit}":
        client_socket.close()
        top.quit()

"This method is called when the application is closing"
def on_closing(event=None):
    my_msg.set("{quit}")
    send()

"UI creation"
top = tkinter.Tk()
top.title("Chatter")
messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("Type your messages here.")
scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.

msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()
top.protocol("WM_DELETE_WINDOW", on_closing)

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

receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop()  # Starts GUI execution.
