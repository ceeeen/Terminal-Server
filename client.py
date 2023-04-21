"""
    Python 3
    Usage: python3 localhost 12000
    coding: utf-8
    author: z5310735 Raymond Cen
    
"""
from socket import *
import threading
from time import *
import sys
from helper import *



#Server would be running on the same host as Client
if len(sys.argv) != 3:
    print("\n===== Error usage, python3 client.py SERVER_IP SERVER_PORT ======\n")
    exit(0)
serverHost = sys.argv[1]
serverPort = int(sys.argv[2])
# define a socket for the client side, it would be used to communicate with the server
clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
# build connection with the server and send message to it
clientSocket.connect((serverHost, serverPort))

clientSocket.setblocking(False)
# clientSocket.settimeout(1)

private_recv_socket = socket(AF_INET, SOCK_STREAM)
private_recv_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
private_recv_socket.bind((clientSocket.getsockname()[0], clientSocket.getsockname()[1]))
private_recv_socket.listen(1)
private_socket_dict = {}

online = False

username = input("Username: ").strip()
send_message(username, clientSocket)

while True:
    incoming_message = receive_message(clientSocket)
    if incoming_message is not False:
        break
if ("does not exist. Now creating new user" in incoming_message['data'].decode()):
    print(incoming_message['data'].decode())

password = input("Password: ").strip()
send_message(password, clientSocket)

print(f'Entered --> username:{username} and password: {password}')

while online is False:
    login_response = receive_message(clientSocket)
    if login_response is False:
        continue
    response = login_response['data'].decode()
    print(response)
    if response == "Logged in successfully":
        online = True
    elif response == "Invalid Password":
        password = input("Password: ").strip()
        print(f'Entered >> username:{username} and password: {password}')
        send_message(password, clientSocket)
        if response is False:
            continue   
    elif "already logged in" in response:
        sys.exit()
    
msg = None
# commands after login

def check_online():
    global online
    return online

def client_send():
    while check_online():
        msg = input()
        if msg == "":
            continue
        if msg.split()[0] == "stopprivate":
            if len(msg.split()) != 2:
                print("invalid arguments")
                continue
            disconnecting_user = msg.split()[1]
            private_disconnect(disconnecting_user)
            send_message("!!CURRENTLY PRIVATE MESSAGE!!", clientSocket)
        elif msg.split()[0] == "private":
            if len(msg.split()) < 3:
                print("invalid arguments")
                continue 
            command = msg.split(' ', 2)
            private_message(command[1], command[2])
            send_message("!!CURRENTLY PRIVATE MESSAGE!!", clientSocket)
        else:
            send_message(msg, clientSocket)  

def client_recv():
    global online
    while online:
        incoming_message = receive_message(clientSocket)
        if incoming_message is False:   
            continue
        if incoming_message['data'].decode() == "Timed out due to inactivity byebyebyebye " + username:
            print(incoming_message['data'].decode())
            online = False
            sys.exit()
        elif incoming_message['data'].decode() == "Logged out " + username:
            print(incoming_message['data'].decode())
            online = False
            sys.exit()
        elif "starting private" in incoming_message['data'].decode():
            new_private_address = incoming_message['data'].decode()
            new_private_address = new_private_address.split()
            private_add = new_private_address[3][2:]
            private_add = private_add[:-2]
            private_port = int(new_private_address[4][:-1])
            new_private_socket = socket(AF_INET, SOCK_STREAM)
            new_private_socket.connect((private_add, private_port))
            private_socket_dict[new_private_address[2]] = new_private_socket
            print("successfully started p2p")
            
            send_message(f"p2p started with {username}", new_private_socket)
        elif "end" in incoming_message["data"].decode() and "p2p connection with" in incoming_message["data"].decode():
            private_disconnect(incoming_message["data"].decode().split(' ')[3])
        elif incoming_message is not False:
            print(incoming_message["data"].decode())

def private_message(user, message):
    if user == username:
        print("Cannot send message to yourslef")
    if user in private_socket_dict:
        send_message(f"PRIVATE {username}:{message}", private_socket_dict[user])
    else:
        print("invalid user")

def private_disconnect(disconnect_username):
    if disconnect_username in private_socket_dict:
        send_message(f"p2p connection with {username} end", private_socket_dict[disconnect_username])
        private_socket_dict[disconnect_username].close()
        del private_socket_dict[disconnect_username]
        print(f"p2p connection with {disconnect_username} end")
    else:
        print("invalid user")

def private_client_recv_handle():
    # get new p2p connection
    global online
    while online:
        connection_socket, _ = private_recv_socket.accept()
        print("Private session started")
        private_socket_dict
        private_socket_thread = threading.Thread(target=private_client_recv, args=(connection_socket,),daemon=True)
        private_socket_thread.start()
        
def private_client_recv(socket):
    global online
    while online:
        incoming_message = receive_message(socket)
        if incoming_message is False:
            continue
        print(incoming_message['data'].decode())
        
client_receive_thread = threading.Thread(target = client_recv, daemon=True)
client_receive_thread.start()
private_receive_thread = threading.Thread(target = private_client_recv_handle, daemon=True)
private_receive_thread.start()

client_send()

# close the socket
clientSocket.close()

