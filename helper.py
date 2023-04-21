from socket import *
from threading import Thread
from time import *
from helper import *
import sys, select

def receive_message(client_socket):
       
    try:
        message_header = client_socket.recv(20)
        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(SHUT_RDWR)
        if not len(message_header):
            return False

        # Convert header to int value
        message_length = int(message_header.decode().strip())
        # Return a dict object of message header and message data
        return {'header': message_header, 'data': client_socket.recv(message_length)}

    except:
        # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
        # or just lost his connection
        # socket.close() also invokes socket.shutdown(socket.SHUT_RDWR) what sends information about closing the socket (shutdown read/write)
        # and that's also a cause when we receive an empty message
        return False

def checkLoginDetails(credential):
    for line in open('credentials.txt'):
        real_user = line.split(' ')[0].strip()
        real_pass = line.split(' ')[1].strip()  
        if credential == [real_user, real_pass]:
            return True
        elif (credential[0] == real_user and credential[1] != real_pass):
            return "Invalid Password"
    return "Invalid User"  

def checkUserExists(username):
    print(username)
    exists = False
    for line in open('credentials.txt'):
        if username == line.split(' ')[0].strip():
            exists = True
            break
    return exists

def send_message(message, socket):
    message_header = f"{len(message.encode()):<{20}}".encode()
    socket.send(message_header + message.encode())
        # credentials = credentials.encode()
        # user_header = f"{len(credentials):<{20}}".encode()
        # clientSocket.send(user_header + credentials)
def recvMsg(clientSocket):
    while True:
        try:
            data = clientSocket.recv(1024)
            recvData = data.decode()
            print(recvData)
        except:
            pass


def updateLastActive(dict, key):
    if key in dict:
        dict[key]['last-active'] = time()
    return dict
