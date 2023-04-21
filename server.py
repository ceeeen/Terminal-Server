"""
    Python 3
    Usage: python3 server.py 12000 200 200
    coding: utf-8
    author: z5310735 Raymond Cen
"""

from datetime import datetime
from socket import *
from threading import Thread
from time import *
from helper import *
import sys, select

# acquire server host and port from command line parameter
if len(sys.argv) < 4 or len(sys.argv) > 4:
    print('Please enter valid arguments')
    exit(0)

BLOCK_DURATION = sys.argv[2]
BLOCK_DURATION = float(BLOCK_DURATION)
TIMEOUT = sys.argv[3]
TIMEOUT = float(TIMEOUT)
serverPort = int(sys.argv[1])
serverHost = "127.0.0.1"

serverAddress = (serverHost, serverPort)

# define socket for the server side and bind address
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serverSocket.bind(serverAddress)
serverSocket.listen()

# List of sockets for select.select()
sockets_list = [serverSocket]

clients = {}
online_clients = {}
offline_clients = {}
blocked_clients = {}

print("\n===== Server is running =====")
print("===== Waiting for connection request from clients...=====")
      

while True:
    # check timeout
    temp_online_dict = dict(online_clients)
    for key, value in temp_online_dict.items():
        
        if time() - value['last_active'] >= TIMEOUT:
            print("Timed out due to inactivity byebyebyebye {}".format(key))
            for key2, value2 in online_clients.items():
                send_message(f"Timed out due to inactivity byebyebyebye {key}", value2['socket'])
                # send_message(f"{key} timed out", value['socket'])
            for key2, value2 in offline_clients.items():
                if key2 == key:
                    continue
                offline_clients[key2]['offline_messages'].append("Timed out due to inactivity byebyebyebye {}".format(key))
            offline_clients[key] = value
            del online_clients[key]
            sockets_list.remove(value['socket'])
    # read in data
    read_sockets, _, _ = select.select(sockets_list, [], [], 1)
    for notified_socket in read_sockets:
        if notified_socket == serverSocket:
            client_socket, client_address = serverSocket.accept()
            invalid_pass = False
            username = ''
            while True:
                if invalid_pass is True:
                    password = receive_message(client_socket)
                    if password is False:
                        continue
                    password = password['data'].decode()
                    print(username)
                    print(password)
                    print(clients[credentials[0]]["tries"])
                else:
                    user = receive_message(client_socket)
                    # Disconnected
                    if user is False:
                        continue
                    username = user['data'].decode()
                    if checkUserExists(username):
                        send_message("valid", client_socket)
                    else:
                        print("invalid user creating a new user")
                        send_message(f'{username} does not exist. Now creating new user enter a password', client_socket)                    
                    password = receive_message(client_socket)
                    if password is False:
                        continue
                    password = password['data'].decode()
                    if checkUserExists(username) is False:
                        with open("credentials.txt", "a+") as file_object:
                            file_object.seek(0)
                            file_object.write("\n")
                            file_object.write(f'{username} {password}')
                
                credentials = [username, password]
                if credentials[0] in blocked_clients:
                    if blocked_clients[credentials[0]] > time():
                        time_left = blocked_clients[credentials[0]] - time()
                        send_message(' == Your account is locked for {} seconds. Please try later.'.format(time_left), client_socket)
                        break
                    else:
                        del blocked_clients[credentials[0]]

                        
                print('Accepted new connection from {}:{}, credentials: {} {}'.format(*client_address, username, password))

                
                if credentials[0] not in clients:
                    user['tries'] = 1
                    clients[credentials[0]] = user
                login_response = checkLoginDetails(credentials)
                print(login_response)
                if login_response is True:
                    if credentials[0] in online_clients:
                        send_message(f"{credentials[0]} is already logged in", client_socket)
                        break
                    if credentials[0] not in offline_clients:
                        online_clients[credentials[0]] = clients[credentials[0]]
                        online_clients[credentials[0]]['logged_in_time'] = time()
                        online_clients[credentials[0]]['last_active'] = time()
                        online_clients[credentials[0]]['socket'] = client_socket
                        online_clients[credentials[0]]['blocked_users'] = []
                        online_clients[credentials[0]]['offline_messages'] = []
                        online_clients[credentials[0]]['address'] = client_address
                    else:
                        offline_clients[credentials[0]]['socket'] = client_socket
                        online_clients[credentials[0]] = offline_clients[credentials[0]]
                        online_clients[credentials[0]]['last_active'] = time()
                        online_clients[credentials[0]]['logged_in_time'] = time()

                    send_message("Logged in successfully", client_socket)    
                    sockets_list.append(client_socket)
                    
                    if credentials[0] in offline_clients:
                        # DISPLAY OFFLINE MESSAGES
                        for offline_message in offline_clients[credentials[0]]['offline_messages']:
                            send_message(offline_message, offline_clients[credentials[0]]['socket'])
                        del offline_clients[credentials[0]]
                    
                    # NOTIFY OTHERS
                    for key, value in online_clients.items():
                        if key == credentials[0]:
                            continue
                        if credentials[0] in value['blocked_users']:
                            continue
                        send_message(f'{credentials[0]} logged in', value['socket'])
                    for key, value in offline_clients.items():
                        if key == credentials[0]:
                            continue
                        if credentials[0] not in value['blocked_users']:
                            value['offline_messages'].append(f'{credentials[0]} logged in')
                    
                    break
                elif login_response == "Invalid Password":
                    send_message(login_response, client_socket)
                    clients[credentials[0]]["tries"] += 1
                    invalid_pass = True
                    if clients[credentials[0]]["tries"] >= 3:
                        send_message(f' >>> Your account is blocked for {BLOCK_DURATION} seconds. Please try later.<<<', client_socket)
                        blocked_clients[credentials[0]] = time() + BLOCK_DURATION
                        break
                        
                   
        else:
            temp_online_dict = dict(online_clients)
            for key, value in temp_online_dict.items():
                if value['socket'] == notified_socket:
                    client_message = receive_message(notified_socket)
                    if client_message is False:
                        continue
                    client_command = client_message['data'].decode()
                    print(f'{key}:  {client_command}')

                    if key in online_clients:
                        online_clients[key]['last-active'] = time()                    
                    if client_message['data'].decode() == "":
                        send_message("invalid command", notified_socket)
                        continue
                    client_command = client_message['data'].decode().split()[0]
                    if client_command == "message":
                        message_receiver = client_message['data'].decode().split()[1]
                        receive_client = {}
                        if checkUserExists(message_receiver) is False:
                            send_message(f'Failed to send because {message_receiver} does not exist ', notified_socket)
                            continue
                        if message_receiver in online_clients:
                            receive_client[message_receiver] = online_clients[message_receiver]
                            receive_client[message_receiver]['status'] = 'online'
                        elif message_receiver in offline_clients:
                            receive_client[message_receiver] = offline_clients[message_receiver]
                            receive_client[message_receiver]['status'] = 'offline'
                        else:
                            send_message(f'Failed to send because {message_receiver} has never logged in ', notified_socket)
                            continue
                        if key in receive_client[message_receiver]['blocked_users']:
                            send_message(f'Failed to send because {message_receiver} has blocked you ', notified_socket)
                        elif key == message_receiver:
                            send_message(f'You are sending a message to yourself ', notified_socket)
                        else:
                            msg = client_message['data'].decode().split(' ', 2)[2]
                            if receive_client[message_receiver]['status'] == 'online':
                                send_message(f'{key}: {msg}', receive_client[message_receiver]['socket'])
                            else:
                                offline_clients[message_receiver]['offline_messages'].append(f'{key}: {msg}')
                                
                    elif client_command == "broadcast":
                        for key2, value2 in online_clients.items():
                            if key2 == key:
                                continue
                            msg = client_message['data'].decode().split(' ', 2)[1]
                            send_message(f'{key}: {msg}', online_clients[key2]['socket'])
                        for key2, value2 in offline_clients.items():
                            if key2 == key:
                                continue
                            msg = client_message['data'].decode().split(' ', 2)[1]
                            offline_clients[key2]['offline_messages'].append(f'{key}: {msg}')
                    elif client_command == "whoelse":
                        for key2, value2 in online_clients.items():
                            if key2 == key:
                                continue
                            if key not in value2['blocked_users']:
                                send_message(f'{key2}', online_clients[key]['socket'])
                    elif client_command == "whoelsesince":
                        for key2, value2 in online_clients.items():
                            if key2 == key:
                                continue
                            timeSince = client_message['data'].decode().split(' ', 2)[1]
                            timeSince = time() - float(timeSince)
                            if online_clients[key2]['logged_in_time'] >= timeSince and key not in value2['blocked_users']:
                                send_message(f'{key2}', online_clients[key]['socket'])
                        for key2, value2 in offline_clients.items():
                            if key2 == key:
                                continue
                            timeSince = client_message['data'].decode().split(' ', 2)[1]
                            timeSince = time() - float(timeSince)
                            if offline_clients[key2]['logged_in_time'] >= timeSince and key not in value2['blocked_users']:
                                send_message(f'{key2}', online_clients[key]['socket'])
                    elif client_command == "block":
                        blocked = False
                        blocking_client = client_message['data'].decode().split()[1]
                        if key == blocking_client:
                            send_message(f'cant block yourself lol ', notified_socket)
                        for key2, value2 in online_clients.items():
                            if key2 == blocking_client:
                                send_message(f'Blocked {blocking_client}', online_clients[key]['socket'])
                                value['blocked_users'].append(blocking_client)
                                blocked = True  
                                break
                        
                        for key2, value2 in offline_clients.items():
                            if blocked:
                                break
                            if key2 == blocking_client:
                                send_message(f'Are you sure you want to block {blocking_client}? Type yes or no', online_clients[key]['socket'])
                                confirm_block = receive_message(notified_socket)
                                if confirm_block['data'].decode().lower() == "yes":
                                    send_message(f'Blocked {blocking_client}', online_clients[key]['socket'])
                                    value['blocked_users'].append(blocking_client)
                                    blocked = True  
                                else:
                                    send_message(f'did not block {blocking_client}', online_clients[key]['socket'])
                                break

                    elif client_command == "unblock":
                        unblocked = False
                        blocking_client = client_message['data'].decode().split()[1]
                        if key == blocking_client:
                            send_message(f'cant unblock yourself lol ', notified_socket)
                        for key2, value2 in online_clients.items():
                            if key2 == blocking_client:
                                send_message(f'Unblocked {blocking_client}', online_clients[key]['socket'])
                                value['blocked_users'].remove(blocking_client)
                                unblocked = True  
                                break
                        
                        for key2, value2 in offline_clients.items():
                            if unblocked:
                                break
                            if key2 == blocking_client:
                                send_message(f'Unblocked {blocking_client}', online_clients[key]['socket'])
                                value['blocked_users'].remove(blocking_client)
                                blocked = True  
                                break
                    elif client_command == "logout":
                        offline_clients[key] = value
                        send_message(f'Logged out {key}', online_clients[key]['socket'])
                        for key2, value2 in online_clients.items():
                            if key2 == key:
                                continue
                            if key in value2['blocked_users']:
                                continue
                            send_message(f'{key} logged out', value2['socket'])
                        for key2, value2 in offline_clients.items():
                            if key == key2:
                                continue
                            if key not in value2['blocked_users']:
                                value2['offline_messages'].append(f'{key} logged out')
                        del online_clients[key]
                    elif client_command == "startprivate":
                        message_receiver = client_message['data'].decode().split()[1]
                        if checkUserExists(message_receiver) is False:
                            send_message(f'Failed to send because {message_receiver} does not exist ', notified_socket)
                            continue
                        if message_receiver not in online_clients and message_receiver not in offline_clients:
                            send_message(f'Failed to send because {message_receiver} has never logged in ', notified_socket)
                            continue
                        if message_receiver == key:
                            send_message(f'Cannot start private session with yourself ', notified_socket)
                            continue
                        if message_receiver in online_clients and key in online_clients[message_receiver]['blocked_users']:
                            send_message(f'Failed to start private session because {message_receiver} blocked you ', notified_socket)
                            continue
                        if message_receiver in offline_clients:
                            send_message(f'Failed to start private session because {message_receiver} is not online ', notified_socket)
                            continue
                        send_message(f"Start private messaging with {message_receiver}", notified_socket)
                        send_message(f"{key} would like to enter private message, enter y or n: ", online_clients[message_receiver]['socket'])
                        while True:
                            confirmation_p2p = receive_message(online_clients[message_receiver]['socket'])
                            if confirmation_p2p is False:
                                continue
                            if confirmation_p2p['data'].decode() == "y":
                                send_message(f"starting private {message_receiver} {online_clients[message_receiver]['address']} ", notified_socket)
                                send_message(f"starting private {key} {online_clients[key]['address']} ", online_clients[message_receiver]['socket'])
                            else:
                                send_message(f"Failed, {message_receiver} has denied your request ", notified_socket)
                            break
                    elif client_message['data'].decode() == "!!CURRENTLY PRIVATE MESSAGE!!":
                        continue
                    else:
                        send_message(f'Invalid command', online_clients[key]['socket'])


                    break
            
