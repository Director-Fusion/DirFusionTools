# Connect to a socket

import socket

IPAdd = input("Type the IP address you wish to connect to: ")
IPPort = int(input("Type the port number: "))


my_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
my_sock = socket.connect((IPAdd, IPPort))
print("Connection Established")

message = input("Message to send: ")
my_sock.sendall(message.encode())
my_sock.close()


