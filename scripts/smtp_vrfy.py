#!/usr/bin/python
import socket
import sys

if len(sys.argv) != 3:
    print("Usage: vrfy.py <IP> <usernames_file>")
    sys.exit(0)
  
target_ip = input("Enter the IP address of the target: ")

# Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
server_address = (sys.argv[1], 25)
s.connect(server_address)

# Receive the banner
banner = s.recv(1024)
print(banner)

# VRFY a list of users
with open(sys.argv[2], 'r') as f:
    usernames = f.read().splitlines()

for username in usernames:
    s.send('VRFY ' + username + '\r\n')
    result = s.recv(1024)
    print(result)

# Close the socket
s.close()
