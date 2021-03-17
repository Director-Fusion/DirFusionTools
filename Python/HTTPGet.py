# HTTP GET REQUEST BY: Cory M Keller

import http.client

print("*** THIS PROGRAM SENDS A GET REQUEST TO SEARCH FOR HTTP RESOURCES ***")

HOST = input("Host name/ip address: ")
PORT = input("Port number(Default: 80): ")
URL = input("Place URL to check resource(ex. /index.php): ")

if(PORT == ""):
    PORT = 80

try:
    conn = http.client.HTTPConnection(HOST, PORT)
    conn.request('GET', URL)
    stat = conn.getresponse()
    print("Server Response:",stat.status, stat.reason)
    connection.close()
except:
    print("Connection Failed!")

    
