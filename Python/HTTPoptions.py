# HTTP Client options checker

import http.client

print("*** This program returns alist of methods if OPTIONS is enabled ***\n")

host = input("Insert the host/ip: ")
port = input("Insert the port(default: 80): ")

if(port == ""):
    port = 80

try:
    connection = http.client.HTTPConnection(host, port)
    connection.request('OPTIONS', '/')
    response = connection.getresponse()
    print("Enabled methods are: ", response.getheader('allow'))
    connection.close()
except:
    print("Connection Failed!")
