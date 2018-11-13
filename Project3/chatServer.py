#!/usr/bin/python

'''
Developers:  Nick Hurt, Keith Schmitt, Jerry ---
'''

import select
import socket
import sys
import traceback
import signal

#need to pip install this
#Server will use this to read private and public keys, and encrypt data
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


BUFSIZ = 1024

"""
main class that will handle the logic of the server, will rely on the
files RSApub.pem and RSApriv.pem in order to create a symmetric pair with The
generated client keys
"""
class ChatServer(object):
	def __init__(self, port=1234, backlog=5):
		self.port = port
		self.clients = 0
		self.clientmap = {}
		self.groupmap = {}
		self.getPublicKey()
		self.getPrivateKey()
		self.outputs = []
		self.inputs = []
		self.adminPassword = 'votetoday'
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server.bind(('',port))
		print ('Listening to port: {}'.format(self.port))
		self.server.listen(backlog)
		signal.signal(signal.SIGINT, self.sighandler)

	def sighandler(self, signum, frame):
		print ('Shutting down server...')
		for o in s:
			o.close()
		self.server.close()

	def getname(self, client):
		return self.clientmap[client][1]

	def getPublicKey(self, file = "RSApub.pem"):
		with open(file, "rb") as keyfile:
			self.public_key = serialization.load_pem_public_key(keyfile.read(), backend = default_backend())

	def getPrivateKey(self, file = "RSApriv.pem"):
		with open(file, "rb") as keyfile:
			self.private_key = serialization.load_pem_private_key(keyfile.read(), password = None, backend = default_backend())

	def encrypt(self,data, key):
		encrypted = key.encrypt(data, padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None ) )
		return encrypted


	def decrypt(self, ciphertext, key):
		decrypted_message = key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm = hashes.SHA1()),algorithm=hashes.SHA1(), label = None))
		return decrypted_message

	def getHelp(self, client):
		helpCmd = '''
			LIST OF COMMANDS:

			help - provide list of all chat commands
			list - provide list of all users online
			send user message- send a message to a user on the network
			broadcast message- send a message to everyone on the network.
			kick user password - as admin kick a user.
		'''

		for o in self.outputs:
			if o == client:
				o.send(self.clientmap[o][2].encrypt(helpCmd.encode()))

	def getListOfUsers(self, client):
		users = []
		for keyClient in self.clientmap:
			clientInfo = self.clientmap[keyClient]
			users.append(clientInfo[1])
		listOfUsers = 'Online Users ' + str(users)
		for o in self.outputs:
			if o == client:
				o.send(self.clientmap[o][2].encrypt(listOfUsers.encode()))

	def sendMessageToAll(self, client, arguments):
		for o in self.outputs:
			if o != client: #send to everyone except ourselves.
				msg = ''
				for arg in arguments:
					msg += (arg + ' ')
				p = '{}: '.format(self.getname(client))
				o.send(self.clientmap[o][2].encrypt((p + msg).encode()))

	def sendMessage(self, client, arguments):
		if len(arguments) < 2:
			e = 'To send a message you need two arguments. A user, and a message'
			self.errorMessage(client, '', e)
			return
		#otherwise see who its for
		for key in self.clientmap:
			user = self.clientmap[key][1]
			#arguments[0] is the user
			if user == arguments[0]:
				msg = ''
				for arg in range(1, len(arguments)):
					msg += (arguments[arg] + ' ')
				for o in self.outputs:
					if o == key:
						p = '{}: '.format(self.getname(client))
						o.send(self.clientmap[o][2].encrypt((p + msg).encode()))
						return
		e = 'User {} is not connected.'.format(arguments[0])
		self.errorMessage(client, '', e)

	def adminKick(self, client, arguments):
		if len(arguments) < 2:
			e = 'To kick a user you must specify the user and enter the password'
			self.errorMessage(client, '', e)
			return
		if arguments[1] != self.adminPassword:
			e = 'Invalid password. Unable to kick user'
			self.errorMessage(client, '', e)
			return
		usr = arguments[0]
		for gkey in self.groupmap: #remove user from all groups
				if usr in self.groupmap[gkey]:
					self.groupmap[gkey].remove(usr)
		for key in self.clientmap:
			usr = self.clientmap[key][1]
			if usr == arguments[0]:
				for o in self.outputs:
					if o == key:
						o.send(self.clientmap[o][2].encrypt(('Shutdown').encode()))
						self.inputs.remove(o)
						self.outputs.remove(o)
						self.clientmap.pop(key)
						key.close()
						o.close()
						return

	def errorMessage(self, client, data, errorMsg=''):
		error = '"{}" is not a valid command. Press help for valid commands.'.format(data)
		if errorMsg != '':
			error = errorMsg
		for o in self.outputs:
			if o == client:
				o.send(self.clientmap[o][2].encrypt(error.encode()))

	def isUserOnline(self, userName):
		for key in self.clientmap:
			usr = self.clientmap[key][1]
			if usr == userName:
				return True
		return False

	def handleClientData(self, data, client):
		instructions = data.split(' ')
		cmd = instructions[0].strip()
		arguments = []
		if len(instructions) > 1:
			for i in range(1, len(instructions)):
				arguments.append(instructions[i])
		if cmd == 'help': self.getHelp(client); return;
		if cmd == 'list': self.getListOfUsers(client); return;
		if cmd == 'broadcast': self.sendMessageToAll(client, arguments); return;
		if cmd == 'send': self.sendMessage(client, arguments); return;
		if cmd == 'kick': self.adminKick(client, arguments); return;
		self.errorMessage(client, data)

	def serve(self):

		self.inputs = [self.server, sys.stdin]
		self.outputs = []

		running = 1
		while running:
			try:
				inputready,outputready,exceptready = select.select(self.inputs, self.outputs, [])
			except select.error as e:
				print("PRINTING STACKTRACE")
				traceback.print_exc()
				break
			except socket.error as e:
				print("PRINTING STACKTRACE")
				traceback.print_exc()
				break

			for s in inputready:

				if s == self.server:
					# handle the server socket
					client, address = self.server.accept()

					print ('Connected new user from {}'.format(address))
					#encrypt key with private key
					tmp_key = client.recv(BUFSIZ)
					print(tmp_key)

					#decrypt into public key
					self.sym_key = self.decrypt(tmp_key, self.private_key)


					tmp_fern = Fernet(self.sym_key)
					print(self.sym_key)

					#send encrypted key
					client.send(tmp_fern.encrypt(self.sym_key))


					# Read the login name
					cname = tmp_fern.decrypt(client.recv(BUFSIZ)).decode().split('NAME: ')[1]


					# Compute client name and send back
					self.clients += 1
					client.send(tmp_fern.encrypt(('CLIENT: ' + str(address[0])).encode()))
					self.inputs.append(client)

					#add tmp_fern to clientmap
					self.clientmap[client] = (address, cname, tmp_fern)
					# Send joining information to other clients
					msg = 'Connected a new client'
					for o in self.outputs:
						#2-> will give the fernet object, so we are using the right one
						o.send(self.clientmap[o][2].encrypt(msg.encode()))

					self.outputs.append(client)

				elif s == sys.stdin:
					# handle standard input
					junk = sys.stdin.readline()
					running = 0
				else:
					# handle all other sockets
					try:
						raw_data = s.recv(BUFSIZ)
						data = self.clientmap[s][2].decrypt(raw_data).decode()
						print("raw_data from client: " ,raw_data)
						print("Decrypted with sym key: ", data)
						if data:
							self.handleClientData(data, s)
						else:
							#print 'chatserver: %d hung up' % s.fileno()
							self.clients -= 1
							s.close()
							self.inputs.remove(s)
							self.outputs.remove(s)

							# Send client leaving information to others
							msg = 'A client has hung up'
							usr = self.clientmap[s][1]
							for key in self.groupmap:
								if usr in self.groupmap[key]:
									self.groupmap[key].remove(usr)
							self.clientmap.pop(s)
							for o in self.outputs:
								# o.send(msg)
								o.send(self.clientmap[o][2].ecnrypt(msg.encode()))

					except socket.error as e:
						# Remove
						self.inputs.remove(s)
						self.outputs.remove(s)

		self.server.close()

'''
getPort is a helper method for error handling of raw input for port nums
'''
def getPort(argsFromCommandLine):

	if len(argsFromCommandLine) == 2:
		port = int(argsFromCommandLine[1])

	else:
		port = input('port: ')

		# check for non-characters and negative or large port numbers
		while not port.isdigit() or int(port) < 0 or int(port) > 65536:
			print ("Invalid Port Number, try again.")
			port = input('port: ')

		# cast port only when know it's valid
		port = int(port)

	return port

def main(argv):

	port = getPort(argv)
	s = ChatServer(port)


	s.serve()

if __name__ == "__main__":
	main(sys.argv)
