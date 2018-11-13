#!/usr/bin/python

'''
Developers:  Nick Hurt, Keith Schmitt, Jerry ---
'''

import sys, socket, select, re, os

#need to pip install this: pip install cryptography
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
main class aiming to handle the client side interactions,
when first instantiated, it will do a setup routine with the Server
in order to create a symmetric key that it generates

"""
class ChatClient(object):

	def __init__(self, host='127.0.0.1', port=1234, name=None):
		self.name = name
		self.flag = False
		self.port = int(port)
		self.host = host
		self.prompt='[{}]> '.format(name)

		#loading public key
		self.getPublicKey()


		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.sock.connect((host, self.port))
			print(('Welcome to The Office fanatics chatroom.'))
			#client will generate initial private key
			self.gen_key = Fernet.generate_key()
			self.fern = Fernet(self.gen_key)
			print(self.gen_key)
			#encrypt generated key using public key
			enc_key = self.encrypt(self.gen_key, self.public_key)

			self.sock.send(enc_key)

			#recv the private symmetric encrypted key
			enc_data = self.sock.recv(BUFSIZ)


			self.sock.send(self.fern.encrypt(('NAME: ' + self.name).encode()))
			data = self.sock.recv(BUFSIZ)

			addr = self.fern.decrypt(data).decode().split('CLIENT: ')[1] #get client address and set it
			self.prompt = '[{}]> '.format(name)

		except socket.error:
			print( 'Uh oh...something went wrong connecting to chat server')
			sys.exit(1)


	def getPublicKey(self, file = "RSApub.pem"):
		with open(file, "rb") as keyfile:
			self.public_key = serialization.load_pem_public_key(keyfile.read(), backend = default_backend())

	def encrypt(self,data, key):
		encrypted = key.encrypt(data, padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None ) )
		return encrypted


	def decrypt(self, ciphertext, key):
		decrypted_message = key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm = hashes.SHA1()),algorithm=hashes.SHA1(), label = None))
		return decrypted_message

	def cmdloop(self):

		while not self.flag:
			try:
				sys.stdout.write(self.prompt)
				sys.stdout.flush()

				# Wait for input from stdin & socket
				inputready, outputready,exceptrdy = select.select([0, self.sock], [],[])

				for i in inputready:
					if i == 0:
						data = sys.stdin.readline().strip()
						#regenerating initialization vector, but self.fern already implements a iv, otherwise would include it
						self.iv = os.urandom(16)
						#encrypting data using symm key
						enc = self.fern.encrypt(data.encode())
						self.sock.send(enc)
					elif i == self.sock:
						data = self.fern.decrypt(self.sock.recv(BUFSIZ))
						if data.decode() == 'Shutdown':
							print( 'Admin booted you from chat.')
							self.flag = True
							break
						if not data:
							print( 'Shutting down.')
							self.flag = True
							break
						else:
							sys.stdout.write(data.decode() + '\n')
							sys.stdout.flush()

			except KeyboardInterrupt:
				print( '...received interrupt.\nCome again soon!')
				self.sock.close()
				break

#Regular Expression check for valid host name
#http://stackoverflow.com/questions/2532053/validate-a-hostname-string
def is_valid_hostname(hostname):
	if len(hostname) > 255:
		return False
	if hostname[-1] == ".":
		# strip exactly one dot from the right, if present
		hostname = hostname[:-1]
	allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
	return all(allowed.match(x) for x in hostname.split("."))

def getHostAndPort(argsFromCommandLine):

	# either enter host/port by command line or user input
	if len(argsFromCommandLine) == 4:
		host = argsFromCommandLine[1]
		port = int(argsFromCommandLine[2])
		username = argsFromCommandLine[3]

	else:
		username = input("username: ")

		host = input('host: ')

		# use regular expression function
		while not is_valid_hostname(host):
			print( "Invalid host, try again.")
			host = input('host: ')

		port = input('port: ')

		# check for non-characters and negative or large port numbers
		while not port.isdigit() or int(port) < 0 or int(port) > 65536:
			print( "Invalid Port Number, try again.")
			port = input('port: ')

		# cast port only when know it's valid
		port = int(port)

	return host, port, username

def main(argv):

	host, port, username = getHostAndPort(argv)
	c = ChatClient(host, port, username)
	c.cmdloop()

if __name__ == "__main__":
	main(sys.argv)
