#!/usr/bin/python

'''
Developers:  Nick Hurt, Keith Schmitt, Jerry ---
'''

import sys, socket, select, re

#need to pip install this
#client needs to randomly generate an initialization vector each time it sends a message 
import rsa

BUFSIZ = 1024

class ChatClient(object):

	def __init__(self, host='127.0.0.1', port=1234, name=None):
		self.name = name
		self.flag = False
		self.port = int(port)
		self.host = host
		self.prompt='[{}]> '.format(name)
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.sock.connect((host, self.port))
			print(('Welcome to The Office fanatics chatroom.'))
			self.sock.send('NAME: ' + self.name)
			data = self.sock.recv(BUFSIZ)
			addr = data.split('CLIENT: ')[1] #get client address and set it
			self.prompt = '[{}]> '.format(name)
		except socket.error:
			print( 'Uh oh...something went wrong connecting to chat server')
			sys.exit(1)

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
						if data: self.sock.send(data)
					elif i == self.sock:
						data = self.sock.recv(BUFSIZ)
						if data == 'Shutdown':
							print( 'Admin booted you from chat.')
							self.flag = True
							break
						if not data:
							print( 'Shutting down.')
							self.flag = True
							break
						else:
							sys.stdout.write(data + '\n')
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
