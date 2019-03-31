import socket
import struct
import xml.etree.ElementTree as ElementTree
import re

class RokuDevice:
	def __init__(self):
		#Device identification
		self.usn = ''
		self.device_group = ''
		#Location Data
		self.ip_address = ''
		self.port = 0

def ParseIdentification(packet):
	usn = ''
	device_group = ''
	
	id = re.search(b'USN: uuid:roku:ecp:.*', packet)
	if id is not None:
		m = re.search(b'(?<=USN: uuid:roku:ecp:)\w*', id.group(0))
		usn = m.group(0)
		
	id = re.search(b'device-group.roku.com: .*', packet)
	if id is not None:
		m = re.search(b'(?<=device-group.roku.com: )(\w|\d)*', id.group(0))
		device_group = m.group(0)
	
	return (usn, device_group)
		
def ParseLocation(packet):
	ip = ''
	port = 0
	
	loc = re.search(b'LOCATION: http://(\d+\.*)+:\d+', packet)
	if loc is not None:
		m = re.search(b'\d+\.\d+\.\d+\.\d+', loc.group(0))
		ip = m.group(0)
		
	if loc is not None:
		m = re.search(b':\d+', loc.group(0))
		m = re.search(b'\d+', m.group(0))
		port = int(m.group(0))
		
	return (ip, port)
	
def BuildRokuDevice(packet):
	(ip, port) = ParseLocation(packet)
	(usn, device_group) = ParseIdentification(packet)
	
	dev = RokuDevice()
	dev.ip_address = ip
	dev.port = port
	dev.usn = usn
	dev.device_group = device_group
	
	return dev

def main():
	MULTICAST_GROUP = ('239.255.255.250', 1900)
	BUFFER_SIZE = 2048
	MESSAGE = b'M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: "ssdp:discover"\r\nST: roku:ecp\r\n\r\n'
	
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	ttl = struct.pack('b', 1)
	sock.settimeout(5)
	sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
	roku = RokuDevice()

	try:
		print('sending "%s"' % MESSAGE)
		sent = sock.sendto(MESSAGE, MULTICAST_GROUP)
		print('sent %d bytes' % sent)
		
		# Look for responses from all recipients
		while True:
			print('waiting to receive')
			try:
				(data, server) = sock.recvfrom(512)

			except socket.timeout:
				print('timed out, no more responses')
				break
			else:
				print('received "%s" from %s' % (data, server))
				roku = BuildRokuDevice(data)

	finally:
		print('closing socket')
		sock.close()

	if roku.port > 0:
		print('New socket')
		print((roku.ip_address, roku.port))
		msg = 'GET ' + '/query/apps' + ' HTTP/1.1\r\n\r\n'
		print(msg)
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((roku.ip_address, roku.port))
		sock.send(msg)
		data = sock.recv(BUFFER_SIZE)
		print(data)
		data = sock.recv(BUFFER_SIZE)
		root = ElementTree.fromstring(data)
		
		for child in root:
			print child.tag, child.attrib, child.text
		
		sock.close()
		
if __name__ == "__main__":
	main()