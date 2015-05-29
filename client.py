import socket # for creating a socket
import fcntl  # for get_ip_address
import struct # for get_ip_address

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

# should later use directory service, instead of hard code IP
dst = "172.31.13.99"
# AN port
port = 50000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

AN_code = \
"""
def print_hw():
	print "Hello World"
print_hw()
"""

sock.sendto(AN_code, (dst,port))
