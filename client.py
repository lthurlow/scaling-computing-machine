import socket
import anhost

# should later use directory service, instead of hard code IP
dst = "10.0.0.4" 
# AN port
port = 50000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

AN_code = """
def print_hw():
	print "Hello World"
print_hw()
"""

sock.sendto(AN_code, (dst,port))
