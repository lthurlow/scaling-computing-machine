import socket

# should later use directory service, instead of hard code IP
dst = "10.0.0.3" 
# AN port
port = 50000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

AN_code = """
print "Hello World"
"""

sock.sendto(AN_code, (dst,port))
