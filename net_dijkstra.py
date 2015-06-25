import socket # for creating a socket
import re # for pattern matching ip address
import anhost # for all the active node things

dst = "172.31.13.99"
src = anhost.get_ip_address("eth0")

# AN port
port = 50000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

AN_code = \
"""
import anhost
import socket

dst = "172.31.13.1"
port = 50000
fi = __file__

anhost.send_broadcast(dst,open(fi).read(),port)
"""
# we should run it locally first to populate, send to self first, then forward.
local = anhost.get_ip_address("eth0")
local_code = anhost.set_src_dst(AN_code, src,dst)
sock.sendto(local_code, (local,port))
