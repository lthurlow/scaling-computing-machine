import pdb          # for debuggin
import sys
import time
import pprint 

import fcntl  # for get_ip_address
import struct # for get_ip_address


import SocketServer # for UDPServer
import threading # for threading UDPServer
import socket # for UDPServer

sys.path.append("./third_party/libs/") # for scapy
import StringIO # for dummy_exec

import logging # for logging, scapy modify logging level
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

import anhost  # linux networking files

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

def set_env():
	return

def dummy_exec(code):
	# create file-like string to capture output
	codeOut = StringIO.StringIO()
	codeErr = StringIO.StringIO()
	# capture output and errors
	sys.stdout = codeOut
	sys.stderr = codeErr
	try:
		exec code
	except:
		sys.stdout = "error"
		sys.stderr = "error"
	# restore stdout and stderr
	sys.stdout = sys.__stdout__
	sys.stderr = sys.__stderr__

	#For now throw away the errors
	return str(codeOut.getvalue())

def handle_pkt(eth):
	eth_src  = ':'.join(hex(x) for x in map(ord, eth.src))
	eth_dst  = ':'.join(hex(x) for x in map(ord, eth.dst))
	if eth.type != dpkt.ethernet.ETH_TYPE_IP:
		#print "Ethernet pkt"
		return
	ip = eth.data
	if ip.p == dpkt.ip.IP_PROTO_UDP:
		ip_src  = '.'.join(str(x) for x in map(ord, ip.src))
		ip_dst  = '.'.join(str(x) for x in map(ord, ip.dst))
		udp     = ip.data
		udp_src = udp.sport
		udp_dst = udp.dport
		udp_data = dummy_exec(str(udp.data))
		print ip_src, ip_dst
		send(IP(dst=ip_dst,src=ip_src)/UDP(sport=udp_src,dport=udp_dst)/udp_data,\
			 iface="eth1", verbose=True)
	else:
		return



HOST, PORT = str(get_ip_address('eth0')), 50000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST,PORT))

while True:
	msg, addr = sock.recvfrom(1024)
	print "msg:", msg
    	server_thread = threading.Thread(target=dummy_exec,args=(msg,))
	server_thread.start()
	server_thread.join()


"""
class MyUDPHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        print "%s wrote: " % self.client_address[0]
	print self.request[0]
	out = dummy_exec(self.request[0])
	#print "code output: %s" % out
        socket.sendto(((self.request[0]).strip()).upper(), self.client_address)

if __name__ == "__main__":
    HOST, PORT = str(get_ip_address('eth0')), 50001
    server = SocketServer.UDPServer((HOST, PORT), MyUDPHandler)
    #server.serve_forever()
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    while True:
	pass
"""

