import pdb
import pprint
import sys
import time
sys.path.append("./third_party/libs/")
import StringIO

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import pcap, dpkt

import anhost 

def dummy_exec(code):
	# create file-like string to capture output
	codeOut = StringIO.StringIO()
	codeErr = StringIO.StringIO()
	# capture output and errors
	sys.stdout = codeOut
	sys.stderr = codeErr
	exec code
	# restore stdout and stderr
	sys.stdout = sys.__stdout__
	sys.stderr = sys.__stderr__
	#print f(4)
	#s = codeErr.getvalue()
	#print "error:\n%s\n" % s
	#s = codeOut.getvalue()
	#print "output:\n%s" % s
	return str(codeOut.getvalue())

def handle_pkt(eth):
	eth_src  = ':'.join(hex(x) for x in map(ord, eth.src))
	eth_dst  = ':'.join(hex(x) for x in map(ord, eth.dst))
	#eth = dpkt.ethernet.Ethernet(pkt)
	if eth.type != dpkt.ethernet.ETH_TYPE_IP:
		#print "Ethernet pkt"
		return
	ip = eth.data
	#if ip.p == dpkt.ip.IP_PROTO_TCP:
	#print "TCP pkt"
	if ip.p == dpkt.ip.IP_PROTO_UDP:
		#print "UDP pkt"
		ip_src  = '.'.join(str(x) for x in map(ord, ip.src))
		ip_dst  = '.'.join(str(x) for x in map(ord, ip.dst))
		udp     = ip.data
		udp_src = udp.sport
		udp_dst = udp.dport
		udp_data = dummy_exec(str(udp.data))
		print ip_src, ip_dst
		#send(Ether(src=eth_src,dst=eth_dst)/IP(dst=ip_dst,src=ip_src)/UDP(sport=udp_src,dport=udp_dst)/udp_data, iface="eth1", verbose=True)
		send(IP(dst=ip_dst,src=ip_src)/UDP(sport=udp_src,dport=udp_dst)/udp_data, iface="eth1", verbose=True)
	else:
		return




pc = pcap.pcap("eth0")
## ts = timestamp
for ts, raw_pkt in pc:
	pkt = dpkt.ethernet.Ethernet(raw_pkt)
	print "recv: ", ts
	start = time.time()
	handle_pkt(pkt)
	end = time.time()
	print "in handle: ", end - start
	#retran = pcap.pcap("eth1")
	#retran.inject(raw_pkt,len(raw_pkt))
