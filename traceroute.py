import socket # for creating a socket
import fcntl  # for get_ip_address
import struct # for get_ip_address
import anhost

# should later use directory service, instead of hard code IP
#dst = "172.31.13.99"
dst = "puertocayo.soe.ucsc.edu"
# AN port
port = 50000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

AN_code = \
"""
hop = []
trace = []
import anhost as an
import socket as sk
import datetime as dt
import time
dn = time.mktime(dt.datetime.now().timetuple())
dst = "128.114.52.22"
src = "128.114.52.25"
sport = 50000
fin = 0
tmr = 0
fi = __file__
sock = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
ch = an.get_ip_address("eth0")
this_file = open(str(fi),'r')
udp_data = this_file.read()
this_file.close()
if not fin:
  if ch == src:
    an.chg_val(fi,0.0,"tmr",dn,'w')
  else:
    an.chg_val(fi,[],"hop",ch,'a')
    if tmr:
      an.chg_val(fi,[],"trace",dn-tmr,'a')
      an.chg_val(fi,[],"tmr",dn,'w')
    else:
      an.chg_val(fi,0.0,"tmr",dn,'w')
    if ch == dst:
      an.chg_val(fi,[],"fin",1,'w')
      tmp = dst
      an.chg_val(fi,"","dst",src,'w')
      an.chg_val(fi,"","src",tmp,'w')
else:
  if ch == src:
    iter = 0
    for hop in trace:
      iter +=1
      print "%d\t%s" % (iter,hop)
sock.sendto(open(fi).read(), (dst,50000))
"""
# we should run it locally first to populate, send to self first, then forward.
local = anhost.get_ip_address("eth0")
sock.sendto(AN_code, (local,port))
