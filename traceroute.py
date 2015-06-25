import socket # for creating a socket
#import fcntl  # for get_ip_address
#import struct # for get_ip_address
import re # for pattern matching ip address
import anhost

def help_traceroute():
  print("\ttraceroute -- print the route packets take to active network hosts")
  print()
  print("\tuse: traceroute host")
  return

def traceroute(args):
  re_ip = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
  if not re_ip.match(str(args)):
    help_traceroute()
    return
  # should later use directory service, instead of hard code IP
  dst = str(args)
  src = anhost.get_ip_address("eth0")
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
dn = an.get_time()
dst = ""
src = ""
fin = 0
tmr = 0
fi = __file__
sock = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
ch = an.get_ip_address("eth0")
if not fin:
  if ch == src:
    an.chg_val(fi,0.0,"tmr",dn,'w')
  else:
    an.chg_val(fi,[],"hop",ch,'a')
    if tmr:
      print type(dn),type(tmr)
      an.chg_val(fi,[],"trace",tmr-dn,'a')
      an.chg_val(fi,0.0,"tmr",dn,'w')
    if ch == dst:
      an.chg_val(fi,0,"fin",1,'w')
      tmp = dst
      an.chg_val(fi,"","dst",src,'w')
      an.chg_val(fi,"","src",tmp,'w')
  sock.sendto(open(fi).read(), (dst,50000))
else:
  if ch == dst:
    iter = 0
    for h,tr in zip(hop,trace):
      iter +=1
      print "%4s\t%20s\t%4s" % ("hop","host","delay")
      print "%4d\t%20s\t%4s" % (iter,h,tr)
  else:
    sock.sendto(open(fi).read(), (dst,50000))
"""
  # we should run it locally first to populate, send to self first, then forward.
  local = anhost.get_ip_address("eth0")
  local_code = anhost.set_src_dst(AN_code, src,dst)
  print local_code
  sock.sendto(local_code, (local,port))
  #sock.sendto(AN_code, (local,port))
