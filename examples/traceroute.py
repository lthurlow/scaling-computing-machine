import socket # for creating a socket
import re # for pattern matching ip address
import logging
import logging.handlers
import os

import sys
sys.path.append("..")
from anhost import anhost
from anhost import inputs

FORMAT = "[%(filename)s:%(lineno)s - %(threadName)s %(funcName)20s] %(levelname)10s %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("%s | %s | " % (os.getpid(), __file__) )
logger.setLevel(logging.DEBUG)

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
  # AN port
  src = anhost.get_ip_address('eth1')
  port = 50000
  """
  inf, po = inputs.user()
  if inf:
    src = anhost.get_ip_address(inf)
  if po:
    port = po
  print("Connecting to: %s on port: %s" % (dst,port))
  """
  
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  AN_code = \
"""
import socket as sk
import datetime as dt
import threading
import logging
import os

import sys
sys.path.append("..")
from anhost import anhost

FORMAT = "[%(filename)s:%(lineno)s - %(threadName)s %(funcName)20s] %(levelname)10s %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("%s | %s | " % (os.getpid(), __file__) )
logger.setLevel(logging.DEBUG)

hop = []
trace = []

mgmt = "eth0"
lh = ""
dn = anhost.get_time()
dst = ""
src = ""
fin = 0
tmr = 0
fi = __file__
sock = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
ch = ""
## get the last hop, see which interface its asciated with, then get ip
if lh:
  ch = anhost.get_ip_address(anhost.get_interface(lh,mgmt))
else:
  ## we assume this is the source host then
  ch = anhost.get_ip_address(anhost.get_interface(dst,mgmt))
  
logger.debug("fin flag set: %s" % fin)
logger.debug("last host: %s" % lh)
logger.debug("current host: %s" % ch)
anhost.chg_val(fi,"","lh",ch,'w')
logger.debug("updated last host: %s" % ch)

new_dst = anhost.get_forward_ip(dst)

if not fin:
  if ch == src:
    logger.debug("on sender, setting timer: %s" % dn)
    anhost.chg_val(fi,0.0,"tmr",dn,'w')
  else:
    anhost.chg_val(fi,[],"hop",ch,'a')
    if tmr:
      print type(dn),type(tmr)
      anhost.chg_val(fi,[],"trace",dn-tmr,'a')
      anhost.chg_val(fi,0.0,"tmr",dn,'w')
    if ch == dst or anhost.check_same_host(ch,dst,mgmt):
      anhost.chg_val(fi,0,"fin",1,'w')
      tmp = dst
      anhost.chg_val(fi,"","dst",src,'w')
      anhost.chg_val(fi,"","src",tmp,'w')
      new_dst = anhost.get_forward_ip(src)
  logger.debug("sending to: %s" % dst)
  logger.debug("checking route table for interface/ip")
  logger.debug("selected forward interface: %s" % new_dst)
  sock.sendto(open(fi).read(), (new_dst,50000))
  #sock.sendto(open(fi).read(), ("10.0.0.2",50000))
else:
  if ch == dst:
    iter = 0
    for h,tr in zip(hop,trace):
      iter +=1
      print "%4s\t%20s\t%4s" % ("hop","host","delay")
      print "%4d\t%20s\t%4s" % (iter,h,tr)
  else:
    logger.debug("sending to: %s" % dst)
    sock.sendto(open(fi).read(), (new_dst,50000))


#trace = threading.Thread(target=function,args=(,))
#trace.start()
#trace.join()
"""
  # we should run it locally first to populate, send to self first, then forward.
  local_code = anhost.set_src_dst(AN_code, src,dst)
  sock.sendto(local_code, (src,port))

if __name__ == '__main__':
  dst = raw_input("Destination: ")
  traceroute(dst)
