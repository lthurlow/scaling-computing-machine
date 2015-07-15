import socket # for creating a socket
import re # for pattern matching ip address
import sys
sys.path.append("..")
from anhost import anhost# for all the active node things

src = anhost.get_ip_address("eth1")
dst = src

# AN port
port = 50000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

## So here I am actively going to use filenames instead of using prctl to check if a process is
## running.

AN_code = \
"""
## host: update_time
neighbors = {}
import socket
import os
import os.path
import time
import threading
import logging
import logging.handlers
import datetime
import sys
sys.path.append("..")
from anhost import anhost
from anhost import rip

FORMAT = "[%(filename)s:%(lineno)s - %(funcName)s()] %(levelname)s %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("%s | %s |" % (os.getpid(), __file__) )
#logger = logging.getLogger(FORMAT)
logger.setLevel(logging.DEBUG)
socketHandler = logging.handlers.SocketHandler('localhost',
                    logging.handlers.DEFAULT_TCP_LOGGING_PORT)
logger.addHandler(socketHandler)

serv_port = 50000 #active node server
net_port = 50001 # rip port to use
fi = __file__ # file name
route_fi = ".route_rip" #server file flag

mgmt_dev = "eth0"
iface = "eth1"
visit = ["eth1"]
temp = route_fi + iface

logger.debug("Checking for RIP file: %s" % temp)

iface_list = anhost.sim_routes(mgmt_dev)
this_iface_l = []
for ifaces in iface_list:
  dev_iface = ifaces["Iface"]
  this_iface_l.append(dev_iface)
  if dev_iface not in visit and dev_iface != mgmt_dev:
    anhost.chg_val(fi,"","iface",dev_iface,"w")
    anhost.chg_val(fi,[],"visit",dev_iface,"a")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    iface_ip = anhost.get_ip_address(dev_iface)
    sock.sendto(open(fi).read(), (iface_ip,serv_port))

## start service on this host
if not os.path.exists(temp) and iface != mgmt_dev and iface in this_iface_l:
  logger.info("Starting RIP server on [%s]" % (iface))
  rip_thread = threading.Thread(target=rip.rip_server, args=(open(fi).read(),\
                                serv_port,net_port,iface,mgmt_dev,))
  logger.debug("%s Thread: RIP Server" % fi)
  logger.debug("PID: %s" % os.getpid())
  rip_thread.start()
  rip_thread.join()
  logger.debug("RIP Server started")

  t2 = open(temp,'w')
  t2.close()
else:
  logger.debug("ROUTE FILE EXISTS- EXIT")


exit(0)
"""

# we should run it locally first to populate, send to self first, then forward.
local_code = anhost.set_src_dst(AN_code, src,dst)
sock.sendto(local_code, (src,port))
