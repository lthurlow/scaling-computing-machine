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

logger.debug("Checking for RIP file: %s" % route_fi)
## start service on this host
if not os.path.exists(route_fi):
  logger.info("Starting RIP server" )
  rip_thread = threading.Thread(target=rip.rip_server, args=(open(fi).read(),\
                                serv_port,net_port,))
  logger.debug("%s Thread: RIP Server" % fi)
  logger.debug("PID: %s" % os.getpid())
  rip_thread.start()
  rip_thread.join()
  logger.debug("RIP Server started")

  t2 = open(route_fi,'w')
  t2.close()
else:
  logger.debug("ROUTE FILE EXISTS- EXIT")


exit(0)
"""

# we should run it locally first to populate, send to self first, then forward.
local_code = anhost.set_src_dst(AN_code, src,dst)
sock.sendto(local_code, (src,port))
