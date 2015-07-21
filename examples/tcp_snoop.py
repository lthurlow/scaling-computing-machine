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
from anhost import snoop

FORMAT = "[%(filename)s:%(lineno)s - %(funcName)s()] %(levelname)s %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("%s | %s |" % (os.getpid(), __file__) )
logger.setLevel(logging.DEBUG)

serv_port = 50000 #active node server
net_port = 80001
fi = __file__ # file name
snoop = ".snoop"
## we are only going to snoop up to 3 hops away for statistics
net_thresh = 3

logger.debug("Checking for RIP file: %s" % route_fi)
## start service on this host
if anhost.service_running(snoop):
  logger.info("Starting SNOOP" )
  snoop_thread = threading.Thread(target=snoop.snoop_server, args=(open(fi).read(),\
                                serv_port,net_port,))
  logger.debug("%s Thread: SNOOP Server" % fi)
  logger.debug("PID: %s" % os.getpid())
  snoop_thread.start()
  snoop_thread.join()
  logger.debug("RIP Server started")

  t2 = open(route_fi,'w')
  t2.close()
else:
  logger.debug("Snoop already running")

exit(0)
"""

# we should run it locally first to populate, send to self first, then forward.
local_code = anhost.set_src_dst(AN_code, src,dst)
sock.sendto(local_code, (src,port))
