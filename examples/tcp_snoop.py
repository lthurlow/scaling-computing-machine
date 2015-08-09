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
sys.path.append("../python-tcpsnoop")
import snoop

FORMAT = "[%(filename)s:%(lineno)s - %(funcName)s()] %(levelname)s %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("%s | %s |" % (os.getpid(), __file__) )
logger.setLevel(logging.DEBUG)

serv_port = 50000 #active node server
net_port = 80005
fi = __file__ # file name
tcp_fi = ".snoop_fi".strip()

## start service on this host
if not anhost.service_running(tcp_fi):

  logger.info("Starting SNOOP" )
  t2 = open(tcp_fi,'w')
  t2.close()

  snoop_thread = threading.Thread(target=snoop.start_snoop, args=(["eth1","eth2"],"NFQUEUE",1,))
  logger.debug("%s Thread: SNOOP Server" % fi)
  logger.debug("PID: %s" % os.getpid())
  snoop_thread.start()
  snoop_thread.join()
  logger.debug("SNOOP Server started")

else:
  logger.debug(os.getcwd())
  logger.debug(os.listdir("."))
  logger.debug("Snoop already running")




exit(0)
"""

# we should run it locally first to populate, send to self first, then forward.
local_code = anhost.set_src_dst(AN_code, src,dst)
sock.sendto(local_code, (src,port))
