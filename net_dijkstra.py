import socket # for creating a socket
import re # for pattern matching ip address
import anhost # for all the active node things

dst = "172.31.13.99"
src = anhost.get_ip_address("eth0")

# AN port
port = 50000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

## So here I am actively going to use filenames instead of using prctl to check if a process is
## running.

AN_code = \
"""
## host: update_time
neighbors = {}
import anhost
import socket
import os.path
import time
import threading
import logging
import datetime

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__file__)

dst = "172.31.13.1"
port = 50000
net_port = 50001
lo_port = 10000
fi = __file__
route_fi = "./net_routing"

logger.debug("test")
## if network server not running, start it
if not os.path.exists(route_fi):
  logger.debug("writing file: %s" % route_fi)
  logger.debug("file here: %s" % os.getcwd())
  fi_o = open(route_fi,'w')
  fi_o.write("1")
  fi_o.close()

  
  logger.debug("start recv")
  LHOST = str(anhost.get_ip_address('lo'))
  lsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  lsock.bind((LHOST,lo_port))
  #non-blocking recv.
  lsock.setblocking(0)

  recv_thread = threading.Thread(target=anhost.recv_update, args=(neighbors,net_port, lo_port,))
  recv_thread.start()

  ##send message to neighbors
  anhost.send_broadcast(dst,open(fi).read(),port)

  ## running, want to thread these off.
  logger.debug("start send")
  while True:
    logger.debug("update %s" % datetime.datetime.now())
    send_thread = threading.Thread(target=anhost.send_update, args=(neighbors,net_port))
    send_thread.start()
    time.sleep(5) #just incase non-blocking too much
    d_list = []
    for k,v in neighbors:
      neighbors[k] -= 5
      if neighbors[k] == 0:
        d_list.append(k1)
    for d in d_list:
      del neighbors[d]

    #msg, addr = lsock.recvfrom(4096)
    msg = ""
    if (msg):
      n_update = list(msg)
      for k2 in n_update:
        neighbors[k2] = 60
    logger.info(neighbors)
          

  ##delete file to show we no longer use it
  ##os.remove(route_fi)
"""

# we should run it locally first to populate, send to self first, then forward.
local = anhost.get_ip_address("eth0")
local_code = anhost.set_src_dst(AN_code, src,dst)
sock.sendto(local_code, (local,port))
