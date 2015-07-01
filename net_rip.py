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
import os
import os.path
import time
import threading
import logging
import logging.handlers
import datetime

FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s()] %(levelname)s %(message)s"
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

logger.debug( "Checking for File")
## if network server not running, start it
if not os.path.exists(route_fi):
  logger.debug( "FILE DOES NOT EXIST: %s" % route_fi)
  try:
    fi_o = open(route_fi,'w')
    fi_o.close()
    logger.debug( "starting rip server thread")
    rip_thread = threading.Thread(target=anhost.rip_server, args=(fi,serv_port,net_port,route_fi,))
    rip_thread.start()
    rip_thread.join()

  except Exception,e:
    logger.debug( "deleting route file: %s" % route_fi)
    os.remove(route_fi)
    exit(1)
  except KeyboardInterrupt:
    logger.debug( "deleting route file: %s" % route_fi)
    os.remove(route_fi)
    exit(1)
    
else:
  logger.debug( "FILES EXISTS DO NOTHING")
"""

# we should run it locally first to populate, send to self first, then forward.
local = anhost.get_ip_address("eth0")
local_code = anhost.set_src_dst(AN_code, src,dst)
sock.sendto(local_code, (local,port))
