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

dst = "172.31.13.1"
port = 50000
net_port = 50001
fi = __file__
route_fi = "./net_routing"

## if network server not running, start it
if not os.path.exists(route_fi):
  print "writing file: %s" % route_fi
  print "file here: %s" % os.getcwd()
  fi_o = open(route_fi,'w')
  fi_o.write("1")
  fi_o.close()

  ##start server
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  HOST = str(anhost.get_ip_address('eth0'))
  sock.bind((HOST,net_port))

  ##send message to neighbors
  #anhost.send_broadcast(dst,open(fi).read(),port)
  
  print "start recv"
  recv_thread = threading.Thread(target=anhost.recv_update(), args=(neighbors,net_port))
  recv_thread.start()

  ## running, want to thread these off.
  while True:
    print "start send"
    send_thread = threading.Thread(target=anhost.send_update(), args=(neighbors,net_port))
    send_thread.start()
    time.sleep(30)

  ##delete file to show we no longer use it
  os.remove(route_fi)
"""

# we should run it locally first to populate, send to self first, then forward.
local = anhost.get_ip_address("eth0")
local_code = anhost.set_src_dst(AN_code, src,dst)
sock.sendto(local_code, (local,port))
