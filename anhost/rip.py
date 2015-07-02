import logging
import socket
import datetime
import time
import os
import logging
import logging.handlers
import anhost
import pprint


FORMAT = "[%(filename)s:%(lineno)s - %(threadName)s %(funcName)s] %(levelname)20s %(message)s"
logging.basicConfig(format=FORMAT)

logger = logging.getLogger("%s | %s | " % (os.getpid(), __file__) )
logger.setLevel(logging.DEBUG)
socketHandler = logging.handlers.SocketHandler('localhost',
                    logging.handlers.DEFAULT_TCP_LOGGING_PORT)
logger.addHandler(socketHandler)

## short simple code to just broadcast unicast message
def send_broadcast(local_ip,msg,port):
  logger.debug("\tSEND_BROADCAST")
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  prefix = '.'.join(local_ip.split(".")[0:3])+'.'
  suff = local_ip.split(".")[-1]
  logger.debug("\t\tbroadcasting to: %s*" % prefix)
  logger.debug("\t\tnot sending to: %s" % prefix+suff)
  for i in range(1,254):
    if i != int(suff):
      sock.sendto(msg, (prefix+str(i),port))
    else:
      logger.debug(i)
  logger.debug("broadcast done.")

def write_n_fi(n_fi, n_dict):
  x = open(n_fi,'w')
  for k,v in n_dict:
    x.write(k+','+v[0]+','+v[1])
  x.close()

def read_n_fi(n_fi):
  x = open(n_fi,'r')
  neighbor = {}
  for l in x:
    k = l.split(',')
    neighbor.update({k[0]:[k[1],k[2]]})
  x.close()
  return neighbor

def send_update(sock,n_fi):
  logger.debug("sending update")
  sock.sendto(n_list)
  logger.debug("update sent")

def recv_update(n_fi, addr, update):
  add_list = []
  up_list = []
  dst_list = [x for x in up_list] # dst key list
  logger.debug("\tRECV_UPDATE")
  logger.debug("\t\tupdate from: %s" % addr)
  logger.debug("\t\toriginal list: %s" % neighbors)
  logger.debug("\t\tneighbor's list: %s" % update)

  #add newly discovered nodes
  for node in update:
    cost = update[node][1] + 1 #add cost to us
    if node not in dst_list:
      add_list.append({node:[addr,cost]})
  #update old cost updates
    else:
      ## cost strictly less than, otherwise no upd
      if cost < neighbors[node][1]:
        up_list.append({node:[addr,cost]})


  logger.debug("added list: %s" % add_list)
  logger.debug("updated list: %s" % up_list)

  # need to update and return our modified dict
  dst_list = []
  if up_list:
    dst_list = [i.keys()[0] for i in up_list]
    #for i in up_list:
    #  dst_list.append(i.keys()[0])
  # new dict
  update_neighbors = {}
  # add new entries
  for k in add_list:
    update_nighbors.update(k)

  # add original entries
  for k in neighbors:
    # add original entries
    if k not in dst_list:
      update_neighbors.update(neighbors[k])
    # add updated entries
    else:
      for i in up_list:
        if k == i.keys()[0]:
           update_neighbors.update(up_list[i])

  logger.debug(pprint.format(update_neighbors))
  return update_neighbors

def rip_server(code, serv_port, rip_port,serv_fi):
  neigh = "%s.rip" % rip_port
  logger.debug("RIP SERVER:")
  logger.debug("PID: %s" % os.getpid())
  local_ip = get_ip_address("eth0")
  # dst : via, cost
  n_list = {local_ip:[local_ip,0]}
  
  logger.debug("\tinitial neighbor list: %s" % n_list)

  #set up rip server socket
  rip_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  rip_sock.bind((local_ip,rip_port))
  rip_sock.setblocking(1) # blocking recv

  ## start rip on neighbors
  send_broadcast(local_ip, code,serv_port)

  try:
    while True:
      logger.debug("\taceepting messages...")
      msg, addr = rip_sock.recvfrom(4096)
      logger.debug("\tmessage: %s" % msg)
      logger.debug("\tsender's addr: %s" %addr)
      n_list = recv_update(n_list, addr, dict(msg))
      send_update(serv_sock, n_list)
      time.sleep(10)
  except KeyboardInterrupt:
    logging.info("\tServer killed by Ctrl-C")
    os.remove(serv_fi)
    os.remove(neigh)
  except Exception, e:
    logging.error("\tRIP Server Crash: %s" % e)
    os.remove(serv_fi)
    os.remove(neigh)
