import logging
import socket
import datetime
import time
import os
import logging
import logging.handlers
import pprint
import threading
import anhost
import json


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
  for k in n_dict:
    x.write(k+','+n_dict[k][0]+','+n_dict[k][1])
  x.close()

def read_n_fi(n_fi):
  x = open(n_fi,'r')
  neighbor = {}
  for l in x:
    k = l.split(',')
    neighbor.update({k[0]:[k[1],k[2]]})
  x.close()
  return neighbor

def send_update(sock,n_fi,rip_port):
  logger.debug("sending update")
  n_dict = read_n_fi(n_fi)
  ip_self = sock.getsockname()[0]
  data_str = json.dumps(n_dict)
  send_broadcast(ip_self,data_str,rip_port)
  #FIXME, dont broadcast
  #for k in n_dict:
  #  if k != ip_self:
  #    sock.sendto(k,n_dict)
  logger.debug("update sent")

def send_handler(sock,n_fi,port):
  while True:
    logger.debug("Sending update")
    send_update(sock, n_fi,port)
    time.sleep(10)

def recv_update(neigh_fi,addr, update):
  add_list = []
  up_list = []
  dst_list = [x for x in up_list] # dst key list
  neighbors = read_n_fi(neigh_fi)
  logger.debug("\tRECV_UPDATE")
  logger.debug("\t\tupdate from: %s" % addr[0])
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

  logger.debug(pprint.pformat(update_neighbors))
  return update_neighbors

def recv_handler(rip_sock,n_fi):
  #try:
  while True:
    logger.debug("\taceepting messages...")
    msg, addr = rip_sock.recvfrom(4096)
    logger.debug("\tmessage: %s" % msg)
    logger.debug("\tsender's addr: (%s,%s)" % (addr[0],addr[1]))
    update = recv_update(n_fi,addr, json.loads(msg))
    write_n_fi(n_fi,update)
    logger.debug("\tupdate written out to file.")
    time.sleep(15)
  #except Exception,e:
  #  logger.error("Recver Error: %s" % str(e))

def rip_server(code, serv_port, rip_port,serv_fi):
  neigh = "%s.rip" % rip_port
  logger.debug("RIP SERVER:")
  logger.debug("PID: %s" % os.getpid())
  local_ip = anhost.get_ip_address("eth0")
  # dst : via, cost
  x = open(neigh,'w')
  x.close()
  write_n_fi(neigh,{local_ip:[local_ip,0]})
  
  
  logger.debug("\tinitial neighbor list: %s" % n_list)

  #set up rip server socket
  rip_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  rip_sock.bind((local_ip,rip_port))
  rip_sock.setblocking(1) # blocking recv

  ## start rip on neighbors
  send_broadcast(local_ip, code,serv_port)

  try:
    ## recver thread
    recv_thread = threading.Thread(target=recv_handler, args=(rip_sock,neigh,))
    recv_thread.start()
  except Exception,e:
    logger.error("Receving Thread Error")
    raise Exception(e)

  try:
    ## sender thread
    send_thread = threading.Thread(target=send_handler, args=(rip_sock,neigh,rip_port))
    send_thread.start()
  except Exception,e:
    logger.error("Sending Thread Error")
    raise Exception(e)

  try:
    recv_thread.join()
    send_thread.join()
  except KeyboardInterrupt:
    logging.info("\tServer killed by Ctrl-C")
    os.remove(serv_fi)
    os.remove(neigh)
    raise KeyboardInterrupt
  except Exception, e:
    logging.error("\tRIP Server Crash: %s" % e)
    os.remove(serv_fi)
    os.remove(neigh)
    raise Exception(e)
