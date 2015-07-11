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
import sys
sys.path.append("..")
import netaddr

rip_neighbors = []

FORMAT = "[%(filename)s:%(lineno)s - %(threadName)s %(funcName)20s] %(levelname)10s %(message)s"
logging.basicConfig(format=FORMAT)

logger = logging.getLogger("%s | %s | " % (os.getpid(), __file__) )
logger.setLevel(logging.DEBUG)
socketHandler = logging.handlers.SocketHandler('localhost',
                    logging.handlers.DEFAULT_TCP_LOGGING_PORT)
logger.addHandler(socketHandler)

def str_to_dict(str_dict):
  unicode_dict = json.loads(str_dict)
  string_dict = {}
  for k in unicode_dict:
    string_dict[k.encode('utf-8')] = unicode_dict[k].encode('utf-8')
  return string_dict

def bit_mask(mask):
  x = mask.split(".")
  bc = 0
  for k in x:
    bc += bin(int(k)).count("1")
  return str(bc)

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
  logger.debug("\t\tbroadcast done.")

def write_n_fi(n_fi, n_list):
  logger.debug("\t\tWRITE_N_FI")
  x = open(n_fi,'w')
  for k in n_list:
    logger.debug("\t\t\twriting: %s" % k)
    x.write(json.dumps(k)+'\n')
  x.close()

def read_n_fi(n_fi):
  logger.debug("\t\tREAD_N_FI")
  x = open(n_fi,'r')
  neighbor = []
  for l in x:
    p = str_to_dict(l.strip())
    logger.debug("\t\t\tloaded: %s" % p)
    neighbor.append(p)
  x.close()
  logger.info("%s" % neighbor)
  return neighbor

def send_update(sock,n_fi,rip_port,dev):
  global rip_neighbors
  logger.debug("\tSEND_UPDATE")
  ## list of dicts
  n_dict = read_n_fi(n_fi)
  ip_self = sock.getsockname()[0]
  ## before we send out, we should update the gateway to be
  ## this node.
  rip_update = []
  for k in n_dict:
    x = anhost.Route()
    x.set_route(k)
    ## not a class, is dict?
    x.set_gw(anhost.get_ip_address(dev))
    rip_update.append(x.transmit_route())
  data_str = json.dumps(rip_update)

  #sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  #pull neighbors from updates, send to that set
  #for rip_neigh in rip_neighbors:
  #  for route in rip_update:
  #    sock.sendto(data_str, (rip_neigh,rip_port))
  #    logger.debug("\t\tupdate sent to %s" % rip_neigh)
  send_broadcast(anhost.get_ip_address(dev),data_str,rip_port)
  


def send_handler(sock,n_fi,port,dev):
  while True:
    logger.debug("SEND_HANDLER")
    send_update(sock, n_fi,port,dev)
    time.sleep(10)

#FIXME: add routes to linux routing table
def recv_update(neigh_fi,addr, update):
  add_list = []
  up_list = []
  neighbors = read_n_fi(neigh_fi)
  logger.debug("\tRECV_UPDATE")
  logger.debug("\t\tupdate from: %s" % addr)
  current_time = datetime.datetime.now()

  #list of Routes
  logger.debug(pprint.pformat(update))

  for route in update:
    x = anhost.Route()
    x.set_route(route)
    x.update_metric()
    pprint.pprint(x)
    if x.met <= 16:
      net_str = convert_mask(x.dst,x.mask)
      bm = bit_mask(x.mask)
      network = netaddr.IPNetwork("%s/%s" % (x.dst,bm))
      there = False
      for neigh in neighbors:
        bm = bit_mask(neigh.mask)
        have_net = netaddr.IPNetwork("%s/%s" % (neigh.dst,bm))
        if network == have_net:
          there = neighbors[neigh]
          break
      if there:
        add_list.append(x)
      else:
        ## FIXME should make it as int through get function
        if int(x.met) < int(there.met):
          up_list.append(x)

  logger.info("neighbors before add: %s" % neighbors)
  logger.debug("added list: %s" % add_list)
  logger.debug("updated list: %s" % up_list)

  ### need to update and return our modified dict
  # create new neighbor list
  update_neighbors = []
  # add new entries
  for k in add_list:
    k.set_ttl(current_time)
    update_neighbors.append(k.get_route())
    ##FIXME: add to linux route table

  #logger.info("dst_list: %s" % dst_list)
  #logger.info("neighbors: %s" % neighbors)
  logger.info("update neigh: %s" % update_neighbors)

  ## add new updates to replace originals in this update
  for k in up_list:
    k.set_ttl(current_time)
    update_neighbors.append(k.get_route())
  
  ## add original entries not seen in this update
  ## by not adding above, we remove all update entries
  for k in neighbors:
    if k not in update_neighbors:
      if (current_time-k.get_ttl() > datetime.timedelta(minutes=1)):
        logger.info("Route timeout: %s" % k)
        logger.info("current time %s, last update %s"%(current_time,k.get_ttl()))
      else:
        update_neighbors.append(k.get_route())
    ## delete the current linux route table information
    ## FIXME: else:

  logger.debug(pprint.pformat(update_neighbors))
  return update_neighbors

def recv_handler(rip_sock,n_fi):
  global rip_neighbors
  logger.debug("\tRECV_HANDLER")
  #try:
  while True:
    logger.debug("\t\taceepting messages...")
    msg, addr = rip_sock.recvfrom(4096)
    logger.debug("\t\tmessage: %s" % msg)
    logger.debug("\t\tsender's addr: (%s,%s)" % (addr[0],addr[1]))
    ## FIXME need to tie rip_neighbors with a ttl and the route table
    if addr[0] not in rip_neighbors:
      rip_neighbors.append(addr[0])
    update = recv_update(n_fi,addr[0], json.loads(msg))
    write_n_fi(n_fi,update)
    logger.debug("\t\tupdate written out to file.")
    time.sleep(15)
    logger.info("UPDATED NEIGHBORS: %s" % pprint.pformat(read_n_fi(n_fi)))
  #except Exception,e:
  #  logger.error("Recver Error: %s" % str(e))

def rip_server(code, serv_port, rip_port,serv_fi, dev):
  neigh = "%s.rip" % rip_port
  logger.debug("RIP SERVER:")
  logger.debug("PID: %s" % os.getpid())
  logger.debug("DEVICES: %s" % dev)
  local_ip = anhost.get_ip_address(dev)
  # dst : via, cost
  x = open(neigh,'w')
  x.close()
  #write_n_fi(neigh,{local_ip:[local_ip,0]})
  routes = anhost.non_default_routes()
  l_route = []
  for route in routes:
    ## FIXME for kvm - eth0 is management
    if route["Iface"] != "eth0":
      ## default routes gets linux, but now we need to add arbitrary ttl for rip
      ##FIXME change get_routes to use Routes()
      route["TTL"] = datetime.datetime.now().strftime("%Y%j%H%M%S%f")
      l_route.append(route)
  write_n_fi(neigh,l_route)

  logger.debug("\tinitial neighbor list: %s" % read_n_fi(neigh))

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
    send_thread = threading.Thread(target=send_handler,\
                  args=(rip_sock,neigh,rip_port,dev,))
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
