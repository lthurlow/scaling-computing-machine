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

def update_ttls(neighbors):
  logger.debug("\t\tUPDATE_TTLS")
  current_time = datetime.datetime.now()
  n_neigh = []
  for k in neighbors:
    p = anhost.Route()
    p.set_route(k)
    p.set_ttl(current_time)
    n_neigh.append(p.transmit_route())
    logger.debug("updated ttl: %s" % p.get_route())
  return n_neigh
    
  
def check_timeout(fi,neighbors,mgmt,dev):
  logger.debug("\t\tCHECK_TIMEOUT")
  current_time = datetime.datetime.now()
  new_neigh = []

  for k in neighbors:
    r = anhost.Route()
    r.set_route(k)
    ## this will make our default routes in the lists not be dropped.
    ## if we are the owner of this route, we should update it.
    if (r.get_iface() == dev):
      if r.get_gw() != "0.0.0.0":
        if (current_time-r.get_ttl() > datetime.timedelta(minutes=2)):
          logger.info("Route timeout: %s" % k)
          logger.info("\t\t\tCurrent time %s, last update %s"%(current_time,r.get_ttl()))
        else:
          new_neigh.append(r.transmit_route())
      else:
        new_neigh.append(r.transmit_route())
    ## the device is not owned by us, and has not been set to free
    ## therefore the owner of the device should only be allow to remove it.
    else:
      new_neigh.append(r.transmit_route())

  logger.debug("\t\t\tRoute table after Check: %s" % new_neigh)
  write_n_fi(fi,new_neigh)
  anhost.modify_linux_tables(new_neigh,mgmt)
  return new_neigh

def send_update(sock,n_fi,rip_port,dev,mgmt):
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
    #x.set_gw(anhost.get_ip_address(dev))
    rip_update.append(x.transmit_route())

  rip_update = check_timeout(n_fi,rip_update,mgmt,dev)
  rip_checked = []
  for k in rip_update:
    x = anhost.Route()
    x.set_route(k)
    x.set_gw(anhost.get_ip_address(dev))
    rip_checked.append(x.transmit_route())
  
 
  data_str = json.dumps(rip_checked)
  logger.debug("\t\tMSG: %s" % data_str)

  anhost.send_broadcast(anhost.get_ip_address(dev),data_str,rip_port)
  anhost.send_to_local_interfaces(data_str,dev,mgmt,rip_port)
  


def send_handler(sock,n_fi,port,dev,mgmt):
  while True:
    logger.debug("SEND_HANDLER")
    send_update(sock, n_fi,port,dev,mgmt)
    time.sleep(10)

def recv_update(neigh_fi,addr, dev,mgmt, update):
  add_list = []
  up_list = []
  neighbors = read_n_fi(neigh_fi)
  logger.debug("\tRECV_UPDATE")
  logger.debug("\t\tupdate from: %s" % addr)
  logger.debug("\t\t\tmsg: %s" % update)
  
  #neighbors = update_ttls(neighbors)
  neighbors = check_timeout(neigh_fi,neighbors,mgmt,dev)
  current_time = datetime.datetime.now()

  for route in update:
    x = anhost.Route()
    x.set_route(route)
    x.update_metric()
    ## change the interface value to the one it was recieved by
    x.set_iface(dev)
    # RIP prevent CTI
    if int(x.met) < 16:
      bm = bit_mask(x.mask)
      network = netaddr.IPNetwork("%s/%s" % (x.dst,bm))
      there = False
      for neigh in neighbors:
        y = anhost.Route()
        y.set_route(neigh)
        bm = bit_mask(y.mask)
        have_net = netaddr.IPNetwork("%s/%s" % (y.dst,bm))
        logger.debug("\t\t\ttesting %s and %s" % (have_net,network))
        if network == have_net:
          logger.debug("\t\t\tsame net")
          there = True
          if x.get_count() < y.get_count():
            logger.debug("\t\t\tUPDATING W/ better hop: %s" % x.get_route())
            add_list.append(x)
          else:
            logger.debug("\t\t\tUPDATING old route: %s" % y.get_route())
            if y.get_iface() == dev:
              add_list.append(y)
            else:
              logger.debug("\t\t\t\theard from different interface, ignoring")
          break
      if not there:
        logger.debug("\t\t\tADDING: %s" % x.get_route())
        add_list.append(x)

  logger.debug("getting added:")
  logger.debug("getting updated")

  ### need to update and return our modified dict
  # create new neighbor list
  update_neighbors = []
  # add new entries
  for k in add_list:
    k.set_ttl(current_time)
    update_neighbors.append(k.transmit_route())
    ##FIXME: add to linux route table

  ## accidently deleted, need this for when the route is updated for that round
  for k in neighbors:
    there = False
    for p in update_neighbors:
      if anhost.same_route(k,anhost.uni_decode(p)):
        logger.info("same:\n%s\n%s" % (k,anhost.uni_decode(p))) 
        there = True
    if not there:
      update_neighbors.append(k)

  logger.info("FINAL route table: %s" % update_neighbors)
  return update_neighbors

def recv_handler(rip_sock,dev,mgmt,n_fi):
  logger.debug("\tRECV_HANDLER")
  #try:
  while True:
    logger.debug("\t\taceepting messages...")
    msg, addr = rip_sock.recvfrom(4096)
    logger.debug("\t\tmessage: %s" % msg)
    logger.debug("\t\tsender's addr: (%s,%s)" % (addr[0],addr[1]))
    update = recv_update(n_fi,addr[0], dev,mgmt,json.loads(msg))
    write_n_fi(n_fi,update)
    logger.debug("\t\tupdate written out to file.")
    time.sleep(15)
    logger.info("UPDATED NEIGHBORS: %s" % read_n_fi(n_fi))
  #except Exception,e:
  #  logger.error("Recver Error: %s" % str(e))

def rip_server(code, serv_port, rip_port, dev, mgmt):
  neigh = "%s.rip" % rip_port
  logger.debug("RIP SERVER:")
  logger.debug("PID: %s" % os.getpid())
  logger.debug("DEVICES: %s" % dev)
  local_ip = anhost.get_ip_address(dev)

  l_route = []
  routes = anhost.non_default_routes()

  ##this write needs to have guards to make sure it doesnt wipe out another
  ##interfaces update
  ##FIXME: Clean this code up later
  if not os.path.exists(neigh):
    x = open(neigh,'w')
    x.close()
    for route in routes:
      if route["Iface"] != mgmt:
        ## default routes gets linux, but now we need to add arbitrary ttl for rip
        ##FIXME change get_routes to use Routes()
        x = anhost.Route()
        x.set_route(route)
        x.set_ttl(datetime.datetime.now())
        l_route.append(x.transmit_route())
  else:
    prev_routes = read_n_fi(neigh)
    for proute in prev_routes:
      y = anhost.Route()
      y.set_route(proute)
      y.set_ttl(datetime.datetime.now())
      there = False
      for route in routes:
        x = anhost.Route()
        x.set_route(route)
        x.set_ttl(datetime.datetime.now())
        if anhost.same_route(x,y):
          there = True
      if not there:
        l_route.append(y)
      else:
        l_route.append(x)
        
  write_n_fi(neigh,l_route)

  logger.debug("\tinitial neighbor list: %s" % read_n_fi(neigh))

  #set up rip server socket
  rip_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  rip_sock.bind((local_ip,rip_port))
  rip_sock.setblocking(1) # blocking recv

  ## start rip on neighbors
  anhost.send_broadcast(local_ip, code,serv_port)

  try:
    ## recver thread
    recv_thread = threading.Thread(target=recv_handler,\
                        args=(rip_sock,dev,mgmt,neigh,))
    recv_thread.start()
  except Exception,e:
    logger.error("Receving Thread Error")
    raise Exception(e)

  try:
    ## sender thread
    send_thread = threading.Thread(target=send_handler,\
                  args=(rip_sock,neigh,rip_port,dev,mgmt,))
    send_thread.start()
  except Exception,e:
    logger.error("Sending Thread Error")
    raise Exception(e)

  try:
    recv_thread.join()
    send_thread.join()
  except KeyboardInterrupt:
    logging.info("\tServer killed by Ctrl-C")
    os.remove(neigh)
    raise KeyboardInterrupt
  except Exception, e:
    logging.error("\tRIP Server Crash: %s" % e)
    os.remove(neigh)
    raise Exception(e)
