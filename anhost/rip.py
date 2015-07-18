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
import select
sys.path.append("..")
import netaddr


## global logging infromation
FORMAT = "[%(filename)s:%(lineno)s - %(threadName)s %(funcName)20s] %(levelname)10s %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("%s | %s | " % (os.getpid(), __file__) )
logger.setLevel(logging.DEBUG)
socketHandler = logging.handlers.SocketHandler('localhost',
                    logging.handlers.DEFAULT_TCP_LOGGING_PORT)
logger.addHandler(socketHandler)

## file mutex for consistant state on routing table between interfaces
mutex = threading.Lock()
recv_mutex = threading.Lock()

## convert json's unicode entries to string for comparisions
def str_to_dict(str_dict):
  unicode_dict = json.loads(str_dict)
  string_dict = {}
  for k in unicode_dict:
    string_dict[k.encode('utf-8')] = unicode_dict[k].encode('utf-8')
  return string_dict

## get the / netmask value for route comparision /24 vs /25
def bit_mask(mask):
  x = mask.split(".")
  bc = 0
  for k in x:
    bc += bin(int(k)).count("1")
  return str(bc)

## write to the rip route file, should be protected write access
def write_n_fi(n_fi, n_list):
  mutex.acquire()
  logger.debug("WRITE_N_FI")
  x = open(n_fi,'w')
  for k in n_list:
    logger.debug("\twriting: %s" % k)
    x.write(json.dumps(k)+'\n')
  x.close()
  mutex.release()

## read from the rip route file, synchronized reads for consistant state
## return a list of dictionaries, synonymous with anhost.Route class
def read_n_fi(n_fi):
  mutex.acquire()
  logger.debug("READ_N_FI")
  x = open(n_fi,'r')
  neighbor = []
  for l in x:
    p = str_to_dict(l.strip())
    logger.debug("\tloaded: %s" % p)
    neighbor.append(p)
  x.close()
  logger.info("%s" % neighbor)
  mutex.release()
  return neighbor

## check timeout makes sure to timeout stale routes
## gets called by both recieve and send in a timely fashion
def check_timeout(fi,neighbors,mgmt,dev):
  logger.debug("CHECK_TIMEOUT (%s) " % dev)
  current_time = datetime.datetime.now()
  new_neigh = []
  ##for each route in the route file
  ##  check if the route is owned by the device calling check_timeout
  ##    if it is, the device, can timeout the route - thereby killing it
  ##    if not owned by the device, do nothing.
  for k in neighbors:
    r = anhost.Route()
    r.set_route(k)

    if (r.get_iface() == dev):
      if (current_time-r.get_ttl() > datetime.timedelta(minutes=2)):
        ## this branch will timeout a route if and only if we own it
        logger.info("Route timeout: %s" % k)
        logger.info("\t\t\tCurrent time %s, last update %s"%(current_time,r.get_ttl()))
      else:
        ## we will have seperate code to force interfaces with installed routes
        ## to not timeout on their own host (if the interface does go down, it will
        ## break the server, so that will require fixing.
        if r.get_gw() == anhost.default_gw:
          r.set_ttl(current_time)
        ## if it is under the timeout value, add the route again, dont touch ttl
        ## that should only be handled by recieving on an update of the route.
        new_neigh.append(r.transmit_route())

    ## the device is not owned by us
    ## therefore the owner of the device should only be allow to remove it.
    else:
      new_neigh.append(r.transmit_route())

  logger.debug("\tRoute table after Check: %s" % new_neigh)
  write_n_fi(fi,new_neigh)
  anhost.modify_linux_tables(new_neigh,mgmt)
  return new_neigh

## send updates from current device to all link local devices
## see FIX comment below
def send_update(sock,n_fi,rip_port,dev,mgmt):
  logger.debug("SEND_UPDATE (%s)" % dev)
  ## get our current routes from file
  n_dict = read_n_fi(n_fi)
  ip_self = sock.getsockname()[0]
  ## convert from route table to Route, from route into expected string format
  rip_update = []
  for k in n_dict:
    x = anhost.Route()
    x.set_route(k)
    rip_update.append(x.transmit_route())

  ## check to see if in the absence of recieve_update, a route has timed-out
  rip_update = check_timeout(n_fi,rip_update,mgmt,dev)

  rip_checked = []
  for k in rip_update:
    x = anhost.Route()
    x.set_route(k)
    ## before we send out, we change the gw to be this node's ip
    x.set_gw(anhost.get_ip_address(dev))
    rip_checked.append(x.transmit_route())
  
  ## convert from dictionary to json for transmission
  data_str = json.dumps(rip_checked)
  logger.debug("\tSENT MSG: %s" % data_str)

  ##FIXME: This should be a traditional unicast message, but for simplicity
  ##       it is just easier to broadcast to all local network interfaces
  anhost.send_broadcast(anhost.get_ip_address(dev),data_str,rip_port)

## keep-alive sending interface
def send_handler(sock,n_fi,port,dev,mgmt):
  ## once every time interval schedule a send to neighbors
  while True:
    logger.debug("SEND_HANDLER")
    send_update(sock, n_fi,port,dev,mgmt)
    time.sleep(10)

## handle the updates recieved by neighbors
## XXX here
def recv_update(neigh_fi,addr, dev,mgmt, update):
  ## only allow one update to happen at a time to maintain
  ## consistancy when reading and writing to the route table file
  recv_mutex.acquire()

  add_list = []
  up_list = []
  neighbors = read_n_fi(neigh_fi)
  logger.debug("RECV_UPDATE (%s)" % dev)
  logger.debug("\tfrom: %s" % addr)
  logger.debug("\tRECV MSG: %s" % update)
  
  ## before we check our current message, lets check timeouts.
  ## if anything does timeout, but is in this message, it will be
  ## added back, and because timeout will only remove if it is from the
  ## current interface, this interface will have the first chance to update
  neighbors = check_timeout(neigh_fi,neighbors,mgmt,dev)
  current_time = datetime.datetime.now()

  ## route (x) = updates from the neighbor
  for route in update:
    x = anhost.Route()
    x.set_route(route)
    ## increase the ttl by +1
    x.update_metric()
    ## on recv, change the route to have the interface received on.
    x.set_iface(dev)

    ## force routes to be less than 16 hops away
    if int(x.met) < 16:
      bm = bit_mask(x.mask)
      network = netaddr.IPNetwork("%s/%s" % (x.dst,bm))
      there = False
      
      # neigh (y) = routes previously knwon
      for neigh in neighbors:
        y = anhost.Route()
        y.set_route(neigh)
        bm = bit_mask(y.mask)
        have_net = netaddr.IPNetwork("%s/%s" % (y.dst,bm))

        ## test if route (x) and neigh (y) are the same network route advertisement
        logger.debug("\ttesting %s and %s" % (have_net,network))
        if network == have_net:
          logger.debug("\t\tsame net")
          ## if the route is already there, make sure to indicate so we can
          ## easily check for which routes are not, and add them.
          there = True
          ## check if what were just recved has a better hop count than existing
          ## if so, add it to new route
          if x.get_count() < y.get_count():
            logger.debug("\t\tUPDATING W/ better hop: %s" % x.get_route())
            add_list.append(x)
          else:
            ## if the hop count is the same or worst, then we have to check
            ## who is the owner of the route, if this device is the owner then
            ## we will update the timer on the route.
            if y.get_iface() == dev:
              ##FIXME: need to fix the logic here.  If the hop count is the same
              ## or if the hop count is larger, should I let the route timeout, or
              ## just accept as is.  For now, I am approaching it as the latter.
              logger.debug("\t\tUPDATING old route: %s" % y.get_route())
              add_list.append(y)
            else:
              logger.debug("\t\t\t\theard from different interface, ignoring")
          break
      ## the route was not previously stored, so add it.
      if not there:
        logger.debug("\t\t\tADDING: %s" % x.get_route())
        add_list.append(x)

  logger.debug("getting added: %s" % x.transmit_route())

  # create new neighbor list to hold an updated route table
  update_neighbors = []
  # add new entries
  for k in add_list:
    k.set_ttl(current_time)
    update_neighbors.append(k.transmit_route())


  ## Now that we have added routes that were in this update but not in our routing table
  ## We also updated routes that were in both as long as they were owned by the same device
  ## the next step is add all the routes known previously which were not transmited by this
  ## update, this is the case when hearing updates from multiple networks (eth1,eth2,eth3)

  # old route table
  for k in neighbors:
    there = False
    # new route table
    for p in update_neighbors:
      # check for differences
      if anhost.same_route(k,anhost.uni_decode(p)):
        logger.info("same:\n%s\n%s" % (k,anhost.uni_decode(p))) 
        there = True
    # if the old route was not in the new route, add it.
    if not there:
      update_neighbors.append(k)

  ##write out the updated routes to the route file
  write_n_fi(n_fi,update_neighbors)
  ##FIXME: add to linux route table
  anhost.modify_linux_tables(update_neighbore,mgmt)

  logger.info("\tAfter Update route table: %s" % update_neighbors)

  ## release the mutex for updates
  recv_mutex.release()

#FIXME when I get there, impletement poison-reverse for Counting problem
def rip_server(code, serv_port, rip_port, dev, mgmt):
  neigh = "%s.rip" % rip_port
  logger.debug("RIP SERVER:")
  logger.debug("PID: %s" % os.getpid())
  logger.debug("DEVICES: %s" % dev)
  #local_ip = anhost.get_ip_address(dev)

  l_route = []
  routes = anhost.sim_routes(mgmt)
  rip_interfaces = []

  ##this write needs to have guards to make sure it doesnt wipe out another
  ##interfaces update
  ##FIXME: Clean this code up later
  logger.debug("RIP server already running: %s" % os.path.exists(neigh))
  if not os.path.exists(neigh):
    x = open(neigh,'w')
    x.close()
    for route in routes:
      iface_ip = anhost.get_ip_address(route["Iface"])
      if iface_ip != mgmt:
        ## default routes gets linux, but now we need to add arbitrary ttl for rip
        ##FIXME change get_routes to use Routes()
        x = anhost.Route()
        x.convert_route(route)
        x.set_ttl(datetime.datetime.now())
        l_route.append(x.transmit_route())

        ## create sockets to be added to select for synchronous updates across interfaces
        rip_serv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rip_serv.bind((iface_ip,rip_port)) 
        rip_serv.setblocking(0) #non-blocking
        rip_interfaces.append(rip_serv)
        logger.debug("socket created: (%s,%s)" % rip_serv.getsockname())

        ##bootstrap neighbors into starting RIP
        logger.debug("bootstraping RIP on local neighbors")
        anhost.send_broadcast(iface_ip, code,serv_port)

    ## once we have gone through all of our default linux rotes, update our route file
    write_n_fi(neigh,l_route)
    logger.debug("\tinitial neighbor list: %s" % read_n_fi(neigh))

  
    ## start threads after we update the route table so we have something to send first
    for route in routes:
      ## i think I want to thread off the senders, they can be asychronous with respect
      ## to eachother compared to synchronous recieves
      logger.debug("starting RIP update thread for %s" % route["Iface"])
      send_thread = threading.Thread(target=send_handler,\
                     args=(rip_serv,neigh,rip_port,route["Iface"],mgmt,))
      send_thread.start()
      send_thread.join()



    while True:
      inputready,outputready,exceptready = select.select(rip_interfaces,[],[]) 
      logger.debug("input que: %s" % inputready)
      for sock in inputready: 
        logger.debug("\t\taceepting messages...")
        msg, addr = sock.recvfrom(4096)
        logger.debug("\t\tmessage: %s" % msg)
        logger.debug("\t\tsender's addr: (%s,%s)" % (addr[0],addr[1]))
        recv_update(addr[0], sock.getnameinfo()[0],mgmt,json.loads(msg))
        logger.debug("\t\tupdate written out to file.")
        logger.info("UPDATED NEIGHBORS: %s" % read_n_fi(n_fi))
       


  """
  else:
    prev_routes = read_n_fi(neigh)
    for proute in prev_routes:
      y = anhost.Route()
      y.set_route(proute)
      y.set_ttl(datetime.datetime.now())
      logger.debug("Adding Memory Route: %s" % y.transmit_route())
      l_route.append(y.transmit_route())
        
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
  """

"""
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

"""

"""
def update_ttls(neighbors):
  logger.debug("UPDATE_TTLS")
  current_time = datetime.datetime.now()
  n_neigh = []
  for k in neighbors:
    p = anhost.Route()
    p.set_route(k)
    p.set_ttl(current_time)
    n_neigh.append(p.transmit_route())
    logger.debug("updated ttl: %s" % p.get_route())
  return n_neigh
"""
 
