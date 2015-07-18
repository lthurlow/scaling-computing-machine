import re
import socket
import fcntl  # for get_ip_address
import struct # for get_ip_address
import logging
import logging.handlers
import datetime
import time
import os
import pprint as pp
import subprocess

default_gw = "0.0.0.0"

class Route:
  dst = ""
  gw = ""
  mask = ""
  flag = ""
  met = 0
  ref = 0
  use = 0
  iface = ""
  update = 0
  owner = ""
  in_use = ""
  def __init__(self):
    self.dst = ""
    self.gw = ""
    self.mask = ""
    self.flag = ""
    self.met = 0
    self.ref = 0
    self.use = 0
    self.iface = ""
    self.update = ""
    self.owner = ""
    self.in_use = ""
  def set_ttl(self,dt):
    self.update = dt.strftime("%Y%j%H%M%S%f")
  def set_gw(self, gw):
    self.gw = gw
  def set_iface(self,iface):
    self.iface = iface
  #def set_owner(self,dev):
  #  self.owner = dev
  #  self.in_use = True
  #def set_used(self,is_used):
  #  self.is_used = is_used

  #def get_owner(self):
  #  return self.owner
  #def get_used(self):
  #  return self.in_use
  def get_gw(self):
    return self.gw
  def get_iface(self):
    return self.iface
  def get_count(self):
    return int(self.met)
  def get_ttl(self):
    return datetime.datetime.strptime(self.update,"%Y%j%H%M%S%f")

  def update_metric(self):
    as_int = int(self.met)
    as_int += 1
    self.met = str(as_int)
  def get_route(self):
    rdict = {}
    rdict['Destination'] = self.dst
    rdict['Gateway'] = self.gw
    rdict['Genmask'] = self.mask
    rdict['Flags'] = self.flag
    rdict['Metric'] = self.met
    rdict['Ref'] = self.ref
    rdict['Use'] = self.use
    rdict['Iface'] = self.iface
    rdict['TTL'] = datetime.datetime.strptime(self.update,"%Y%j%H%M%S%f")
    #rdict['Owner'] = self.owner
    #rdict['InUse'] = self.is_used
    return  rdict
  def transmit_route(self):
    rdict = {}
    rdict['Destination'] = self.dst
    rdict['Gateway'] = self.gw
    rdict['Genmask'] = self.mask
    rdict['Flags'] = self.flag
    rdict['Metric'] = self.met
    rdict['Ref'] = self.ref
    rdict['Use'] = self.use
    rdict['Iface'] = self.iface
    rdict['TTL'] = self.update
    #rdict['Owner'] = self.owner
    #rdict['InUse'] = self.is_used
    return  rdict
  def set_route(self,rdict):
    self.dst = rdict['Destination'] 
    self.gw = rdict['Gateway'] 
    self.mask = rdict['Genmask'] 
    self.flag = rdict['Flags']
    self.met = rdict['Metric']
    self.ref = rdict['Ref']
    self.use = rdict['Use']
    self.iface = rdict['Iface']
    #self.owner = rdict['Owner']
    #self.is_used = rdict['InUse']
    #try:
    #logger.debug("TTL: type %s value %s" % (type(rdict["TTL"]),rdict["TTL"]))
    if (type(rdict['TTL']) == str):
      self.update = rdict['TTL']
    else:
      temp = datetime.datetime.strptime(rdict['TTL'],"%Y%j%H%M%S%f")
      self.update = datetime.datetime.strftime(temp,"%Y%j%H%M%S%f")
    #except KeyError:
    #  logger.error("KeyError with adding TTL")
  def convert_route(self,rdict):
    self.dst = rdict['Destination'] 
    self.gw = rdict['Gateway'] 
    self.mask = rdict['Genmask'] 
    self.flag = rdict['Flags']
    self.met = rdict['Metric']
    self.ref = rdict['Ref']
    self.use = rdict['Use']
    self.iface = rdict['Iface']
    self.update = 0


def same_route(r1,r2):
  #logger.debug("\tSAME_ROUTE")
  #logger.debug("testing:\n%s\n%s" % (r1,r2))
  if r1['Destination'] == r2['Destination'] and \
     r1['Gateway'] == r2['Gateway'] and \
     r1['Genmask'] == r2['Genmask'] and \
     r1['Metric'] == r2['Metric'] and \
     r1['Iface'] == r2['Iface']:
     #r1['Owner'] == r2['Owner']:
    #logger.debug("Same Route")
    return True
  else:
    #logger.debug("Different Route")
    return False
    
FORMAT = "[%(filename)s:%(lineno)s - %(threadName)s %(funcName)20s] %(levelname)10s %(message)s"
logging.basicConfig(format=FORMAT)

logger = logging.getLogger("%s | %s | " % (os.getpid(), __file__) )
logger.setLevel(logging.DEBUG)
socketHandler = logging.handlers.SocketHandler('localhost',
                    logging.handlers.DEFAULT_TCP_LOGGING_PORT)
logger.addHandler(socketHandler)

## assuming linux

def uni_decode(uni):
  string_dict = {}
  for k in uni:
    string_dict[k.encode('utf-8')] = uni[k].encode('utf-8')
  return string_dict


def get_ip_address(ifname):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

## get interface ip for python3
def get_int_ip():
  ip_f = open("/proc/net/tcp","r")
  x = [l.strip() for l in ip_f]
  ip_inv = x[-1].split(":")[1].strip()
  ip = [int(((int(x)*10)+int(y))) for x,y in zip(ip_inv[0::2], ip_inv[1::2])]
  ip_num = ip[::-1]
  ip = [str(int(str(l),16)) for l in ip_num]
  return '.'.join(ip)

#get access to the arp table, return the contents
def get_arp_table():
	arp_f = open("/proc/net/arp","r")
	header = False
	headers = []
	entries = []
	for line in arp_f:
		table = {}
		if not header:
			header = True
			[headers.append(x) for x in re.findall(r'([a-zA-Z]+\s?[a-zA-Z]+)',line)]
		else:
			row = re.findall(r'([a-zA-Z0-9.:]+\s?[a-zA-Z0-9.:]+|[\*])',line)
			count = 0
			for x in row:
				table[headers[count]] = x
				count += 1
			entries.append(table)
	return entries

def conv_hexip_to_dex(a):
	return('.'.join(str(x) for x in [int(a[6:8],16),int(a[4:6],16),
					int(a[2:4],16),int(a[0:2],16) ]))

#get the ip routing table, return the contents
def get_route_table():
  output = subprocess.check_output(['route', '-nv'])
  count = 0
  keys = []
  routes = []
  for line in output.split('\n')[1:-1]:
    if count == 0:
      keys = line.split()
    else:
      route = {}
      for i in xrange(0,len(keys)):
        route[keys[i]] = line.split()[i]
      routes.append(route)
    count += 1
  return routes

#get the ip routing table, return the contents
def non_default_routes():
  output = subprocess.check_output(['route', '-nv'])
  count = 0
  keys = []
  routes = []
  for line in output.split('\n')[1:-1]:
    if count == 0:
      keys = line.split()
    else:
      route = {}
      for i in xrange(0,len(keys)):
        route[keys[i]] = line.split()[i]
      if route["Destination"] != "0.0.0.0":
        routes.append(route)
    count += 1
  return routes

def sim_routes(mgmt):
  output = subprocess.check_output(['route', '-nv'])
  count = 0
  keys = []
  routes = []
  for line in output.split('\n')[1:-1]:
    if count == 0:
      keys = line.split()
    else:
      route = {}
      for i in xrange(0,len(keys)):
        route[keys[i]] = line.split()[i]
      if route["Iface"] != mgmt:
        routes.append(route)
    count += 1
  return routes



#Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
def set_route_table(rdict,flag="add"):
  a =b =c =d =e = ""
  for k in rdict:
    if k == "Destination":
      a=rdict[k]
    elif k == "Gateway":
      b=rdict[k]
    elif k == "Genmask": 
      c=rdict[k]
    elif k == "Metric": 
      d=rdict[k]
    elif k == "Iface": 
      e=rdict[k]
    #elif k == "Ref": 
    #elif k == "Flags":
  try:
    #gw cannot be 0.0.0.0
    #cmd requires sudo access
    cmd = ""
    if flag == "add":
      cmd = "route add -net %s netmask %s metric %s gw %s dev %s" % (a,c,d,b,e)
    else:
      cmd = "route del -net %s netmask %s metric %s gw %s dev %s" % (a,c,d,b,e)
    cmd = cmd.split()
    x = subprocess.call(cmd)
    if x != 0:
      logger.error("cmd failed: %s" % cmd)
    return x
  except Exception,e:
    logger.error("Unable to make changes to Kernel Routing Table")
    logger.error(str(e))
    return -1

def modify_linux_tables(mem_t,mgmt):
  logger.debug("MODIFY_LINUX_TABLES")
  linux = sim_routes(mgmt)
  for r1 in linux:
    same = False
    for r2 in mem_t:
      if same_route(r1,r2):
        same = True
    if not same and r1["Iface"] != mgmt:
      logger.debug("Deleting Linux Route: %s" % r1)
      try:
        e = set_route_table(r1,flag="del")
        logger.info("set route returned with exit status: %s" % str(e))
      except Exception,e:
        logger.error("Error deleting route.")

  for r2 in mem_t:
    same = False
    for r1 in linux:
      if same_route(r1,r2):
        same = True
    if not same and r2["Iface"] != mgmt:
      logger.debug("Adding Linux Route: %s" % r2)
      try:
        e = set_route_table(r2,flag="add")
        logger.info("set route returned with exit status: %s" % str(e))
      except Exception,e:
        logger.error("Error deleting route.")
  

#get the device information for all interfaces
def get_dev_info():
	dev_f = open("/proc/net/dev","r")
	lcount = 0
	headers = []
	entries = []
	for line in dev_f:
		table = {}
		if lcount != 0:
			if lcount == 1:
				row = re.findall(r'([a-zA-Z]+)',line)
				count = 0
				for x in row:
					if count == 0:
						headers.append('interface')
					elif (count < (len(row)/2)):
						headers.append('r_'+x.split()[0])
					else:
						headers.append('t_'+x.split()[0])
					count += 1
			else:
				row = re.findall(r'([a-zA-Z0-9]+)',line)
				count = 0
				for x in row:
					table[headers[count]] = x
					count += 1
				entries.append(table)
		lcount += 1
		
	return entries

#http://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
def send_msg(sock, msg):
  msg = struct.pack('>I', len(msg)) + msg
  sock.sendall(msg)

def recv_msg(sock):
  raw_msglen = recvall(sock, 4)
  if not raw_msglen:
    return None
  msglen = struct.unpack('>I', raw_msglen)[0]
  # Read the message data
  return recvall(sock, msglen)

def recvall(sock, n):
  data = ''
  while len(data) < n:
    packet = sock.recv(n - len(data))
    if not packet:
      return None
    data += packet
  return data

def set_src_dst(CODE,src,dst):
  new_CODE = ""
  for line in CODE.split('\n'):
    if line == "src = \"\"":
      new_CODE += "src = \"%s\"\n" % src
    elif line == "dst = \"\"":
      new_CODE += "dst = \"%s\"\n" % dst
    else:
      new_CODE = new_CODE + line + "\n"
  return new_CODE

## this code has so many assumptions, but for quick and dirty
## modify the value in a file as if it was memory that could write
## itself out
def chg_val(disk_file, var_type, var_name, var_val, write_type):
  logger.debug("file: %s, type: %s, name: %s, value: %s, write: %s" %\
              (disk_file, var_type, var_name, var_val, write_type))
  try:
    f = open(disk_file,'r')
    file_contents = []
    for line in f:
      file_contents.append(line)
    f.close()
    index_value = 0
    for item in file_contents:
      x = re.findall(r'^\b%s\s*=\s*.*' % var_name ,item) #so many assumptions
      if x:
        logger.debug(x)
        index_value = file_contents.index(item)
        logger.debug(index_value)
    ## not bothering to check values passed in, because that would be correct
    logger.debug("line to re-write: %s" % file_contents[index_value].strip())
    logger.debug("with %s" % var_val)
    t_str = ""
    if write_type == "w":
      if type(var_type) == list:
        if type(var_val) == list:
          t_str = "%s = %s\n" % (var_name,var_val)
        elif type(var_val) == str:
          t_str = "%s = %s\n" % (var_name,"["+"\""+var_val+"\""+"]")
        elif type(var_val) == float:
          t_str = "%s = %s\n" % (var_name,"["+"\""+str(var_val)+"\""+"]")
        file_contents[index_value] = t_str
      elif type(var_type) == float:
        t_str = "%s = %s\n" % (var_name,str(var_val))
        file_contents[index_value] = t_str
      elif type(var_type) == int:
        t_str = "%s = %s\n" % (var_name,str(var_val))
        file_contents[index_value] = t_str
      elif type(var_type) == str:
        t_str = "%s = \"%s\"\n" % (var_name,var_val)
        file_contents[index_value] = t_str

    elif write_type == "a":
      if type(var_type) == list:
        if type(var_val) == list:
          t_str = file_contents[index_value]
          t_str = t_str.strip().replace("]","")
          t_str = t_str + ','+ ','.join([str(y) for y in var_val]) + "]\n"
          file_contents[index_value] = t_str
        elif type(var_val) == str:
          t_str = file_contents[index_value]
          l_size = t_str.split("\"")
          logging.info(l_size)
          t_str = t_str.strip().replace("]","")
          if len(l_size) > 1:
            t_str = t_str + ','+ "\""+ var_val +"\"" + "]\n"
          else:
            t_str = t_str + "\""+ var_val +"\""+ "]\n"
          file_contents[index_value] = t_str
        elif type(var_val) == float:
          t_str = file_contents[index_value]
          l_size = t_str.split(",")
          logging.info(l_size)
          t_str = t_str.strip().replace("]","")
          if len(l_size) > 1:
            t_str = t_str + str(var_val)+"," + "]\n"
          else:
            t_str = t_str + str(var_val)+","+ "]\n"
          file_contents[index_value] = t_str


    logger.debug("post write: %s" % file_contents[index_value])
    f2 = open(disk_file,'w')
    for lne in file_contents:
      f2.write(lne)
    f2.close()
        
  except Exception, e:
    logger.error("Error in chg_val: %s" % str(e))
    raise Exception(e)

def get_time():
  epoch = datetime.datetime.utcfromtimestamp(0)
  now = datetime.datetime.now()
  now -= epoch
  return float("%s.%s" % (now.seconds%60,now.microseconds/1000))

##FIXME
def use_default_route():
  rtable = get_route_table()
  for eth in rtable:
    for eth_d in eth:
      for val in eth[eth_d]:
        if val == "Destination" and eth[eth_d][val] == "0.0.0.0":
          return eth[eth_d]["Gateway"]
  return -1


def send_to_local_interfaces(msg,dev_iface,mgmt,port):
  logger.debug("\t\tSEND_TO_ALL_INTERFACES")
  iface_list = non_default_routes()
  #logger.debug("Non-default Routes: %s" % iface_list)
  for iface in iface_list:
    ## dont send back to us.
    if iface["Iface"] != dev_iface and iface["Iface"] != mgmt:
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      iface_ip = get_ip_address(dev_iface)
      logger.debug("\t\t\tSending update to (%s,%s)" % (iface_ip,iface["Iface"]))
      sock.sendto(msg, (iface_ip,port))

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
  ##FIXME: why is this not being printed?
  logger.debug("\t\tbroadcast done.")

