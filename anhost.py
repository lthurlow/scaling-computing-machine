import re
import socket
import fcntl  # for get_ip_address
import struct # for get_ip_address
import logging
import pprint

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

## assuming linux

def get_ip_address(ifname):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

"""
class Capsule:
  self.src = None
  self.dst = None
  self.sport = None
  self.dport = None
  self.code = None
  def __init__(self, src_ip, dst_ip, dst_port):
    self.src = src_ip
    self.dst = dst_ip
    ## again, until better prototype sans transport
    self.sport = dst_port ## just to save some time
    self.dport = dst_port 
    self.code = None

  def set_code(code):
    self.code = code

  def copy():
    return self 

  def invert():
    tmp = self.src
    self.src = self.dst
    self.dst = tmp
    ## no need to swap ports, cause this is ghetto
"""

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
	route_f = open("/proc/net/route","r")
	header = False
	headers = []
	entries = []
	for line in route_f:
		table = {}
		if not header:
			header = True
			[headers.append(x) for x in re.findall(r'([a-zA-Z]+)',line)]
			for x in headers:
				table[x] = []
		else:
			row = re.findall(r'([a-zA-Z0-9]+)',line)
			count = 0
			for x in row:
				if (headers[count] == 'Mask' or headers[count] == 'Destination' or\
				    headers[count] == 'Gateway'):
					table[headers[count]] = conv_hexip_to_dex(x)
				else:
					table[headers[count]] = x
				count += 1
			entries.append(table)
	return entries

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
      x = re.findall(r'.*%s.*=.*' % var_name ,item) #so many assumptions
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
        file_contents[index_value] = t_str
    elif write_type == "a":
      if type(var_type) == list:
        t_str = file_contents[index_value]
        t_str = t_str.strip().replace("]","")
        t_str = t_str + ','+ ','.join([str(y) for y in var_val]) + "]\n"
        file_contents[index_value] = t_str
    logger.debug("post write: %s" % file_contents[index_value])
    f2 = open(disk_file,'w')
    for lne in file_contents:
      f2.write(lne)
    f2.close()
        
  except Exception, e:
    return str(e)


#def use_default_route():
  
