import pdb                # for debuggin
import pprint             # for pretty print
import subprocess         # for running exec code
import os                 # for deleting temp file
import fcntl              # for get_ip_address
import struct             # for get_ip_address
import multiprocessing    # for server threading
import socket             # for communication
import logging            # for logging and debugging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

INTERFACE = 'eth0'
PORT = 50000

## For amazon AWS, use this to get eth0 interface and use as socket
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

## For AWS, when code is invalid, return notification to sending
def return_code_error(error, addr):
  udp_data = (code,error)
  udp_src = udp_dst = PORT
  # should be returned from the correct interface in future
  try:
    send(IP(dst=addr,src=get_ip_address(INTERFACE))/UDP(sport=udp_src,dport=udp_dst)/udp_data,\
       iface="eth0", verbose=True)
  except Exception, e:
    logger.debug("message could not be sent: %s", e)

## For running the code (yes incrediably insecure)
def dummy_exec(code,addr):
  ## language detection and sandboxing here
  try:
    tpid = multiprocessing.current_process().name
    print tpid
    tf = open(str(tpid),'w')
    tf.write(code)
    tf.close()
    sp = subprocess.Popen(["python",str(tpid)], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    var = sp.communicate()[0]
    sp.stdin.close()
    os.remove(str(tpid))
    return var
  except Exception, e:
    logger.debug("Error caught, sending back to %s for %s", addr, e)
    return ("Exception",e)


HOST = str(get_ip_address(INTERFACE))
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST,PORT))


while True:
  msg, addr = sock.recvfrom(1024)
  print "msg:", msg
  pool = multiprocessing.Pool(processes=1)
  async_result = pool.apply_async(dummy_exec, (msg,addr[0],))
  return_val = async_result.get()
  if type(return_val) == str:
    print return_val
  elif type(return_val) == tuple:
    return_code_error(e,addr[0])
