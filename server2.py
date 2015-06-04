import pdb                # for debuggin
import pprint             # for pretty print
import subprocess         # for running exec code
import os                 # for deleting temp file
import multiprocessing    # for server threading
import socket             # for communication
import logging            # for logging and debugging
import time

import anhost

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

INTERFACE = 'eth0'
PORT = 50000

## For AWS, when code is invalid, return notification to sending
def return_code_error(error, addr):
  udp_data = (code,error)
  udp_src = udp_dst = PORT
  # should be returned from the correct interface in future
  try:
    send(IP(dst=addr,src=anhost.get_ip_address(INTERFACE))/UDP(sport=udp_src,dport=udp_dst)/udp_data,\
       iface="eth0", verbose=True)
  except Exception, e:
    logger.debug("message could not be sent: %s", e)

## For running the code (yes incrediably insecure)
def dummy_exec(code,addr):
  ## language detection and sandboxing here
  try:
    tpid = multiprocessing.current_process().name
    logger.debug("Thread Value: %s" % tpid)
    for line in code.split('\n'):
      logger.debug(line)
    tf = open(str(tpid),'w')
    tf.write(code)
    tf.close()
    sp = subprocess.Popen(["python",str(tpid)], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(5)
    sp.terminate()
    #var = sp.communicate()[1]
    sp.wait()  # while p runs, the command's stdout and stderr should behave as usual
    var = sp.stdout.read()  # unfortunately, this will return '' unless you use subprocess.PIPE
    print var
    var = sp.stderr.read()  # ditto
    print var
    # comment out to verify change in file after
    os.remove(str(tpid))
    return var
  except Exception, e:
    logger.debug("Error caught, sending back to %s for %s", addr, e)
    return ("Exception",e)


HOST = str(anhost.get_ip_address(INTERFACE))
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST,PORT))


while True:
  msg, addr = sock.recvfrom(1024)
  #print "msg:", msg
  pool = multiprocessing.Pool(processes=1)
  async_result = pool.apply_async(dummy_exec, (msg,addr[0],))
  return_val = async_result.get()
  #if type(return_val) == str:
  #  print return_val
  #elif type(return_val) == tuple:
  print return_val
  #if type(return_val) == tuple:
  #  return_code_error(e,addr[0])
