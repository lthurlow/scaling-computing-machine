import pdb                # for debuggin
import pprint             # for pretty print
import subprocess         # for running exec code
import os                 # for deleting temp file
import multiprocessing    # for server threading
import socket             # for communication
import logging            # for logging and debugging
import logging.handlers   # for twisted logging for multiple processes
import time               # for sleeping

import anhost             # for all my active networks stuff


FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s()] %(levelname)s %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("%s | %s |" % (os.getpid(), __file__) )
logger.setLevel(logging.DEBUG)
socketHandler = logging.handlers.SocketHandler('localhost',
                    logging.handlers.DEFAULT_TCP_LOGGING_PORT)
logger.addHandler(socketHandler)


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

def proc_exe(command):
  process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
stderr=subprocess.STDOUT)

  # Poll process for new output until finished
  while True:
    nextline = process.stdout.readline()
    if nextline == '' and process.poll() != None:
      break
    sys.stdout.write(nextline)
    sys.stdout.flush()

  output = process.communicate()[0]
  exitCode = process.returncode

  if (exitCode == 0):
    return output
  else:
    raise Exception(command, exitCode, output)

## For running the code (yes incrediably insecure)
def dummy_exec(code,addr):
  ## language detection and sandboxing here
  try:
    tpid = multiprocessing.current_process().name
    logger.debug("Thread Value: %s" % tpid)
    ## create a file to contain the code to run
    tf = open(str(tpid),'w')
    tf.write(code)
    tf.close()
    logger.debug("File opened, running code")
    ## function to run the code
    var = proc_exe("python %s " % str(tpid))
    ## kill file after
    os.remove(str(tpid))
    return var
  except Exception, e:
    logger.debug("Error caught, sending back to %s for %s", addr, e)
    tpid = multiprocessing.current_process().name
    os.remove(str(tpid))
    return ("Exception",e)


HOST = str(anhost.get_ip_address(INTERFACE))
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST,PORT))
sock.setblocking(1) ## blocking socket

try:
  ## Server will always read
  while True:
    msg, addr = sock.recvfrom(4096)
    pool = multiprocessing.Pool(processes=1)
    print addr
    ## what we are reading is code, so execute it
    async_result = pool.apply_async(dummy_exec, (msg,addr[0],))
    return_val = async_result.get()
    print return_val

except KeyboardInterrupt:
  logging.info("Server killed by Ctrl-C")
  print("\n")
  exit(1)
