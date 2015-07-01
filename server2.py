import pdb                # for debuggin
import pprint             # for pretty print
import subprocess         # for running exec code
import os                 # for deleting temp file
import multiprocessing    # for server threading
import socket             # for communication
import signal             # for killing multiprocess
import logging            # for logging and debugging
import logging.handlers   # for twisted logging for multiple processes
import time               # for sleeping

import anhost             # for all my active networks stuff

#def init_worker():
#    signal.signal(signal.SIGINT, signal.SIG_IGN)

FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s()] %(levelname)s %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("%s | %s |" % (os.getpid(), __file__) )
#logger = logging.getLogger(FORMAT)
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
  logger.debug("proc_exe")
  logger.debug("Proc_exe executing: %s" % command)
  #process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  try:
    while True:
      nextline = process.stdout.readline()
      if nextline == '' and process.poll() != None:
        exec_cont = -1
      sys.stdout.write(nextline)
      sys.stdout.flush()
    logger.debug("command finished")

    output = process.communicate()[0]
    exitCode = process.returncode
    logger.debug("process killed")

    if (exitCode == 0):
      return output
    else:
      logging.error("%s  %s  %s" % (command, exitCode, output))
      raise Exception(command,exitCode,output)
  except Exception, e:
    logger.error("proc_exe: process killed: %s", e)
    process.kill()
    return -1
  except KeyboardInterrupt:
    logger.error("proc_exe: keyboard killed")
    process.kill()
    return -1

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
    #var = proc_exe("python %s " % str(tpid))
    var = 0
    logger.debug("exit value of var=%s" % var)
    if os.path.exists(tpid):
      os.remove(str(tpid))
    return var
  except Exception, e:
    logger.error("Error caught:  %s", str(e))
    tpid = multiprocessing.current_process().name
    if os.path.exists(tpid):
      os.remove(str(tpid))
    raise Exception(tpid,e)


HOST = str(anhost.get_ip_address(INTERFACE))
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST,PORT))
sock.setblocking(1) ## blocking socket
logger.debug("server starting")

try:
  pool = multiprocessing.Pool(1)
  while True:
    msg, addr = sock.recvfrom(4096)
    logger.debug("server recieve from: %s" %addr[0])
    ## what we are reading is code, so execute it
    async_result = pool.apply_async(dummy_exec, (msg,addr[0],))
    try:
      return_val = async_result.get()
      logger.debug("server-mult returns: %s" % return_val)
    except KeyboardInterrupt:
      logger.error("Caught KeyboardInterrupt")
      pool.terminate()
      pool.join()
      ## definately need to fix this
      ## FIXME
      os.remove(".route_rip")
      break
    except Exception, e:
      logger.error("Top level: %s" % str(e))
      pool.close()
      pool.join()
      break
except Exception,e:
  logger.error("Error in server: %s" % e)
except KeyboardInterrupt:
  logger.error("Keyboard Killed Server")
  
sock.close()
exit(10)
