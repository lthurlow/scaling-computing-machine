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
import SocketServer       # for test server
import threading          # for test thread server
#import sys                # for sandbox output
import sys
sys.path.append("..")
from anhost import anhost             # for all my active networks stuff

FORMAT = "[%(filename)s:%(lineno)s - %(threadName)s %(funcName)20s] %(levelname)s %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("%s | %s |" % (os.getpid(), __file__) )
#logger = logging.getLogger(FORMAT)
logger.setLevel(logging.DEBUG)
socketHandler = logging.handlers.SocketHandler('localhost',
                    logging.handlers.DEFAULT_TCP_LOGGING_PORT)
logger.addHandler(socketHandler)

INTERFACE = 'eth0'
PORT = 50000
HOST = str(anhost.get_ip_address(INTERFACE))
PROCESS_TRACKER = []

## For AWS, when code is invalid, return notification to sending
def return_code_error(error, addr):
  logger.debug("Return Error Code")
  logger.debug("\tError Value: %s" % error)
  logger.debug("\tTo: (%s,%s)" % (addr,PORT))
  udp_data = error
  udp_src = udp_dst = PORT
  # should be returned from the correct interface in future
  try:
    #FIXME this used old code libraries since removed
    ## Could just use a socket...
    #send(IP(dst=addr,src=anhost.get_ip_address(INTERFACE))/UDP(sport=udp_src,dport=udp_dst)/udp_data,\
    #   iface="eth0", verbose=True)
    logger.debug("Message sent")
  except Exception, e:
    logger.error("Message could not be sent: %s", e)

def sandbox(command):
  logger.debug("Sandbox")
  logger.debug("\texecuting: %s" % command)
  try:
    ## this command fucks with the output I think due to using PIPEs and multiple processes
    #process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ## this command fucks with the PID returned as the spawned process, so +1
    #process = subprocess.Popen(command, shell=True)
    process = subprocess.Popen(command.split(' '))
    PROCESS_TRACKER.append(process.pid)
    logger.debug("\tprocess started: %s" % process.pid)
    try:
      out, err = process.communicate()
      logger.debug("\tproc out:\n%s" % (str(out).strip()))
      logger.debug("\tproc err:\n%s" % (str(err).strip()))
      logger.debug("\treturn status: %s" % process.returncode)

      exitCode = process.returncode
      if (exitCode == 0):
        logger.debug("returning - no errors")
        return process.pid
      else:
        logger.error("\tcmd:%s  return:%s" % (command, exitCode))
        raise Exception(command,exitCode,out)
    except Exception, e:
      logger.error("\tError in Sandbox:: %s" % str(e))
      raise Exception(e)
  except Exception, e:
    logger.error("\tProcess unable to run!")
    logger.error(str(e))
    raise Exception(e)

def kill_processes():
  logger.debug("KILL_PROCESSES")
  for proc in PROCESS_TRACKER:
    try:
      #logger.info("Sending Hangup to %s" % proc)
      #os.kill(proc,signal.SIGHUP)
      #time.sleep(1)
      ## sigkill is not allowed to be caught
      os.kill(proc,signal.SIGKILL)
      logger.info("Process %s killed" % proc)
      ##FIXME
      logger.info("Removing .route_rip")
      if os.path.exists(".route_rip"):
        os.remove(".route_rip")
      logger.info("Removing 50000.rip")
      if os.path.exists("50001.rip"):
        os.remove("50001.rip")
    except Exception,e:
      logger.info("\tPrcoess %s unable to kill: %s" % (proc,str(e)))

class ThreadedUDPRequestHandler(SocketServer.BaseRequestHandler):
  ##FIXME needs a way to differentiate active code from other
  ## Especially ERROR messages coming back
  def handle(self):
    data = self.request[0].strip()
    port = self.client_address[1]
    addr = (self.client_address[0])
    cur_thread = threading.current_thread()
    tname = cur_thread.name
    logger.debug("thread %s" % tname )
    logger.debug("\tconnection recv'd from (%s,%s)" % (addr,port))
    #logger.debug("\tdata sent: %s" % data)
    thread_fi = "%s.%s.%s" % (addr,port,tname)
    ##writing data out to file for reading later
    tf = open(thread_fi,'w')
    tf.write(data)
    tf.close()
    tf = open("debugger.txt",'w')
    tf.write(data)
    tf.close()
    try:
      pid = sandbox("python %s" % thread_fi)
      if os.path.exists(thread_fi):
        logger.debug("\tThread: Safe Remove: %s" % thread_fi)
        os.remove(thread_fi)
        logger.debug("\tRemoving PID %s from list" % pid)
        PROCESS_TRACKER.remove(pid)
        logger.debug("\tUpdated PID List: %s" % PROCESS_TRACKER)
    except Exception, error:
      logger.error("\tThread Excecution Error: %s" % error)
      return_code_error(error, addr)
      if os.path.exists(thread_fi):
        logger.debug("\tThread: Error Remove: %s" % thread_fi)
        os.remove(thread_fi)
      

class ThreadedUDPServer(SocketServer.ThreadingMixIn,SocketServer.UDPServer):
  pass


server = ThreadedUDPServer((HOST, PORT), ThreadedUDPRequestHandler)
ip, port = server.server_address
logger.debug("server started on: (%s,%s)" % (ip,port))
try:
  server.serve_forever()
  server_thread = threading.Thread(target=server.serve_forever)
  # When this process dies, all threads die as well
  server_thread.daemon = True
  server_thread.start()
  server.shutdown()
except KeyboardInterrupt:
  #graceful death
  logger.error("Recieved Keyboard Interrupt")
  kill_processes()
  server.shutdown()
  ## not so graceful
  #os._exit(1)
except Exception,e:
  logger.error("Unknown Server Error thrown: %s" % str(e))
  kill_processes()
  server.shutdown()
  #os._exit(2)
