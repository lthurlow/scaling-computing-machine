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
import re                 # for purging server files
import select             # for queing packsets on all interfaces
import sys
sys.path.append("..")
from anhost import anhost             # for all my active networks stuff
from anhost import inputs

FORMAT = "[%(filename)s:%(lineno)s - %(threadName)s %(funcName)20s] %(levelname)10s %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("%s | %s |" % (os.getpid(), __file__) )
#logger = logging.getLogger(FORMAT)
logger.setLevel(logging.DEBUG)
socketHandler = logging.handlers.SocketHandler('localhost',
                    logging.handlers.DEFAULT_TCP_LOGGING_PORT)
logger.addHandler(socketHandler)

## less typing for now.
PORT = 50000
""""
inf, po = inputs.user()
if inf:
  INTERFACE = inf
if po:
  PORT = po
HOST = str(anhost.get_ip_address(INTERFACE))
"""
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

def purge(pattern):
  x = re.compile(r'%s'%pattern)
  for f in os.listdir("."):
    if x.findall(f):
      logger.debug("file removed: %s" % f)
      os.remove(f)

def kill_processes():
  logger.debug("KILL_PROCESSES")
  ##FIXME
  purge("rip")
  purge("snoop")
  for proc in PROCESS_TRACKER:
    try:
      #logger.info("Sending Hangup to %s" % proc)
      #os.kill(proc,signal.SIGHUP)
      #time.sleep(1)
      ## sigkill is not allowed to be caught
      os.kill(proc,signal.SIGKILL)
      logger.info("Process %s killed" % proc)
    except Exception,e:
      logger.info("\tPrcoess %s unable to kill: %s" % (proc,str(e)))
  subprocess.call(["sudo","iptables","-F"])

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

## get all of the routes in our sim environment
routes = anhost.sim_routes()
p_open = []
server_list = []
for route in routes:
  iface_ip = anhost.get_ip_address(route["Iface"])
  ## check that the interface attached is not mgmt and not already opened
  if iface_ip != anhost.mgmt and iface_ip not in p_open:
    ## add to list, and create server to attach to the device ip and an_port
    p_open.append(iface_ip)
    server = ThreadedUDPServer((iface_ip, PORT), ThreadedUDPRequestHandler)
    server_list.append(server)
    ip, port = server.server_address
    logger.debug("server started on: (%s,%s)" % (ip,port))
    try:
      ## start a thread to handle connections
      server_thread = threading.Thread(target=server.serve_forever)
      server_thread.daemon = True
      server_thread.start()
    except Exception,e:
      logger.error("Unknown Server Error thrown: %s" % str(e))
      kill_processes()
      server.shutdown()
try:
  ## dont let the threads end, but dont join, just run until keyboard inputs
  for server in server_list:
    server.serve_forever()
    #server.shutdown()
except KeyboardInterrupt:
  #graceful death
  logger.error("Recieved Keyboard Interrupt")
  kill_processes()
  server.shutdown()
