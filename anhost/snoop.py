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
import sys
sys.path.append("../netfilterqueue")
from netfilterqueue import NetfilterQueue

FORMAT = "[%(filename)s:%(lineno)s - %(threadName)s %(funcName)20s] %(levelname)10s %(message)s"
logging.basicConfig(format=FORMAT)
logger = logging.getLogger("%s | %s | " % (os.getpid(), __file__) )
logger.setLevel(logging.DEBUG)

#sudo apt-get install build-essential python-dev libnetfilter-queue-dev
# https://github.com/kti/python-netfilterqueue
## https://github.com/fqrouter/python-netfilterqueue.git
## http://sign0f4.blogspot.com/2015/03/using-nfqueue-with-python-right-way.html
## fqrouter fork has a set_payload implementation compared with kti's kit

## we will want the snoop code to run iptables over the interfaces to snoop on
## which for us, for atleast this first part will be on all interfaces.

## from there it we can either add them all to the same queue, or a queue per interface
## sudo iptables -I INPUT -i eth1 -j NFQUEUE --queue-num 1


#this function will need to track all the snoop neccesary variables:
# such as if it is tcp, what byte is being acknowledge, what the last byte  ack was
# also need to have 2 queues for normal and high priority
# those queues should be pointers to the packets

# we should drop packets as required, will need to find a way to re-create the pkt
# may need to go back to scapy, and use the copied packet, to generate packet from
# the ground up using scapy
def print_and_accept(pkt):
  print pkt
  pkt.accept()
  pdb.set_trace()

def start_snoop(interface,qname="NFQUEUE",qval=1):
  subprocess.call("sudo iptables -I INPUT -i eth%s -j %s --queue-num %s"\
                  % (interface,qname,int(qval)))
  nfqueue = NetfilterQueue()
  nfqueue.bind(qval, print_and_accept)
  ## this is a blocking call, so I should call this via a thread
  try:
    nfqueue.run()
  except Exception,e:
    logger.error("Error in Snoop start: %s" % str(e))
