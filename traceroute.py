import socket # for creating a socket
import fcntl  # for get_ip_address
import struct # for get_ip_address

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

# should later use directory service, instead of hard code IP
#dst = "172.31.13.99"
dst = "puertocayo.soe.ucsc.edu"
# AN port
port = 50000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

## Two ways to approach this
## 1. have code exist on node (anhost)
## 2. have code exist in capsule

## Node code

## Capsule code
# get current time (soon as possible)
# if fin flag set
#   forward packet, do nothing special
# if not fin flag
#   if timer flag set
#     1. subtract previous value from current time, delay to hop
#     2. add new time to list of times
#   if not timer flag
#     do nothing
#   get new current time, set variable and timer flag


AN_code = \
"""
trace = []
import anhost
import socket
import datetime
import time
dn = time.mktime(datetime.datetime.now().timetuple())

dst = "puertocayo.soe.ucsc.edu"
src = "71.198.218.220"
sport = 50000
fin = 0
tmr = 0

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
curr_host = anhost.get_ip_address("eth0")
print "this_host: %s" % curr_host

this_file = open(str(__file__),'r')
udp_data = this_file.read()
this_file.close()

if not fin:
  if tmr:
    anhost.chg_val(__file__,[],"trace",dn-tmr,'a')
  else:
    anhost.chg_val(__file__,0.0,"tmr",dn,'w')
  if curr_host == dst:
    fin = 1
    tmp = dst
    anhost.chg_val(__file__,"","dst",src,'w')
    anhost.chg_val(__file__,"","src",tmp,'w')
    
else:
  if curr_host == src:
    iter = 0
    for hop in trace:
      print "%d\t%s" % (iter+=1,hop)
sock.send(open(__file__).read(), (anhost.use_default_route(),50000))
"""

sock.sendto(AN_code, (dst,port))
