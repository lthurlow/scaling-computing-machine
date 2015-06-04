import socket # for creating a socket
import fcntl  # for get_ip_address
import struct # for get_ip_address

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

# should later use directory service, instead of hard code IP
dst = "172.31.13.99"
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
dn = datetime.datetime.now()

dst = "172.31.13.99"
src = "172.31.13.100"
sport = 50000
fin = 0
tmr = 0

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
curr_host = anhost.get_ip_address("eth0")

this_file = open(str(__file__),'r')
udp_data = this_file.read()
this_file.close()

if not fin:
  if tmr:
    
else:
  anhost.use_default_route()
  if curr_host == src:
    print_trace()
  

"""

sock.sendto(AN_code, (dst,port))
