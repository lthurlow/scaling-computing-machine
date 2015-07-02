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

AN_code = \
"""
import anhost
import socket

fdst = "172.31.13.99"
sdst = "172.31.13.98"
esrc = "172.31.13.100"

sport = 50001

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
curr_host = anhost.get_ip_address("eth0")
print curr_host

this_file = open(str(__file__))
udp_data = this_file.read()
this_file.close()
print udp_data

try:
  if curr_host == fdst:
    sock.sendto(udp_data,(sdst,50000))

    ## cant sent to 50000 because server will grab it, so 50001 for app
    HOST = str(anhost.get_ip_address("eth0"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST,sport))
    msg, addr = sock.recvfrom(2048)

    ## if we got a copy back, we know it got there, so respond back to src
    if msg == udp_data:
      print "packet recv from an3, sending back to an1"
      sock.sendto(udp_data,(esrc,50000))
    else:
      print "Mismatch"
      print msg
      print udp_data

  elif curr_host == sdst:
    sock.sendto(udp_data,(fdst,50001))
    print "packet recv, sending back"

except Exception, e:
  udp_data = str(e)
  sock.sendto(udp_data,(esrc,50000))
"""

sock.sendto(AN_code, (dst,port))
