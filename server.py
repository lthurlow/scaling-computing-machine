import socket

serv = "10.0.0.4"
port = 50000
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((serv,port))

while True:
  msg, addr = sock.recvfrom(1024)
  print "msg:", msg
