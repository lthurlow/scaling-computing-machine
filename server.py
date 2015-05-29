import sys

if sys.version_info[0] == 2:
  exec(open("server2.py").read())
elif sys.version_info[0] == 3:
  exec(open("server3.py").read())
