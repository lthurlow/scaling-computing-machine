import sys

print("Starting server, checking Python version")
if sys.version_info[0] == 2:
  print("\tRunning server2.py")
  exec(open("server2.py").read())
elif sys.version_info[0] == 3:
  print("\tRunning server3.py")
  exec(open("server3.py").read())
