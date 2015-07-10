#python2 code
def user():
  try:
    interface = str(raw_input("interface to attach:"))
    port = int(raw_input("port to attach:"))
    return interface,port
  except:
    print "Bad Input"
