import anhost
import os
import logging
import pprint

"""
x = anhost.chg_val("temp.py",[],"trace","x++","w")
print "\n"
os.system("diff temp.py temp.txt")

print "\n"
x = anhost.chg_val("temp.py",[],"trace",[18,22,32],"w")
print "\n"
os.system("diff temp.py temp.txt")

print "\n"
x = anhost.chg_val("temp.py",[],"info",[22200],"a")
print "\n"
os.system("diff temp.py temp.txt")

print "\n"
x = anhost.chg_val("temp.txt",[],"info",[21200,8],"a")
print "\n"
os.system("diff temp.py temp.txt")
"""

x = anhost.use_default_route()
