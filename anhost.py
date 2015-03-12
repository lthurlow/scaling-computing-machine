import re

def get_arp_table():
	arp_f = open("/proc/net/arp","r")
	header = False
	headers = []
	entries = []
	for line in arp_f:
		table = {}
		if not header:
			header = True
			[headers.append(x) for x in re.findall(r'([a-zA-Z]+\s?[a-zA-Z]+)',line)]
		else:
			row = re.findall(r'([a-zA-Z0-9.:]+\s?[a-zA-Z0-9.:]+|[\*])',line)
			count = 0
			for x in row:
				table[headers[count]] = x
				count += 1
			entries.append(table)
	return entries

def conv_hexip_to_dex(a):
	return('.'.join(str(x) for x in [int(a[6:8],16),int(a[4:6],16),
					int(a[2:4],16),int(a[0:2],16) ]))

def get_route_table():
	route_f = open("/proc/net/route","r")
	header = False
	headers = []
	entries = []
	for line in route_f:
		table = {}
		if not header:
			header = True
			[headers.append(x) for x in re.findall(r'([a-zA-Z]+)',line)]
			for x in headers:
				table[x] = []
		else:
			row = re.findall(r'([a-zA-Z0-9]+)',line)
			count = 0
			for x in row:
				if (headers[count] == 'Mask' or headers[count] == 'Destination' or\
				    headers[count] == 'Gateway'):
					table[headers[count]] = conv_hexip_to_dex(x)
				else:
					table[headers[count]] = x
				count += 1
			entries.append(table)
	return entries


get_arp_table()
get_route_table()
