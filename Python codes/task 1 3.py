from scapy.all import *
for i in range(1,11):
	a = IP()
	a.dst = '216.58.205.196'
	a.ttl = i
	b = ICMP()
	p = a/b
	send(p)
