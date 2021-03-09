#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
  pkt.show()
  
print('sniffing packets...')
pkt = sniff(iface=['br-e7b7a0685397', 'enp0s3'], filter='icmp', prn=print_pkt)
