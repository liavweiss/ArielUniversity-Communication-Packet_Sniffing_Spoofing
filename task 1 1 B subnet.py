#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
  pkt.show()
  
print('sniffing packets...')
pkt = sniff(filter='dst net 128.230.0.0/16', prn=print_pkt)
