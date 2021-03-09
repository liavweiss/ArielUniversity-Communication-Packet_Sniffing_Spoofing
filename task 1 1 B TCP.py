#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
  pkt.show()
  
print('sniffing packets...')
pkt = sniff(filter='tcp and dst port 23 and src host 10.0.2.4', prn=print_pkt)
