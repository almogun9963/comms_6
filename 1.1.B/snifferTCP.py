#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
  pkt.show()
  
pkt = sniff(iface='enp0s3', filter='tcp and src host 192.168.1.47 and dst port 23', prn=print_pkt)
