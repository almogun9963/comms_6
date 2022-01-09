from scapy.all import *
a = IP()
a.dst = '213.57.22.5' #www.ynet.co.il
a.ttl = 1
for i in range (20):
    b = ICMP()
    send(a/b)
    a.ttl +=1
