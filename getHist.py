from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

ifilename = 'a.pcap'
pkts=rdpcap(ifilename)
for p in pkts:
	print p.summary()
