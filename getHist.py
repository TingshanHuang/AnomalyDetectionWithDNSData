from scapy.all import *
import sys
## TO DO: FILTER THE DOMAIN NAMES
#ifilename="dns_00000_20150717150532.pcap"
arg = sys.argv
try:
	ifilename=arg[1]
except:
	sys.exit()

## read packets
pkts=rdpcap(ifilename+'.pcap', 1000)

## get frequency
dictQSrcIP={} # source IP addresses of queries
dictQDstIP={} # destination IP addresses of queries
dictRSrcIP={} # source IP addresses of responses
dictRDstIP={} # destination IP addresses of responses
dictQDomain={} # domain names of queries
dictRDomain={} # domain names of responses
for onePKT in pkts:
	try:
		qr=onePKT.qr
	except:
		qr=-1
	# source IP address
	try:
		srcIP = onePKT.src
	except:
		srcIP_value = '0.0.0.0'
	if qr == 0:
		if srcIP not in dictQSrcIP:
			dictQSrcIP[srcIP]=1
		else:
			dictQSrcIP[srcIP]=dictQSrcIP[srcIP]+1
	elif qr == 1: 
		if srcIP not in dictRSrcIP:
			dictRSrcIP[srcIP]=1
		else:
			dictRSrcIP[srcIP]=dictRSrcIP[srcIP]+1

	# destination IP address
	try:
		dstIP = onePKT.dst
	except:
		dstIP_value = '0.0.0.0'
	if qr == 0:
		if dstIP not in dictQDstIP:
			dictQDstIP[dstIP]=1
		else:
			dictQDstIP[dstIP]=dictQDstIP[dstIP]+1
	elif qr == 1: 
		if dstIP not in dictRDstIP:
			dictRDstIP[dstIP]=1
		else:
			dictRDstIP[dstIP]=dictRDstIP[dstIP]+1
	
	try:
		qname = onePKT.qd.qname 
	except:
		qname = ''
	if qr == 0:
		if qname not in dictQDomain:
			dictQDomain[qname]=1
		else:
			dictQDomain[qname]=dictQDomain[qname]+1
	elif qr == 1: 
		if qname not in dictRDomain:
			dictRDomain[qname]=1
		else:
			dictRDomain[qname]=dictRDomain[qname]+1

index = 0
y = dictQSrcIP
g = open('dictQSrcIP'+arg[1]+'.txt','w')
f = open('freqQSrcIP'+arg[1]+'.txt','w')
for x in y.keys():
	print "%d, %d" %(index,y[x])
	print "%s, %d" %(x,y[x])
	f.write("%d %d\n" %(index,y[x]))
	g.write("%s %d\n" %(x,y[x]))
	index=index+1
index = 0
y = dictQDstIP
g = open('dictQDstIP'+arg[1]+'.txt','w')
f = open('freqQDstIP'+arg[1]+'.txt','w')
for x in y.keys():
	print "%d, %d" %(index,y[x])
	print "%s, %d" %(x,y[x])
	f.write("%d %d\n" %(index,y[x]))
	g.write("%s %d\n" %(x,y[x]))
	index=index+1
index = 0
y = dictRSrcIP
g = open('dictRSrcIP'+arg[1]+'.txt','w')
f = open('freqRSrcIP'+arg[1]+'.txt','w')
for x in y.keys():
	print "%d, %d" %(index,y[x])
	print "%s, %d" %(x,y[x])
	f.write("%d %d\n" %(index,y[x]))
	g.write("%s %d\n" %(x,y[x]))
	index=index+1
index = 0
y = dictRDstIP
g = open('dictRDstIP'+arg[1]+'.txt','w')
f = open('freqRDstIP'+arg[1]+'.txt','w')
for x in y.keys():
	print "%d, %d" %(index,y[x])
	print "%s, %d" %(x,y[x])
	f.write("%d %d\n" %(index,y[x]))
	g.write("%s %d\n" %(x,y[x]))
	index=index+1
index = 0
y = dictQDomain
g = open('dictQDomain'+arg[1]+'.txt','w')
f = open('freqQDomain'+arg[1]+'.txt','w')
for x in y.keys():
	print "%d, %d" %(index,y[x])
	print "%s, %d" %(x,y[x])
	f.write("%d %d\n" %(index,y[x]))
	g.write("%s %d\n" %(x,y[x]))
	index=index+1
index = 0
y = dictRDomain
g = open('dictRDomain'+arg[1]+'.txt','w')
f = open('freqRDomain'+arg[1]+'.txt','w')
for x in y.keys():
	print "%d, %d" %(index,y[x])
	print "%s, %d" %(x,y[x])
	f.write("%d %d\n" %(index,y[x]))
	g.write("%s %d\n" %(x,y[x]))
	index=index+1
## save result
# by frequency
# by hash
#with open("test.txt", "a") as myfile:
#    myfile.write("appended text")
#g = open('dictQSrcIP.txt','w')
#f = open('freqQSrcIP.txt','w')
#index = 0
#y = dictQSrcIP
#for x in y.keys():
#	f.write(str(index)+' '+str(y[x])

#dictQSrcIP={} # source IP addresses of queries
#dictQDstIP={} # destination IP addresses of queries
#dictRSrcIP={} # source IP addresses of responses
#dictRDstIP={} # destination IP addresses of responses
#dictQDomain={} # domain names of queries
#dictRDomain={} # domain names of responses


