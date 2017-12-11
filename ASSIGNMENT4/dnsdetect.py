import sys
import os
import argparse
import socket
import scapy
from scapy.all import *
import netifaces as ni
from collections import deque

hosts = {}
mip = '127.0.0.1'
soc = None

# Get input arguments from the user
def get_args():
	parser = argparse.ArgumentParser(add_help=False);
	parser.add_argument('-i', metavar='eth0');
	parser.add_argument('-r', metavar='dns_detect.pcap');
	parser.add_argument('expression', nargs='*', action='store');
	arg = parser.parse_args();
	# set default expression for DNS . UDP port 53
	exp = 'udp port 53'

	if (arg.expression):
		exp = exp + ' and ' + ' '.join(arg.expression)
	return arg.i, arg.r, exp;

# Packet Queue
packet_q = deque(maxlen = 10)

# DNS detector invoked by SNIFF
def dns_detect(packet):
	if (UDP in packet and DNS in packet and packet.haslayer(DNSRR)):
		if (len(packet_q) > 0):
			for pkt in packet_q:
				if (pkt[IP].dst == packet[IP].dst and \
					pkt[IP].payload != packet[IP].payload and \
					pkt[IP].sport == packet[IP].sport and \
					pkt[IP].dport == packet[IP].dport and \
					pkt[DNSRR].rdata != packet[DNSRR].rdata and \
					pkt[DNS].id == packet[DNS].id and \
					pkt[DNS].qd.qname == packet[DNS].qd.qname):
					print "DNS Posisoning Attack Detected"
		packet_q.append(packet)

def main():
	exp = ''
	[i, r, exp] = get_args();
	# Offline file obtained from tcpdump
	if (r) :
		mip = ni.ifaddresses(i)[2][0]['addr'];
		sniff(filter = 'udp port 53', offline = r, prn = dns_detect);
	# live interface
	elif(i):
		mip = ni.ifaddresses(i)[2][0]['addr'];
		sniff(filter = 'udp port 53', iface = i, prn = dns_detect);
	# 
	else:
		mip = ni.ifaddresses(conf.iface)[2][0]['addr'];
		sniff(filter = '', store = 0, prn = dns_detect);
main()
