import sys
import os
import argparse
import socket
import scapy
from scapy.all import *
import netifaces as ni
from collections import deque

hosts = {}
my_ip = '127.0.0.1'
soc = None

def get_args():
	parser = argparse.ArgumentParser(add_help=False);
	parser.add_argument('-i', metavar='eth0');
	parser.add_argument('-r', metavar='192.168.10.1');
	parser.add_argument('expression', nargs='*', action='store');
	arg = parser.parse_args();
	if (arg.expression):
		print arg.expression
	return arg.i, arg.r, arg.expression;

packet_q = deque(maxlen = 10)

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

if __name__ == '__main__':
	exp = ''
	[i, r, exp] = get_args();
	if (r) :
		my_ip = ni.ifaddresses(i)[2][0]['addr'];
		sniff(filter = 'udp port 53', offline = r, prn = dns_detect);
	elif(i):
		my_ip = ni.ifaddresses(i)[2][0]['addr'];
		sniff(filter = 'udp port 53', iface = i, prn = dns_detect);
	else:
		my_ip = ni.ifaddresses(conf.iface)[2][0]['addr'];
		sniff(filter = '', store = 0, prn = dns_detect);
