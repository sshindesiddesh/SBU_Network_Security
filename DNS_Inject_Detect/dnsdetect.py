import sys
import os
import argparse
import socket
import scapy
from scapy.all import *
import netifaces as ni
from collections import deque

hosts = {}
mip = ''
soc = None

# Get input arguments from the user
def get_args():
	parser = argparse.ArgumentParser(add_help=False);
	# get interface using -i or also support default interface
	parser.add_argument('-i', metavar='eth0');
	# see if input cap file is provided
	parser.add_argument('-r', metavar='dns_detect.pcap');
	# check for expression
	parser.add_argument('expression', nargs='*', action='store');
	arg = parser.parse_args();
	# set default expression for DNS . UDP port 53
	exp = 'udp port 53';
	if (arg.expression):
		exp = exp + ' and ' + ' '.join(arg.expression);
	return arg.i, arg.r, exp;

# Packet Queue
packet_q = deque(maxlen = 20)

# DNS detector invoked by SNIFF
def dns_detect(packet):
	if (UDP in packet and DNS in packet and packet.haslayer(DNSRR)):
		if (len(packet_q) > 0):
			# check for every packet in queue
			for pkt in packet_q:
				# check if dst IP match
				# check if source/destination port match
				# check if DNS id matched
				# check if the payload is not exactly same as the attacker has modified the rdata
				# check for the qname to be same
				if (pkt[IP].dst == packet[IP].dst and
					pkt[IP].payload != packet[IP].payload and
					pkt[IP].sport == packet[IP].sport and
					pkt[IP].dport == packet[IP].dport and
					pkt[DNSRR].rdata != packet[DNSRR].rdata and
					pkt[DNS].id == packet[DNS].id and
					pkt[DNS].qd.qname == packet[DNS].qd.qname):
					print "DNS Posisoning Attack Detected"
					# print TXID and IP list
					print "TXID : ", pkt[1][DNS].id,
					print "Request : ", pkt[1][DNS][DNSRR].rrname
					print "Answer 1 : ", str(packet[DNSRR].rdata)
					print "Answer 2 : ", str(pkt[DNSRR].rdata)
					
		# Append the the packet tot he queue
		packet_q.append(packet)

def main():
	exp = ''
	[i, r, exp] = get_args();
	#print exp;
	try :
		# Offline file obtained from tcpdump
		if (r) :
			mip = ni.ifaddresses(i)[2][0]['addr'];
			sniff(filter = exp, offline = r, prn = dns_detect);
		# live interface
		elif(i) :
			mip = ni.ifaddresses(i)[2][0]['addr'];
			sniff(filter = exp, iface = i, prn = dns_detect);
		# default interface
		else :
			mip = ni.ifaddresses(conf.iface)[2][0]['addr'];
			sniff(filter = exp, store = 0, prn = dns_detect);
	except :
		print "Input Incorrect";
		print "Correct Format dnsdetect [-i interface] [-r tracefile] expression";

# Invoke Main funcion
main();