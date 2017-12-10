import sys
import os
import argparse

def get_args():
	parser = argparse.ArgumentParser(add_help=False)
	parser.add_argument('-i', metavar='eth0')
	parser.add_argument('-h', metavar='192.168.10.1')
	parser.add_argument('expression', nargs='*', action='store')
	arg = parser.parse_args()
	if (arg.i):
		#print "Interface",
		print arg.i
	if (arg.h):
		#print "Hostname",
		print arg.h
	if (arg.expression):
		#print "Expression",
		print arg.expression
	return arg.i, arg.h, arg.expression

if __name__ == '__main__':
	print get_args()
