#!/usr/bin/env python

# Author: Victor C. Leal
#
# 19/11/2017

import sys
import os
import argparse
from scapy.all import *
import re
import pprint

def main():
	"""
	HTTP dissector to extract files transferred via HTTP using a pcap capture file
	"""

	cwd = os.getcwd()
	# Argument and command-line options parsing
	parser = argparse.ArgumentParser(description='HTTP dissector for pcap files.')
	parser.add_argument('-r', required=True, metavar='file', dest='pcap',
	                    help='read pcap format file')
	args = parser.parse_args()
	# Read pcap file
	f = rdpcap(args.pcap)
	# Separate session
	streams = f.sessions()
	http_payload = ''
	sdata = {}
	filesave = {}
	save = ''
	i=1
	# Input file parsing
	for s in streams:
		if s.startswith('TCP'):
			for packet in streams[s]:
				try:
					# Reassemble packets from the same stream
					if packet[TCP].dport == 80 or packet[TCP].sport == 80:
						if not save:
							save = s
							# Client connection port
							port = packet[TCP].dport if packet[TCP].sport == 80 else packet[TCP].sport
						http_payload += packet[Raw].load
				except:
					pass
			# Get data and headers
			try:
				indices = [x.start() for x in re.finditer("\r\n\r\n",http_payload)]
				headers = http_payload[:indices[-1]+2]
				data = http_payload[indices[-1]+4:]
			except:
				headers = ''
				data = ''
			# Get filenames
			try:
				filename = re.findall(r' /(.*?) ', headers)[-1]
				filename = filename.split('/')[-1]
				# Filename stored to be included in different stream
				filesave.setdefault(str(port), []).append(filename)
			except:
				filename = ''
			# Get Content-Type
			try:
				ctype = re.findall(r'content-type: (.*?)\r\n', headers.lower())[0]
				ctype = ctype.split(';')[0]
			except:
				ctype = ''
			# Save data and prepare for next stream
			if filename or ctype or data:
				sdata[save] = {'File': filename, 'Content-Type': ctype, 'Data': data}
			http_payload = ''
			save = ''
	# Output files writing
	for key in sdata:
		if sdata[key]['Data']:
			# Match filename with data
			for p in filesave:
				if (':'+p) in key:
					name = filesave[p][0]
			# Save data
			try:
				with open(name) as file:
					with open(str(i)+name,'w') as file:
						file.write(sdata[key]['Data'])
						i+=1
			except IOError as e:
				with open(name,'w') as file:
					file.write(sdata[key]['Data'])
					i=1

if __name__ == '__main__':
	main()
