#!/usr/bin/env python

import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError

import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
print 'Debug On'

import os
import re
import time

from argparse import ArgumentParser
parser = ArgumentParser()
parser.add_argument("-f", "--file", dest="filename",
                    help="parse FILE", metavar="FILE")
parser.add_argument("-d", "--dir", dest="directory",
                    help="Parse all xml in directory", metavar="DIR")
parser.add_argument("-q", "--quiet",
                    action="store_false", dest="verbose", default=True,
                    help="don't print status messages to stdout")

# Global ip list
ipALL = set()

# This is the nessus parser
# it parses .... .nessus files
def parse_nessus_XML(xmlfile):
	logging.debug("Welcome to parse_nessus_XML!")

	# create element tree object
	tree = ""
	
	try:
		tree = ET.parse(xmlfile)
	except ParseError as e:
		logging.warning("CRAP ... had issues with %r", xmlfile)
		return

	root = tree.getroot()

	for block in root:
		if block.tag == "Report":
			for report_host in block:
				ost_properties_dict = dict()
				currIP = "0.0.0.0"
				for report_item in report_host:
	
					if report_item.tag == "HostProperties":
						for host_properties in report_item:
							if host_properties.attrib['name'] == "host-ip":
								currIP = host_properties.text
								logging.debug("Working on %r", currIP)

					if 'pluginName' in report_item.attrib:
						if report_item.attrib['svc_name'] == "general": continue

						fullLine = currIP + " " + report_item.attrib['port'] + " "  + report_item.attrib['protocol'] + " " + report_item.attrib['svc_name'] + " up" 
						ipALL.add(fullLine)

# This is the nmap parser
# it parses .... .xml files
# I need to actually try to ensure its a nMap file
def parse_nMap_XML(xmlfile):
	logging.debug("Welcome to parse_nMap_XML!")

	# create element tree object
	tree = ""

	try:
		tree = ET.parse(xmlfile)
	except ParseError as e:
		logging.warning("CRAP ... had issues with %r", xmlfile)
		return

	# get root element
	root = tree.getroot()

	for item in root.findall('./host'):
		
		# get the stat value
		state = item[0].attrib.get('state')
		
		# We only care about up hosts
		match = re.search('up',state)
		if match:
			logging.debug("Working on %r", item[1].attrib.get('addr'))
			ipADDR = item[1].attrib.get('addr')

			for elem in item:
				if elem.tag == 'ports':

					for a in elem:
						state = a[0].attrib.get('state')

						if state is not None:
							match = re.search('open',state)

							if match:
								port = a.attrib.get('portid')
								proto = a.attrib.get('protocol')
								service = a[-1].attrib.get('name')
								if service is None:
									service = "unknown"

								if port is not None:
									fullLine = ipADDR + " " + port + " " + proto +" " + service +" " + state
									ipALL.add(fullLine)

def main():
	args = parser.parse_args()
	#print "working on:", args

	if args.filename is not None:
		f = args.filename
		if f.endswith('.xml'):
			logging.debug("FILE: %r", f)
			parse_nMap_XML(f)
		elif f.endswith('.nessus'):
				logging.debug("PATH: %r", f)
				parse_nessus_XML(f)
		else :
			logging.warn("skipping: %r", f)


	elif args.directory is not None:
		path = args.directory

		for f in os.listdir(path):

			# For now we assume xml is nMap
			if f.endswith('.xml'): 
				fullname = os.path.join(path, f)
				#print fullname
				logging.debug("PATH: %r", fullname)
				parse_nMap_XML(fullname)
			# .nessus has to be nessus right?
			elif f.endswith('.nessus'):
				fullname = os.path.join(path, f)
				#print fullname
				logging.debug("PATH: %r", fullname)
				parse_nessus_XML(fullname)
			else :
				logging.warn("skipping: %r", f)
	else :
		print "usage issues =("
		exit

def outIT():
	if len(ipALL) < 1:
		print "No data =("
		for x in vulnerabilities:
			print (x)
		quit()

	sorted_IP = sorted(ipALL)
	fN = "ip_pivot_list_" + str(time.time()) + ".txt"
	print "Output saved to :" + fN

	with open(fN, 'w') as f:
		for ip in sorted_IP:
			print >>f, ip

# This is the main
if __name__ == "__main__":
	
	# Logging ... this doesnt work at the moment
	#if not __debug__:
	#	print 'Debug On'
	#logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # call main 
	main()

	# Output it all 
	outIT()
