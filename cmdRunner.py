#!/usr/bin/python 

import os
import re
import time
import ipaddress

import dbQueue
import utils.helper as helper
from utils.osWork import muxER
from web.webTests import webTests

def db_runner(c, query, args=None):
    cur = c.cursor()
    if args:
        cur.execute(query, args)
    else:
        cur.execute(query)
    results = cur.fetchall()
    cur.close()
    return results

def pickWeapon (cmd, host, outFile):
	tools = {}
	if cmd == "nmap":
		tools["nmap_t10000"] = "nmap -sS -n --randomize-hosts --max-retries 1 --top-ports 10000 --data-length=0 --open " + host + " -oA " + outFile + " > " + outFile + ".out"
		tools["nmap_full"] = "nmap -sS -n --randomize-hosts --max-retries 1 -p- --data-length=0 --open " + host + " -oA " + outFile + " > " + outFile + ".out"
		tools["nmap_t100"] = "nmap -sS -n --randomize-hosts --max-retries 1 --top-ports 100 --data-length=0 --open " + host + " -oA " + outFile + " > " + outFile + ".out"
		tools["nmap_default"] = "nmap -sS -n --randomize-hosts --max-retries 1 --data-length=0 --open " + host + " -oA " + outFile + " > " + outFile + ".out"
		
		# make some decision based on config value
		cmd = tools["nmap_full"]
	elif cmd == "fping":
		tools["fping"] = "fping -a -r0 -g $host"

	return cmd

def validateHost (network):
	helper.printB("Validating Host: " + '\033[0m' + network)
	cidr = ""

	# Single IP or a network
	match = re.search(r'(\d+.\d+.\d+.\d+)(/\d+)', network)
	if match:
		matchWork = match.group(1)
		helper.printB("IP Addr: " + '\033[0m' + matchWork)
		helper.printB("Subnet : " + '\033[0m' + match.group(2))
		cidr = match.group(2)

		if match.group(2) == '/32':
			confirmIP(matchWork, cidr)
		else:
			helper.printB("Expanding network : " + '\033[0m' + network)
			expandedIPList = ipaddress.ip_network(network)
			cidr = "/32"
			for ip in expandedIPList:
				confirmIP(ip, cidr)
	else:
		helper.printB("Single IP: " + '\033[0m' + network)
		matchWork = network	
		cidr = "/32"
		confirmIP(matchWork, cidr)

def confirmIP (matchWork, cidr):	
	# Lets see if this is a real IP
	try:
		ipaddress.ip_address(matchWork)
		
		# Add hosts to DB
		h = str(matchWork) + cidr

		# Add the DB task to the Queue
		DBcommit = 'INSERT INTO Hosts VALUES (?,?,?)', [h, "Waiting", "No open ports"]
		dbQueue.workDB.put(DBcommit)

		# Add the ip work to the Queue
		dbQueue.work.put(h)
		return True
	except ValueError:
		helper.printR("Address/Netmask is invalid: "+ '\033[0m' + matchWork + cidr)
		return False
	except Exception as e:
		helper.whine('[validateHost] ' + str(e) + " " + str(matchWork))
		return False

def portLandia (file):
	# get all open ports per host
	cmd = "cat " + file + " | grep Ports: " 
	CBH = muxER(cmd)
	
	allPort = set()
	httpList = set()
	H = None

	p = re.search(r'Host: (\d+\.\d+\.\d+\.\d+).*Ports: (.*)',CBH)
	if p:

		H = p.group(1)
		pL = p.group(2).split(',')
		for o in pL:
			# 8834/open/tcp//ssl|http//Nessus vulnerability scanner http UI/
			mo = re.search(r'(\d+)/open/(\w+)/\w*/(\w+)',o)
			if mo: 
				allPort.add(mo.group(1))
				DBcommit = 'INSERT INTO results VALUES (?,?,?,?)', [H, mo.group(1), mo.group(2), mo.group(3)]
				dbQueue.workDB.put(DBcommit)
				http = re.search(r'(http|https)',mo.group(3),re.IGNORECASE)
				if http:
					url = mo.group(3) + "://" + H + ":" + mo.group(1)
					httpList.add(url)

	return allPort,httpList

def servicABLE (host,ports,file):
	helper.whine("Sevice Identification: " + host)
	pL = ','.join(ports)
	fO = file + ".out"
	cmd = "nmap -sV -n --randomize-hosts --script discovery,vuln --max-retries 0 -Pn -A -p "+ pL + " -T3 --open " + host + " -oA " + file + " > " + fO
	return cmd

def udpScan (network, out):
	DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage5 - Running udp unicornscan", network]
	dbQueue.workDB.put(DBcommit)
	helper.whine("UDP scanning: " + network) 
	f = out + ".udp"
	cmd = "unicornscan -mU " + network + " > " + f
	muxER(cmd)

def fin (network, out, s0, workerName):
	helper.whine("Done with: " + '\033[0m' + network)
	helper.whine("Files located at: "+ '\033[95m' + out + "*" + '\033[0m')
	DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Completed", network]
	dbQueue.workDB.put(DBcommit)
	helper.whine( '\033[92m' + "[" + workerName + "] Session Closed: " + '\033[0m' + s0 )
	muxER('tput rs1')
	
def showResult (selection):
	cmd = "date"

	if selection is 'ALL':
		cmd = "find " + dbQueue.dumpDir + " \\( -name \"*.out\" -o -name \"*.udp\" -o -name \"*.dirb\" -o -name \"*.nikto\" \\)"
	elif "name" in selection:
		cmd = "find " + dbQueue.dumpDir + " " + selection
	else:
		r = selection
		if len(r) > 0:
			print (r[0])
			f = str(r[0]).split("/")[0]
			f = f.split("\'")[1]
			cmd = "find " + dbQueue.dumpDir + "* \\( -name \"*.out\" -o -name \"*.udp\" -o -name \"*.dirb\" -o -name \"*.nikto\" \\) | grep " + f 
		else:
			helper.printR("This entry does not exist: " + selection)
			return
	
	results = muxER(cmd)
	if (len(results)) < 1:
		return

	fList = results.split('\n')
	for f in fList:
		if not os.path.isfile(f): 
			continue
		helper.printP(f)
		cmd = "cat -s " + f + " | egrep -v \"Nmap done|Starting Nmap|Warning|Note\""
		out = muxER(cmd)
		print (out)
	
	# Find and list screenshots
	cmd = "find " + dbQueue.dumpDir + " -name *.png"
	results = muxER(cmd)
	if (len(results)) < 1:
		return
	fList = results.split('\n')
	helper.printP("HTTP Screenshots:")
	for f in fList:
		#if not os.path.isfile(f): continue
		helper.printW("file://" + f)
	print ("")

def sweepER (network, workerName):
	# create a unique identifier date + master
	ts = time.strftime("%m%d%Y_%H_%M_%S", time.gmtime())
	#s0 = network.replace(".","-").replace("/","_") +  "_" + ts
	s0 = network.replace("/","_") +  "_" + ts

	# Add the work to the DB
	DBcommit = 'INSERT INTO stages VALUES (?,?)', [s0, 'init']
	dbQueue.workDB.put(DBcommit)

	s1 = "STAGE_1_" + s0
	s2 = "STAGE_2_" + s0
	s3 = "STAGE_3_" + s0
	s4 = "STAGE_4_" + s0
	s5 = "STAGE_6_" + s0
	s6 = "STAGE_7_" + s0
	sd = "ALLDONE_" + s0

	# create a muxer for the session
	helper.whine('\033[92m' + "[" + workerName + "] Session created: " + '\033[0m' + s0 )
	DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage1 - Running initial nmap sweep", network]
	dbQueue.workDB.put(DBcommit)

	#
	# stage 1 - nMap : check for open ports
	#
	out = dbQueue.dumpDir + s0
	cmd = pickWeapon("nmap", network, out)
	muxER(cmd)

	#
	# Stage 2 - nMap : get open ports from the gnmap file
	#
	DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage2 - Creating list of open ports", network]
	dbQueue.workDB.put(DBcommit)
	f = out + ".gnmap"
	allports,urls = portLandia(f)
	aPorts = "|".join(allports)
	netOut = network + " " + str(allports)
	helper.whine (netOut)
	
	# If a host has 0 in set move on ...
	#########################
	if len(allports) < 1:
		fin(network, out, s0,workerName)
		return

	#
	# Stage 3 - nMap : get service description
	# 
	DBcommit = 'UPDATE Hosts SET status=?, ports=? WHERE host=?', ["Stage3 - Running nMap service description", aPorts, network]
	dbQueue.workDB.put(DBcommit)
	f = dbQueue.serviceDir + s0 + "_ServiceID"
	cmd = servicABLE(network,allports,f)
	muxER(cmd)
	f = f + ".gnmap"

	aPorts = "|".join(allports)
	DBcommit = 'UPDATE Hosts SET ports=? WHERE host=?', [aPorts, network]
	dbQueue.workDB.put(DBcommit)

	#
	# Stage 4 - Web Tests: ScreenShot, Nikto , dirbuster
	#
	webTests(network, urls, out, workerName)

	#
	# Stage 5 - unicornscan: UDP
	#
	udpScan(network, out)

	#
	# Clean-up ... we are done
	#
	fin(network, out, s0, workerName)
