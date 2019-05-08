#!/usr/bin/python 

import os
import re
import sys
import time
import subprocess
import shlex
import ipaddress
import sqlite3
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

import config
import helper

def db_runner(c, query, args=None):
    cur = c.cursor()
    if args:
        cur.execute(query, args)
    else:
        cur.execute(query)
    results = cur.fetchall()
    cur.close()
    return results

def whine (message):
	if config.debug.value is True:
		helper.printY(message)

def muxERToo(command):
	result =[]
	result = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE).communicate()[0].decode('utf-8').strip()
	return result

def muxER(command):
	result =[]
	FNULL = open(os.devnull, 'w')
	p = subprocess.Popen([command], stdout=subprocess.PIPE, stderr=FNULL, shell=True)
	# Add to shared list
	config.pidLIST.append(str(p.pid))
	# Get the result
	(result, err) = p.communicate()
	# once we finish lets remove it from the queue
	config.pidLIST.remove(str(p.pid))
	# return the results
	return result.decode("utf-8").strip() 

def realTimeMuxER(command):
	p = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE)
	while True:
		output = p.stdout.readline().decode()
		if output == '' and p.poll() is not None:
			break
		if output:
			print(output.strip())
	rc = p.poll()

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

def chromeShot (url,f):
	chrome_options = Options()
	chrome_options.add_argument("--headless")
	chrome_options.add_argument("--window-size=1920x1080")
	chrome_options.add_argument("--no-sandbox")
	chrome_options.add_argument("--user-data-dir /tmp")
	chrome_options.add_argument('--ignore-certificate-errors')

	chrome_driver = "/usr/bin/chromedriver"
	driver = webdriver.Chrome(chrome_options=chrome_options, executable_path=chrome_driver)
	driver.set_page_load_timeout(3)

	try:
		driver.get(url)
		driver.get_screenshot_as_file(f)
	except Exception as e:
		whine("screenshot Error:" + str(e))

	driver.quit()

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
		config.workDB.put(DBcommit)

		# Add the ip work to the Queue
		config.work.put(h)
		return True
	except ValueError:
		helper.printR("Address/Netmask is invalid: "+ '\033[0m' + matchWork + cidr)
		return False
	except Exception as e:
		whine('[validateHost] ' + str(e) + " " + str(matchWork))
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
				config.workDB.put(DBcommit)
				http = re.search(r'(http|https)',mo.group(3))
				if http:
					url = mo.group(3) + "://" + H + ":" + mo.group(1)
					httpList.add(url)

	return allPort,httpList

def servicABLE (host,ports,file):
	whine("Sevice Identification: " + host)
	pL = ','.join(ports)
	fO = file + ".out"
	cmd = "nmap -sV -n --randomize-hosts --script discovery,vuln --max-retries 0 -Pn -A -p "+ pL + " -T3 --open " + host + " -oA " + file + " > " + fO
	return cmd

def webTests (network, urls, out, workerName):
	DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage4 - Running Web Tests (screenshot Nikto dirb)", network]
	config.workDB.put(DBcommit)

	whine("Running Web Tests on " + str(len(urls)) + " URL(s)")
	for u in urls:
		match = re.search(r'.*:(\d+)',u)
		if match:
			whine( "Taking Screenshot: " + u )
			f = out + "_Port_" + match.group(1) + ".png"
			chromeShot(u,f)

			whine( "Running Nikto on: " + u )
			f = out + "_" + match.group(1) + ".nikto"
			cmd = "nikto -Cgidirs all -host " + u + " -Format txt -output " + f
			muxER(cmd)

			whine( "Running dirb on: " + u )
			f = out + "_" + match.group(1) + ".dirb"
			cmd = "dirb " + u + " -o " + f
			muxER(cmd)

def udpScan (network, out):
	DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage5 - Running udp unicornscan", network]
	config.workDB.put(DBcommit)
	whine("UDP scanning: " + network) 
	f = out + ".udp"
	cmd = "unicornscan -mU " + network + " > " + f
	muxER(cmd)

def fin (network, out, s0, workerName):
	whine("Done with: " + '\033[0m' + network)
	whine("Files located at: "+ '\033[95m' + out + "*" + '\033[0m')
	DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Completed", network]
	config.workDB.put(DBcommit)
	whine( '\033[92m' + "[" + workerName + "] Session Closed: " + '\033[0m' + s0 )
	muxER('tput rs1')
	
#
# Proc killer: prob not a good idea ...
#
def killER (proc):
	ps = "ps -ef | grep "+ proc + " | grep -v grep"
	pkill = muxER(ps)
	pList = pkill.split('\n')
	for p in pList:
		p = p.rstrip("\n")
		match = re.search(r'root\s+(\d+).*\d\d:\d\d:\d\d(.*)',p)
		if match:
			ps = "kill -9 " + match.group(1)
			helper.printR("killing " + match.group(2))
			muxER(ps)
			time.sleep(1)

def showResult (selection):
	cmd = "date"

	if selection is 'ALL':
		cmd = "find " + config.dumpDir + " \\( -name \"*.out\" -o -name \"*.udp\" -o -name \"*.dirb\" -o -name \"*.nikto\" \\)"
	elif "name" in selection:
		cmd = "find " + config.dumpDir + " " + selection
	else:
		r = db_runner(config.conn, 'SELECT host FROM Hosts WHERE host=?', [selection])
		if len(r) > 0:
			print (r[0])
			f = str(r[0]).split("/")[0]
			f = f.split("\'")[1]
			cmd = "find " + config.dumpDir + "* \\( -name \"*.out\" -o -name \"*.udp\" -o -name \"*.dirb\" -o -name \"*.nikto\" \\) | grep " + f 
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
	cmd = "find " + config.dumpDir + " -name *.png"
	results = muxER(cmd)
	if (len(results)) < 1:
		return
	fList = results.split('\n')
	helper.printP("HTTP Screenshots:")
	for f in fList:
		if not os.path.isfile(f): continue
		helper.printW("file://" + f)
	print ("")

def sweepER (network, workerName):
	# create a unique identifier date + master
	ts = time.strftime("%m%d%Y_%H_%M_%S", time.gmtime())
	#s0 = network.replace(".","-").replace("/","_") +  "_" + ts
	s0 = network.replace("/","_") +  "_" + ts

	# Add the work to the DB
	DBcommit = 'INSERT INTO stages VALUES (?,?)', [s0, 'init']
	config.workDB.put(DBcommit)

	s1 = "STAGE_1_" + s0
	s2 = "STAGE_2_" + s0
	s3 = "STAGE_3_" + s0
	s4 = "STAGE_4_" + s0
	s5 = "STAGE_6_" + s0
	s6 = "STAGE_7_" + s0
	sd = "ALLDONE_" + s0

	# create a muxer for the session
	whine('\033[92m' + "[" + workerName + "] Session created: " + '\033[0m' + s0 )
	DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage1 - Running initial nmap sweep", network]
	config.workDB.put(DBcommit)

	#
	# stage 1 - nMap : check for open ports
	#
	out = config.dumpDir + s0
	cmd = pickWeapon("nmap", network, out)
	muxER(cmd)

	#
	# Stage 2 - nMap : get open ports from the gnmap file
	#
	DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage2 - Creating list of open ports", network]
	config.workDB.put(DBcommit)
	f = out + ".gnmap"
	allports,urls = portLandia(f)
	aPorts = "|".join(allports)
	netOut = network + " " + str(allports)
	whine (netOut)
	
	# If a host has 0 in set move on ...
	#########################
	if len(allports) < 1:
		fin(network, out, s0,workerName)
		return

	#
	# Stage 3 - nMap : get service description
	# 
	DBcommit = 'UPDATE Hosts SET status=?, ports=? WHERE host=?', ["Stage3 - Running nMap service description", aPorts, network]
	config.workDB.put(DBcommit)
	f = config.serviceDir + s0 + "_ServiceID"
	cmd = servicABLE(network,allports,f)
	muxER(cmd)
	f = f + ".gnmap"

	aPorts = "|".join(allports)
	DBcommit = 'UPDATE Hosts SET ports=? WHERE host=?', [aPorts, network]
	config.workDB.put(DBcommit)

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
