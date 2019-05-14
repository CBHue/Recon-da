import re
import ast
import configparser
import os
import dbQueue
from utils.helper import whine
from utils.osWork import muxER
from dbWork import db_runner

def discoverHosts(network):
	whine( "Welcome to discoverHosts: " + network, "info")
	#network should equal 10.10.10.10/24
	#fping -a -I eth0 -R -g network
	#netdiscover -i eth0 -P -r network
	#arp-scan --interface=eth0 network

def msfSafeChecks(network,output):
	whine( "Welcome to MSF Safe Checks: " + '\033[95m' + network + '\033[0m', "info")
	config = configparser.ConfigParser()
	msfCFG = os.path.abspath(os.path.dirname(__file__)) + "/utils/msf.ini"
	whine( "Loading Safe Checks from: " + msfCFG, "debug")
	config.read(msfCFG)
	MSF = ast.literal_eval(config.get("MSF-SAFE", "msfLIST"))

	conn = dbQueue.conn
	
	host = network.split('/', 1)[0]
	DBselect = "SELECT host, port, serviceID FROM results WHERE host='" + host + "'"
	whine( "Gathering ports : " + host, "debug")
	r = db_runner(conn, DBselect)
	if not r: return
	serviceSET = set(r)
	for i in serviceSET:
		port = i[1]
		service = i[2]
		whine( "Identifying MSF Safe Checks for Port: " + port + " Service: " + service, "debug" )
		regEX = ".*" + service
		r = re.compile(regEX)
		msfLIST = list(filter(r.match, MSF))  
		
		for module in msfLIST:
			m = module.rsplit('/', 1)[-1]
			# At this point we already did HTTP so lets skip them. That might change tho
			if "http" in module: continue
			whine( "Running Metasploit Module: " + module, "debug")
			f = output + "Metasploit_" + m + ".out"
			cmd = "msfconsole -x \"use  " + module + ";set rhosts " + host + ";set rport " + port + "; run; exit\" > " + f
			muxER(cmd)

	whine( "Done with MSF Safe Checks: " + '\033[95m' + network + '\033[0m', "info")