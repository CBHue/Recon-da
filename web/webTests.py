
import os
import re
from shutil import copy2
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

import dbQueue
from utils.osWork import muxER
from utils.helper import whine

def webTests (network, urls, out, workerName):
	DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage4 - Running Web Tests (screenshot Nikto dirb)", network]
	dbQueue.workDB.put(DBcommit)

	whine("Running Web Tests on " + str(len(urls)) + " URL(s)", "info")
	for u in urls:
		whine("URL : " + u, "debug")
		match = re.search(r'.*:(\d+)',u)
		if match:

			whine( "Running Metasploit Modules: " + network + ":" + match.group(1) , "debug")
			DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage4 - Running Web Tests (Metasplot Auxilary)", network]
			dbQueue.workDB.put(DBcommit)

			f = out + "_" + match.group(1) + "_" 
			msfHTTPAuxilary(network,match.group(1),f)

			whine( "Taking Screenshot: " + u , "debug")
			DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage4 - Running Web Tests (Taking Screenshot)", network]
			dbQueue.workDB.put(DBcommit)
			f = out + "_Port_" + match.group(1) + ".png"
			chromeShot(u,f)

			whine( "Running Nikto on: " + u , "debug")
			DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage4 - Running Web Tests (Nikto)", network]
			dbQueue.workDB.put(DBcommit)
			f = out + "_nikto_" + match.group(1) + ".txt"
			cmd = "nikto -Cgidirs all -host " + u + " -Format txt -output " + f
			muxER(cmd)

			whine( "Running dirb on: " + u , "debug")
			DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage4 - Running Web Tests (dirb)", network]
			dbQueue.workDB.put(DBcommit)
			f = out + "_dirb_" + match.group(1) + ".txt"
			cmd = "dirb " + u + " -o " + f
			muxER(cmd)

			whine( "Running gobuster on: " + u , "debug")
			DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage4 - Running Web Tests (gobuster)", network]
			dbQueue.workDB.put(DBcommit)
			f = out + "_gobuster_" +"_" + match.group(1) + ".txt"
			cmd = "gobuster dir -q -l -k -e -u " + u + " --wordlist /usr/share/wordlists/dirb/big.txt -o " + f
			muxER(cmd)

def chromeShot (url,f):
	chrome_options = Options()
	chrome_options.add_argument("--headless")
	chrome_options.add_argument("--window-size=1920x1080")
	chrome_options.add_argument("--no-sandbox")
	chrome_options.add_argument("--user-data-dir /tmp")
	chrome_options.add_argument('--ignore-certificate-errors')

	chrome_driver = "/usr/bin/chromedriver"

	try:
		driver = webdriver.Chrome(chrome_options=chrome_options, executable_path=chrome_driver)
		driver.set_page_load_timeout(3)
		driver.get(url)
		driver.get_screenshot_as_file(f)
		copy2(f, dbQueue.screenDir)
		driver.quit()
	except Exception as e:
		whine("screenshot Error:" + str(e), "debug")

def msfHTTPAuxilary(host,port,output):
	import ast
	import configparser
	config = configparser.ConfigParser()
	msfCFG = os.path.abspath(os.path.dirname(__file__)) + "/../utils/msf.ini"
	whine( "Loading Safe Checks from: " + msfCFG, "debug")
	config.read(msfCFG)
	MSF = ast.literal_eval(config.get("MSF-SAFE", "msfLIST"))
	
	r = re.compile(".*http")
	msfLIST = list(filter(r.match, MSF))  
	
	for module in msfLIST:
		m = module.rsplit('/', 1)[-1]
		whine( "Running Metasploit Module: " + module, "debug")
		f = output + "_Metasploit_" + m + ".txt"
		cmd = "msfconsole -x \"use  " + module + ";set rhosts " + host + ";set rport " + port + "; run; exit\" > " + f
		muxER(cmd)
