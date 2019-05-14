
import re
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
			f = out + "_" + match.group(1) + "_" 
			msfHTTPAuxilary(network,match.group(1),f)

			whine( "Taking Screenshot: " + u , "debug")
			f = out + "_Port_" + match.group(1) + ".png"
			chromeShot(u,f)

			whine( "Running Nikto on: " + u , "debug")
			f = out + "_" + match.group(1) + ".nikto"
			cmd = "nikto -Cgidirs all -host " + u + " -Format txt -output " + f
			muxER(cmd)

			whine( "Running dirb on: " + u , "debug")
			f = out + "_" + match.group(1) + ".dirb"
			cmd = "dirb " + u + " -o " + f
			muxER(cmd)

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
		whine("screenshot Error:" + str(e), "debug")

	driver.quit()

def msfHTTPAuxilary(host,port,output):
	#msf = {
	#	'http_version' 	: 'auxiliary/scanner/http/http_version',
	#	'options' 		: 'auxiliary/scanner/http/options',
	#	'cert' 			: 'auxiliary/scanner/http/cert',
	#	'robots_txt' 	: 'auxiliary/scanner/http/robots_txt',
	#	'title' 		: 'auxiliary/scanner/http/title',
	#	'http_header' 	: 'auxiliary/scanner/http/http_header',
	#	'http_put' 		: 'auxiliary/scanner/http/http_put'
	#}

	import configparser
	config = configparser.ConfigParser()
	msfConfig = os.path.abspath(os.path.dirname(__file__)) + "utils/msf.ini"
	config.read(msfConfig)
	MSF = ast.literal_eval(config.get("METASPLOIT_SAFE_CHECKS", "msfLIST"))
	
	r = re.compile(".*http")
	msfLIST = list(filter(r.match, MSF))  
	
	for module in msfLIST:
		whine( "Running Metasploit Module: " + module, "debug")
		f = output + "Metasploit_" + module + ".out"
		cmd = "msfconsole -x \"use  " + module + ";set rhosts " + host + ";set rport " + port + "; run; exit\" > " + f
		muxER(cmd)
