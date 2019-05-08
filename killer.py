import os
import re
import subprocess
import time

def muxER(command):
	result =[]
	result = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE).communicate()[0].decode('utf-8').strip()
	return result
	
def killER (proc):
	ps = "ps -ef | grep "+ proc + " | grep -v grep"
	pkill = muxER(ps)
	pList = pkill.split('\n')
	for p in pList:
		p = p.rstrip("\n")
		match = re.search(r'root\s+(\d+).*\d\d:\d\d:\d\d(.*)',p)
		if match:
			ps = "kill -9 " + match.group(1)
			print("killing " + match.group(2))
			muxER(ps)
			time.sleep(1)

killER("nmap")