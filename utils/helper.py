import os
import time
import logging

'''
 
 	helper.py
    	Helps print the color output and establishes a logger functionality
    	Author: CBHue

'''

def printB(out): print("\033[90m{}\033[00m" .format("[-] " + out))
def printR(out): print("\033[91m{}\033[00m" .format("[!] " + out)) 
def printG(out): print("\033[92m{}\033[00m" .format("[+] " + out)) 
def printY(out): print("\033[93m{}\033[00m" .format("[~] " + out)) 
def printB(out): print("\033[94m{}\033[00m" .format("[-] " + out))  
def printP(out): print("\033[95m{}\033[00m" .format("[-] " + out))  
def printC(out): print("\033[96m{}\033[00m" .format("[-] " + out))
def printW(out): print("[$] " + out)

def loggER(out,*lvl):
	logging.basicConfig(level=logging.DEBUG, format='[ \033[95m%(asctime)s\033[00m ] - %(levelname)s - %(message)s')
	ts = time.strftime("%m/%d/%Y %H:%M:%S", time.gmtime())			
	if "WARN" in lvl:
		if type(out) == dict:
			for x in out:
				print('\033[91m{0:16}: {1}\033[00m'.format("[! " + ts + " ] " + x, out[x]))
		else:
			print("\033[91m{}\033[00m" .format("[! " + ts + " ] " + '\033[0m' + out))
			logging.warn("This is a message: %r", out)
	elif "STATUS" in lvl:
		if type(out) == dict:
			for x in out:
				print('\033[93m{0:16}: {1}\033[00m'.format("[-] " + x, out[x]))
		else:
			print("\033[93m{}\033[00m" .format("[~ " + ts + " ] " + '\033[0m' + out))
			logging.debug("This is a message: %r", out)
	elif "GOOD" in lvl:
		if type(out) == dict:
			for x in out:
				print('\033[93m{0:16}: {1}\033[00m'.format("[-] " + x, out[x]))
		else:
			print("\033[92m{}\033[00m" .format("[+ " + ts + " ] " + '\033[0m' + out))
	else:
		if type(out) == dict:
			for x in out:
				print('\033[92m{0:16}: {1}\033[00m'.format("[*] " + x, out[x]))
		else:
			print("\033[96m{}\033[00m" .format("[- " + ts + " ] " + '\033[0m' + out))		
