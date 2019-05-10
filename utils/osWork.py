import os
import subprocess
import shlex
import dbQueue

def muxERToo(command):
	result =[]
	result = subprocess.Popen(command, shell=True,stdout=subprocess.PIPE).communicate()[0].decode('utf-8').strip()
	return result

def muxER(command):
	result =[]
	FNULL = open(os.devnull, 'w')
	p = subprocess.Popen([command], stdout=subprocess.PIPE, stderr=FNULL, shell=True)
	# Add to shared list
	dbQueue.pidLIST.append(str(p.pid))
	# Get the result
	(result, err) = p.communicate()
	# once we finish lets remove it from the queue
	dbQueue.pidLIST.remove(str(p.pid))
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