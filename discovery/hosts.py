
from dbWork import db_runner

def discoverHosts(network):
	#network should equal 10.10.10.10/24
	#fping -a -I eth0 -R -g network
	#netdiscover -i eth0 -P -r network
	#arp-scan --interface=eth0 network

def msfSafeChecks(host):
	#[ 05/14/2019 11:34:10 - DEBUG - ] dbQueue: 'INSERT INTO results VALUES (?,?,?,?)', ['10.156.158.126', '8080', 'tcp', 'http']
	# DBcommit = 'UPDATE Hosts SET status=? WHERE host=?', ["Stage5 - Running udp unicornscan", network]
	DBselect = 'SELECT host, port, serviceID FROM results WHERE host=?', [host]
	r = db_runner(conn, DBselect)
		for i in r:
			print (i)

