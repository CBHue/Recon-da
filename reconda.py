#!/usr/bin/python 

import os
import re
import time
import multiprocessing
from cmd import Cmd
from argparse import ArgumentParser

# Import local modules
import heading
import cmdRunner
import config
import helper

#
# This is the worker ... He puts in work
#
def wakanda(task,debug,pid):
    workerName = (multiprocessing.current_process()).name    
    while True:
        # Check to see if there is work to do
        task = config.work.get()
        if task:
            cmdRunner.sweepER(task, workerName)
        time.sleep(2)
    helper.printR("[wakanda] Got the poison pill ... DEAD.")

#
# This is the DB worker ... He puts in DB work
#
def MBaku(taskDB):
    workerName = (multiprocessing.current_process()).name    
    while True:
        # Check to see if there is work to do
        taskDB = config.workDB.get()
        if taskDB:
            # need to do some magic here to pass the right data
            s = str(taskDB).strip('()')
            cmdRunner.whine(s)
            pattern = "\'(.*)\', (\[.*\])"
            match = re.match(pattern,s)
            if not match:
                print ("No Match error " + pattern + " " + s)
            sql = match.group(1)
            s = match.group(2).strip("[]")
            s = re.sub(r'\'', '', s)
            args = tuple(item.strip() for item in s.split(','))
            db_runner(sql, args)

    helper.printR("[MBaku] Got the poison pill ... DEAD.")

def db_runner(query, args=None):
    cur = config.conn.cursor()
    if args:
        cur.execute(query, args)
    else:
        cur.execute(query)
    results = cur.fetchall()
    cur.close()
    return results

class MyPrompt(Cmd):

    def emptyline(self):
        print("")
        print ("Global Session: "+ '\033[95m'+ config.master + '\033[0m')
        print ("Output Dir: " + "\033[95m" + config.dumpDir + '\033[0m')
        print ("Debug: " + '\033[95m' + str(config.debug.value) + '\033[0m')
        r = db_runner("SELECT host, status FROM Hosts WHERE status like '%Stage%'")
        print ("Running Processes: " + '\033[92m' + str(len(r)) + '\033[0m')
        r = db_runner("SELECT host, status FROM Hosts WHERE status like '%Waiting%'")
        print ("Remaining Hosts: " + '\033[92m' + str(len(r)) + '\033[0m')

        print ("")
        cmdRunner.realTimeMuxER('stty sane')
        pass

    def do_clear(self, args):
        heading.banner()
        prompt.onecmd('help')

    def do_status(self, args):
        """Gets the status of running processes"""
        print ("Output Dir:" + '\033[95m' + config.dumpDir + '\033[0m')
        
        print ("")
        print ("Finished processes:")
        print ("-------------------")
        r = db_runner("SELECT host,ports FROM Hosts WHERE status like '%Completed%' ORDER BY ports DESC")
        for i in r:
            print (i)
        
        print ("")
        print ("Running processes:")
        print ("------------------")
        r = db_runner("SELECT host, ports, status FROM Hosts WHERE status like '%Stage%'")
        for i in r:
            print (i)
            
        print ("")
        print ("Hosts waiting for work:")
        print ("-----------------------")
        r = db_runner("SELECT host, status FROM Hosts WHERE status like '%Waiting%'")
        print (len(r))
        print ("")

    def do_Debug(self, args):
        
        if config.debug.value is True: 
            config.debug.value = False
            print ("Debug: " + '\033[95m' + str(config.debug.value) + '\033[0m')
        else:
            config.debug.value = True
            print ("Debug: " + '\033[95m' + str(config.debug.value) + '\033[0m')

    def do_exit(self, args):
        """Exits from the console"""
        helper.printC("Closing Queue:")
        config.work.close()

        helper.printC("Shutting down children:")
        for pid in config.pidLIST:
            helper.printC("Killing active children: " + '\033[0m' + str(pid))
            cmdRunner.realTimeMuxER("pkill -9 -P " + str(pid))
       
        time.sleep(2)

        helper.printC("Shutting down workers:")
        for p in multiprocessing.active_children():
            helper.printC("Killing: " + '\033[0m' + str(p))
            p.terminate()

        helper.printC("Done ...")
        cmdRunner.realTimeMuxER('stty sane')
        raise SystemExit

    #
    # Find Hosts runs a single process on a host or network
    #
    def do_ReconHost(self, network): 
        """Single Host or Network: 
        Stages of Recon: 
        1: Nmap for open ports
        2: Http screenshot web ports            
        3: Nmap Service Description
        4: Web Tests: Nikto, Dirb
        5: UDP scan Top Ports

        Example: 
        findHosts 10.10.10.10
        findHosts 10.10.10.0/24
        """

        if network:
            # Validate the host
            out = cmdRunner.validateHost(network)
            if not out: return
            #config.work.put(out)

        else:
            print ("")
            print ("ReconHost 10.10.10.10")
            print ("ReconHost 10.10.10.0/24")
    #
    # load Hosts uses a pool of workers to knock out a larger hostlist
    #
    def do_LoadHostFile(self,hostFile):
        """Load a host list: one host per line
        Example: 
        loadHosts /root/recon/hostlist.txt
        """
        if hostFile:
            try:
                HostSet = set(line.strip() for line in open(hostFile))
                HostList = list(HostSet)
                HostList = filter(None, HostList)

                if len(HostList) < 1:
                    print ("No Hosts loaded ... Check File:" + hostFile)
                    return

                print ("Loaded " + str(len(HostSet)) + " Hosts")
                print ("Output Dir: " + '\033[95m'+ config.dumpDir + '\033[0m')

                # validate the hosts then queue them up
                for host in HostList:
                    vhost = cmdRunner.validateHost(host)
                    if not vhost: continue
                    config.work.put(vhost)

            except IOError:
                print ("Could not read file:"+ hostFile)

        else:
            print ("enter a host file we have workers waiting ...")

    def do_ShowAllResults(self,key):
        """Show Results from all hosts
        Specific File Example: 
        ShowAllResults out
        ShowAllResults nikto
        ShowAllResults dirb
        ShowAllResults udp
        """
        print ("Output Dir: " + '\033[95m'+ config.dumpDir + '\033[0m')
        if key:
            cmdRunner.showResult("-name \"*." + key + "\"")
        else:
            cmdRunner.showResult("ALL")        

    def do_ShowHostResults(self, key):
        # get the output from completed process
        if key:
            cmdRunner.showResult(key)
        else:
            print ("")
            print ("Choose the finished report to view:")
            print ("Example: ShowHostResults 10.10.10.18/32")
            r = cmdRunner.db_runner(config.conn, "SELECT host,ports FROM Hosts WHERE status like 'Completed%' ORDER BY ports DESC")
            for i in r:
                print (i)
            print ("")
    
    def do_MergeXML(self, args):
        """Merge nMap XML
        This uses https://github.com/CBHue/nMap_Merger.git
        Assumes its installed in /opt/
        Run this to create an HTML of your completed nMap Scans
        """
        print ("Output Dir: " + '\033[95m'+ config.dumpDir + '\033[0m')
        # We are going to try and import nMapMerger here
        from os import sys, path
        sys.path.append('/opt/')
        try:
            from nMap_Merger.nMapMerge import main_nMapMerger
        except ImportError:
            print ("Failed to import nMapMerge")

        try:
            cmd = "find " + config.dumpDir + " \\( -name \"*.xml\" \\)"
            xmlFinder = cmdRunner.muxER(cmd)
            xmlList = xmlFinder.split('\n')
            s = set(xmlList)
            print ("XMLs to parse: " + str(len(s)))
            if len(s) > 1:
                main_nMapMerger(s)
            else:
                print ("No XML files in: " + config.dumpDir)
        except Exception as e:
            print ("Error with nmapMerger ... " + str(e))


    def do_config(self, key):
        if key:
            print (key)
        else:
            print ("CONFIG")
            
if __name__ == '__main__':
    
    # Root Check
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

    parser = ArgumentParser()
    parser.add_argument("-w", "--workers",  dest="workers", help="# of processes.\nDefault is 2 * cpu_count", metavar="int")
    parser.add_argument("-q", "--quiet",    dest="debug", action="store_true", default=False, help="don't print status messages to stdout")
    args = parser.parse_args()

    # Setup session DB
    config.db_setup()

    if args.debug:
        config.debug.value = False

    # Make the Pool of workers [Default is 2 * cpu count]
    workers = multiprocessing.cpu_count() * 2
    
    if args.workers:
        workers = int(args.workers)
    
    vibranium = workers
    
    for i in range(vibranium):
        multiprocessing.Process(target=wakanda, args=(config.work,config.debug,config.pidLIST)).start()

    # DB Worker
    multiprocessing.Process(target=MBaku, args=(config.workDB,)).start()

    heading.banner()
    
    print ("Global Session: "+ '\033[95m'+ config.master + '\033[0m')
    print ("Workers: " + '\033[95m'+ str(vibranium) + '\033[0m')
    print ("Output Dir: " + '\033[95m'+ config.dumpDir + '\033[0m')
    print ("Debug: " + '\033[95m'+ str(config.debug.value) + '\033[0m')

    prompt = MyPrompt()
    h = prompt.precmd('help')
    o = prompt.onecmd(h)
    prompt.postcmd(h, o)
    prompt.prompt = "> "
    prompt.cmdloop('Starting prompt...')
