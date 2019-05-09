#!/usr/bin/python 

import os
import random
import sqlite3
import multiprocessing
from multiprocessing import Manager
from ctypes import c_bool
import helper

 # Root Check
if os.geteuid() != 0:
	exit("You need to have root privileges to run this script.\nPlease try again using 'sudo'.")

dirPath = os.path.dirname(os.path.realpath(__file__))

# Master key
############################
master = str(int(random.randint(9999, 999999)))

# Work Queue
#################################
work   = multiprocessing.Queue()
workDB = multiprocessing.Queue()

manager = Manager()
pidLIST = manager.list()

debug  = multiprocessing.Value(c_bool,True)

# Set up the Dump
##############################
dumpDir = dirPath + "/dump/" + master + "/"
serviceDir = dumpDir + "ScriptOut/"

try: 
    os.makedirs(dumpDir)
    os.makedirs(serviceDir)
except OSError:
    if not os.path.isdir(dumpDir):
        raise

# Set up the Database
#############################
dataDIR = dirPath + "/data/" + master + "/"

try: 
    os.makedirs(dataDIR)
except OSError:
    if not os.path.isdir(dataDIR):
        raise

DB = "reconda.db"
DBFILE =  dataDIR + DB


def db_setup():

	conn = sqlite3.connect(DBFILE)
	c = conn.cursor()

	c.execute('DROP TABLE IF EXISTS stages')
	c.execute( '''CREATE TABLE "stages" (
		"stage_id" text PRIMARY KEY,
		"status" text
	)''')

	c.execute('DROP TABLE IF EXISTS results')
	c.execute( '''CREATE TABLE "results" (
		"host" text,
		"port" text,
		"proto" text,
		"serviceID" text    
	)''')

	c.execute('DROP TABLE IF EXISTS Hosts')
	c.execute( '''CREATE TABLE "Hosts" (
		"host" text,
		"status" text,
		"ports" text
	)''')

try:
    # set the database connectiont to autocommit w/ isolation level
    conn = sqlite3.connect(DBFILE, check_same_thread=False)
    conn.text_factory = str
    conn.isolation_level = None

except Exception:
    helper.printR("Could not connect to database")
    helper.printR("Please run install.sh")
    raise SystemExit

def db_connect():
    try:
        # set the database connectiont to autocommit w/ isolation level
        conn = sqlite3.connect(config.DBFILE, check_same_thread=False)
        conn.text_factory = str
        conn.isolation_level = None
        return conn
    except Exception:
        helper.printR("Could not connect to database")
        helper.printR("Please run install.sh")
        raise SystemExit
