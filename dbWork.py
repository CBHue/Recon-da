#!/usr/bin/python 

import os
import sqlite3
import utils.helper as helper
import dbQueue

##### DB IS NOT WORKING ... MAKE THIS STREAMLINED ...

# Root Check
if os.geteuid() != 0:
	exit("You need to have root privileges to run this script.\nPlease try again using 'sudo'.")

def db_getCursor():
    conn = sqlite3.connect(dbQueue.DBFILE)
    c = conn.cursor()
    return c

def db_closeCursor(c):
    c.close()

def db_runner(conn, query, args=None):
    #helper.printR("I GOT WORK!!! - " + str(query) + ":" + str(args))
    #print(conn)
    try:
        c = conn.cursor()
        
        if args:
            c.execute(query, args)
        else:
            c.execute(query)

        results = c.fetchall()
        c.close()
        return results
    except Exception as e:
        print(e)

def db_init():
    try: 
        os.makedirs(dbQueue.dumpDir)
        os.makedirs(dbQueue.serviceDir)
        os.makedirs(dbQueue.dataDIR)
    except OSError:
        if not os.path.isdir(dbQueue.dumpDir):
            raise
        if not os.path.isdir(dbQueue.serviceDir):
            raise
        if not os.path.isdir(dbQueue.dataDIR):
            raise

    try:
        # set the database connectiont to autocommit w/ isolation level
        conn = sqlite3.connect(dbQueue.DBFILE, check_same_thread=False)
        conn.text_factory = str
        conn.isolation_level = None
        #helper.printG("Connection to DB is Good!" + dbQueue.DBFILE)
        return conn

    except Exception:
        helper.printR("Could not connect to database")
        helper.printR("Please run install.sh")
        raise SystemExit

def db_setup(conn):
    #conn = sqlite3.connect(dbQueue.DBFILE)
    #helper.printR("Setting up DB")
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

    c.close()

def db_connect():
    try:
        # set the database connectiont to autocommit w/ isolation level
        conn = sqlite3.connect(dbQueue.DBFILE, check_same_thread=False)
        conn.text_factory = str
        conn.isolation_level = None
        return conn
    except Exception:
        helper.printR("Could not connect to database")
        helper.printR("Please run install.sh")
        raise SystemExit