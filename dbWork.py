#!/usr/bin/python 

import os
import sqlite3
import utils.helper as helper
import dbQueue

def db_getCursor():
    conn = sqlite3.connect(dbQueue.DBFILE)
    c = conn.cursor()
    return c

def db_closeCursor(c):
    c.close()

def db_runner(conn, query, args=None):
    try:
        c = conn.cursor()
        if args: c.execute(query, args)
        else: c.execute(query)

        results = c.fetchall()
        c.close()
        return results
    except Exception as e:
        helper.printR("db_runner: " + str(e))

def db_init():
    try: 
        os.makedirs(dbQueue.dumpDir)
        os.makedirs(dbQueue.serviceDir)
        os.makedirs(dbQueue.screenDir)
        os.makedirs(dbQueue.dataDIR)
    except OSError:
        if not os.path.isdir(dbQueue.dumpDir):
            raise
        if not os.path.isdir(dbQueue.serviceDir):
            raise
        if not os.path.isdir(dbQueue.screenDir):
            raise
        if not os.path.isdir(dbQueue.dataDIR):
            raise

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

def db_setup(conn):
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
