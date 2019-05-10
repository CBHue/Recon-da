#!/usr/bin/python 

import os
import random
import multiprocessing
from multiprocessing import Manager
from ctypes import c_bool, c_wchar_p


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

#debug  = multiprocessing.Value(c_bool,True)
debug  = multiprocessing.Value(c_wchar_p,"info")

# Set up the Dump
##############################
dumpDir = dirPath + "/dump/" + master + "/"
serviceDir = dumpDir + "ScriptOut/"

# Set up the Database
#############################
dataDIR = dirPath + "/data/" + master + "/"

DB = "reconda.db"
DBFILE =  dataDIR + DB

conn = ""