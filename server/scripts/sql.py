#!/usr/bin/python 

from gzip import GzipFile as gz
import MySQLdb as mysql
import sys
import traceback
import os
import random as rnd
import socket, struct
import numpy as np

sql_host = "localhost"
sql_user = "root"
#sql_passwd = "grenouille"
sql_db = "bismark_live_v1"

def sqlconn():
  try:
    conn = mysql.connect(host = sql_host,user = sql_user, db = sql_db)
    cursor = conn.cursor() 
  except:
    print "Could not connect to mysql server"
    sys.exit()
  return conn,cursor

def run_insert_cmd(cmd):
  conn,cursor = sqlconn()
  #print cmd
  try:
    cursor.execute(cmd)
  except:
    print "Couldn't run %s\n"%(cmd)
    return 0 
  #cursor.fetchall()
  return 1 

def run_data_cmd(cmd):
  conn,cursor = sqlconn()
  print cmd
  try:
    cursor.execute(cmd)
  except:
    #print "Couldn't run %s\n"%(cmd)
    return 0 
  result = cursor.fetchall()
  return result 
