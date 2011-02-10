#!/usr/bin/python
import sqlite3 as sqlite
import sys
import time
import os

dbdir = '/root/www/nobody/'
fn = 'bismark.db'

def create_db():
   dbfile = dbdir+fn
   if fn not in os.listdir(dbdir):
     fp = open(dbfile,'w')
     fp.close()
   mconn = sqlite.connect(dbfile)
   cursor = mconn.cursor()
   cmds = ['create table if not exists cmd(valid varchar(100),valchar varchar(1000),valint int)',\
   'create table if not exists val(valid varchar(100),valint int,valchar varchar(1000))',\
   'insert into val(valid, valint) select "privend",0 where not exists(select 1 from val where valid = "privend")',\
   ]
   for cmd in cmds:
     cursor.execute(cmd)
   return mconn,cursor

def run_sql_cmd(cmd=None):
  conn,cursor = create_db()
  cursor.execute(cmd)
  res = cursor.fetchall()
  if 'select' not in cmd:
    conn.commit()
  return res

def read(tab,valid):
  cmd = 'select valint,valchar from %s where valid = "%s"'%(tab,valid)
  res = run_sql_cmd(cmd)
  if len(res) == 0:
    res = [(None,None)]
  return res

def insert(tab,valid,val):
  if isinstance(val,str):
    cmd = "insert into %s (valid,valchar) values ('%s','%s')"%(tab,valid,val)
  if isinstance(val,int):
    cmd = "insert into %s (valid,valint) values ('%s',%s)"%(tab,valid,val)
  if isinstance(val,list):
    cmd = "insert into %s (valid,valint,valchar) values ('%s',%s,'%s')"%(tab,valid,val[0],val[1])
  run_sql_cmd(cmd)

def modify(tab,valid,val):
  qt = ''
  vtype = 'valint'
  if isinstance(val,str):
    qt = '"'
    vtype = 'valchar'
  cmd = 'update %s set %s = %s%s%s where valid = "%s"'%(tab,vtype,qt,val,qt,valid)
  run_sql_cmd(cmd)

if __name__ == '__main__':
  cmd = sys.argv[1]
  dbfile = dbdir+fn
  res = run_sql_cmd(cmd=cmd)
  for rec in res:
    print rec

