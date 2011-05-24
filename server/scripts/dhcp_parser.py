#!/usr/bin/env python
import os
import sys
import subprocess as sub
import gzip as gz
import time
import sql

def get_deviceid(filename):
  filename = filename.split('/')
  filename = filename[len(filename)-1]
  devid = ''
  if '_' in filename:
    devid = filename.split("_")[0]
  else:
    devid = filename.split(".")[0]
  return devid

def ignore_file(file):
  if '.dhcp' not in file:
    return True
  if 'Xuzi' in file:
    return True
  if 'NB_' in file:
    return True
  if 'NBwalter' in file:
    return True
  return False

def write(line,table,devid):
  col = {0:'TIMESTAMP',1:'ACTION',3:'IP',2:'MACID',4:'CLIENT'}
  
  try:
    line = line.split()
  except:
    return
  cmd1 = 'INSERT into %s (DEVICEID,'%(table)
  cmd2 = 'VALUES ("%s",'%(devid) 
  if len(line) < 4:
    return
  for i in range(0,len(line)):
    quotes = '"'
    if i == 0:
      quotes = ''
    if col[i] == 'IP':
      quotes = ''
      line[i] = 'INET_ATON("%s")'%(line[i])
    cmd1 = '%s %s,'%(cmd1,col[i])
    cmd2 = '%s %s%s%s,'%(cmd2,quotes,line[i],quotes)
  cmd1 = cmd1[0:len(cmd1)-1]
  cmd2 = cmd2[0:len(cmd2)-1]
  cmd = '%s) %s)'%(cmd1,cmd2)
  sql.run_insert_cmd(cmd)
  print cmd
  
def parsefile(file,tables,log):
  devid = get_deviceid(file)
  table = tables['dhcp']
  fp = open(file)
  for line in fp:
    write(line,table,devid)
  return 1

if __name__ == '__main__':
  HOME = os.environ['HOME'] + '/'
  MEASURE_FILE_DIR = 'var/data/'
  LOG_DIR = 'var/log/'
  tables = {'measurement':'MEASUREMENTS','traceroute':'TRACEROUTES','hop':'TRACEROUTE_HOPS',\
           'userdevice':'USERDEVICE','wifiscan':'WIFI_SCAN','wifiassoc':'WIFI_ASSOC','dhcp':'DHCP_LOGS'}
  log = gz.open(HOME+LOG_DIR+'dhcp.log.gz','ab')
  files = os.listdir(HOME+MEASURE_FILE_DIR)
  fcnt = 0
  for file in files:
    if ignore_file(file) == True:
      continue
    fcnt += 1
    parsefile(HOME+MEASURE_FILE_DIR+file,tables,log)
    log.write('Done ' + file + '\n')
    #move_file(HOME+MEASURE_FILE_DIR+file,HOME+ARCHIVE_DIR)
    if fcnt < -1:
      sys.exit()
    sys.exit()
  log.close()
