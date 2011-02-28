#!/usr/bin/env python
import os
import sys
import subprocess as sub
import gzip as gz
import time
import sql

def ignore_file(file):
  if '-01.csv' not in file:
    return True
  if 'Xuzi' in file:
    return True
  if 'NB_' in file:
    return True
  if 'NBwalter' in file:
    return True
  return False

def cleanitem(item):
  i = 0
  if len(item) == 0:
    return item
  while item[i] == ' ' :
    i+=1
    if i == len(item):
      item = ''
      return item
  item = item[i:len(item)]
  while '. ' in item:
    item = item.replace('. ','.')
  i = len(item) - 1
  while item[i] == ' ' :
    i-=1
  item = item[0:i+1]
  
  return item
   
def cleanline(line):
  line = line.split(',')
  nline = []
  for item in line:
    item = cleanitem(item)
    nline.append(item)
  return nline

def get_deviceid(filename):
  filename = filename.split('/')
  filename = filename[len(filename)-1]
  devid = filename.split("_")[0]
  return devid

def write(head,body,devid,table):
  field2col = {"bssid":"BSSID","first time seen":"FIRSTSEEN",'last time seen':'LASTSEEN',\
               'channel':'CHANNEL','speed':'SPEED','cipher':'CIPHER','privacy':'PRIVACY',\
               'authentication':'AUTH','power':'POWER','# beacons':'NUMBEACONS','# iv':'NUMIV',\
               'lan ip':'LANIP','id-length':'IDLEN','essid':'ESSID','key':'WKEY','station mac':'STATIONMAC',\
               'power':'POWER','# packets':'NUMPKTS','probed essids':'PROBEDESSID'}
  for i in range(0,len(body)): 
    if len(body[i]) == 1:
      continue
    cmd1 = 'INSERT into %s (DEVICEID,'%(table)
    cmd2 = 'VALUES("%s",'%(devid)
    for j in range(0,len(head)):
      if head[j].lower() in ['lan ip','key']:
        continue
      quotes = '"'
      if head[j].lower() in ['channel','speed','power','# beacons','# iv','id-length','# packets']:
        quotes = ''
      if head[j].lower() in ['first time seen','last time seen']:
        quotes = ''
        try:
          body[i][j] = 'UNIX_TIMESTAMP("%s")'%(body[i][j])
        except:
          continue
      try:
        cmd1 = "%s %s,"%(cmd1,field2col[head[j].lower()])
      except:
        continue
      try:
        cmd2 = "%s %s%s%s,"%(cmd2,quotes,body[i][j],quotes)
      except:
        continue
      #print '%s:%s '%(head[j],body[i][j]),
    cmd1 = cmd1[0:len(cmd1)-1]
    cmd2 = cmd2[0:len(cmd2)-1]
    cmd = '%s) %s)'%(cmd1,cmd2)
    print cmd
    sql.run_insert_cmd(cmd)
  return
  
def check_devid(devid,tables):
  tab = tables['userdevice']
  cmd = 'select * from %s where deviceid="%s" and end is NULL'%(tab,devid)
  res = sql.run_data_cmd(cmd)
  if len(res) == 0:
    return False
  return True
    
def parsefile(file,tables,log):
  fp = open(file)
  part1 = []
  part2 = []
  part1head = []
  part2head = []
  lines = fp.readlines()
  i = 0
  devid = get_deviceid(file)
  #devid = "NULL"
  #exists = check_devid(devid,tables)
  #if exists == False:
  #  return -1
  print file
 
  while 1:
    line = lines[i]
    while 'first time seen' not in line.lower():
      i+=1
      line = lines[i] 
    part1head = cleanline(line.split('\r\n')[0])
    i+=1
    line = lines[i] 
    while 'first time seen' not in line.lower():
      line = line.split('\r\n')[0].lower()
      line = cleanline(line)
      part1.append(line)
      i+=1
      line = lines[i] 
    part2head = cleanline(line.split('\r\n')[0])
    for j in range(i+1,len(lines)):
      line = lines[j] 
      line = line.split('\r\n')[0]
      line = cleanline(line)
      part2.append(line)
      j+=1
    break
  
  write(part1head,part1,devid,tables['wifiscan'])
  write(part2head,part2,devid,tables['wifiassoc'])
  return 1

def move_file(file,dir):
  cmd = ['gzip',file]
  sub.Popen(cmd).communicate()
  zfile = file + '.gz'
  cmd = ['mv',zfile,dir]
  sub.Popen(cmd).communicate()

if __name__ == '__main__':
  HOME = os.environ['HOME'] + '/'
  # HOME = './'
  MEASURE_FILE_DIR = 'var/data/'
  LOG_DIR = 'var/log/'
  ARCHIVE_DIR = 'var/data/old'
  tables = {'userdevice':'USERDEVICE','wifiscan':'WIFI_SCAN','wifiassoc':'WIFI_ASSOC'}
  log = gz.open(HOME+LOG_DIR+'csv.log.gz','ab')
  files = os.listdir(HOME+MEASURE_FILE_DIR)
  fcnt = 0
  for file in files:
    if ignore_file(file) == True:
      continue
    fcnt += 1
    rval = parsefile(HOME+MEASURE_FILE_DIR+file,tables,log)
    if rval == -1:
      continue
    log.write('Done ' + file + '\n')
    move_file(HOME+MEASURE_FILE_DIR+file,HOME+ARCHIVE_DIR)
    if fcnt < -1:
      sys.exit()
  log.close()
