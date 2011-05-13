#!/usr/bin/env python
import os
import sys
import subprocess as sub
import gzip as gz
import time
import sql

def get_fields(line):
  skey = ''
  if '/>' in line:
    skey = '/>'
  else:
    skey = '>'

  try:
    line = line.split('<')[1]
  except:
    return None
  line = line.split(skey)[0]
  val = line.split()
  return val

def get_measurement_params(fids,vals,arr):
  #print arr
  for fid in arr:
    fids.append(fid)
    vals.append(arr[fid])
  return fids,vals

def modify_val(fid,val):
  nval = val
  if val == '':
    nval = 'NULL'
  if fid in ['deviceid','param','tool']:
    nval = '"' + val + '"'
  else:
    if fid in ['srcip','dstip','ip']:
      nval = 'INET_ATON("' + val + '")'
  return nval

def form_insert_cmd(table,fids,vals):
  cmd = 'INSERT into ' + table + '('
  for fid in fids:
    cmd += fid + ","
  cmd = cmd[0:len(cmd)-1]
  cmd += ') SELECT '
  for val in vals:
    ind = vals.index(val)
    nval = modify_val(fids[ind],val)
    cmd += nval + ","
  cmd = cmd[0:len(cmd)-1]
  #cmd += 
  print cmd
  return cmd

def get_id_from_table(table,did,ts):
  cmd = 'SELECT id from ' + table + ' where '
  cmd += 'deviceid = "' + did + '" and timestamp = ' + ts
  res = sql.run_data_cmd(cmd)
  return str(res[0][0])

def get_uid(did,table):
  cmd = 'SELECT userid from ' + table + ' where '
  cmd += 'deviceid = "' + did + '"'
  #res = sql.run_data_cmd(cmd)
  #return str(res[0][0])
  return "NULL"

def write_block_v1_0(data,tables,log,file):
  if 'info' not in data:
    log.write('Error: No info field in %s\n'%(file))
    return
  flag = 0
  for tab in tables:
    if tab in data:
      flag = 1
      break
  if flag == 0:
    log.write('Error: No known fields in %s\n'%(file))
    return

  for tab in tables:
    if tab in data:
      numrec = len(data[tab])
      for i in range(0,numrec):
        table = tables[tab]
        fids = []
        vals = []
        if tab != 'hop':
          fids,vals = get_measurement_params(fids,vals,data['info'][0])
        else:
          ttid = data[tab][i]['ttid']
          data[tab][i].pop('ttid')
          did = data['info'][0]['deviceid']
          ts = data['traceroute'][ttid]['timestamp']
          tid = get_id_from_table(tables['traceroute'],did,ts)
          idtuple = {"tid":tid}
          fids,vals = get_measurement_params(fids,vals,idtuple)
        
        fids,vals = get_measurement_params(fids,vals,data[tab][i])
        cmd = form_insert_cmd(table,fids,vals)
        res = sql.run_insert_cmd(cmd)
        cnt = 0
        while ((res == 0) and (cnt < 5)):
          print "res ", res
          time.sleep(.1)   
          res = sql.run_insert_cmd(cmd)
          cnt += 1
        if res == 0:
          log.write('Could not %s from %s\n'%(cmd,file))

def parse_block_v1_0(block,version,tables,log):
  data = {}
  for line in block:
    fields = get_fields(line)
    if fields == None:
      continue
    head = fields[0]
    if '/' in head:
      continue
    print head
    if head not in data:
      data[head] = []

    tuple = {}
    if head == 'hop':
      tuple['ttid'] = len(data['traceroute']) -1
    for field in fields[1:]:
      field = field.split("=")
      name = field[0]
      val = field[1]
      tuple[name] = val
      #val = field[1].split('"')[1]
      #print name,":", val, ",",
    #print ''
    data[head].append(tuple)
  return data

def parse_block_v1_1(block,version,tables,log):
  data = parse_block_v1_0(block,version,tables,log)
  return data

def parse_block(block,version,tables,log,file):
  if version == '1.0':
    data = parse_block_v1_0(block,version,tables,log)
    write_block_v1_0(data,tables,log,file)
  if version == '1.1':
    data = parse_block_v1_1(block,version,tables,log)
    did = data['info'][0]['deviceid']
    uid = get_uid(did,tables['userdevice'])
    print uid
    data['info'][0]['userid'] = uid
    write_block_v1_0(data,tables,log,file)
  #for i in data:
    #print i, data[i]
  return True

def log_bad_block(log,block,file):
  log.write('Bad block in %s\n'%(file))
  for line in block:
    log.write('%s\n'%(line))

def parsefile(file,tables,log):
  start_block = '<measurements'
  end_block = '</measurements'
  fp = open(file)
  state = 0
  block = []
  version = 0
  for line in fp:
    if state == 0:
      if  start_block in line:
        state = 1
        val = get_fields(line)
        version = val[1].split("=")[1].split('"')[1]
        print version
      continue

    if state == 1:
      if end_block in line:
        stat = parse_block(block,version,tables,log,file)
        if stat == False:
          log_bad_block(log,block,file)
        state = 0
        block = []
        continue
      block.append(line)

def move_file(file,dir):
  cmd = ['gzip',file]
  sub.Popen(cmd).communicate()
  zfile = file + '.gz'
  cmd = ['mv',zfile,dir]
  sub.Popen(cmd).communicate()

def ignore_file(file):
  if '.xml' not in file:
    return True
  if 'Xuzi_' in file:
    return True
  if 'NB_' in file:
    return True
  #if 'NBwalter' in file:
    #return True
  if 'NEW' in file:
    return True
  if 'NBukyhomenetlab' in file:
    return True

  return False

if __name__ == '__main__':
  HOME = os.environ['HOME'] + '/'
  #HOME = '/tmp/bismark_test/'
  MEASURE_FILE_DIR = 'var/data/'
  LOG_DIR = 'var/log/'
  ARCHIVE_DIR = 'var/data/old'
  FILE_LOG = 'var/log/xml_parse_files'
  tables = {'measurement':'MEASUREMENTS','traceroute':'TRACEROUTES','hop':'TRACEROUTE_HOPS','userdevice':'USERDEVICE'}

  filelog = open(HOME+FILE_LOG,'w')
  log = gz.open(HOME+LOG_DIR+'insert.log.gz','ab')
  files = os.listdir(HOME+MEASURE_FILE_DIR)
  fcnt = 0
  for file in files:
    if ignore_file(file) == True:
      continue
    print file
    filelog.write("%s\n"%(file))
    fcnt += 1
    parsefile(HOME+MEASURE_FILE_DIR+file,tables,log)
    log.write('Done ' + file + '\n')
    move_file(HOME+MEASURE_FILE_DIR+file,HOME+ARCHIVE_DIR)
    if fcnt < -1:
      sys.exit()
  log.close()
  filelog.close()

