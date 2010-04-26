#!/usr/bin/env python

def get_fields(line):
  skey = ''
  if '/>' in line:
    skey = '/>'
  else:
    skey = '>'

  line = line.split('<')[1]
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
    cmd += '"' + fid + '"' + ","
  cmd = cmd[0:len(cmd)-1]
  cmd += ') VALUES('
  for val in vals:
    ind = vals.index(val)
    nval = modify_val(fids[ind],val)
    cmd += nval + ","
  cmd = cmd[0:len(cmd)-1]
  cmd += ')'
  print cmd

def write_block_v1_0(data,tables):
  if 'info' not in data:
    log.write('Error: No info field')

  for tab in tables:
    if tab in data:
      numrec = len(data[tab])
      for i in range(0,numrec):
        table = tables[tab]
        fids = []
        vals = []
        if tab != 'hop':
          fids,vals = get_measurement_params(fids,vals,data['info'][0])
        fids,vals = get_measurement_params(fids,vals,data[tab][i])
        form_insert_cmd(table,fids,vals)

def parse_block_v1_0(block,version,tables):
  data = {}
  for line in block:
    fields = get_fields(line)
    head = fields[0]
    if '/' in head:
      continue
    #print head
    if head not in data:
      data[head] = []

    tuple = {}
    for field in fields[1:]:
      field = field.split("=")
      name = field[0]
      val = field[1]
      tuple[name] = val
      #val = field[1].split('"')[1]
      #print name,":", val, ",",
    #print ''
    data[head].append(tuple)
  write_block_v1_0(data,tables)

def parse_block(block,version,tables):
  if version == '1.0':
    data = parse_block_v1_0(block,version,tables)

def parsefile(file,tables):
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
        parse_block(block,version,tables)
        state = 0
        block = []
        continue
      block.append(line)
if __name__ == '__main__':
  file = 'measurements_test.xml'
  tables = {'measurement':'MEASUREMENTS','traceroute':'TRACEROUTES','hop':'TRACEROUTE_HOPS'}
  parsefile(file,tables)
