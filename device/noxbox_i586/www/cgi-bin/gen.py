#!/usr/bin/env python

import os
import time
import sql
import fcntl

file1 = '/root/local.conf'
file2 = '/root/conf/dev.conf'
action_file = '/root/www/nobody/action_file'
if_file = '/root/www/nobody/if_file'
default_pass = 'default'

def check(fp,param_val):
  if param_val == 'DEVICE_ID':
    fpr = open('/root/ID')
    val = fpr.read().split('\n')[0]
    return val
  for i in fp:
    i = i.split('\n')[0]
    i = i.split('=')
    if i[0] == param_val:
      return i[1]
  
  return None

def get_param(fp,param_val):
  while 1:
    val = check(fp,param_val)
    if val in [None,'']:
      return val
    if val[0] == '$':
      param_val = val[1:len(val)]
      fp.seek(0)
    else:
      return val

def currval(param_val):
  try:
    fp = open(file1)
    val = get_param(fp,param_val)
    if val != None:
      return val
  except:
    print ""
  fp = open(file2)
  val = get_param(fp,param_val)
  return val

def login_refresh():
  ctime = int(time.time())
  res = sql.read('val','login:%s'%(os.environ['REMOTE_ADDR']))
  if res[0][0] == None:
    sql.insert('val','login:%s'%(os.environ['REMOTE_ADDR']),ctime)
  else:
    sql.modify('val','login:%s'%(os.environ['REMOTE_ADDR']),ctime)
  return

def login_check():
  res =  sql.read('val','login:%s'%(os.environ['REMOTE_ADDR']))
  if res[0][0] == None:
    sql.insert('val','login:%s'%(os.environ['REMOTE_ADDR']),0)
    res = [(0,0)]
  lastmtime = res[0][0]
  ctime = int(time.time())
  if (ctime - lastmtime) > (5*60):
    return False
  return True

def login_redirect():
  print "Content-Type: text/html"
  print
  print '<html>\n\
  <body>\n\
  <meta http-equiv="REFRESH" content="0;url=login.py">\n\
  </html>\
  '

def redirect(page=None,latency=0,msg=''):
  print '<html>\n\
  <body>\n\
  <meta http-equiv="REFRESH" content="%s;url=%s.py">\n\
  <p>%s\
  </html>\
  '%(latency,page,msg)

def encval(currenc):
  noenc = ''
  wepenc = ''
  wpaenc = ''
  wpa2enc = ''
  if 'NONE' in currenc:
    noenc = 'checked'
  if 'WEP' in currenc:
    wepenc = 'checked'
  if 'WPA2' in currenc:
    wpa2enc = 'checked'
  if ('WPA' in currenc) and ('WPA2' not in currenc):
    wpaenc = 'checked'
  return noenc,wepenc,wpaenc,wpa2enc

def get_signal(file):
    try:
      fd = open(file)
    except:
      os.mkfifo(file)
      os.chmod(file,666)
      fd = open(file)
    fd.readline()
    fd.close()

def get_cmd_type(cmd):
  if 'WIFI_PASS' in cmd:
    return 'Passphrase'
  if 'WIFI_SEC' in cmd:
    return 'Encryption'
  if 'WIFI_SSID' in cmd:
    return 'SSID'

def print_footer():
  print '\
  <p>\
  <p>\
  <p>\
  <p><a href=main.py>Go back to Main Page</a>\
  <p><a href=logout.py>Log out</a>\
  '
def print_header(title=''):
  print "Content-Type: text/html"
  print
  print '<html>\
  <body>\
  <h2><center>BISMARK Configuration Page %s</center></h2>\
  '%(title)
