#!/usr/bin/env python
import cgi
import cgitb
import gen
import sql as sql
import time
import os

cgitb.enable()

def exec_cmd(msg=''):
  fd = open(gen.action_file,'w')
  fd.close()
  gen.get_signal(gen.if_file)
  while 1:
    cmd = 'select * from cmd where valid = "cmd"'
    res = sql.run_sql_cmd(cmd)
    if len(res) == 0:
      break 
    time.sleep(1)
  res = sql.read('cmd','succ')
  ret = True
  if res != [(None,None)]:
    print "<p>%s update successful"%(msg)
  res = sql.read('cmd','err')
  if res != [(None,None)]:
    for rec in res:
      errcmd = rec[1].split(":")[0]
      err = rec[1].split(":")[1]
      cmdtype = gen.get_cmd_type(errcmd)
      print "<p>Update FAILED: %s"%(err)
      ret = False
  cmd = 'delete from cmd'
  sql.run_sql_cmd(cmd)
  return ret
    
def wifi():
  cmds = []
  dir = os.getcwd()
  cmd = ''
  cmdpre = 'cd /root && /root/scripts/action config "'
  cmdsuf = '" && cd %s'%(dir)
  opt = ''
  if 'essid' in form:
    essid = form['essid'].value
    #cmds.append('cd /root && /root/scripts/action config WIFI_SSID=%s && cd %s'%(essid,dir))
    cmd = '%s%sWIFI_SSID=%s'%(cmd,opt,essid)
    opt = '&'
  currenc = gen.currval('WIFI_SEC').replace('"','')
  if ('newenc' in form):
    newenc = form['newenc'].value
    if newenc != currenc:
      cmd='%s%sWIFI_SEC=%s'%(cmd,opt,newenc.upper())
      opt = '&'

  if 'pass' in form:
    if 'newenc' in form:
      enc = form['newenc'].value
    else:
      enc = gen.currval('WIFI_SEC')
    passph = form['pass'].value
    cmd = '%s%sWIFI_PASS=%s'%(cmd,opt,passph)

  if cmd != '':
    cmd = '%s%s%s'%(cmdpre,cmd,cmdsuf)
    sql.insert('cmd','cmd',[0,cmd])
  else:
    print "<p>Nothing to update"
    return
  exec_cmd('Wireless Settings ')

def login():
  res = sql.read('val','webpass')
  if res[0][1] == None:
    sql.insert('val','webpass',gen.default_pass)
    res = [(0,gen.default_pass)]
  pwd = res[0][1]
  if pwd == form['pwd'].value:
    gen.login_refresh()
    latency = 0
    dest = 'main'
    msg = ''
  else:
    latency = 4
    dest = 'login'
    msg = '<p>Wrong Password! Going back to login page...'
  print "Content-Type: text/html"
  print
  print '<html>\
  <body>\
  <meta http-equiv="REFRESH" content="%s;url=%s.py">\n\
  %s\
  </html>\
  '%(latency,dest,msg)
 
def passwd():
  pwd = sql.read('val','webpass')[0][1]
  if pwd != form['opass'].value:
    gen.redirect(page='passwd',latency=3,msg='Error: Web password does not match record.') 
    return
  if form['npass1'].value != form['npass2'].value:
    gen.redirect(page='passwd',latency=3,msg='Error: New passwords do not match.') 
    return
  sql.modify('val','webpass',form['npass1'].value)
  print "<p>New password updated"
  
def privacy():
  try:
    dur = int(form['dur'].value)
    ctime = int(time.time())
    ntime = ctime + dur*60
    res = sql.read('val','privend')
    if res[0][0] == None:
      sql.insert('val','privend',ntime)
    else:
      sql.modify('val','privend',ntime)
    cmd = 'pgrep tie && killall tie'
    sql.insert('cmd','cmd',[0,cmd])
    ret = exec_cmd('Privacy Settings ')
    if ret:
      print "<p>Private mode enabled for %s minutes"%(dur)
    else:
      pass
  except:
    print "<p>Private mode not enabled"
   
def action():
  key = form['key'].value
  if key == 'login':
    login()
    return
  if gen.login_check() == False:
    gen.login_redirect()

  else:
    gen.print_header()
    if key == 'wifi':
      wifi()
    if key == 'privacy':
      privacy()
    if key == 'passwd':
      passwd()
    gen.print_footer()
    print '\
    </html>\
    '
form = cgi.FieldStorage()
action()
