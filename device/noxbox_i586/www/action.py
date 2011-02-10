#!/usr/bin/env python
import os
import sys
sys.path.append('cgi-bin')
import gen
import sql
import subprocess as sub
nfp = open('/dev/null','w')

def handle():
  print 'handling'
  res = sql.read('cmd','cmd')
  cmd = ''
  for rec in res:
    print rec[1]
    out = sub.Popen([rec[1]],shell=True,stdout=nfp,stderr=sub.PIPE).communicate()
    if len(out[1]) > 1:
      cmd = "insert into cmd (valid,valchar) values('err','%s:%s')"%(rec[1],out[1])
    else:
      cmd = "insert into cmd (valid,valchar) values('succ','%s')"%(rec[1])
    sql.run_sql_cmd(cmd)
    cmd = 'delete from cmd where valid = "cmd"'
    sql.run_sql_cmd(cmd)

if __name__ == '__main__':
  while 1:
    print 'in'
    gen.get_signal(gen.action_file)
    print 'got signal'
    fd = open(gen.if_file,'w')
    handle()
    print 'handled'
    fd.close()

