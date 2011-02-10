#!/usr/bin/env python
import cgi
import cgitb
import gen
import sql
import os

cgitb.enable()


res = sql.read('val','login:%s'%(os.environ['REMOTE_ADDR']))
if res[0][0] == None:
  sql.insert('val','login:%s'%(os.environ['REMOTE_ADDR']),0)
else:
  sql.modify('val','login:%s'%(os.environ['REMOTE_ADDR']),0)
gen.print_header()
print '\
Logged out successfully\
<p><a href=login.py>Log back in</a>\
</html>\
'

