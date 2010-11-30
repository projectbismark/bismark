#!/usr/bin/env python
import os
import cgi
import cgitb
import gen

cgitb.enable()

if gen.login_check()  == False:
  gen.login_redirect()

else:
  gen.login_refresh()
  gen.print_header()
  print '\
  <p><a href=wifi.py>Change Wireless Settings</a>\
  <p><a href=privacy.py>Change Privacy Settings</a>\
  <p><a href=passwd.py>Change Web Password</a>\
  <p><a href=logout.py>Logout</a>\
  <p> IP %s\
  </html>\
  '%(os.environ['REMOTE_ADDR'])
  

